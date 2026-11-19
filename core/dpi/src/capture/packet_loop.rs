//! Цикл активного канала, включая вычитывание очереди после Shutdown(RECV).
//! Это не гарантирует доставку пакетов и не снимает предохранитель запуска.
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

const ERROR_NO_DATA: i32 = 232;

pub(crate) trait PacketChannel {
    type Address: Copy;
    fn receive_packet(&self) -> io::Result<(Vec<u8>, Self::Address)>;
    fn send_packet(&self, packet: &[u8], address: &Self::Address) -> io::Result<usize>;
}

/// Владелец обязан сначала установить stop=true, затем вызвать Shutdown(RECV).
/// После этого цикл продолжает возвращать оригиналы вплоть до ERROR_NO_DATA.
/// Отдельно требуется подтвердить успешный Shutdown, завершение потока и закрытие.
/// Ошибки отправки/приёма не приравниваются к успешному опустошению очереди.
pub(crate) fn run<C: PacketChannel>(
    channel: &C,
    stop: &AtomicBool,
    mut process: impl FnMut(&[u8], &C::Address) -> Vec<Vec<u8>>,
) -> io::Result<()> {
    loop {
        let (raw, address) = match channel.receive_packet() {
            Ok(value) => value,
            Err(error)
                if error.raw_os_error() == Some(ERROR_NO_DATA) && stop.load(Ordering::Acquire) =>
            {
                return Ok(())
            }
            Err(error) => return Err(error),
        };
        if raw.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WinDivert вернул пустой пакет",
            ));
        }
        if stop.load(Ordering::Acquire) {
            crate::traffic::reinject::send_packets(&[raw], |packet| {
                channel.send_packet(packet, &address)
            })?;
            continue;
        }
        let processed = process(&raw, &address);
        // Если остановка пришла во время расчёта, вернуть оригинал вместо новых изменений.
        // При уже начавшейся отправке пачки откат невозможен.
        if stop.load(Ordering::Acquire) {
            crate::traffic::reinject::send_packets(&[raw], |packet| {
                channel.send_packet(packet, &address)
            })?;
        } else {
            if processed.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Обработка не вернула пакеты",
                ));
            }
            crate::traffic::reinject::send_packets(&processed, |packet| {
                channel.send_packet(packet, &address)
            })?;
        }
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
impl PacketChannel for super::windivert::DivertChannel {
    type Address = super::address::WinDivertAddress;
    fn receive_packet(&self) -> io::Result<(Vec<u8>, Self::Address)> {
        self.receive()
    }
    fn send_packet(&self, packet: &[u8], address: &Self::Address) -> io::Result<usize> {
        self.send(packet, address).map(|n| n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
    };
    struct Channel {
        queue: RefCell<VecDeque<io::Result<(Vec<u8>, u32)>>>,
        sent: RefCell<Vec<(Vec<u8>, u32)>>,
        partial: Cell<bool>,
    }
    impl Channel {
        fn new(queue: Vec<io::Result<(Vec<u8>, u32)>>) -> Self {
            Self {
                queue: RefCell::new(queue.into()),
                sent: RefCell::new(vec![]),
                partial: Cell::new(false),
            }
        }
    }
    impl PacketChannel for Channel {
        type Address = u32;
        fn receive_packet(&self) -> io::Result<(Vec<u8>, u32)> {
            self.queue
                .borrow_mut()
                .pop_front()
                .expect("missing test receive")
        }
        fn send_packet(&self, p: &[u8], a: &u32) -> io::Result<usize> {
            self.sent.borrow_mut().push((p.to_vec(), *a));
            Ok(if self.partial.get() { 0 } else { p.len() })
        }
    }
    fn no_data() -> io::Result<(Vec<u8>, u32)> {
        Err(io::Error::from_raw_os_error(ERROR_NO_DATA))
    }
    #[test]
    fn stop_drains_originals_and_preserves_address() {
        let c = Channel::new(vec![Ok((vec![1], 10)), Ok((vec![2], 11)), no_data()]);
        let stop = AtomicBool::new(true);
        run(&c, &stop, |_, _| panic!("draining must not modify")).unwrap();
        assert_eq!(*c.sent.borrow(), vec![(vec![1], 10), (vec![2], 11)]);
    }
    #[test]
    fn stop_during_processing_returns_original() {
        let c = Channel::new(vec![Ok((vec![1], 9)), no_data()]);
        let stop = AtomicBool::new(false);
        run(&c, &stop, |_, _| {
            stop.store(true, Ordering::Release);
            vec![vec![99]]
        })
        .unwrap();
        assert_eq!(*c.sent.borrow(), vec![(vec![1], 9)]);
    }
    #[test]
    fn unexpected_eof_and_receive_failures_are_errors_even_when_stopping() {
        for (set, code) in [(false, 232), (true, 5)] {
            let c = Channel::new(vec![Err(io::Error::from_raw_os_error(code))]);
            assert_eq!(
                run(&c, &AtomicBool::new(set), |_, _| vec![])
                    .unwrap_err()
                    .raw_os_error(),
                Some(code)
            );
        }
    }
    #[test]
    fn partial_send_and_empty_results_fail_instead_of_claiming_drain() {
        let c = Channel::new(vec![Ok((vec![1], 0))]);
        c.partial.set(true);
        assert_eq!(
            run(&c, &AtomicBool::new(true), |_, _| vec![])
                .unwrap_err()
                .kind(),
            io::ErrorKind::WriteZero
        );
        let c = Channel::new(vec![Ok((vec![1], 0))]);
        assert_eq!(
            run(&c, &AtomicBool::new(false), |_, _| vec![])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[test]
    fn normal_processing_sends_in_order_until_error() {
        let c = Channel::new(vec![Ok((vec![1], 7)), no_data()]);
        let result = run(&c, &AtomicBool::new(false), |_, _| vec![vec![2], vec![3]]);
        assert!(result.is_err());
        assert_eq!(*c.sent.borrow(), vec![(vec![2], 7), (vec![3], 7)]);
    }
}
