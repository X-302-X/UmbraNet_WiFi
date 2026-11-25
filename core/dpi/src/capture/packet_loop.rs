//! Цикл активного канала, включая вычитывание очереди после Shutdown(RECV).
//! Это не гарантирует доставку пакетов и не снимает предохранитель запуска.
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};

const ERROR_NO_DATA: i32 = 232;

pub(crate) trait PacketChannel {
    type Address: Copy;
    fn receive_packet(&self) -> io::Result<(Vec<u8>, Self::Address)>;
    fn send_packet(&self, packet: &[u8], address: &Self::Address) -> io::Result<usize>;
}

/// При неудачной подготовке пачки, пока ничего ещё не отправлено, один раз
/// пытаемся вернуть исходный пакет. Даже успешный Send не доказывает доставку.
fn return_original_after_processing_error<C: PacketChannel>(
    channel: &C,
    raw: Vec<u8>,
    address: &C::Address,
    error: io::Error,
) -> io::Error {
    match crate::traffic::reinject::send_packets(&[raw], |packet| {
        channel.send_packet(packet, address)
    }) {
        Ok(()) => error,
        Err(send_error) => io::Error::new(
            send_error.kind(),
            format!("{error}; не удалось вернуть исходный пакет: {send_error}"),
        ),
    }
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
        // После panic внутреннее состояние обработчика может быть повреждено:
        // возвращаем оригинал один раз и завершаем поток с ошибкой, не продолжая его.
        // При panic=abort перехват невозможен.
        let processed = match catch_unwind(AssertUnwindSafe(|| process(&raw, &address))) {
            Ok(packets) => packets,
            Err(_) => {
                return Err(return_original_after_processing_error(
                    channel,
                    raw,
                    &address,
                    io::Error::other("Обработчик DPI завершился с panic"),
                ));
            }
        };
        // Если остановка пришла во время расчёта, вернуть оригинал вместо новых изменений.
        // При уже начавшейся отправке пачки откат невозможен.
        if stop.load(Ordering::Acquire) {
            crate::traffic::reinject::send_packets(&[raw], |packet| {
                channel.send_packet(packet, &address)
            })?;
        } else {
            // Проверяем ВСЮ пачку до первой отправки: после частичной отправки
            // повтор исходника может создать дубли или повредить поток.
            if processed.is_empty() || processed.iter().any(Vec::is_empty) {
                return Err(return_original_after_processing_error(
                    channel,
                    raw,
                    &address,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Обработка вернула пустую или некорректную пачку",
                    ),
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
    fn processing_panic_returns_original_once_and_stops_with_error() {
        let channel = Channel::new(vec![Ok((vec![1, 2, 3], 42))]);
        let result = run(&channel, &AtomicBool::new(false), |_, _| -> Vec<Vec<u8>> {
            panic!("processor failure")
        });
        assert!(result.unwrap_err().to_string().contains("panic"));
        assert_eq!(*channel.sent.borrow(), vec![(vec![1, 2, 3], 42)]);
    }
    #[test]
    fn malformed_batches_are_rejected_before_sending_any_modified_packet() {
        for output in [vec![], vec![vec![9], vec![]], vec![vec![], vec![9]]] {
            let channel = Channel::new(vec![Ok((vec![1, 2], 19))]);
            let result = run(&channel, &AtomicBool::new(false), |_, _| output.clone());
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert_eq!(*channel.sent.borrow(), vec![(vec![1, 2], 19)]);
        }
    }
    #[test]
    fn fallback_send_failure_preserves_both_errors_without_retry() {
        let channel = Channel::new(vec![Ok((vec![1], 3))]);
        channel.partial.set(true);
        let error = run(&channel, &AtomicBool::new(false), |_, _| vec![]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert!(error.to_string().contains("пустую"));
        assert!(error
            .to_string()
            .contains("не удалось вернуть исходный пакет"));
        assert_eq!(*channel.sent.borrow(), vec![(vec![1], 3)]);
    }
    #[test]
    fn processing_panic_during_stop_is_not_hidden_by_drain() {
        let channel = Channel::new(vec![Ok((vec![1], 7))]);
        let stop = AtomicBool::new(false);
        let error = run(&channel, &stop, |_, _| -> Vec<Vec<u8>> {
            stop.store(true, Ordering::Release);
            panic!("processing panic during stop")
        })
        .unwrap_err();
        assert!(error.to_string().contains("panic"));
        assert_eq!(*channel.sent.borrow(), vec![(vec![1], 7)]);
    }
    #[test]
    fn failed_modified_send_never_retries_original() {
        let channel = Channel::new(vec![Ok((vec![1], 7))]);
        channel.partial.set(true);
        let error = run(&channel, &AtomicBool::new(false), |_, _| {
            vec![vec![9], vec![8]]
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert_eq!(*channel.sent.borrow(), vec![(vec![9], 7)]);
    }
    #[test]
    fn later_send_failure_does_not_duplicate_an_already_sent_fragment() {
        struct FailSecond {
            receives: Cell<usize>,
            sent: RefCell<Vec<(Vec<u8>, u32)>>,
        }
        impl PacketChannel for FailSecond {
            type Address = u32;
            fn receive_packet(&self) -> io::Result<(Vec<u8>, u32)> {
                assert_eq!(self.receives.replace(1), 0);
                Ok((vec![1, 2, 3], 17))
            }
            fn send_packet(&self, packet: &[u8], address: &u32) -> io::Result<usize> {
                let mut sent = self.sent.borrow_mut();
                sent.push((packet.to_vec(), *address));
                if sent.len() == 2 {
                    Err(io::Error::other("вторая отправка не удалась"))
                } else {
                    Ok(packet.len())
                }
            }
        }
        let channel = FailSecond {
            receives: Cell::new(0),
            sent: RefCell::new(vec![]),
        };
        let error = run(&channel, &AtomicBool::new(false), |_, _| {
            vec![vec![9], vec![8], vec![7]]
        })
        .unwrap_err();
        assert!(error.to_string().contains("вторая отправка"));
        assert_eq!(*channel.sent.borrow(), vec![(vec![9], 17), (vec![8], 17)]);
    }
    #[test]
    fn normal_processing_sends_in_order_until_error() {
        let c = Channel::new(vec![Ok((vec![1], 7)), no_data()]);
        let result = run(&c, &AtomicBool::new(false), |_, _| vec![vec![2], vec![3]]);
        assert!(result.is_err());
        assert_eq!(*c.sent.borrow(), vec![(vec![2], 7), (vec![3], 7)]);
    }
}
