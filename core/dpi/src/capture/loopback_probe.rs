//! Ручной Windows smoke-test только для собственного IPv4 localhost TCP.
//! Это активный перехват, а не SNIFF: временно изымает и возвращает пакеты.
//! Он НЕ проверяет внешний интернет, потери/LSO, безопасность или работу DPI.
use super::packet_loop::{self, PacketChannel};
use super::windivert::{DivertChannel, WinDivertAddress};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

const WAIT_FOR_WORKER: Duration = Duration::from_secs(5);
#[derive(Debug)]
pub struct Outcome {
    pub packets_received: u64,
    pub packets_returned: u64,
}
struct Counts {
    received: AtomicU64,
    returned: AtomicU64,
}
struct Counted {
    channel: Arc<DivertChannel>,
    counts: Arc<Counts>,
}
impl PacketChannel for Counted {
    type Address = WinDivertAddress;
    fn receive_packet(&self) -> io::Result<(Vec<u8>, Self::Address)> {
        let result = self.channel.receive()?;
        self.counts.received.fetch_add(1, Ordering::Relaxed);
        Ok(result)
    }
    fn send_packet(&self, packet: &[u8], address: &Self::Address) -> io::Result<usize> {
        let sent = self.channel.send(packet, address)? as usize;
        if sent == packet.len() {
            self.counts.returned.fetch_add(1, Ordering::Relaxed);
        }
        Ok(sent)
    }
}

/// Только loopback/IPv4/собственный локальный порт, без сохранения пакетов.
/// Возможны ошибка, временная потеря тестовых пакетов и запуск общей службы
/// WinDivert. Не останавливает общую службу и не доказывает её выгрузку.
/// Ошибки cleanup всегда возвращаются, даже если echo было успешным.
pub fn run(dll_path: &Path) -> Result<Outcome, String> {
    let listener = super::loopback_exchange::listener()
        .map_err(|e| format!("Не удалось занять локальный порт: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Не удалось получить тестовый порт: {e}"))?
        .port();
    let channel = Arc::new(
        DivertChannel::open_loopback_probe(dll_path, port)
            .map_err(|e| format!("Не удалось открыть WinDivert для loopback-проверки: {e}"))?,
    );
    let stop = Arc::new(AtomicBool::new(false));
    let counts = Arc::new(Counts {
        received: AtomicU64::new(0),
        returned: AtomicU64::new(0),
    });
    let counted = Counted {
        channel: channel.clone(),
        counts: counts.clone(),
    };
    let thread_stop = stop.clone();
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let worker = match std::thread::Builder::new()
        .name("umbra-loopback-probe".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // Только неизменённый пакет и исходный WINDIVERT_ADDRESS.
                packet_loop::run(&counted, &thread_stop, |raw, _| vec![raw.to_vec()])
            }));
            let result = match result {
                Ok(r) => r.map_err(|e| e.to_string()),
                Err(_) => Err("panic тестового потока".into()),
            };
            let _ = done_tx.send(result);
        }) {
        Ok(worker) => worker,
        Err(error) => {
            let shutdown = channel.shutdown();
            let close = channel.close_checked();
            return Err(format!(
                "Не удалось создать тестовый поток: {error}; shutdown: {}; close: {}",
                describe(&shutdown),
                describe(&close)
            ));
        }
    };
    let exchange = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        super::loopback_exchange::exchange(&listener)
    }))
    .unwrap_or_else(|_| Err(io::Error::other("panic тестового обмена")));
    stop.store(true, Ordering::Release);
    let shutdown = channel.shutdown();
    let thread_result = match done_rx.recv_timeout(WAIT_FOR_WORKER) {
        Ok(result) => result,
        Err(error) => {
            // Не закрываем handle, пока receive/send возможно выполняются.
            // Дочерний тестовый процесс должен завершиться: результат НЕ успешен.
            return Err(format!("Поток loopback-проверки не завершён ({error}); shutdown: {}; закрытие не подтверждено", describe(&shutdown)));
        }
    };
    let joined = worker.join();
    let close = channel.close_checked();
    let received = counts.received.load(Ordering::Relaxed);
    let returned = counts.returned.load(Ordering::Relaxed);
    if exchange.is_err()
        || shutdown.is_err()
        || thread_result.is_err()
        || joined.is_err()
        || close.is_err()
        || received == 0
        || returned != received
    {
        return Err(format!("Loopback-проверка не подтверждена: обмен {}; shutdown {}; поток {}; join {}; close {}; получено {received}, возвращено {returned}",
            describe(&exchange), describe(&shutdown), thread_result.err().unwrap_or_else(|| "ok".into()),
            if joined.is_ok() { "ok" } else { "panic" }, describe(&close)));
    }
    Ok(Outcome {
        packets_received: received,
        packets_returned: returned,
    })
}
fn describe(result: &io::Result<()>) -> String {
    result
        .as_ref()
        .err()
        .map_or_else(|| "ok".into(), ToString::to_string)
}
