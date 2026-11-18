//! Проверка результата отправки; не обеспечивает атомарность пачки пакетов.
use std::io;

/// Останавливается при ошибке или частичной отправке и возвращает ошибку.
/// Уже отправленные пакеты нельзя откатить; сетевой fallback здесь не реализован.
pub fn send_packets<F>(packets: &[Vec<u8>], mut send: F) -> io::Result<()>
where
    F: FnMut(&[u8]) -> io::Result<usize>,
{
    for packet in packets {
        let sent = send(packet)?;
        if sent != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "WinDivert отправил не весь пакет",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sends_in_order_and_checks_lengths() {
        let packets = vec![vec![1, 2], vec![3, 4, 5]];
        let mut seen = Vec::new();
        send_packets(&packets, |p| {
            seen.push(p.to_vec());
            Ok(p.len())
        })
        .unwrap();
        assert_eq!(seen, packets);
    }
    #[test]
    fn returns_error_and_stops_after_failed_or_partial_send() {
        let packets = vec![vec![1], vec![2], vec![3]];
        for partial in [false, true] {
            let mut calls = 0;
            let result = send_packets(&packets, |p| {
                calls += 1;
                if calls == 2 {
                    if partial {
                        Ok(0)
                    } else {
                        Err(io::Error::new(io::ErrorKind::Other, "test"))
                    }
                } else {
                    Ok(p.len())
                }
            });
            assert!(result.is_err());
            assert_eq!(calls, 2);
        }
    }
}
