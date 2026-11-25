//! Собственный localhost echo для ограниченной WinDivert-проверки.
//! Не содержит адресов внешних узлов, не доказывает обработку реального трафика.
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(3);
const REQUEST: &[u8] = b"UmbraNet localhost passthrough probe request";
const RESPONSE: &[u8] = b"UmbraNet localhost passthrough probe response";

pub(super) fn filter(port: u16) -> io::Result<String> {
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Нулевой порт проверки",
        ));
    }
    Ok(format!("loopback and outbound and !impostor and ip and tcp and ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.1 and tcp.DstPort == {port}"))
}

pub(super) fn listener() -> io::Result<TcpListener> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

pub(super) fn exchange(listener: &TcpListener) -> io::Result<()> {
    let port = listener.local_addr()?.port();
    let endpoint = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let mut client = TcpStream::connect_timeout(&endpoint, WAIT)?;
    client.set_read_timeout(Some(WAIT))?;
    client.set_write_timeout(Some(WAIT))?;
    client.set_nodelay(true)?;
    let until = Instant::now() + WAIT;
    let mut server = loop {
        match listener.accept() {
            Ok((stream, peer))
                if peer.ip().is_loopback() && peer.port() == client.local_addr()?.port() =>
            {
                break stream
            }
            Ok(_) => return Err(io::Error::other("Неожиданное соединение с тестовым портом")),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Тестовое соединение не принято",
                ))
            }
            Err(error) => return Err(error),
        }
    };
    server.set_read_timeout(Some(WAIT))?;
    server.set_write_timeout(Some(WAIT))?;
    server.set_nodelay(true)?;
    client.write_all(REQUEST)?;
    let mut request = vec![0; REQUEST.len()];
    server.read_exact(&mut request)?;
    if request != REQUEST {
        return Err(io::Error::other("Тестовый запрос изменился"));
    }
    server.write_all(RESPONSE)?;
    let mut response = vec![0; RESPONSE.len()];
    client.read_exact(&mut response)?;
    if response != RESPONSE {
        return Err(io::Error::other("Тестовый ответ изменился"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn filter_requires_nonzero_port_and_limits_direction_and_address() {
        assert!(super::filter(0).is_err());
        let filter = super::filter(54321).unwrap();
        assert!(filter.contains("loopback and outbound and !impostor"));
        assert!(filter.contains("ip.SrcAddr == 127.0.0.1"));
        assert!(filter.contains("ip.DstAddr == 127.0.0.1"));
        assert!(filter.contains("tcp.DstPort == 54321"));
    }
    #[test]
    fn echo_is_confined_to_a_local_ephemeral_listener() {
        let listener = super::listener().unwrap();
        assert!(listener.local_addr().unwrap().ip().is_loopback());
        assert_ne!(listener.local_addr().unwrap().port(), 0);
        super::exchange(&listener).unwrap();
    }
}
