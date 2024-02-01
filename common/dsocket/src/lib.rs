use socket2::Socket;
use std::io;
use std::os::fd::{FromRawFd, IntoRawFd};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
use tracing::trace;

pub struct Dsocket {
    inner: socket2::Socket,
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
const VRF_NAME: &str = "mgmt";

pub enum SocketProtocol {
    Tcp,
    Udp,
}

impl TryFrom<Dsocket> for TcpSocket {
    type Error = io::Error;

    fn try_from(socket: Dsocket) -> Result<Self, io::Error> {
        let new_sock = socket.inner;
        new_sock.set_nonblocking(true)?;
        // Safety: `from_raw_fd` is only safe to call if ownership of the raw
        // file descriptor is transferred. Since we call `into_raw_fd` on the
        // socket2 socket, it gives up ownership of the fd and will not close
        // it, so this is safe.
        let fs = new_sock.into_raw_fd();
        let sock = unsafe { TcpSocket::from_raw_fd(fs) };
        Ok(sock)
    }
}

impl TryFrom<Dsocket> for TcpStream {
    type Error = io::Error;

    fn try_from(socket: Dsocket) -> Result<Self, Self::Error> {
        TcpStream::from_std(socket.inner.into())
    }
}

impl AsRef<Socket> for Dsocket {
    fn as_ref(&self) -> &Socket {
        &self.inner
    }
}

impl TryFrom<Dsocket> for UdpSocket {
    type Error = io::Error;

    fn try_from(socket: Dsocket) -> Result<Self, Self::Error> {
        let new_sock = socket.inner;
        new_sock.set_nonblocking(true)?;
        UdpSocket::from_std(new_sock.into())
    }
}

impl Dsocket {
    #[must_use]
    pub fn into_inner(self) -> socket2::Socket {
        self.inner
    }

    /// Convenience method to set `O_NONBLOCKING`. When converting to `tokio::net::Socket`
    /// from socket2 the caller is responsible for setting nonblocking on the socket.
    ///
    /// # Errors
    ///
    /// Return an `io::Error` if the underlying socket2 call fails.
    pub fn set_nonblocking(&self) -> Result<(), io::Error> {
        self.inner.set_nonblocking(true)
    }

    /// Convenience method to set `SO_REUSEADDR` on underlying socket2 for `DpulyfeSocket`
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the underlying socket2 call fails.
    pub fn set_reuse_address(&self) -> Result<(), io::Error> {
        self.inner.set_reuse_address(true)
    }

    /// Convenience method to set `SO_MARK` on underlying socket2 for `DpulyfeSocket`
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the kernel does not support the `SO_MARK` option.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn set_mark(&self, mark: u32) -> Result<(), io::Error> {
        self.inner.set_mark(mark)
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    pub fn set_mark(&self, _mark: u32) -> Result<(), io::Error> {
        Ok(())
    }

    /// Convenience method to set `SO_BINDTODEVICE` on underlying socket2 for `DpulyfeSocket`
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the underlying socket2 cannot bind to the specified interface.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn bind_device(&self, interface: Option<&[u8]>) -> Result<(), io::Error> {
        self.inner.bind_device(interface)
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    pub fn bind_device(&self, _interface: Option<&[u8]>) -> Result<(), io::Error> {
        Ok(())
    }

    /// Set `SO_BINDddODEVICE`, `O_NONBLOCKING` and `SO_REUSEADDR` on underlying socket2
    /// This is intended to be followed by a `into_inner()` to convert to a `socket2::Socket`
    ///
    /// # Errors
    ///
    /// Returns and `io::Error` if any of the underlying socket2 calls fail.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fn use_mgmt_vrf(&self) -> Result<(), io::Error> {
        trace!("Using SO_BINDTODEVICE to bind to mgmt VRF");
        self.bind_device(Some(VRF_NAME.as_bytes()))?;
        self.set_reuse_address()?;
        self.set_nonblocking()
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    pub fn use_mgmt_vrf(&self) -> Result<(), io::Error> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    /// Convenience method to create a new IPv6 TCP Socket
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if unable to create a new socket
    pub fn new_ipv6_tcp() -> Result<Dsocket, io::Error> {
        Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)
            .map(|socket| Dsocket { inner: socket })
    }

    /// Convenience method to create a new IPv6 UDP Socket
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if unable to create a new socket
    pub fn new_ipv6_udp() -> Result<Dsocket, io::Error> {
        Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)
            .map(|socket| Dsocket { inner: socket })
    }

    /// Convenience method to create a new IPv4 TCP Socket
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if unable to create a new socket  
    pub fn new_ipv4_tcp() -> Result<Dsocket, io::Error> {
        Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
            .map(|socket| Dsocket { inner: socket })
    }

    /// Convenience method to create a new IPv4 UDP Socket
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if unable to create a new socket  
    pub fn new_ipv4_udp() -> Result<Dsocket, io::Error> {
        Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
            .map(|socket| Dsocket { inner: socket })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{Interest, Ready};
    use tokio::net::TcpStream;
    use tokio::runtime;

    #[test]
    fn into_inner() {
        let socket = Dsocket::new_ipv4_tcp().unwrap();
        let inner = socket.into_inner();
        let domain = inner.domain().unwrap();
        assert_eq!(domain, socket2::Domain::IPV4);
    }
    #[test]
    fn into_tokio_udp_socket() {
        let rt = runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_stack_size(8 * 1024 * 1024)
            .worker_threads(2)
            .max_blocking_threads(2)
            .build()
            .unwrap();
        let socket = Dsocket::new_ipv4_udp().unwrap();
        rt.spawn(async move {
            let tokio_socket: UdpSocket = socket.try_into().unwrap();
            assert!(tokio_socket.local_addr().unwrap().is_ipv4());
        });
    }

    #[test]
    fn into_tcp_stream() {
        let rt = runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_stack_size(8 * 1024 * 1024)
            .worker_threads(2)
            .max_blocking_threads(2)
            .build()
            .unwrap();
        rt.spawn(async move {
            let socket = Dsocket::new_ipv4_tcp().unwrap();
            let stream: TcpStream = socket.try_into().unwrap();
            assert_eq!(
                stream.ready(Interest::READABLE).await.unwrap(),
                Ready::READABLE
            );
        });
    }
    #[test]
    fn into_tokio_tcp_socket() {
        let rt = runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_stack_size(8 * 1024 * 1024)
            .worker_threads(2)
            .max_blocking_threads(2)
            .build()
            .unwrap();
        rt.spawn(async move {
            let socket = Dsocket::new_ipv4_tcp().unwrap();
            let tokio_socket: TcpSocket = socket.try_into().unwrap();
            assert!(tokio_socket
                .bind(tokio_socket.local_addr().unwrap())
                .is_ok());
        });
    }

    #[test]
    fn non_blocking() {
        let socket = Dsocket::new_ipv4_tcp().unwrap();
        socket.set_nonblocking().unwrap();
        assert!(socket.inner.nonblocking().unwrap());
    }
}
