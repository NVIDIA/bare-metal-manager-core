/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::vec;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::error::ResolveError;
use hickory_resolver::name_server::{ConnectionProvider, GenericConnector, RuntimeProvider};
use hickory_resolver::proto::TokioTime;
use hickory_resolver::proto::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::{AsyncResolver, Name, TokioHandle};
use hyper::service::Service;
use socket2::SockAddr;
use tokio::net::{TcpSocket, TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket};
use tracing::trace;

#[cfg(target_os = "linux")]
const MGMT_VRF_NAME: &[u8] = "mgmt".as_bytes();

type HickoryResolverFuture =
    Pin<Box<dyn Future<Output = Result<SocketAddrs, ResolveError>> + Send>>;

#[derive(Clone, Default)]
pub struct ForgeRuntimeProvider {
    handle: TokioHandle,
    use_mgmt_vrf: bool,
}

impl ForgeRuntimeProvider {
    pub fn new() -> Self {
        Self {
            handle: TokioHandle::default(),
            use_mgmt_vrf: false,
        }
    }
    #[must_use]
    pub fn use_mgmt_vrf(mut self, use_mgmt_frf: bool) -> Self {
        self.use_mgmt_vrf = use_mgmt_frf;
        self
    }

    pub fn create_ipv4_tcp_socket(use_mgmt: bool) -> std::io::Result<socket2::Socket> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        if use_mgmt {
            #[cfg(target_os = "linux")]
            socket.bind_device(Some(MGMT_VRF_NAME))?;
        }
        Ok(socket)
    }
    pub fn create_ipv4_udp_socket(use_mgmt: bool) -> std::io::Result<socket2::Socket> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_nonblocking(true)?;
        if use_mgmt {
            #[cfg(target_os = "linux")]
            socket.bind_device(Some(MGMT_VRF_NAME))?;
        }
        Ok(socket)
    }
}

impl RuntimeProvider for ForgeRuntimeProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = TokioUdpSocket;
    type Tcp = AsyncIoTokioAsStd<TokioTcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        if self.use_mgmt_vrf {
            let socket = match ForgeRuntimeProvider::create_ipv4_tcp_socket(true) {
                Ok(socket) => socket,
                Err(io_err) => {
                    return Box::pin(async move { Err(io_err) });
                }
            };

            Box::pin(async move {
                //  Set non_blocking which is required for Tokio::TcpSocket
                let raw_fd = socket.into_raw_fd();
                // This is safe because we own the raw_fd from socket.into_raw_fd()
                // Convert socket into a TokioTcpSocket
                let tcp_socket: TcpSocket = unsafe { TcpSocket::from_raw_fd(raw_fd) };

                tcp_socket.connect(server_addr).await.map(AsyncIoTokioAsStd)
            })
        } else {
            Box::pin(async move {
                // Without management VRF, we can just use the default TCP socket
                TokioTcpStream::connect(server_addr)
                    .await
                    .map(AsyncIoTokioAsStd)
            })
        }
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        if self.use_mgmt_vrf {
            let socket = match ForgeRuntimeProvider::create_ipv4_udp_socket(true) {
                Ok(socket) => socket,
                Err(io_err) => {
                    return Box::pin(async move { Err(io_err) });
                }
            };

            let sock_addr = SockAddr::from(local_addr);

            match socket.bind(&sock_addr) {
                Ok(_) => (),
                Err(io_err) => {
                    return Box::pin(async move { Err(io_err) });
                }
            }

            // Convert socket2::Socket -> UdpSocket
            let std_socket: std::net::UdpSocket = socket.into();
            // Convert std::net::UdpSocket to TokioUdpSocket
            let tokio_socket = match TokioUdpSocket::from_std(std_socket) {
                Ok(socket) => socket,
                Err(io_err) => {
                    return Box::pin(async move { Err(io_err) });
                }
            };

            Box::pin(async move { Ok(tokio_socket) })
        } else {
            // Without management VRF, we can just use the default UDP socket
            Box::pin(tokio::net::UdpSocket::bind(local_addr))
        }
    }
}

/// A hyper resolver using `hickory`'s [`TokioAsyncResolver`].
pub type ForgeResolver = HickoryResolver<ForgeTokioConnectionProvider>;

/// A [`hickory_resolver::name_server::ConnectionProvider`] for Tokio.
/// This allows us to set socket options on the sockets we create for DNS resolution.
pub type ForgeTokioConnectionProvider = GenericConnector<ForgeRuntimeProvider>;

#[derive(Clone, Debug, Default)]
pub struct ForgeResolverOpts {
    inner: ResolverOpts,
    use_mgmt_vrf: bool,
}

#[derive(Clone)]
pub struct HickoryResolver<C: ConnectionProvider> {
    resolver: Arc<AsyncResolver<C>>,
}

/// Iterator over DNS lookup results.
#[derive(Clone)]
pub struct SocketAddrs {
    iter: vec::IntoIter<SocketAddr>,
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl ForgeResolverOpts {
    pub fn new() -> Self {
        Self {
            inner: ResolverOpts::default(),
            use_mgmt_vrf: false,
        }
    }

    #[must_use]
    pub fn timeout(mut self, d: Duration) -> Self {
        self.inner.timeout = d;
        self
    }

    #[must_use]
    pub fn use_mgmt_vrf(mut self) -> Self {
        let ignore_mgmt_vrf = std::env::var("IGNORE_MGMT_VRF").is_ok();
        self.use_mgmt_vrf = !ignore_mgmt_vrf;
        self
    }
}

/// Get the default resolver options as configured per crate features.
/// This allows us to enable DNSSEC conditionally.
fn default_opts() -> ForgeResolverOpts {
    ForgeResolverOpts::default()
}

impl ForgeResolver {
    /// Create a new [`ForgeResolver`] with the default config options.
    /// This must be run inside a Tokio runtime context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new [`ForgeResolver`] with the resolver configuration
    /// options specified.
    /// This must be run inside a Tokio runtime context.
    //#[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn with_config_and_options(config: ResolverConfig, options: ForgeResolverOpts) -> Self {
        if options.use_mgmt_vrf {
            let rt = ForgeRuntimeProvider::new().use_mgmt_vrf(options.use_mgmt_vrf);
            let cp = ForgeTokioConnectionProvider::new(rt);
            let resolver = AsyncResolver::new(config, options.inner, cp);
            Self::from_async_resolver(resolver)
        } else {
            let rt = ForgeRuntimeProvider::new();
            let cp = ForgeTokioConnectionProvider::new(rt);
            let resolver = AsyncResolver::new(config, options.inner, cp);
            Self::from_async_resolver(resolver)
        }
    }
}

impl Default for ForgeResolver {
    fn default() -> Self {
        Self::with_config_and_options(ResolverConfig::default(), default_opts())
    }
}

impl<C: ConnectionProvider> HickoryResolver<C> {
    /// Create a [`HickoryResolver`] from the given [`AsyncResolver`]
    #[must_use]
    pub fn from_async_resolver(async_resolver: AsyncResolver<C>) -> Self {
        let resolver = Arc::new(async_resolver);

        Self { resolver }
    }
}

impl<C: ConnectionProvider> Service<Name> for HickoryResolver<C> {
    type Response = SocketAddrs;
    type Error = ResolveError;
    type Future = HickoryResolverFuture;

    fn call(&self, name: Name) -> Self::Future {
        let resolver = self.resolver.clone();

        Box::pin(async move {
            let response = resolver.lookup_ip(name.to_string()).await?;
            trace!("response from DNS Server{:?}", response);
            let addresses = response.into_iter();

            Ok(SocketAddrs {
                iter: addresses
                    .map(|ip_addr| SocketAddr::new(ip_addr, 0))
                    .collect::<Vec<_>>()
                    .into_iter(),
            })
        })
    }
}

impl SocketAddrs {
    pub(super) fn new(addrs: Vec<SocketAddr>) -> Self {
        SocketAddrs {
            iter: addrs.into_iter(),
        }
    }

    pub fn try_parse(host: &str, port: u16) -> Option<SocketAddrs> {
        if let Ok(addr) = host.parse::<Ipv4Addr>() {
            let addr = SocketAddrV4::new(addr, port);
            return Some(SocketAddrs {
                iter: vec![SocketAddr::V4(addr)].into_iter(),
            });
        }
        if let Ok(addr) = host.parse::<Ipv6Addr>() {
            let addr = SocketAddrV6::new(addr, port, 0, 0);
            return Some(SocketAddrs {
                iter: vec![SocketAddr::V6(addr)].into_iter(),
            });
        }
        None
    }

    #[inline]
    fn filter(self, predicate: impl FnMut(&SocketAddr) -> bool) -> SocketAddrs {
        SocketAddrs::new(self.iter.filter(predicate).collect())
    }

    pub(super) fn split_by_preference(
        self,
        local_addr_ipv4: Option<Ipv4Addr>,
        local_addr_ipv6: Option<Ipv6Addr>,
    ) -> (SocketAddrs, SocketAddrs) {
        match (local_addr_ipv4, local_addr_ipv6) {
            (Some(_), None) => (self.filter(SocketAddr::is_ipv4), SocketAddrs::new(vec![])),
            (None, Some(_)) => (self.filter(SocketAddr::is_ipv6), SocketAddrs::new(vec![])),
            _ => {
                let preferring_v6 = self
                    .iter
                    .as_slice()
                    .first()
                    .is_some_and(SocketAddr::is_ipv6);

                let (preferred, fallback) = self
                    .iter
                    .partition::<Vec<_>, _>(|addr| addr.is_ipv6() == preferring_v6);

                (SocketAddrs::new(preferred), SocketAddrs::new(fallback))
            }
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.iter.as_slice().is_empty()
    }

    pub(super) fn len(&self) -> usize {
        self.iter.as_slice().len()
    }
}
