use core::cmp::min;
use managed::ManagedSlice;

use {Error, Result};
use wire::{IpProtocol, IpRepr, IpEndpoint, UdpRepr};
use socket::{Socket, SocketMeta, SocketHandle};
use storage::RingBuffer;

// Endpoint and size of an UDP packet.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketMetadata {
    endpoint: IpEndpoint,
    payload_size: usize,
    /// Dummy packets can be used to avoid wrap-arounds of packets in the payload buffer
    dummy: bool,
}

/// An UDP packet ring buffer.
#[derive(Debug)]
pub struct SocketBuffer<'a> {
    metadata_buffer: RingBuffer<'a, PacketMetadata>,
    payload_buffer: RingBuffer<'a, u8>,
}

impl<'a> SocketBuffer<'a> {
    /// Create a new socket buffer with the provided metadata and payload storage.
    ///
    /// Metadata storage limits the maximum _number_ of UDP packets in the buffer and payload
    /// storage limits the maximum _cumulated size_ of UDP packets.
    pub fn new<MS, PS>(metadata_storage: MS, payload_storage: PS) -> SocketBuffer<'a>
        where MS: Into<ManagedSlice<'a, PacketMetadata>>, PS: Into<ManagedSlice<'a, u8>>,
    {
        SocketBuffer {
            metadata_buffer: RingBuffer::new(metadata_storage),
            payload_buffer: RingBuffer::new(payload_storage),
        }
    }

    fn is_full(&self) -> bool {
        self.metadata_buffer.is_full() || self.payload_buffer.is_full()
    }

    fn is_empty(&self) -> bool {
        self.metadata_buffer.is_empty() || self.payload_buffer.is_empty()
    }
}

/// An User Datagram Protocol socket.
///
/// An UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
#[derive(Debug)]
pub struct UdpSocket<'a> {
    pub(crate) meta: SocketMeta,
    endpoint:  IpEndpoint,
    rx_buffer: SocketBuffer<'a>,
    tx_buffer: SocketBuffer<'a>,
    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>
}

impl<'a> UdpSocket<'a> {
    /// Create an UDP socket with the given buffers.
    pub fn new(rx_buffer: SocketBuffer<'a>,
               tx_buffer: SocketBuffer<'a>) -> UdpSocket<'a> {
        UdpSocket {
            meta:      SocketMeta::default(),
            endpoint:  IpEndpoint::default(),
            rx_buffer: rx_buffer,
            tx_buffer: tx_buffer,
            hop_limit: None
        }
    }

    /// Return the socket handle.
    #[inline]
    pub fn handle(&self) -> SocketHandle {
        self.meta.handle
    }

    /// Return the bound endpoint.
    #[inline]
    pub fn endpoint(&self) -> IpEndpoint {
        self.endpoint
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method
    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        // A host MUST NOT send a datagram with a hop limit value of 0
        if let Some(0) = hop_limit {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.hop_limit = hop_limit
    }

    /// Bind the socket to the given endpoint.
    ///
    /// This function returns `Err(Error::Illegal)` if the socket was open
    /// (see [is_open](#method.is_open)), and `Err(Error::Unaddressable)`
    /// if the port in the given endpoint is zero.
    pub fn bind<T: Into<IpEndpoint>>(&mut self, endpoint: T) -> Result<()> {
        let endpoint = endpoint.into();
        if endpoint.port == 0 { return Err(Error::Unaddressable) }

        if self.is_open() { return Err(Error::Illegal) }

        self.endpoint = endpoint;
        Ok(())
    }

    /// Check whether the socket is open.
    #[inline]
    pub fn is_open(&self) -> bool {
        self.endpoint.port != 0
    }

    /// Check whether the transmit buffer is full.
    #[inline]
    pub fn can_send(&self) -> bool {
        !self.tx_buffer.is_full()
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.is_empty()
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and return a pointer
    /// to its payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the transmit buffer is full,
    /// `Err(Error::Truncated)` if the requested size is larger than the payload buffer
    /// size, and `Err(Error::Unaddressable)` if local or remote port, or remote address,
    /// are unspecified.
    pub fn send(&mut self, size: usize, endpoint: IpEndpoint) -> Result<&mut [u8]> {
        if self.endpoint.port == 0 { return Err(Error::Unaddressable) }
        if !endpoint.is_specified() { return Err(Error::Unaddressable) }

        if self.tx_buffer.payload_buffer.capacity() < size {
            return Err(Error::Truncated);
        }

        if self.tx_buffer.metadata_buffer.is_full() || self.tx_buffer.payload_buffer.window() < size {
            return Err(Error::Exhausted);
        }

        if self.tx_buffer.payload_buffer.contiguous_window() < size {
            // we reached the end of buffer, so the data does not fit without wrap-around
            // -> insert dummy and try again
            self.tx_buffer.payload_buffer.enqueue_many(size);
            let metadata_buf = self.tx_buffer.metadata_buffer.enqueue_one()?;
            metadata_buf.dummy = true;
        }

        if self.tx_buffer.metadata_buffer.is_full() || self.tx_buffer.payload_buffer.window() < size {
            return Err(Error::Exhausted);
        }

        let payload_buf = self.tx_buffer.payload_buffer.enqueue_many(size);
        assert_eq!(payload_buf.len(), size);

        let metadata_buf = self.tx_buffer.metadata_buffer.enqueue_one()?;
        metadata_buf.endpoint = endpoint;
        metadata_buf.payload_size = size;
        metadata_buf.dummy = false;

        net_trace!("{}:{}:{}: buffer to send {} octets",
                   self.meta.handle, self.endpoint, metadata_buf.endpoint, size);
        Ok(payload_buf)
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(&mut self, data: &[u8], endpoint: IpEndpoint) -> Result<()> {
        self.send(data.len(), endpoint)?.copy_from_slice(data);
        Ok(())
    }

    /// Dequeue a packet received from a remote endpoint, and return the endpoint as well
    /// as a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<(&[u8], IpEndpoint)> {
        let mut metadata_buf = *self.rx_buffer.metadata_buffer.dequeue_one()?;
        if metadata_buf.dummy {
            // packet is dummy packet -> drop it and try again
            self.rx_buffer.payload_buffer.dequeue_many(metadata_buf.payload_size);
            metadata_buf = *self.rx_buffer.metadata_buffer.dequeue_one()?;
        }

        assert!(!metadata_buf.dummy);
        let payload_buf = self.rx_buffer.payload_buffer.dequeue_many(metadata_buf.payload_size);
        assert_eq!(metadata_buf.payload_size, payload_buf.len()); // ensured by inserting logic

        net_trace!("{}:{}:{}: receive {} buffered octets",
                   self.meta.handle, self.endpoint,
                metadata_buf.endpoint, metadata_buf.payload_size);
        Ok((payload_buf, metadata_buf.endpoint))
    }

    /// Dequeue a packet received from a remote endpoint, copy the payload into the given slice,
    /// and return the amount of octets copied as well as the endpoint.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<(usize, IpEndpoint)> {
        let (buffer, endpoint) = self.recv()?;
        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, endpoint))
    }

    pub(crate) fn accepts(&self, ip_repr: &IpRepr, repr: &UdpRepr) -> bool {
        if self.endpoint.port != repr.dst_port { return false }
        if !self.endpoint.addr.is_unspecified() &&
           self.endpoint.addr != ip_repr.dst_addr() { return false }

        true
    }

    pub(crate) fn process(&mut self, ip_repr: &IpRepr, repr: &UdpRepr) -> Result<()> {
        debug_assert!(self.accepts(ip_repr, repr));

        let size = repr.payload.len();

        if self.rx_buffer.payload_buffer.capacity() < size {
            return Err(Error::Truncated);
        }

        if self.rx_buffer.metadata_buffer.is_full() || self.rx_buffer.payload_buffer.window() < size {
            return Err(Error::Exhausted);
        }

        if self.rx_buffer.payload_buffer.contiguous_window() < size {
            // we reached the end of buffer, so the data does not fit without wrap-around
            // -> insert dummy and try again
            self.rx_buffer.payload_buffer.enqueue_many(size);
            let metadata_buf = self.rx_buffer.metadata_buffer.enqueue_one()?;
            metadata_buf.dummy = true;
        }

        if self.rx_buffer.metadata_buffer.is_full() || self.rx_buffer.payload_buffer.window() < size {
            return Err(Error::Exhausted);
        }

        let payload_buf = self.rx_buffer.payload_buffer.enqueue_many(size);
        assert_eq!(payload_buf.len(), size);

        let metadata_buf = self.rx_buffer.metadata_buffer.enqueue_one()?;
        metadata_buf.endpoint = IpEndpoint { addr: ip_repr.src_addr(), port: repr.src_port };
        metadata_buf.payload_size = size;
        metadata_buf.dummy = false;
        payload_buf.copy_from_slice(repr.payload);

        net_trace!("{}:{}:{}: receiving {} octets",
                   self.meta.handle, self.endpoint,
                   metadata_buf.endpoint, metadata_buf.payload_size);
        Ok(())
    }

    pub(crate) fn dispatch<F>(&mut self, emit: F) -> Result<()>
            where F: FnOnce((IpRepr, UdpRepr)) -> Result<()> {
        let handle   = self.handle();
        let endpoint = self.endpoint;
        let hop_limit = self.hop_limit.unwrap_or(64);

        let SocketBuffer { ref mut metadata_buffer, ref mut payload_buffer } = self.tx_buffer;

        // dequeue potential dummy
        let result = metadata_buffer.dequeue_one_with(|metadata_buf| {
            if metadata_buf.dummy {
                Ok(metadata_buf.payload_size) // dequeue metadata
            } else {
                Err(Error::Exhausted) // don't dequeue metadata
            }
        });
        if let Ok(size) = result {
            payload_buffer.dequeue_many(size); // dequeue dummy payload
        }

        metadata_buffer.dequeue_one_with(move |metadata_buf| {
            assert!(!metadata_buf.dummy);
            payload_buffer.dequeue_many_with(|payload_buf| {
                let payload_buf = &payload_buf[..metadata_buf.payload_size];

                net_trace!("{}:{}:{}: sending {} octets",
                            handle, endpoint,
                            metadata_buf.endpoint, metadata_buf.payload_size);

                let repr = UdpRepr {
                    src_port: endpoint.port,
                    dst_port: metadata_buf.endpoint.port,
                    payload:  payload_buf,
                };
                let ip_repr = IpRepr::Unspecified {
                    src_addr:    endpoint.addr,
                    dst_addr:    metadata_buf.endpoint.addr,
                    protocol:    IpProtocol::Udp,
                    payload_len: repr.buffer_len(),
                    hop_limit:   hop_limit,
                };
                match emit((ip_repr, repr)) {
                    Ok(ret) => (metadata_buf.payload_size, Ok(ret)),
                    Err(ret) => (0, Err(ret)),
                }
            }).1
        })
    }

    pub(crate) fn poll_at(&self) -> Option<u64> {
        if self.tx_buffer.is_empty() {
            None
        } else {
            Some(0)
        }
    }
}

impl<'a, 'b> Into<Socket<'a, 'b>> for UdpSocket<'a> {
    fn into(self) -> Socket<'a, 'b> {
        Socket::Udp(self)
    }
}

#[cfg(test)]
mod test {
    use wire::{IpAddress, IpRepr, UdpRepr};
    #[cfg(feature = "proto-ipv4")]
    use wire::Ipv4Repr;
    #[cfg(feature = "proto-ipv6")]
    use wire::Ipv6Repr;
    use wire::ip::test::{MOCK_IP_ADDR_1, MOCK_IP_ADDR_2, MOCK_IP_ADDR_3};
    use super::*;

    fn buffer(packets: usize) -> SocketBuffer<'static> {
        SocketBuffer::new(vec![Default::default(); packets], vec![0; 16 * packets])
    }

    fn socket(rx_buffer: SocketBuffer<'static>,
              tx_buffer: SocketBuffer<'static>)
            -> UdpSocket<'static> {
        UdpSocket::new(rx_buffer, tx_buffer)
    }

    const LOCAL_PORT:  u16        = 53;
    const REMOTE_PORT: u16        = 49500;

    pub const LOCAL_END:   IpEndpoint = IpEndpoint { addr: MOCK_IP_ADDR_1, port: LOCAL_PORT  };
    pub const REMOTE_END:  IpEndpoint = IpEndpoint { addr: MOCK_IP_ADDR_2, port: REMOTE_PORT };

    pub const LOCAL_IP_REPR: IpRepr = IpRepr::Unspecified {
        src_addr: MOCK_IP_ADDR_1,
        dst_addr: MOCK_IP_ADDR_2,
        protocol: IpProtocol::Udp,
        payload_len: 8 + 6,
        hop_limit: 64,
    };

    const LOCAL_UDP_REPR: UdpRepr = UdpRepr {
        src_port: LOCAL_PORT,
        dst_port: REMOTE_PORT,
        payload: b"abcdef"
    };

    const REMOTE_UDP_REPR: UdpRepr = UdpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        payload: b"abcdef"
    };

    fn remote_ip_repr() -> IpRepr {
        match (MOCK_IP_ADDR_2, MOCK_IP_ADDR_1) {
            #[cfg(feature = "proto-ipv4")]
            (IpAddress::Ipv4(src), IpAddress::Ipv4(dst)) => IpRepr::Ipv4(Ipv4Repr {
                src_addr: src,
                dst_addr: dst,
                protocol: IpProtocol::Udp,
                payload_len: 8 + 6,
                hop_limit: 64
            }),
            #[cfg(feature = "proto-ipv6")]
            (IpAddress::Ipv6(src), IpAddress::Ipv6(dst)) => IpRepr::Ipv6(Ipv6Repr {
                src_addr: src,
                dst_addr: dst,
                next_header: IpProtocol::Udp,
                payload_len: 8 + 6,
                hop_limit: 64
            }),
            _ => unreachable!()
        }
    }

    #[test]
    fn test_bind_unaddressable() {
        let mut socket = socket(buffer(0), buffer(0));
        assert_eq!(socket.bind(0), Err(Error::Unaddressable));
    }

    #[test]
    fn test_bind_twice() {
        let mut socket = socket(buffer(0), buffer(0));
        assert_eq!(socket.bind(1), Ok(()));
        assert_eq!(socket.bind(2), Err(Error::Illegal));
    }

    #[test]
    #[should_panic(expected = "the time-to-live value of a packet must not be zero")]
    fn test_set_hop_limit_zero() {
        let mut s = socket(buffer(0), buffer(1));
        s.set_hop_limit(Some(0));
    }

    #[test]
    fn test_send_unaddressable() {
        let mut socket = socket(buffer(0), buffer(1));
        assert_eq!(socket.send_slice(b"abcdef", REMOTE_END), Err(Error::Unaddressable));
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));
        assert_eq!(socket.send_slice(b"abcdef",
                                     IpEndpoint { addr: IpAddress::Unspecified, ..REMOTE_END }),
                   Err(Error::Unaddressable));
        assert_eq!(socket.send_slice(b"abcdef",
                                     IpEndpoint { port: 0, ..REMOTE_END }),
                   Err(Error::Unaddressable));
        assert_eq!(socket.send_slice(b"abcdef", REMOTE_END), Ok(()));
    }

    #[test]
    fn test_send_truncated() {
        let mut socket = socket(buffer(0), buffer(1));
        assert_eq!(socket.bind(LOCAL_END), Ok(()));

        assert_eq!(socket.send_slice(&[0; 32][..], REMOTE_END), Err(Error::Truncated));
    }

    #[test]
    fn test_send_dispatch() {
        let mut socket = socket(buffer(0), buffer(1));
        assert_eq!(socket.bind(LOCAL_END), Ok(()));

        assert!(socket.can_send());
        assert_eq!(socket.dispatch(|_| unreachable!()),
                   Err(Error::Exhausted));

        assert_eq!(socket.send_slice(b"abcdef", REMOTE_END), Ok(()));
        assert_eq!(socket.send_slice(b"123456", REMOTE_END), Err(Error::Exhausted));
        assert!(!socket.can_send());

        assert_eq!(socket.dispatch(|(ip_repr, udp_repr)| {
            assert_eq!(ip_repr, LOCAL_IP_REPR);
            assert_eq!(udp_repr, LOCAL_UDP_REPR);
            Err(Error::Unaddressable)
        }), Err(Error::Unaddressable));
        assert!(!socket.can_send());

        assert_eq!(socket.dispatch(|(ip_repr, udp_repr)| {
            assert_eq!(ip_repr, LOCAL_IP_REPR);
            assert_eq!(udp_repr, LOCAL_UDP_REPR);
            Ok(())
        }), Ok(()));
        assert!(socket.can_send());
    }

    #[test]
    fn test_recv_process() {
        let mut socket = socket(buffer(1), buffer(0));
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        assert!(!socket.can_recv());
        assert_eq!(socket.recv(), Err(Error::Exhausted));

        assert!(socket.accepts(&remote_ip_repr(), &REMOTE_UDP_REPR));
        assert_eq!(socket.process(&remote_ip_repr(), &REMOTE_UDP_REPR),
                   Ok(()));
        assert!(socket.can_recv());

        assert!(socket.accepts(&remote_ip_repr(), &REMOTE_UDP_REPR));
        assert_eq!(socket.process(&remote_ip_repr(), &REMOTE_UDP_REPR),
                   Err(Error::Exhausted));
        assert_eq!(socket.recv(), Ok((&b"abcdef"[..], REMOTE_END)));
        assert!(!socket.can_recv());
    }

    #[test]
    fn test_recv_truncated_slice() {
        let mut socket = socket(buffer(1), buffer(0));
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        assert!(socket.accepts(&remote_ip_repr(), &REMOTE_UDP_REPR));
        assert_eq!(socket.process(&remote_ip_repr(), &REMOTE_UDP_REPR),
                   Ok(()));

        let mut slice = [0; 4];
        assert_eq!(socket.recv_slice(&mut slice[..]), Ok((4, REMOTE_END)));
        assert_eq!(&slice, b"abcd");
    }

    #[test]
    fn test_recv_truncated_packet() {
        let mut socket = socket(buffer(1), buffer(0));
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        let udp_repr = UdpRepr { payload: &[0; 100][..], ..REMOTE_UDP_REPR };
        assert!(socket.accepts(&remote_ip_repr(), &udp_repr));
        assert_eq!(socket.process(&remote_ip_repr(), &udp_repr),
                   Err(Error::Truncated));
    }

    #[test]
    fn test_set_hop_limit() {
        let mut s = socket(buffer(0), buffer(1));
        assert_eq!(s.bind(LOCAL_END), Ok(()));

        s.set_hop_limit(Some(0x2a));
        assert_eq!(s.send_slice(b"abcdef", REMOTE_END), Ok(()));
        assert_eq!(s.dispatch(|(ip_repr, _)| {
            assert_eq!(ip_repr, IpRepr::Unspecified{
                src_addr: MOCK_IP_ADDR_1,
                dst_addr: MOCK_IP_ADDR_2,
                protocol: IpProtocol::Udp,
                payload_len: 8 + 6,
                hop_limit: 0x2a,
            });
            Ok(())
        }), Ok(()));
    }

    #[test]
    fn test_doesnt_accept_wrong_port() {
        let mut socket = socket(buffer(1), buffer(0));
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        let mut udp_repr = REMOTE_UDP_REPR;
        assert!(socket.accepts(&remote_ip_repr(), &udp_repr));
        udp_repr.dst_port += 1;
        assert!(!socket.accepts(&remote_ip_repr(), &udp_repr));
    }

    #[test]
    fn test_doesnt_accept_wrong_ip() {
        fn generate_bad_repr() -> IpRepr {
            match (MOCK_IP_ADDR_2, MOCK_IP_ADDR_3) {
                #[cfg(feature = "proto-ipv4")]
                (IpAddress::Ipv4(src), IpAddress::Ipv4(dst)) => IpRepr::Ipv4(Ipv4Repr {
                    src_addr: src,
                    dst_addr: dst,
                    protocol: IpProtocol::Udp,
                    payload_len: 8 + 6,
                    hop_limit: 64
                }),
                #[cfg(feature = "proto-ipv6")]
                (IpAddress::Ipv6(src), IpAddress::Ipv6(dst)) => IpRepr::Ipv6(Ipv6Repr {
                    src_addr: src,
                    dst_addr: dst,
                    next_header: IpProtocol::Udp,
                    payload_len: 8 + 6,
                    hop_limit: 64
                }),
                _ => unreachable!()
            }
        }

        let mut port_bound_socket = socket(buffer(1), buffer(0));
        assert_eq!(port_bound_socket.bind(LOCAL_PORT), Ok(()));
        assert!(port_bound_socket.accepts(&generate_bad_repr(), &REMOTE_UDP_REPR));

        let mut ip_bound_socket = socket(buffer(1), buffer(0));
        assert_eq!(ip_bound_socket.bind(LOCAL_END), Ok(()));
        assert!(!ip_bound_socket.accepts(&generate_bad_repr(), &REMOTE_UDP_REPR));
    }
}
