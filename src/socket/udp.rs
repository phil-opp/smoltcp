use core::marker::PhantomData;
use core::borrow::BorrowMut;

use Error;
use wire::{InternetAddress as Address, InternetProtocolType as ProtocolType};
use wire::{InternetEndpoint as Endpoint};
use wire::{UdpPacket, UdpRepr};
use socket::{Socket, PacketRepr};

/// A buffered UDP packet.
#[derive(Debug, Default)]
pub struct BufferElem<T: BorrowMut<[u8]>> {
    endpoint: Endpoint,
    size:     usize,
    payload:  T
}

impl<T: BorrowMut<[u8]>> BufferElem<T> {
    /// Create a buffered packet.
    pub fn new(payload: T) -> BufferElem<T> {
        BufferElem {
            endpoint: Endpoint::INVALID,
            size:     0,
            payload:  payload
        }
    }
}

/// An UDP packet buffer.
#[derive(Debug)]
pub struct Buffer<
    T: BorrowMut<[u8]>,
    U: BorrowMut<[BufferElem<T>]>
> {
    storage: U,
    read_at: usize,
    length:  usize,
    phantom: PhantomData<T>
}

impl<
    T: BorrowMut<[u8]>,
    U: BorrowMut<[BufferElem<T>]>
> Buffer<T, U> {
    /// Create a packet buffer with the given storage.
    pub fn new(mut storage: U) -> Buffer<T, U> {
        for elem in storage.borrow_mut() {
            elem.endpoint = Default::default();
            elem.size = 0;
        }

        Buffer {
            storage: storage,
            read_at: 0,
            length:  0,
            phantom: PhantomData
        }
    }

    fn mask(&self, index: usize) -> usize {
        index % self.storage.borrow().len()
    }

    fn incr(&self, index: usize) -> usize {
        self.mask(index + 1)
    }

    fn empty(&self) -> bool {
        self.length == 0
    }

    fn full(&self) -> bool {
        self.length == self.storage.borrow().len()
    }

    /// Enqueue an element into the buffer, and return a pointer to it, or return
    /// `Err(Error::Exhausted)` if the buffer is full.
    pub fn enqueue(&mut self) -> Result<&mut BufferElem<T>, Error> {
        if self.full() {
            Err(Error::Exhausted)
        } else {
            let index = self.mask(self.read_at + self.length);
            let result = &mut self.storage.borrow_mut()[index];
            self.length += 1;
            Ok(result)
        }
    }

    /// Dequeue an element from the buffer, and return a pointer to it, or return
    /// `Err(Error::Exhausted)` if the buffer is empty.
    pub fn dequeue(&mut self) -> Result<&BufferElem<T>, Error> {
        if self.empty() {
            Err(Error::Exhausted)
        } else {
            self.length -= 1;
            let result = &self.storage.borrow()[self.read_at];
            self.read_at = self.incr(self.read_at);
            Ok(result)
        }
    }
}

/// An User Datagram Protocol socket.
///
/// An UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
pub struct UdpSocket<
    T: BorrowMut<[u8]>,
    U: BorrowMut<[BufferElem<T>]>
> {
    endpoint:  Endpoint,
    rx_buffer: Buffer<T, U>,
    tx_buffer: Buffer<T, U>
}

impl<
    T: BorrowMut<[u8]>,
    U: BorrowMut<[BufferElem<T>]>
> UdpSocket<T, U> {
    /// Create an UDP socket with the given buffers.
    pub fn new(endpoint: Endpoint, rx_buffer: Buffer<T, U>, tx_buffer: Buffer<T, U>)
            -> UdpSocket<T, U> {
        UdpSocket {
            endpoint:  endpoint,
            rx_buffer: rx_buffer,
            tx_buffer: tx_buffer
        }
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and return a pointer
    /// to its payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the size is greater than what
    /// the transmit buffer can accomodate.
    pub fn send(&mut self, endpoint: Endpoint, size: usize) -> Result<&mut [u8], Error> {
        let packet_buf = try!(self.tx_buffer.enqueue());
        packet_buf.endpoint = endpoint;
        packet_buf.size = size;
        Ok(&mut packet_buf.payload.borrow_mut()[..size])
    }

    /// Dequeue a packet received from a remote endpoint, and return the endpoint as well
    /// as a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn recv<R, F>(&mut self) -> Result<(Endpoint, &[u8]), Error> {
        let packet_buf = try!(self.rx_buffer.dequeue());
        Ok((packet_buf.endpoint, &packet_buf.payload.borrow()[..packet_buf.size]))
    }
}

impl<
    T: BorrowMut<[u8]>,
    U: BorrowMut<[BufferElem<T>]>
> Socket for UdpSocket<T, U> {
    fn collect(&mut self, src_addr: &Address, dst_addr: &Address,
               protocol: ProtocolType, payload: &[u8])
            -> Result<(), Error> {
        if protocol != ProtocolType::Udp { return Err(Error::Rejected) }

        let packet = try!(UdpPacket::new(payload));
        let repr = try!(UdpRepr::parse(&packet, src_addr, dst_addr));

        if repr.dst_port != self.endpoint.port { return Err(Error::Rejected) }
        if !self.endpoint.addr.is_unspecified() {
            if self.endpoint.addr != *dst_addr { return Err(Error::Rejected) }
        }

        let packet_buf = try!(self.rx_buffer.enqueue());
        packet_buf.endpoint = Endpoint { addr: *src_addr, port: repr.src_port };
        packet_buf.size = repr.payload.len();
        packet_buf.payload.borrow_mut()[..repr.payload.len()].copy_from_slice(repr.payload);
        Ok(())
    }

    fn dispatch(&mut self, f: &mut FnMut(&Address, &Address,
                                         ProtocolType, &PacketRepr) -> Result<(), Error>)
            -> Result<(), Error> {
        let packet_buf = try!(self.tx_buffer.dequeue());
        f(&self.endpoint.addr,
          &packet_buf.endpoint.addr,
          ProtocolType::Udp,
          &UdpRepr {
            src_port: self.endpoint.port,
            dst_port: packet_buf.endpoint.port,
            payload:  packet_buf.payload.borrow()
          })
    }
}

impl<'a> PacketRepr for UdpRepr<'a> {
    fn len(&self) -> usize {
        self.len()
    }

    fn emit(&self, src_addr: &Address, dst_addr: &Address, payload: &mut [u8]) {
        let mut packet = UdpPacket::new(payload).expect("undersized payload slice");
        self.emit(&mut packet, src_addr, dst_addr)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_buffer() {
        let mut storage = vec![];
        for _ in 0..5 {
            storage.push(BufferElem::new(vec![0]))
        }
        let mut buffer = Buffer::new(&mut storage[..]);

        assert_eq!(buffer.empty(), true);
        assert_eq!(buffer.full(),  false);
        buffer.enqueue().unwrap().size = 1;
        assert_eq!(buffer.empty(), false);
        assert_eq!(buffer.full(),  false);
        buffer.enqueue().unwrap().size = 2;
        buffer.enqueue().unwrap().size = 3;
        assert_eq!(buffer.dequeue().unwrap().size, 1);
        assert_eq!(buffer.dequeue().unwrap().size, 2);
        buffer.enqueue().unwrap().size = 4;
        buffer.enqueue().unwrap().size = 5;
        buffer.enqueue().unwrap().size = 6;
        buffer.enqueue().unwrap().size = 7;
        assert_eq!(buffer.enqueue().unwrap_err(), Error::Exhausted);
        assert_eq!(buffer.empty(), false);
        assert_eq!(buffer.full(),  true);
        assert_eq!(buffer.dequeue().unwrap().size, 3);
        assert_eq!(buffer.dequeue().unwrap().size, 4);
        assert_eq!(buffer.dequeue().unwrap().size, 5);
        assert_eq!(buffer.dequeue().unwrap().size, 6);
        assert_eq!(buffer.dequeue().unwrap().size, 7);
        assert_eq!(buffer.dequeue().unwrap_err(), Error::Exhausted);
        assert_eq!(buffer.empty(), true);
        assert_eq!(buffer.full(),  false);
    }
}
