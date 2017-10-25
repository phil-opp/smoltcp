#[cfg(feature = "std")]
use std::cell::RefCell;
#[cfg(feature = "std")]
use std::io::Write;
use byteorder::{ByteOrder, NativeEndian};

use Result;
use super::{DeviceCapabilities, Device};
use phy;

enum_with_unknown! {
    /// Captured packet header type.
    pub doc enum PcapLinkType(u32) {
        /// Ethernet frames
        Ethernet =   1,
        /// IPv4 or IPv6 packets (depending on the version field)
        Ip       = 101
    }
}

/// Packet capture mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapMode {
    /// Capture both received and transmitted packets.
    Both,
    /// Capture only received packets.
    RxOnly,
    /// Capture only transmitted packets.
    TxOnly
}

/// A packet capture sink.
pub trait PcapSink {
    /// Write data into the sink.
    fn write(&self, data: &[u8]);

    /// Write an `u16` into the sink, in native byte order.
    fn write_u16(&self, value: u16) {
        let mut bytes = [0u8; 2];
        NativeEndian::write_u16(&mut bytes, value);
        self.write(&bytes[..])
    }

    /// Write an `u32` into the sink, in native byte order.
    fn write_u32(&self, value: u32) {
        let mut bytes = [0u8; 4];
        NativeEndian::write_u32(&mut bytes, value);
        self.write(&bytes[..])
    }

    /// Write the libpcap global header into the sink.
    ///
    /// This method may be overridden e.g. if special synchronization is necessary.
    fn global_header(&self, link_type: PcapLinkType) {
        self.write_u32(0xa1b2c3d4);       // magic number
        self.write_u16(2);                // major version
        self.write_u16(4);                // minor version
        self.write_u32(0);                // timezone (= UTC)
        self.write_u32(0);                // accuracy (not used)
        self.write_u32(65535);            // maximum packet length
        self.write_u32(link_type.into()); // link-layer header type
    }

    /// Write the libpcap packet header into the sink.
    ///
    /// See also the note for [global_header](#method.global_header).
    fn packet_header(&self, timestamp: u64, length: usize) {
        assert!(length <= 65535);

        let (seconds, micros) = (timestamp / 1000, timestamp % 1000 * 1000);
        self.write_u32(seconds as u32);   // timestamp seconds
        self.write_u32(micros  as u32);   // timestamp microseconds
        self.write_u32(length  as u32);   // captured length
        self.write_u32(length  as u32);   // original length
    }

    /// Write the libpcap packet header followed by packet data into the sink.
    ///
    /// See also the note for [global_header](#method.global_header).
    fn packet(&self, timestamp: u64, packet: &[u8]) {
        self.packet_header(timestamp, packet.len());
        self.write(packet)
    }
}

impl<T: AsRef<PcapSink>> PcapSink for T {
    fn write(&self, data: &[u8]) {
        self.as_ref().write(data)
    }
}

#[cfg(feature = "std")]
impl<T: AsMut<Write>> PcapSink for RefCell<T> {
    fn write(&self, data: &[u8]) {
        self.borrow_mut().as_mut().write_all(data).expect("cannot write")
    }

    fn packet(&self, timestamp: u64, packet: &[u8]) {
        self.packet_header(timestamp, packet.len());
        PcapSink::write(self, packet);
        self.borrow_mut().as_mut().flush().expect("cannot flush")
    }
}

/// A packet capture writer device.
///
/// Every packet transmitted or received through this device is timestamped
/// and written (in the [libpcap] format) using the provided [sink].
/// Note that writes are fine-grained, and buffering is recommended.
///
/// The packet sink should be cheaply cloneable, as it is cloned on every
/// transmitted packet. For example, `&'a mut Vec<u8>` is cheaply cloneable
/// but `&std::io::File`
///
/// [libpcap]: https://wiki.wireshark.org/Development/LibpcapFileFormat
/// [sink]: trait.PcapSink.html
#[derive(Debug)]
pub struct PcapWriter<D: for<'a> Device<'a>, S: PcapSink + Clone> {
    lower:      D,
    sink:       S,
    mode:       PcapMode,
}

impl<D: for<'a> Device<'a>, S: PcapSink + Clone> PcapWriter<D, S> {
    /// Creates a packet capture writer.
    pub fn new(lower: D, sink: S, mode: PcapMode, link_type: PcapLinkType) -> PcapWriter<D, S> {
        sink.global_header(link_type);
        PcapWriter { lower, sink, mode }
    }
}

impl<'a, D, S> Device<'a> for PcapWriter<D, S>
    where D: for<'b> Device<'b>,
          S: PcapSink + Clone + 'a,
{
    type RxToken = RxToken<<D as Device<'a>>::RxToken, S>;
    type TxToken = TxToken<<D as Device<'a>>::TxToken, S>;

    fn capabilities(&self) -> DeviceCapabilities { self.lower.capabilities() }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let &mut Self { ref mut lower, ref sink, mode, .. } = self;
        lower.receive().map(|(rx_token, tx_token)| {
            let rx = RxToken { token: rx_token, sink: sink.clone(), mode: mode };
            let tx = TxToken { token: tx_token, sink: sink.clone(), mode: mode };
            (rx, tx)
        })
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        let &mut Self { ref mut lower, ref sink, mode } = self;
        lower.transmit().map(|token| {
            TxToken { token, sink: sink.clone(), mode: mode }
        })
    }
}

#[doc(hidden)]
pub struct RxToken<T: phy::RxToken, S: PcapSink> {
    token:     T,
    sink:      S,
    mode:      PcapMode
}

impl<T: phy::RxToken, S: PcapSink> phy::RxToken for RxToken<T, S> {
    fn consume<R, F: FnOnce(&[u8]) -> Result<R>>(self, timestamp: u64, f: F) -> Result<R> {
        let Self { token, sink, mode } = self;
        token.consume(timestamp, |buffer| {
            match mode {
                PcapMode::Both | PcapMode::RxOnly =>
                    sink.packet(timestamp, buffer.as_ref()),
                PcapMode::TxOnly => ()
            }
            f(buffer)
        })
    }
}

#[doc(hidden)]
pub struct TxToken<T: phy::TxToken, S: PcapSink> {
    token:     T,
    sink:      S,
    mode:      PcapMode
}

impl<T: phy::TxToken, S: PcapSink> phy::TxToken for TxToken<T, S> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, timestamp: u64, len: usize, f: F) -> R {
        let Self { token, sink, mode } = self;
        token.consume(timestamp, len, |buffer| {
            let ret = f(buffer);
            match mode {
                PcapMode::Both | PcapMode::TxOnly =>
                    sink.packet(timestamp, &buffer),
                PcapMode::RxOnly => ()
            };
            ret
        })
    }
}
