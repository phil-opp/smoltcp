// See https://tools.ietf.org/html/rfc2131 for the DHCP specification.

use byteorder::{ByteOrder, NetworkEndian};

use {Error, Result};
use super::{EthernetAddress, Ipv4Address};

/// A read/write wrapper around a Dynamic Host Configuration Protocol packet buffer.
#[derive(Debug, PartialEq)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T
}

mod field {
    #![allow(non_snake_case)]
    #![allow(unused)]

    use wire::field::*;

    pub const OP: usize = 0;
    pub const HTYPE: usize = 1;
    pub const HLEN: usize = 2;
    pub const HOPS: usize = 3;
    pub const XID: Field = 4..8;
    pub const SECS: Field = 9..10;
    pub const FLAGS: Field = 10..12;
    pub const CIADDR: Field = 12..16;
    pub const YIADDR: Field = 16..20;
    pub const SIADDR: Field = 20..24;
    pub const GIADDR: Field = 24..28;
    pub const CHADDR: Field = 28..44;
    pub const SNAME: Field = 44..108;
    pub const FILE: Field = 108..236;
    pub const MAGIC_NUMBER: Field = 236..240;
    pub const OPTIONS: Rest = 240..;

    // Vendor Extensions
    pub const OPT_END: u8 = 255;
    pub const OPT_PAD: u8 = 0;
    pub const OPT_SUBNET_MASK: u8 = 1;
    pub const OPT_TIME_OFFSET: u8 = 2;
    pub const OPT_ROUTER: u8 = 3;
    pub const OPT_TIME_SERVER: u8 = 4;
    pub const OPT_NAME_SERVER: u8 = 5;
    pub const OPT_DOMAIN_NAME_SERVER: u8 = 6;
    pub const OPT_LOG_SERVER: u8 = 7;
    pub const OPT_COOKIE_SERVER: u8 = 8;
    pub const OPT_LPR_SERVER: u8 = 9;
    pub const OPT_IMPRESS_SERVER: u8 = 10;
    pub const OPT_RESOURCE_LOCATION_SERVER: u8 = 11;
    pub const OPT_HOST_NAME: u8 = 12;
    pub const OPT_BOOT_FILE_SIZE: u8 = 13;
    pub const OPT_MERIT_DUMP: u8 = 14;
    pub const OPT_DOMAIN_NAME: u8 = 15;
    pub const OPT_SWAP_SERVER: u8 = 16;
    pub const OPT_ROOT_PATH: u8 = 17;
    pub const OPT_EXTENSIONS_PATH: u8 = 18;

    // IP Layer Parameters per Host
    pub const OPT_IP_FORWARDING: u8 = 19;
    pub const OPT_NON_LOCAL_SOURCE_ROUTING: u8 = 20;
    pub const OPT_POLICY_FILTER: u8 = 21;
    pub const OPT_MAX_DATAGRAM_REASSEMBLY_SIZE: u8 = 22;
    pub const OPT_DEFAULT_TTL: u8 = 23;
    pub const OPT_PATH_MTU_AGING_TIMEOUT: u8 = 24;
    pub const OPT_PATH_MTU_PLATEU_TABLE: u8 = 25;

    // IP Layer Parameters per Interface
    pub const OPT_INTERFACE_MTU: u8 = 26;
    pub const OPT_ALL_SUBNETS_ARE_LOCAL: u8 = 27;
    pub const OPT_BROADCAST_ADDRESS: u8 = 28;
    pub const OPT_PERFORM_MASK_DISCOVERY: u8 = 29;
    pub const OPT_MASK_SUPPLIER: u8 = 30;
    pub const OPT_PERFORM_ROUTER_DISCOVERY: u8 = 31;
    pub const OPT_ROUTER_SOLICITATION_ADDRESS: u8 = 32;
    pub const OPT_STATIC_ROUTE: u8 = 33;

    // Link Layer Parameters per Interface
    pub const OPT_TRAILER_ENCAPSULATION: u8 = 34;
    pub const OPT_ARP_CACHE_TIMEOUT: u8 = 35;
    pub const OPT_ETHERNET_ENCAPSULATION: u8 = 36;

    // TCP Parameters
    pub const OPT_TCP_DEFAULT_TTL: u8 = 37;
    pub const OPT_TCP_KEEPALIVE_INTERVAL: u8 = 38;
    pub const OPT_TCP_KEEPALIVE_GARBAGE: u8 = 39;

    // Application and Service Parameters
    pub const OPT_NIS_DOMAIN: u8 = 40;
    pub const OPT_NIS_SERVERS: u8 = 41;
    pub const OPT_NTP_SERVERS: u8 = 42;
    pub const OPT_VENDOR_SPECIFIC_INFO: u8 = 44;
    pub const OPT_NETBIOS_SERVER: u8 = 45;
    pub const OPT_NETBIOS_NODE_TYPE: u8 = 46;
    pub const OPT_NETBIOS_SCOPE: u8 = 47;
    pub const OPT_X_WINDOW_FONT_SERVER: u8 = 48;
    pub const OPT_X_WINDOW_DISPLAY_MANAGER: u8 = 49;
    pub const OPT_NIS_PLUS_DOMAIN: u8 = 64;
    pub const OPT_NIS_PLUS_SERVERS: u8 = 65;
    pub const OPT_MOBILE_IP_HOME_AGENT: u8 = 68;
    pub const OPT_SMTP_SERVER: u8 = 69;
    pub const OPT_POP3_SERVER: u8 = 70;
    pub const OPT_NNTP_SERVER: u8 = 71;
    pub const OPT_WWW_SERVER: u8 = 72;
    pub const OPT_FINGER_SERVER: u8 = 73;
    pub const OPT_IRC_SERVER: u8 = 74;
    pub const OPT_STREETTALK_SERVER: u8 = 75;
    pub const OPT_STDA_SERVER: u8 = 76;

    // DHCP Extensions
    pub const OPT_REQUESTED_IP: u8 = 50;
    pub const OPT_IP_LEASE_TIME: u8 = 51;
    pub const OPT_OPTION_OVERLOAD: u8 = 52;
    pub const OPT_TFTP_SERVER_NAME: u8 = 66;
    pub const OPT_BOOTFILE_NAME: u8 = 67;
    pub const OPT_DHCP_MESSAGE_TYPE: u8 = 53;
    pub const OPT_SERVER_IDENTIFIER: u8 = 54;
    pub const OPT_PARAMETER_REQUEST_LIST: u8 = 55;
    pub const OPT_MESSAGE: u8 = 56;
    pub const OPT_MAX_DHCP_MESSAGE_SIZE: u8 = 57;
    pub const OPT_RENEWAL_TIME_VALUE: u8 = 58;
    pub const OPT_REBINDING_TIME_VALUE: u8 = 59;
    pub const OPT_VENDOR_CLASS_ID: u8 = 60;
    pub const OPT_CLIENT_ID: u8 = 61;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with DHCP packet structure.
    pub fn new(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new] and [check_len].
    ///
    /// [new]: #method.new
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::MAGIC_NUMBER.end {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Returns wether this packet is a request (1) or a reply (2).
    pub fn opcode(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::OP]
    }

    pub fn hardware_address_type(&self) -> HardwareAddressType {
        let data = self.buffer.as_ref();
        HardwareAddressType::from(data[field::HTYPE])
    }

    pub fn hardware_address_len(&self) -> u8 {
        self.buffer.as_ref()[field::HLEN]
    }

    pub fn transaction_id(&self) -> u32 {
        let field = &self.buffer.as_ref()[field::XID];
        NetworkEndian::read_u32(field)
    }

    pub fn client_hardware_address(&self) -> EthernetAddress {
        let field = &self.buffer.as_ref()[field::CHADDR];
        EthernetAddress::from_bytes(field)
    }

    pub fn hops(&self) -> u8 {
        self.buffer.as_ref()[field::HOPS]
    }

    pub fn secs(&self) -> u16 {
        let field = &self.buffer.as_ref()[field::SECS];
        NetworkEndian::read_u16(field)
    }

    pub fn magic_number(&self) -> u32 {
        let field = &self.buffer.as_ref()[field::MAGIC_NUMBER];
        NetworkEndian::read_u32(field)
    }

    pub fn client_ip(&self) -> Ipv4Address {
        let field = &self.buffer.as_ref()[field::CIADDR];
        Ipv4Address::from_bytes(field)
    }

    pub fn your_ip(&self) -> Ipv4Address {
        let field = &self.buffer.as_ref()[field::YIADDR];
        Ipv4Address::from_bytes(field)
    }

    pub fn server_ip(&self) -> Ipv4Address {
        let field = &self.buffer.as_ref()[field::SIADDR];
        Ipv4Address::from_bytes(field)
    }

    pub fn relay_agent_ip(&self) -> Ipv4Address {
        let field = &self.buffer.as_ref()[field::GIADDR];
        Ipv4Address::from_bytes(field)
    }

    pub fn broadcast_flag(&self) -> Result<bool> {
        let field = &self.buffer.as_ref()[field::FLAGS];
        match NetworkEndian::read_u16(field) {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Malformed),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the options.
    #[inline]
    pub fn options(&self) -> Result<&'a [u8]> {
        let data = self.buffer.as_ref();
        data.get(field::OPTIONS).ok_or(Error::Malformed)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    pub fn set_opcode(&mut self, value: u8) {
        assert!(value == 1 || value == 2);
        let data = self.buffer.as_mut();
        data[field::OP] = value;
    }

    pub fn set_hardware_address_type(&mut self, value: HardwareAddressType) {
        let data = self.buffer.as_mut();
        data[field::HTYPE] = value.into();
    }

    pub fn set_hardware_address_len(&mut self, value: u8) {
        self.buffer.as_mut()[field::HLEN] = value;
    }

    pub fn set_transaction_id(&mut self, value: u32) {
        let field = &mut self.buffer.as_mut()[field::XID];
        NetworkEndian::write_u32(field, value)
    }

    pub fn set_client_hardware_address(&mut self, value: EthernetAddress) {
        let field = &mut self.buffer.as_mut()[field::CHADDR];
        field.copy_from_slice(value.as_bytes());
    }

    pub fn set_hops(&mut self, value: u8) {
        self.buffer.as_mut()[field::HOPS] = value;
    }

    pub fn set_secs(&mut self, value: u16) {
        let field = &mut self.buffer.as_mut()[field::SECS];
        NetworkEndian::write_u16(field, value);
    }

    pub fn set_magic_number(&mut self, value: u32) {
        let field = &mut self.buffer.as_mut()[field::MAGIC_NUMBER];
        NetworkEndian::write_u32(field, value);
    }

    pub fn set_client_ip(&mut self, value: Ipv4Address) {
        let field = &mut self.buffer.as_mut()[field::CIADDR];
        field.copy_from_slice(value.as_bytes());
    }

    pub fn set_your_ip(&mut self, value: Ipv4Address) {
        let field = &mut self.buffer.as_mut()[field::YIADDR];
        field.copy_from_slice(value.as_bytes());
    }

    pub fn set_server_ip(&mut self, value: Ipv4Address) {
        let field = &mut self.buffer.as_mut()[field::SIADDR];
        field.copy_from_slice(value.as_bytes());
    }

    pub fn set_relay_agent_ip(&mut self, value: Ipv4Address) {
        let field = &mut self.buffer.as_mut()[field::GIADDR];
        field.copy_from_slice(value.as_bytes());
    }

    pub fn set_broadcast_flag(&mut self, value: bool) {
        let field = &mut self.buffer.as_mut()[field::FLAGS];
        NetworkEndian::write_u16(field, if value { 1 } else { 0 });
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return a pointer to the options.
    #[inline]
    pub fn options_mut(&mut self) -> Result<&mut [u8]> {
        let data = self.buffer.as_mut();
        data.get_mut(field::OPTIONS).ok_or(Error::Truncated)
    }
}


enum_with_unknown! {
    /// The possible opcodes/message types of a DHCP packet.
    pub enum MessageType(u8) {
        Discover = 1,
        Offer = 2,
        Request = 3,
        Decline = 4,
        Ack = 5,
        Nak = 6,
        Release = 7,
        Inform = 8,
    }
}

impl MessageType {
    fn opcode(&self) -> Result<u8> {
        match *self {
            MessageType::Discover | MessageType::Inform | MessageType::Request |
                MessageType::Decline | MessageType::Release => Ok(1),
            MessageType::Offer | MessageType::Ack | MessageType::Nak => Ok(2),
            MessageType::Unknown(_) => Err(Error::Malformed),
        }
    }
}

enum_with_unknown! {
    /// The possible hardware address types of a DHCP packet.
    pub enum HardwareAddressType(u8) {
        Ethernet = 1,
        ExperimentalEthernet = 2,
        AmateurRadio = 3,
        ProNet = 4,
        Chaos = 5,
        Ieee802 = 6,
        Arcnet = 7,
        Hyperchannel = 8,
        Lanstar = 9,
    }
}

/// A representation of a single DHCP option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DhcpOption<'a> {
    EndOfList,
    MessageType(MessageType),
    RequestedIp(Ipv4Address),
    ServerIdentifier(Ipv4Address),
    Other { kind: u8, data: &'a [u8] }
}

impl<'a> DhcpOption<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<(&'a [u8], DhcpOption<'a>)> {
        // See https://tools.ietf.org/html/rfc2132 for all possible DHCP options.

        let (length, option);
        match *buffer.get(0).ok_or(Error::Truncated)? {
            field::OPT_END => {
                length = 1;
                option = DhcpOption::EndOfList;
            }
            field::OPT_PAD => {
                unimplemented!();
                // “The pad option can be used to cause subsequent fields to align on word
                // boundaries.”
                // TODO: what does this mean? Align the next field or align all following fields?
            }
            kind => {
                length = *buffer.get(1).ok_or(Error::Truncated)? as usize;
                let data = buffer.get(2..(2+length)).ok_or(Error::Truncated)?;
                match (kind, length) {
                    (field::OPT_END, _) |
                    (field::OPT_PAD, _) =>
                        unreachable!(),
                    (field::OPT_DHCP_MESSAGE_TYPE, 1) => {
                        option = DhcpOption::MessageType(MessageType::from(data[0]));
                    },
                    (field::OPT_REQUESTED_IP, 4) => {
                        option = DhcpOption::RequestedIp(Ipv4Address::from_bytes(data));
                    }
                    (field::OPT_SERVER_IDENTIFIER, 4) => {
                        option = DhcpOption::ServerIdentifier(Ipv4Address::from_bytes(data));
                    }
                    (_, _) => {
                        option = DhcpOption::Other { kind: kind, data: data };
                    }
                }
            }
        }
        Ok((&buffer[length..], option))
    }

    pub fn buffer_len(&self) -> usize {
        match self {
            &DhcpOption::EndOfList => 1,
            &DhcpOption::MessageType(_) => 3,
            &DhcpOption::RequestedIp(ip) | &DhcpOption::ServerIdentifier(ip) => {
                2 + ip.as_bytes().len()
            },
            &DhcpOption::Other { data, .. } => 2 + data.len()
        }
    }

    pub fn emit<'b>(&self, buffer: &'b mut [u8]) -> &'b mut [u8] {
        let length;
        match self {
            &DhcpOption::EndOfList => {
                length    = 1;
                buffer[0] = field::OPT_END;
            }
            _ => {
                length = self.buffer_len();
                buffer[1] = length as u8;
                match self {
                    &DhcpOption::EndOfList => unreachable!(),
                    &DhcpOption::MessageType(value) => {
                        buffer[0] = field::OPT_DHCP_MESSAGE_TYPE;
                        buffer[2] = value.into();
                    }
                    &DhcpOption::RequestedIp(ip) | &DhcpOption::ServerIdentifier(ip) => {
                        buffer[2..].copy_from_slice(ip.as_bytes());
                    }
                    &DhcpOption::Other { kind, data: provided } => {
                        buffer[0] = kind;
                        buffer[2..].copy_from_slice(provided);
                    }
                }
            }
        }
        &mut buffer[length..]
    }
}

/// A high-level representation of a Dynamic Host Configuration Protocol packet.
///
/// DHCP messages have the following layout (see [RFC 2131](https://tools.ietf.org/html/rfc2131)
/// for details):
///
/// ```no_rust
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | message_type  | htype (N/A)   |   hlen (N/A)  |   hops        |
/// +---------------+---------------+---------------+---------------+
/// |                       transaction_id                          |
/// +-------------------------------+-------------------------------+
/// |           secs                |           flags               |
/// +-------------------------------+-------------------------------+
/// |                           client_ip                           |
/// +---------------------------------------------------------------+
/// |                            your_ip                            |
/// +---------------------------------------------------------------+
/// |                           server_ip                           |
/// +---------------------------------------------------------------+
/// |                        relay_agent_ip                         |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                    client_hardware_address                    |
/// |                                                               |
/// |                                                               |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          sname  (N/A)                         |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          file    (N/A)                        |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          options                              |
/// +---------------------------------------------------------------+
/// ```
///
/// It is assumed that the access layer is Ethernet, so `htype` (the field representing the
/// hardware address type) is always set to `1`, and `hlen` (which represents the hardware address
/// length) is set to `6`.
///
/// The `options` field has a variable length.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr<'a> {
    /// This field is also known as `op` in the RFC. It indicates the type of DHCP message this
    /// packet represents.
    pub message_type: MessageType,
    /// This field is also known as `xid` in the RFC. It is a random number chosen by the client,
    /// used by the client and server to associate messages and responses between a client and a
    /// server.
    pub transaction_id: u32,
    /// This field is also known as `chaddr` in the RFC and for networks where the access layer is
    /// ethernet, it is the client MAC address.
    pub client_hardware_address: EthernetAddress,
    /// This field is also known as `ciaddr` in the RFC. It is only filled in if client is in
    /// BOUND, RENEW or REBINDING state and can respond to ARP requests.
    pub client_ip: Ipv4Address,
    /// This field is also known as `yiaddr` in the RFC.
    pub your_ip: Ipv4Address,
    /// This field is also known as `siaddr` in the RFC. It may be set by the server in DHCPOFFER
    /// and DHCPACK messages, and represent the address of the next server to use in bootstrap.
    pub server_ip: Ipv4Address,
    /// This field is also known as `giaddr` in the RFC. In order to allow DHCP clients on subnets
    /// not directly served by DHCP servers to communicate with DHCP servers, DHCP relay agents can
    /// be installed on these subnets. The DHCP client broadcasts on the local link; the relay
    /// agent receives the broadcast and transmits it to one or more DHCP servers using unicast.
    /// The relay agent stores its own IP address in the `relay_agent_ip` field of the DHCP packet.
    /// The DHCP server uses the `relay_agent_ip` to determine the subnet on which the relay agent
    /// received the broadcast, and allocates an IP address on that subnet. When the DHCP server
    /// replies to the client, it sends the reply to the `relay_agent_ip` address, again using
    /// unicast. The relay agent then retransmits the response on the local network
    pub relay_agent_ip: Ipv4Address,
    /// Broadcast flags. It can be set in DHCPDISCOVER, DHCPINFORM and DHCPREQUEST message if the
    /// client requires the response to be broadcasted.
    pub broadcast: bool,
    /// The "requested IP address" option. It can be used by clients in DHCPREQUEST or DHCPDISCOVER
    /// messages, or by servers in DHCPDECLINE messages.
    pub requested_ip: Option<Ipv4Address>,
    /// The "server identifier" option. It is used both to identify a DHCP server
    /// in a DHCP message and as a destination address from clients to servers.
    pub server_identifier: Option<Ipv4Address>,
    pub parameter_request_list: Option<&'a [u8]>,
}

impl<'a> Repr<'a> {
    /// Parse a DHCP packet and return a high-level representation.
    pub fn parse<T>(packet: &Packet<&'a T>) -> Result<Self>
            where T: AsRef<[u8]> + ?Sized {

        packet.check_len()?;
        let transaction_id = packet.transaction_id();
        let client_hardware_address = packet.client_hardware_address();
        let client_ip = packet.client_ip();
        let your_ip = packet.your_ip();
        let server_ip = packet.server_ip();
        let relay_agent_ip = packet.relay_agent_ip();

        let mut message_type = None;
        let mut requested_ip = None;
        let mut server_identifier = None;
        let mut parameter_request_list = None;

        let mut options = packet.options()?;
        while options.len() > 0 {
            let (next_options, option) = DhcpOption::parse(options)?;
            match option {
                DhcpOption::EndOfList => break,
                DhcpOption::MessageType(value) => {
                    if value.opcode()? != packet.opcode() {
                        return Err(Error::Malformed);
                    }
                    message_type = Some(value);
                },
                DhcpOption::RequestedIp(ip) => {
                    requested_ip = Some(ip);
                }
                DhcpOption::ServerIdentifier(ip) => {
                    server_identifier = Some(ip);
                }
                DhcpOption::Other {kind: field::OPT_PARAMETER_REQUEST_LIST, data} => {
                    parameter_request_list = Some(data);
                }
                DhcpOption::Other {..} => {}
            }
            options = next_options;
        }

        // only ethernet is supported right now
        match packet.hardware_address_type() {
            HardwareAddressType::Ethernet => {
                if packet.hardware_address_len() != 6 {
                    return Err(Error::Malformed);
                }
            }
            _ => return Err(Error::Unrecognized), // unimplemented
        }

        // check magic number
        if packet.magic_number() != 0x63825363 {
            return Err(Error::Malformed);
        }

        let broadcast = packet.broadcast_flag()?;

        Ok(Repr {
            transaction_id, client_hardware_address, client_ip, your_ip, server_ip, relay_agent_ip,
            broadcast, requested_ip, server_identifier, parameter_request_list,
            message_type: message_type.ok_or(Error::Malformed)?,
        })
    }

    /// Emit a high-level representation into a Transmission Control Protocol packet.
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>) -> Result<()>
            where T: AsRef<[u8]> + AsMut<[u8]> + ?Sized {
        packet.set_opcode(self.message_type.opcode()?);
        packet.set_hardware_address_type(HardwareAddressType::Ethernet);
        packet.set_hardware_address_len(6);
        packet.set_transaction_id(self.transaction_id);
        packet.set_client_hardware_address(self.client_hardware_address);
        packet.set_hops(0);
        packet.set_secs(0); // TODO
        packet.set_magic_number(0x63825363);
        packet.set_client_ip(self.client_ip);
        packet.set_your_ip(self.your_ip);
        packet.set_server_ip(self.server_ip);
        packet.set_relay_agent_ip(self.relay_agent_ip);
        packet.set_broadcast_flag(self.broadcast);

        {
            let mut options = packet.options_mut()?;
            let tmp = options; options = DhcpOption::MessageType(self.message_type).emit(tmp);
            if let Some(list) = self.parameter_request_list {
                let option = DhcpOption::Other{ kind: field::OPT_PARAMETER_REQUEST_LIST, data: list };
                let tmp = options; options = option.emit(tmp);
            }
            if let Some(ip) = self.requested_ip {
                let tmp = options; options = DhcpOption::RequestedIp(ip).emit(tmp);
            }
            DhcpOption::EndOfList.emit(options);
        }

        Ok(())
    }
}
