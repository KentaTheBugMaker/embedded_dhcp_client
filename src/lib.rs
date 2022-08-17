#[derive(Clone, Copy)]
#[repr(packed)]
pub struct DHCPMessageRaw {
    op: u8,
    htype: u8,
    /// hardware address len
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,

    ciaddr: [u8; 4],
    /// your (client) IP address
    yiaddr: [u8; 4],
    /// IP address of next server yo use in boot strap.
    siaddr: [u8; 4],
    /// Relay agent IP address
    giaddr: [u8; 4],
    /// Client hardware address
    chaddr: [u8; 16],
    ///Server host name
    sname: [u8; 64],
    ///Boot file name
    file: [u8; 128],
    options: [u8; 312],
    option_len: usize,
}
pub enum DecodeBuffer {
    Offer,
    Ack,
    Nak,
}

impl DHCPMessageRaw {
    pub unsafe fn decode_received_message(bytes: &[u8], received_bytes: usize) -> Self {
        assert!(bytes.len() > (core::mem::size_of::<Self>() - core::mem::size_of::<usize>()));
        assert!(received_bytes < core::mem::size_of::<Self>());
        fn transmute_u16(bytes: &[u8]) -> u16 {
            assert!(bytes.len() == 2);
            u16::from_be_bytes([bytes[0], bytes[1]])
        }
        fn copy_addr(bytes: &[u8]) -> [u8; 4] {
            assert!(bytes.len() == 4);
            [bytes[0], bytes[1], bytes[2], bytes[3]]
        }
        let mut chaddr = [0; 16];
        chaddr.copy_from_slice(&bytes[28..44]);
        let mut sname = [0; 64];
        sname.copy_from_slice(&bytes[44..108]);
        let mut file = [0; 128];
        file.copy_from_slice(&bytes[108..236]);
        let option_len = received_bytes - 236;
        let mut options = [0; 312];
        options[0..(received_bytes - 236)].copy_from_slice(&bytes[236..received_bytes]);
        Self {
            op: bytes[0],
            htype: bytes[1],
            hlen: bytes[2],
            hops: bytes[3],
            xid: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            secs: transmute_u16(&bytes[8..10]),
            flags: transmute_u16(&bytes[10..12]),
            ciaddr: copy_addr(&bytes[12..16]),
            yiaddr: copy_addr(&bytes[16..20]),
            siaddr: copy_addr(&bytes[20..24]),
            giaddr: copy_addr(&bytes[24..28]),
            chaddr,
            sname,
            file,
            options,
            option_len,
        }
    }

    pub fn decode_to_rustic_message(self, decode_buffer: DecodeBuffer) -> DHCPMessage<'static> {
        unsafe {
            match decode_buffer {
                DecodeBuffer::Offer => {
                    DHCP_OFFER_DECODE_BUFFER.copy_from_slice(&self.options);
                }
                DecodeBuffer::Ack => {
                    DHCP_ACK_DECODE_BUFFER.copy_from_slice(&self.options);
                }
                DecodeBuffer::Nak => {
                    DHCP_NAK_DECODE_BUFFER.copy_from_slice(&self.options);
                }
            }
        }
        let decoder = OptionDecoder::from_bytes(unsafe {
            match decode_buffer {
                DecodeBuffer::Offer => &DHCP_OFFER_DECODE_BUFFER,
                DecodeBuffer::Ack => &DHCP_ACK_DECODE_BUFFER,
                DecodeBuffer::Nak => &DHCP_NAK_DECODE_BUFFER,
            }
        })
        .unwrap();
        let mut options = [
            Options::Pad,
            Options::Pad,
            Options::Pad,
            Options::Pad,
            Options::Pad,
            Options::Pad,
            Options::Pad,
            Options::Pad,
            Options::Pad,
            Options::Pad,
        ];
        decoder
            .zip(options.iter_mut())
            .for_each(|(option, cell)| *cell = option);

        DHCPMessage {
            op: match self.op {
                1 => Op::BootRequest,
                2 => Op::BootReply,
                _ => {
                    unreachable!("")
                }
            },
            htype: match self.htype {
                1 => HType::Ethernet,
                _ => {
                    unreachable!("")
                }
            },
            hlen: self.hlen,
            hops: self.hops,
            xid: self.xid,
            secs: self.secs,
            flags: match self.flags {
                0x8000 => true,
                0x0000 => false,
                _ => {
                    unreachable!("invalid flags.")
                }
            },
            ciaddr: self.ciaddr,
            yiaddr: self.yiaddr,
            siaddr: self.siaddr,
            giaddr: self.giaddr,
            chaddr: self.chaddr,
            sname: self.sname,
            file: self.file,
            options,
        }
    }
}

#[derive(Debug)]
pub struct DHCPMessage<'a> {
    pub op: Op,
    pub htype: HType,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: bool,
    pub ciaddr: [u8; 4],
    pub yiaddr: [u8; 4],
    pub siaddr: [u8; 4],
    pub giaddr: [u8; 4],
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    pub options: [Options<'a>; 10],
}

/// migic cookie
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

static mut DHCP_OFFER_DECODE_BUFFER: [u8; 312] = [0; 312];
static mut DHCP_ACK_DECODE_BUFFER: [u8; 312] = [0; 312];
static mut DHCP_NAK_DECODE_BUFFER: [u8; 312] = [0; 312];
impl<'a> DHCPMessage<'a> {
    pub fn new_discover(
        transaction_id: u32,
        hardware_address: HwAddress<'a>,
        hw_type: HType,
        parameter_request_list: &'a [u8],
    ) -> Self {
        let (htype, hlen) = hw_type.into();
        let options = [
            Options::DHCPMessageType(MessageTy::Discover),
            Options::ClientIdentifier(htype, hardware_address.addr()),
            Options::VendorClassIdentifier("rust-embedded-dhcp-client"),
            Options::ParameterRequestList(parameter_request_list),
            Options::End,
            Options::Pad,
            Options::Pad,
            Options::Pad,
            Options::Pad,
            Options::Pad,
        ];
        let mut chaddr = [0; 16];
        chaddr[0..hlen as usize].copy_from_slice(hardware_address.addr());
        Self {
            op: Op::BootRequest,
            htype: hw_type,
            hlen,
            hops: 0,
            xid: transaction_id,
            secs: 0,
            flags: true,
            ciaddr: 0u32.to_be_bytes(),
            yiaddr: 0u32.to_be_bytes(),
            siaddr: 0u32.to_be_bytes(),
            giaddr: 0u32.to_be_bytes(),
            chaddr,
            sname: [0x0; 64],
            file: [0x0; 128],
            options,
        }
    }

    pub fn new_request(
        transaction_id: u32,
        hardware_address: HwAddress<'a>,
        hw_type: HType,
        offered_ip_addr: [u8; 4],
        server_ip_addr: [u8; 4],
    ) -> Self {
        let (htype, hlen) = hw_type.into();
        let options = [
            Options::DHCPMessageType(MessageTy::Request),
            Options::RequestedIPAddress(offered_ip_addr),
            Options::ServerIdentifer(server_ip_addr),
            Options::ClientIdentifier(htype, hardware_address.addr()),
            Options::VendorClassIdentifier("rust-embedded-dhcp-client"),
            Options::End,
            Options::Pad,
            Options::Pad,
            Options::Pad,
            Options::Pad,
        ];
        let mut chaddr = [0; 16];
        chaddr[0..hlen as usize].copy_from_slice(hardware_address.addr());
        Self {
            op: Op::BootRequest,
            htype: hw_type,
            hlen,
            hops: 0,
            xid: transaction_id,
            secs: 0,
            flags: true,
            ciaddr: 0u32.to_be_bytes(),
            yiaddr: 0u32.to_be_bytes(),
            siaddr: 0u32.to_be_bytes(),
            giaddr: 0u32.to_be_bytes(),
            chaddr,
            sname: [0x0; 64],
            file: [0x0; 128],
            options,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum HwAddress<'a> {
    Ethernet(&'a [u8; 6]),
}

impl<'a> HwAddress<'a> {
    fn addr(&self) -> &'a [u8] {
        match self {
            HwAddress::Ethernet(x) => *x,
        }
    }
}

impl<'a> Into<HType> for HwAddress<'a> {
    fn into(self) -> HType {
        match self {
            HwAddress::Ethernet(_) => HType::Ethernet,
        }
    }
}

impl<'a> Into<DHCPMessageRaw> for DHCPMessage<'a> {
    fn into(self) -> DHCPMessageRaw {
        let encoder = self
            .options
            .iter()
            .fold(OptionEncoder::new().init(), |encoder, option| {
                encoder.encode(option)
            });
        let OptionEncoder {
            buffer: options,
            next_pos: option_len,
        } = encoder;
        let (htype, hlen) = self.htype.into();
        DHCPMessageRaw {
            op: match self.op {
                Op::BootRequest => 1,
                Op::BootReply => 2,
            },
            htype,
            hlen,
            hops: self.hops,
            xid: self.xid.to_be(),
            secs: self.secs,
            flags: if self.flags { 0x8000u16.to_be() } else { 0 },
            ciaddr: self.ciaddr,
            yiaddr: self.yiaddr,
            siaddr: self.siaddr,
            giaddr: self.giaddr,
            chaddr: self.chaddr,
            sname: self.sname,
            file: self.file,
            options,
            option_len,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Op {
    BootRequest,
    BootReply,
}

#[derive(Clone, Copy, Debug)]
pub enum HType {
    /// ethernet or wifi.
    Ethernet,
    ExperimentalEthernet,
    AX25,
    ProteonProNETTokenRing,
    Chaos,
    IEEE802Networks,
    ARCNET,
    Hyperchannel,
    Lanstar,
    AutonetShortAddress,
    LocalTalk,
    LocalNet,
    Ultralink,
    SMDS,
    FrameRelay,
    Atm,
    HDLC,
    FibreChannel,
    SerialLine,
}

impl Into<(u8, u8)> for HType {
    /// implementation for hardware type and hardware address length.
    fn into(self) -> (u8, u8) {
        match self {
            HType::Ethernet => (1, 6),
            HType::ExperimentalEthernet => todo!(),
            HType::AX25 => todo!(),
            HType::ProteonProNETTokenRing => todo!(),
            HType::Chaos => todo!(),
            HType::IEEE802Networks => todo!(),
            HType::ARCNET => todo!(),
            HType::Hyperchannel => todo!(),
            HType::Lanstar => todo!(),
            HType::AutonetShortAddress => todo!(),
            HType::LocalTalk => todo!(),
            HType::LocalNet => todo!(),
            HType::Ultralink => todo!(),
            HType::SMDS => todo!(),
            HType::FrameRelay => todo!(),
            HType::Atm => todo!(),
            HType::HDLC => todo!(),
            HType::FibreChannel => todo!(),
            HType::SerialLine => todo!(),
        }
    }
}

/// see RFC 2132 .
///
/// Don't support VSI.
#[derive(Debug)]
pub enum Options<'a> {
    Pad,
    End,
    SubNetMask([u8; 4]),
    TimeOffset([u8; 4]),
    Router(&'a [[u8; 4]]),
    TimeServer(&'a [[u8; 4]]),
    NameServer(&'a [[u8; 4]]),
    DNS(&'a [[u8; 4]]),
    LogServer(&'a [[u8; 4]]),
    CookieServer(&'a [[u8; 4]]),
    LPRServer(&'a [[u8; 4]]),
    ImpressServer(&'a [[u8; 4]]),
    ResourceLocationServer(&'a [[u8; 4]]),
    Hostname(&'a str),
    BootfileSize(u16),
    MeritDumpFile(&'a str),
    DomainName(&'a str),
    SwapServer([u8; 4]),
    RootPath(&'a str),
    ExtensionPath(&'a str),
    IpForwarding(bool),
    NonLocalSourceRouting(bool),
    PolicyFilter(&'a [([u8; 4], [u8; 4])]),
    MaximumDatagramReassemblySize(u16),
    DefaultIpTTL(u8),
    PathMTUAgingTimeout(u32),
    PathMTUPalteauTable(&'a [u16]),
    InterfaceMTU(u16),
    AllSubnetsAreLocal(bool),
    BroadCastAddress([u8; 4]),
    PerformMaskDiscovery(bool),
    MaskSupplier(bool),
    PerformRouterDiscovery(bool),
    RouterSolicitationAddress([u8; 4]),
    StaticRoute(&'a [([u8; 4], [u8; 4])]),
    TrailerEncapsulation(bool),
    ARPCacheTimeout(u32),
    EthernetEncapsulation(bool),
    TCPDefaultTTL(u8),
    TCPKeepaliveInterval(u32),
    TCPKeepaliveGarbage(bool),
    NetworkInformationServiceDomain(&'a str),
    NetworkInformationServers(&'a [[u8; 4]]),
    NTPServer(&'a [[u8; 4]]),
    //VendorSpecificInformation(u16,),
    NetBIOSoverTCPIPNameServer(&'a [[u8; 4]]),
    NetBIOSoverTCPIPDatagramDistributionServer(&'a [[u8; 4]]),
    NetBIOSoverTCPIPNodeType(u8),
    NetBIOSoverTCPIPScope(&'a str),
    XWindowSystemFontServer(&'a [[u8; 4]]),
    XWindowSystemDisplayManager(&'a [[u8; 4]]),
    NetworkInformationServicePlusDomain(&'a str),
    NetworkInformationServicePlusServers(&'a [[u8; 4]]),
    MobileIPHomeAgent(&'a [[u8; 4]]),
    SMTPServer(&'a [[u8; 4]]),
    POPServer(&'a [[u8; 4]]),
    NNTPServer(&'a [[u8; 4]]),
    DefaultWWWServer(&'a [[u8; 4]]),
    DefaultFingerServer(&'a [[u8; 4]]),
    DefaultIRCServer(&'a [[u8; 4]]),
    StreetTalkServer(&'a [[u8; 4]]),
    StreetTalkDirectoryAssistanceServer(&'a [[u8; 4]]),
    RequestedIPAddress([u8; 4]),
    IPAddressLeaseTime(u32),
    OptionOverload(OverloadMode),
    TFTPServerName(&'a str),
    BootFileName(&'a str),
    DHCPMessageType(MessageTy),
    ServerIdentifer([u8; 4]),
    ParameterRequestList(&'a [u8]),
    Message(&'a str),
    MaximumDHCPMessageSize(u16),
    RenewalTime(u32),
    RebindingTime(u32),
    VendorClassIdentifier(&'a str),
    ClientIdentifier(u8, &'a [u8]),
}

impl<'a> Options<'a> {
    pub fn tag_number(&self) -> u8 {
        match self {
            Options::Pad => 0,
            Options::End => 255,
            Options::SubNetMask(_) => 1,
            Options::TimeOffset(_) => 2,
            Options::Router(_) => 3,
            Options::TimeServer(_) => 4,
            Options::NameServer(_) => 5,
            Options::DNS(_) => 6,
            Options::LogServer(_) => 7,
            Options::CookieServer(_) => 8,
            Options::LPRServer(_) => 9,
            Options::ImpressServer(_) => 10,
            Options::ResourceLocationServer(_) => 11,
            Options::Hostname(_) => 12,
            Options::BootfileSize(_) => 13,
            Options::MeritDumpFile(_) => 14,
            Options::DomainName(_) => 15,
            Options::SwapServer(_) => 16,
            Options::RootPath(_) => 17,
            Options::ExtensionPath(_) => 18,
            Options::IpForwarding(_) => 19,
            Options::NonLocalSourceRouting(_) => 20,
            Options::PolicyFilter(_) => 21,
            Options::MaximumDatagramReassemblySize(_) => 22,
            Options::DefaultIpTTL(_) => 23,
            Options::PathMTUAgingTimeout(_) => 24,
            Options::PathMTUPalteauTable(_) => 25,
            Options::InterfaceMTU(_) => 26,
            Options::AllSubnetsAreLocal(_) => 27,
            Options::BroadCastAddress(_) => 28,
            Options::PerformMaskDiscovery(_) => 29,
            Options::MaskSupplier(_) => 30,
            Options::PerformRouterDiscovery(_) => 31,
            Options::RouterSolicitationAddress(_) => 32,
            Options::StaticRoute(_) => 33,
            Options::TrailerEncapsulation(_) => 34,
            Options::ARPCacheTimeout(_) => 35,
            Options::EthernetEncapsulation(_) => 36,
            Options::TCPDefaultTTL(_) => 37,
            Options::TCPKeepaliveInterval(_) => 38,
            Options::TCPKeepaliveGarbage(_) => 39,
            Options::NetworkInformationServiceDomain(_) => 40,
            Options::NetworkInformationServers(_) => 41,
            Options::NTPServer(_) => 42,
            Options::NetBIOSoverTCPIPNameServer(_) => 44,
            Options::NetBIOSoverTCPIPDatagramDistributionServer(_) => 45,
            Options::NetBIOSoverTCPIPNodeType(_) => 46,
            Options::NetBIOSoverTCPIPScope(_) => 47,
            Options::XWindowSystemFontServer(_) => 48,
            Options::XWindowSystemDisplayManager(_) => 49,
            Options::NetworkInformationServicePlusDomain(_) => 64,
            Options::NetworkInformationServicePlusServers(_) => 65,
            Options::MobileIPHomeAgent(_) => 68,
            Options::SMTPServer(_) => 69,
            Options::POPServer(_) => 70,
            Options::NNTPServer(_) => 71,
            Options::DefaultWWWServer(_) => 72,
            Options::DefaultFingerServer(_) => 73,
            Options::DefaultIRCServer(_) => 74,
            Options::StreetTalkServer(_) => 75,
            Options::StreetTalkDirectoryAssistanceServer(_) => 76,
            Options::RequestedIPAddress(_) => 50,
            Options::IPAddressLeaseTime(_) => 51,
            Options::OptionOverload(_) => 52,
            Options::TFTPServerName(_) => 66,
            Options::BootFileName(_) => 67,
            Options::DHCPMessageType(_) => 53,
            Options::ServerIdentifer(_) => 54,
            Options::ParameterRequestList(_) => 55,
            Options::Message(_) => 56,
            Options::MaximumDHCPMessageSize(_) => 57,
            Options::RenewalTime(_) => 58,
            Options::RebindingTime(_) => 59,
            Options::VendorClassIdentifier(_) => 60,
            Options::ClientIdentifier(_, _) => 61,
        }
    }
}

struct OptionDecoder {
    bytes: &'static [u8],
    next_pos: usize,
}
impl OptionDecoder {
    pub fn from_bytes(bytes: &'static [u8]) -> Option<Self> {
        if bytes[0..4] == MAGIC_COOKIE {
            Some(Self { bytes, next_pos: 4 })
        } else {
            None
        }
    }
}
impl Iterator for OptionDecoder {
    type Item = Options<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        let first_byte = self.bytes[self.next_pos];
        match first_byte {
            0x0 => {
                self.next_pos += 1;
                Some(Options::Pad)
            }
            0xff => {
                self.next_pos += 1;
                Some(Options::End)
            }
            //[u8;4]
            1 | 2 | 16 | 28 | 32 | 50 | 54 => {
                let data = [
                    self.bytes[self.next_pos + 2],
                    self.bytes[self.next_pos + 3],
                    self.bytes[self.next_pos + 4],
                    self.bytes[self.next_pos + 5],
                ];

                self.next_pos += 6;
                Some(match first_byte {
                    1 => Options::SubNetMask(data),
                    2 => Options::TimeOffset(data),
                    16 => Options::SwapServer(data),
                    28 => Options::BroadCastAddress(data),
                    32 => Options::RouterSolicitationAddress(data),
                    50 => Options::RequestedIPAddress(data),
                    54 => Options::ServerIdentifer(data),
                    _ => {
                        unreachable!()
                    }
                })
            }
            //&[[u8;4]]
            3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 41 | 42 | 44 | 45 | 48 | 49 | 65 | 68 | 69
            | 70 | 71 | 72 | 73 | 74 | 75 | 76 => {
                let ptr = (&self.bytes[self.next_pos + 2] as *const u8) as *const [u8; 4];
                let bytes_of_data = self.bytes[self.next_pos + 1];
                let slice =
                    unsafe { core::slice::from_raw_parts(ptr, (bytes_of_data / 4) as usize) };

                self.next_pos += 2 + bytes_of_data as usize;
                Some(match first_byte {
                    3 => Options::Router(slice),
                    4 => Options::TimeServer(slice),
                    5 => Options::NameServer(slice),
                    6 => Options::DNS(slice),
                    7 => Options::LogServer(slice),
                    8 => Options::CookieServer(slice),
                    9 => Options::LPRServer(slice),
                    10 => Options::ImpressServer(slice),
                    11 => Options::ResourceLocationServer(slice),
                    41 => Options::NetworkInformationServers(slice),
                    42 => Options::NTPServer(slice),
                    44 => Options::NetBIOSoverTCPIPNameServer(slice),
                    45 => Options::NetBIOSoverTCPIPDatagramDistributionServer(slice),
                    48 => Options::XWindowSystemFontServer(slice),
                    49 => Options::XWindowSystemDisplayManager(slice),
                    65 => Options::NetworkInformationServicePlusServers(slice),
                    68 => Options::MobileIPHomeAgent(slice),
                    69 => Options::SMTPServer(slice),
                    70 => Options::POPServer(slice),
                    71 => Options::NNTPServer(slice),
                    72 => Options::DefaultWWWServer(slice),
                    73 => Options::DefaultFingerServer(slice),
                    74 => Options::DefaultIRCServer(slice),
                    75 => Options::StreetTalkServer(slice),
                    76 => Options::StreetTalkDirectoryAssistanceServer(slice),
                    _ => {
                        unreachable!()
                    }
                })
            }
            //&str
            12 | 14 | 15 | 17 | 18 | 40 | 47 | 64 | 66 | 67 | 56 | 60 => {
                let ptr = &self.bytes
                    [self.next_pos + 2..self.next_pos + 2 + self.bytes[self.next_pos + 1] as usize];

                let txt = core::str::from_utf8(ptr).unwrap();
                Some(match first_byte {
                    12 => Options::Hostname(txt),
                    14 => Options::MeritDumpFile(txt),
                    15 => Options::DomainName(txt),
                    17 => Options::RootPath(txt),
                    18 => Options::ExtensionPath(txt),
                    40 => Options::NetworkInformationServiceDomain(txt),
                    47 => Options::NetBIOSoverTCPIPScope(txt),
                    64 => Options::NetworkInformationServicePlusDomain(txt),
                    66 => Options::TFTPServerName(txt),
                    67 => Options::BootFileName(txt),
                    56 => Options::Message(txt),
                    60 => Options::VendorClassIdentifier(txt),
                    _ => {
                        unreachable!()
                    }
                })
            }
            //u16
            13 | 22 | 26 | 57 => {
                let x = [self.bytes[self.next_pos + 2], self.bytes[self.next_pos + 3]];
                let x: u16 = unsafe { core::mem::transmute(x) };
                let x = u16::from_be(x);
                self.next_pos += 4;
                Some(match first_byte {
                    13 => Options::BootfileSize(x),
                    22 => Options::MaximumDatagramReassemblySize(x),
                    26 => Options::InterfaceMTU(x),
                    57 => Options::MaximumDHCPMessageSize(x),
                    _ => unreachable!(),
                })
            }
            //bool
            19 | 20 | 27 | 29 | 30 | 31 | 34 | 36 | 39 => {
                let x = self.bytes[self.next_pos + 2];
                let x = if x == 0 { false } else { true };
                self.next_pos += 3;
                Some(match first_byte {
                    19 => Options::IpForwarding(x),
                    20 => Options::NonLocalSourceRouting(x),
                    27 => Options::AllSubnetsAreLocal(x),
                    29 => Options::PerformMaskDiscovery(x),
                    30 => Options::MaskSupplier(x),
                    31 => Options::PerformRouterDiscovery(x),
                    34 => Options::TrailerEncapsulation(x),
                    36 => Options::EthernetEncapsulation(x),
                    39 => Options::TCPKeepaliveGarbage(x),
                    _ => {
                        unreachable!()
                    }
                })
            }
            //&[([u8;4],[u8;4])]
            21 | 33 => {
                let ptr =
                    (&self.bytes[self.next_pos + 2] as *const u8) as *const ([u8; 4], [u8; 4]);
                let bytes_of_data = self.bytes[self.next_pos + 1];
                let slice =
                    unsafe { core::slice::from_raw_parts(ptr, (bytes_of_data / 8) as usize) };
                self.next_pos += 2 + bytes_of_data as usize;
                Some(match first_byte {
                    21 => Options::PolicyFilter(slice),
                    33 => Options::StaticRoute(slice),
                    _ => {
                        unreachable!()
                    }
                })
            }
            // u8
            23 | 37 | 46 | 53 => {
                let x = self.bytes[self.next_pos + 2];
                self.next_pos += 3;

                Some(match first_byte {
                    23 => Options::DefaultIpTTL(x),
                    37 => Options::TCPDefaultTTL(x),
                    46 => Options::NetBIOSoverTCPIPNodeType(x),
                    52 => Options::OptionOverload(match x {
                        1 => OverloadMode::File,
                        2 => OverloadMode::SName,
                        3 => OverloadMode::Both,
                        _ => unreachable!(),
                    }),
                    53 => Options::DHCPMessageType(match x {
                        1 => MessageTy::Discover,
                        2 => MessageTy::Offer,
                        3 => MessageTy::Request,
                        4 => MessageTy::Decline,
                        5 => MessageTy::Ack,
                        6 => MessageTy::Nak,
                        7 => MessageTy::Release,
                        8 => MessageTy::Inform,
                        _ => unreachable!(),
                    }),
                    _ => unreachable!(),
                })
            }
            //u32
            24 | 35 | 38 | 51 | 58 | 59 => {
                let x = [
                    self.bytes[self.next_pos + 2],
                    self.bytes[self.next_pos + 3],
                    self.bytes[self.next_pos + 4],
                    self.bytes[self.next_pos + 5],
                ];
                let x: u32 = unsafe { core::mem::transmute(x) };
                let x = u32::from_be(x);
                self.next_pos += 6;
                Some(match first_byte {
                    24 => Options::PathMTUAgingTimeout(x),
                    35 => Options::ARPCacheTimeout(x),
                    38 => Options::TCPKeepaliveInterval(x),
                    51 => Options::IPAddressLeaseTime(x),
                    58 => Options::RenewalTime(x),
                    59 => Options::RebindingTime(x),

                    _ => unreachable!(),
                })
            }
            //&[u16]
            25 => {
                let index = self.next_pos + 2;
                let ptr = (&self.bytes[index] as *const u8) as *mut u16;
                let bytes_of_data = self.bytes[self.next_pos + 1];
                let slice =
                    unsafe { core::slice::from_raw_parts_mut(ptr, (bytes_of_data / 2) as usize) };
                slice.iter_mut().for_each(|ptr| {
                    *ptr = u16::from_be(*ptr);
                });
                self.next_pos += 2 + bytes_of_data as usize;
                Some(match first_byte {
                    25 => Options::PathMTUPalteauTable(slice),
                    _ => {
                        unreachable!()
                    }
                })
            }
            55 => {
                let ptr = &self.bytes
                    [self.next_pos + 2..self.next_pos + 2 + self.bytes[self.next_pos + 1] as usize];
                self.next_pos += 2 + self.bytes[self.next_pos + 1] as usize;
                Some(Options::ParameterRequestList(ptr))
            }
            61 => {
                let len = (self.bytes[self.next_pos + 1] - 1) as usize;
                let ty = self.bytes[self.next_pos + 2];
                let slice = &self.bytes[self.next_pos + 3..self.next_pos + 3 + len];
                self.next_pos += 3 + len;
                Some(Options::ClientIdentifier(ty, slice))
            }
            _ => None,
        }
    }
}

struct OptionEncoder {
    buffer: [u8; 312],
    next_pos: usize,
}

impl OptionEncoder {
    fn new() -> Self {
        Self {
            buffer: [0; 312],
            next_pos: 0,
        }
    }
    fn init(mut self) -> Self {
        self.buffer[0..4].copy_from_slice(&MAGIC_COOKIE);
        self.next_pos = 4;
        self
    }
    fn encode(mut self, option: &Options) -> Self {
        let first_byte = option.tag_number();
        self.buffer[self.next_pos] = first_byte;
        self.next_pos += 1;
        match option {
            Options::Pad => {}
            Options::End => {}
            Options::SubNetMask(x)
            | Options::TimeOffset(x)
            | Options::SwapServer(x)
            | Options::BroadCastAddress(x)
            | Options::RouterSolicitationAddress(x)
            | Options::RequestedIPAddress(x)
            | Options::ServerIdentifer(x) => {
                self.buffer[self.next_pos] = 4;
                self.next_pos += 1;
                self.buffer[self.next_pos..self.next_pos + 4].copy_from_slice(x);
                self.next_pos += 4;
            }

            Options::Router(x)
            | Options::TimeServer(x)
            | Options::NameServer(x)
            | Options::DNS(x)
            | Options::LogServer(x)
            | Options::CookieServer(x)
            | Options::LPRServer(x)
            | Options::ImpressServer(x)
            | Options::ResourceLocationServer(x)
            | Options::NetworkInformationServers(x)
            | Options::NTPServer(x)
            | Options::NetBIOSoverTCPIPNameServer(x)
            | Options::NetBIOSoverTCPIPDatagramDistributionServer(x)
            | Options::XWindowSystemFontServer(x)
            | Options::XWindowSystemDisplayManager(x)
            | Options::NetworkInformationServicePlusServers(x)
            | Options::MobileIPHomeAgent(x)
            | Options::SMTPServer(x)
            | Options::POPServer(x)
            | Options::NNTPServer(x)
            | Options::DefaultWWWServer(x)
            | Options::DefaultFingerServer(x)
            | Options::DefaultIRCServer(x)
            | Options::StreetTalkServer(x)
            | Options::StreetTalkDirectoryAssistanceServer(x) => {
                self.buffer[self.next_pos] = 4 * x.len() as u8;
                self.next_pos += 1;
                for addr in *x {
                    self.buffer[self.next_pos..self.next_pos + 4].copy_from_slice(addr);
                    self.next_pos += 4;
                }
                self.next_pos += 1;
            }

            Options::Hostname(x)
            | Options::MeritDumpFile(x)
            | Options::DomainName(x)
            | Options::RootPath(x)
            | Options::ExtensionPath(x)
            | Options::NetworkInformationServiceDomain(x)
            | Options::NetBIOSoverTCPIPScope(x)
            | Options::NetworkInformationServicePlusDomain(x)
            | Options::TFTPServerName(x)
            | Options::BootFileName(x)
            | Options::Message(x)
            | Options::VendorClassIdentifier(x) => {
                self.buffer[self.next_pos] = x.len() as u8;
                self.next_pos += 1;
                self.buffer[self.next_pos..self.next_pos + x.len()].copy_from_slice(x.as_bytes());
                self.next_pos += x.len();
                self.next_pos += 1;
            }

            Options::DefaultIpTTL(x)
            | Options::NetBIOSoverTCPIPNodeType(x)
            | Options::TCPDefaultTTL(x) => {
                self.buffer[self.next_pos] = 1;
                self.next_pos += 1;
                self.buffer[self.next_pos] = *x;
                self.next_pos += 1;
            }

            Options::BootfileSize(x)
            | Options::MaximumDatagramReassemblySize(x)
            | Options::InterfaceMTU(x)
            | Options::MaximumDHCPMessageSize(x) => {
                self.buffer[self.next_pos] = 2;
                self.next_pos += 1;
                self.buffer[self.next_pos..self.next_pos + 2].copy_from_slice(&x.to_be_bytes());
                self.next_pos += 1;
            }

            Options::PathMTUAgingTimeout(x)
            | Options::TCPKeepaliveInterval(x)
            | Options::ARPCacheTimeout(x)
            | Options::IPAddressLeaseTime(x)
            | Options::RenewalTime(x)
            | Options::RebindingTime(x) => {
                self.buffer[self.next_pos] = 4;
                self.next_pos += 1;
                self.buffer[self.next_pos..self.next_pos + 4].copy_from_slice(&x.to_be_bytes());
                self.next_pos += 1;
            }

            Options::PathMTUPalteauTable(x) => todo!(),

            Options::IpForwarding(x)
            | Options::NonLocalSourceRouting(x)
            | Options::AllSubnetsAreLocal(x)
            | Options::PerformMaskDiscovery(x)
            | Options::MaskSupplier(x)
            | Options::PerformRouterDiscovery(x)
            | Options::TrailerEncapsulation(x)
            | Options::EthernetEncapsulation(x)
            | Options::TCPKeepaliveGarbage(x) => {
                self.buffer[self.next_pos] = 1;
                let x = if *x { 0 } else { 1 };
                self.next_pos += 1;
                self.buffer[self.next_pos] = x;
                self.next_pos += 1;
            }

            Options::PolicyFilter(x) | Options::StaticRoute(x) => todo!(),

            Options::OptionOverload(x) => {
                self.buffer[self.next_pos] = 1;
                let x = match x {
                    OverloadMode::File => 1,
                    OverloadMode::SName => 2,
                    OverloadMode::Both => 3,
                };
                self.next_pos += 1;
                self.buffer[self.next_pos] = x;
                self.next_pos += 1;
            }

            Options::DHCPMessageType(x) => {
                self.buffer[self.next_pos] = 1;
                let x = match x {
                    MessageTy::Discover => 1,
                    MessageTy::Offer => 2,
                    MessageTy::Request => 3,
                    MessageTy::Decline => 4,
                    MessageTy::Ack => 5,
                    MessageTy::Nak => 6,
                    MessageTy::Release => 7,
                    MessageTy::Inform => 8,
                };
                self.next_pos += 1;
                self.buffer[self.next_pos] = x;
                self.next_pos += 1;
            }
            Options::ParameterRequestList(x) => {
                self.buffer[self.next_pos] = x.len() as u8;
                self.next_pos += 1;
                self.buffer[self.next_pos..self.next_pos + x.len()].copy_from_slice(x);
                self.next_pos += x.len();
            }
            Options::ClientIdentifier(x, y) => {
                self.buffer[self.next_pos] = (y.len() + 1) as u8;
                self.next_pos += 1;
                self.buffer[self.next_pos] = *x;
                self.next_pos += 1;
                self.buffer[self.next_pos..self.next_pos + y.len()].copy_from_slice(y);
                self.next_pos += y.len();
            }
        }
        self
    }
}

#[derive(Debug)]
pub enum OverloadMode {
    File,
    SName,
    Both,
}
#[derive(Debug)]
pub enum MessageTy {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}
