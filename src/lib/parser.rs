use std::fmt::{Debug, Display, Formatter};
use std::net::IpAddr;
use pcap::Device;
use pktparse::arp::parse_arp_pkt;
use pktparse::ethernet::{EtherType, parse_ethernet_frame};
use chrono;
use pktparse::ip::IPProtocol;
use pktparse::ipv4::parse_ipv4_header;
use pktparse::ipv6::parse_ipv6_header;
use pktparse::tcp::parse_tcp_header;
use pktparse::udp::parse_udp_header;
use pktparse::icmp::{IcmpCode, parse_icmp_header};

use serde::Serialize;
use crate::error::ParserError;

#[derive(Debug, Serialize)]
pub struct Packet {
    pub interface: String,
    pub src_address: IpAddr,
    pub dest_address: IpAddr,
    pub src_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub length: u16,
    pub transport: String,
    pub application: String,
    pub timestamp: String,
}

impl Packet {
    pub fn new(
        interface: String,
        src_address: IpAddr,
        dest_address: IpAddr,
        src_port: Option<u16>,
        dest_port: Option<u16>,
        length: u16,
        transport: String,
        application: String,
        timestamp: String,
    ) -> Self {
        Packet {
            interface,
            src_address,
            dest_address,
            src_port,
            dest_port,
            length,
            transport,
            application,
            timestamp,
        }
    }
}

impl Display for Packet {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

pub fn ethernet_frame(interface: &Device, ethernet: &[u8]) -> Result<Packet, ParserError> {
    let interface_name = interface.name.as_str();
    let ethernet_frame = parse_ethernet_frame(ethernet);

    match ethernet_frame {
        Ok(result) => {
            let payload = result.0;
            let header = result.1;
            match header.ethertype {
                EtherType::IPv4 => ipv4_packet(interface_name, payload),
                EtherType::IPv6 => ipv6_packet(interface_name, payload),
                EtherType::ARP => arp_packet(interface_name, payload),
                _ => Err(
                    ParserError::EthernetPacketUnrecognized
                )
            }
        },
        Err(_) => Err(ParserError::EthernetPacketError)
    }
}

fn arp_packet(interface_name: &str, packet: &[u8]) -> Result<Packet, ParserError> {
    let parsed_arp_packet = parse_arp_pkt(packet);

    match parsed_arp_packet {
        Ok(result) => {
            let header = result.1;

            Ok(Packet::new(
                interface_name.to_string(),
                IpAddr::from(header.src_addr),
                IpAddr::from(header.dest_addr),
                None,
                None,
                packet.len() as u16,
                "ARP".to_string(),
                "".to_string(),
                chrono::offset::Local::now().to_string()
            ))
        },
        Err(_) => Err(ParserError::ArpPacketError)
    }
}

fn ipv6_packet(interface_name: &str, packet: &[u8]) -> Result<Packet, ParserError> {
    let parsed_ipv6_packet = parse_ipv6_header(packet);

    match parsed_ipv6_packet {
        Ok(result) => {
            let payload = result.0;
            let header = result.1;

            transport_protocol_parser(
                interface_name,
                header.next_header,
                payload,
                IpAddr::V6(header.source_addr),
                IpAddr::V6(header.dest_addr)
            )
        },
        Err(_) => Err(ParserError::IPv6PacketError)
    }
}

fn ipv4_packet(interface_name: &str, packet: &[u8]) -> Result<Packet, ParserError> {
    let parsed_ipv4_packet = parse_ipv4_header(packet);

    match parsed_ipv4_packet {
        Ok(result) => {
            let payload = result.0;
            let header = result.1;

            transport_protocol_parser(
                interface_name,
                header.protocol,
                payload,
                IpAddr::V4(header.source_addr),
                IpAddr::V4(header.dest_addr)
            )
        },
        Err(_) => Err(ParserError::IPv4PacketError)
    }
}

fn tcp_packet(interface_name: &str, source_addr: IpAddr, dest_addr: IpAddr, packet: &[u8]) -> Result<Packet, ParserError> {
    let parsed_tcp_header = parse_tcp_header(packet);

    match parsed_tcp_header {
        Ok(result) => {
            let header = result.1;
            let application_protocol = application_protocol_parser(&header.dest_port);

            Ok(Packet::new(
                interface_name.to_string(),
                source_addr,
                dest_addr,
                Some(header.source_port),
                Some(header.dest_port),
                packet.len() as u16,
                "TCP".to_string(),
                application_protocol,
                chrono::offset::Local::now().to_string()
            ))
        },
        Err(_) => Err(ParserError::TCPSegmentError)
    }
}

fn udp_packet(interface_name: &str, source_addr: IpAddr, dest_addr: IpAddr, packet: &[u8]) -> Result<Packet, ParserError> {
    let parsed_udp_header = parse_udp_header(packet);

    match parsed_udp_header {
        Ok(result) => {
            let header = result.1;
            let application_protocol = application_protocol_parser(&header.dest_port);

            Ok(Packet::new(
                interface_name.to_string(),
                source_addr,
                dest_addr,
                Some(header.source_port),
                Some(header.dest_port),
                packet.len() as u16,
                "TCP".to_string(),
                application_protocol,
                chrono::offset::Local::now().to_string()
            ))
        }
        Err(_) => Err(ParserError::UDPDatagramError)
    }
}

fn icmp_packet(interface_name: &str, source_addr: IpAddr, dest_addr: IpAddr, packet: &[u8]) -> Result<Packet, ParserError> {
    let parsed_icmp_header = parse_icmp_header(packet);

    match parsed_icmp_header {
        Ok(result) => {
            let header = result.1;

            Ok(Packet::new(
                interface_name.to_string(),
                source_addr,
                dest_addr,
                None,
                None,
                packet.len() as u16,
                ["ICMP", icmp_code_parser(header.code)].join(" - "),
                "".to_string(),
                chrono::offset::Local::now().to_string()
            ))
        }
        Err(_) => Err(ParserError::ICMPPacketError)
    }
}

fn generic_t_packet(interface_name: &str, source_addr: IpAddr, dest_addr: IpAddr, packet: &[u8]) -> Result<Packet, ParserError> {
    Ok(Packet::new(
        interface_name.to_string(),
        source_addr,
        dest_addr,
        None,
        None,
        packet.len() as u16,
        "unknown".to_string(),
        "unknown".to_string(),
        chrono::offset::Local::now().to_string()
    ))
}

// Function to parse the packet with the correct transport layer
fn transport_protocol_parser(interface_name: &str, t_protocol: IPProtocol, payload: &[u8], source_addr: IpAddr, dest_addr: IpAddr) -> Result<Packet, ParserError> {
    match t_protocol {
        IPProtocol::TCP => {
            tcp_packet(interface_name, source_addr, dest_addr, payload)
        },
        IPProtocol::UDP => {
            udp_packet(interface_name, source_addr, dest_addr, payload)
        },
        IPProtocol::ICMP => {
            icmp_packet(interface_name, source_addr, dest_addr, payload)
        },
        IPProtocol::Other(..) => {
            generic_t_packet(interface_name, source_addr, dest_addr, payload)
        }
        _ => Err(
            ParserError::TransportProtocolError
        )
    }
}

// Function to parse well-known application protocols
fn application_protocol_parser(port: &u16) -> String {
    match port {
        7 => "ECHO",
        20 => "FTP Data",
        21 => "FTP Control",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 => "BOOTP/DHCP Server",
        68 => "BOOTP/DHCP Client",
        69 => "TFTP",
        80 => "HTTP",
        88 => "Kerberos",
        110 => "POP",
        123 => "NTP",
        143 => "IMAP4",
        443 => "HTTPS",
        465 => "SMTP",
        853 => "DNSoverTLS",
        993 => "IMAP4overTLS",
        995 => "POP3overTLS",
        _ => "unknown"
    }.to_string()
}

fn icmp_code_parser<'a>(code: IcmpCode) -> &'a str {
    match code {
        IcmpCode::EchoReply => "Echo Reply",
        IcmpCode::Reserved => "Reserved",
        IcmpCode::DestinationUnreachable(_some) => "Destination Unreachable",
        IcmpCode::SourceQuench => "Source Quench",
        IcmpCode::Redirect(_some) => "Redirect",
        IcmpCode::EchoRequest => "Echo Request",
        IcmpCode::RouterAdvertisment => "Router Advertisement",
        IcmpCode::RouterSolicication => "Router Solicitation",
        IcmpCode::TimeExceeded(_some) => "Time Exceeded",
        IcmpCode::ParameterProblem(_some) => "Parameter Problem",
        IcmpCode::Timestamp => "Timestamp",
        IcmpCode::TimestampReply => "Timestamp Reply",
        IcmpCode::ExtendedEchoRequest => "Extended Echo Request",
        IcmpCode::ExtendedEchoReply(_some) => "Extended Echo Reply",
        IcmpCode::Other(_some) => "Unknown"
    }
}