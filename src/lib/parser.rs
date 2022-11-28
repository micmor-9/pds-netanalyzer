use std::error::{Error};
use std::fmt::{Debug, Display, Formatter, Result};
use std::net::IpAddr;
use pcap::Device;
use pktparse::ethernet::{EtherType, parse_ethernet_frame};

use serde::Serialize;

#[derive(Debug)]
pub enum ParserError {
    EthernetPacketUnrecognized,
    EthernetPacketError,
    GenericError
}

impl Error for ParserError {}

impl Display for ParserError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            ParserError::EthernetPacketUnrecognized => write!(f, "[Parser] Packet not recognized!"),
            ParserError::EthernetPacketError => write!(f, "[Parser] Parsing error!"),
            ParserError::GenericError => write!(f, "[Parser] Generic error!")
        }
    }
}

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
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
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