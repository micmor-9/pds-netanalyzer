use std::fmt::{Display, Formatter, Result};

#[derive(Debug)]
pub enum ParserError {
    EthernetPacketUnrecognized,
    EthernetPacketError,
    ArpPacketError,
    IPv4PacketError,
    IPv6PacketError,
    TransportProtocolError,
    TCPSegmentError,
    UDPDatagramError,
    ICMPPacketError,
    GenericError,
}

impl std::error::Error for ParserError {}

impl Display for ParserError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            ParserError::EthernetPacketUnrecognized => write!(f, "Packet not recognized!"),
            ParserError::EthernetPacketError => write!(f, "Ethernet Packet error!"),
            ParserError::ArpPacketError => write!(f, "ARP Packet error!"),
            ParserError::IPv4PacketError => write!(f, "IPv4 Packet error!"),
            ParserError::IPv6PacketError => write!(f, "IPv6 Packet error!"),
            ParserError::TransportProtocolError => write!(f, "Transport Protocol error!"),
            ParserError::TCPSegmentError => write!(f, "TCP Segment error!"),
            ParserError::UDPDatagramError => write!(f, "UDP Datagram error!"),
            ParserError::ICMPPacketError => write!(f, "ICMP Packet error!"),
            ParserError::GenericError => write!(f, "Generic error!"),
        }
    }
}
