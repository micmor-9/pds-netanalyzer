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
    GenericError
}

impl std::error::Error for ParserError {}

impl Display for ParserError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            ParserError::EthernetPacketUnrecognized => write!(f, "[Parser] Packet not recognized!"),
            ParserError::EthernetPacketError => write!(f, "[Parser] Ethernet Packet error!"),
            ParserError::ArpPacketError => write!(f, "[Parser] ARP Packet error!"),
            ParserError::IPv4PacketError => write!(f, "[Parser] IPv4 Packet error!"),
            ParserError::IPv6PacketError => write!(f, "[Parser] IPv6 Packet error!"),
            ParserError::TransportProtocolError => write!(f, "[Parser] Transport Protocol error!"),
            ParserError::TCPSegmentError => write!(f, "[Parser] TCP Segment error!"),
            ParserError::UDPDatagramError => write!(f, "[Parser] UDP Datagram error!"),
            ParserError::ICMPPacketError => write!(f, "[Parser] ICMP Packet error!"),
            ParserError::GenericError => write!(f, "[Parser] Generic error!")
        }
    }
}