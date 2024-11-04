use pnet::packet::arp::Arp;
use pnet::packet::ethernet::{EtherTypes, Ethernet, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4, Ipv4Packet};
use pnet::packet::ipv6::{Ipv6, Ipv6Packet};
use pnet::packet::tcp::{Tcp, TcpPacket};
use pnet::packet::udp::{Udp, UdpPacket};
use pnet::packet::Packet;
use strum_macros::{Display};
use crate::protocol_utils::*;

// Define Full Packet structs
#[derive(Debug, Clone)]
pub struct TcpIpv4 {
    ethernet: Ethernet,
    ip: Ipv4,
    tcp: Tcp,
}

#[derive(Debug, Clone)]
pub struct UdpIpv4 {
    ethernet: Ethernet,
    ip: Ipv4,
    udp: Udp,
}

#[derive(Debug, Clone)]
pub struct TcpIpv6 {
    ethernet: Ethernet,
    ip: Ipv6,
    tcp: Tcp,
}

#[derive(Debug, Clone)]
pub struct UdpIpv6 {
    ethernet: Ethernet,
    ip: Ipv6,
    udp: Udp,
}

#[derive(Debug, Clone)]
pub struct FullArp {
    ethernet: Ethernet,
    arp: Arp,
}

#[derive(Debug, Clone)]
pub struct FullIpv4 {
    ethernet: Ethernet,
    ip: Ipv4,
}

#[derive(Debug, Clone)]
pub struct FullIpv6 {
    ethernet: Ethernet,
    ip: Ipv6,
}

#[derive(Debug, Clone, Display)]
pub enum FullPacket {
    TcpIpv4(TcpIpv4),
    UdpIpv4(UdpIpv4),
    TcpIpv6(TcpIpv6),
    UdpIpv6(UdpIpv6),
    Arp(FullArp),
    Ethernet(Ethernet),
    FullIpv4(FullIpv4),
    FullIpv6(FullIpv6),
}

impl FullPacket {
    pub fn new(packet_bytes: &[u8]) -> FullPacket {
        let ethernet_packet =
            EthernetPacket::new(packet_bytes).expect("Coudldn't create Ethernet Packet");

        let ethernet_header = ethernet_packet.into_header();

        match ethernet_header.ethertype {
            
            EtherTypes::Ipv4 => {

                let ipv4 = Ipv4Packet::new(ethernet_packet.payload())
                    .expect("Coudln't Create ipv4 packet");
                let ipv4_header = ipv4.into_header();

                match ipv4_header.next_level_protocol {

                    IpNextHeaderProtocols::Tcp => {

                        let tcp = TcpPacket::new(&ipv4_header.payload)
                            .expect("Couldn't Create Tcp Packet");

                        return FullPacket::TcpIpv4(TcpIpv4 {
                            ethernet: ethernet_header,
                            ip: ipv4_header.clone(),
                            tcp: tcp.into_header(),
                        });
                    }

                    IpNextHeaderProtocols::Udp => {

                        let udp = UdpPacket::new(&ipv4_header.payload)
                            .expect("Coudln't Create udp Packet");

                        return FullPacket::UdpIpv4(UdpIpv4 {
                            ethernet: ethernet_header,
                            ip: ipv4_header.clone(),
                            udp: udp.into_header()
                        });

                    }

                    _ => FullPacket::FullIpv4(FullIpv4 {
                        ethernet: ethernet_header,
                        ip: ipv4_header,
                    }),
                }
            }

            EtherTypes::Ipv6 => {

                let ipv6 = Ipv6Packet::new(ethernet_packet.payload())
                    .expect("Coudln't Create ipv6 packet");
                let ipv6_header = ipv6.into_header();
                
                match ipv6_header.next_header {


                    IpNextHeaderProtocols::Tcp => {

                        let tcp = TcpPacket::new(&ipv6_header.payload)
                            .expect("Couldn't Create Tcp Packet");

                        return FullPacket::TcpIpv6(TcpIpv6 {
                            ethernet: ethernet_header,
                            ip: ipv6_header.clone(),
                            tcp: tcp.into_header(),
                        });
                    }

                    IpNextHeaderProtocols::Udp => {

                        let udp = UdpPacket::new(&ipv6_header.payload)
                            .expect("Coudln't Create udp Packet");

                        return FullPacket::UdpIpv6(UdpIpv6 {
                            ethernet: ethernet_header,
                            ip: ipv6_header.clone(),
                            udp: udp.into_header()
                        });

                    }

                    _ => FullPacket::FullIpv6(FullIpv6 {
                        ethernet: ethernet_header,
                        ip: ipv6_header,
                    }),
                    
                }

            }

            _ => FullPacket::Ethernet(ethernet_header),
        }
    }
}
