use pnet::packet::arp::{Arp, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, Ethernet, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4, Ipv4Packet};
use pnet::packet::ipv6::{Ipv6, Ipv6Packet};
use pnet::packet::tcp::{Tcp, TcpPacket};
use pnet::packet::udp::{Udp, UdpPacket};
use pnet::packet::Packet;
use strum_macros::Display;
use crate::protocol_utils::*;
use paste::paste;

macro_rules! FullEthernetPacket {
    
    ($( $protocol:ident ),*) => {
        paste! {
            #[derive(Debug, Clone)]
            #[allow(dead_code)]
            pub struct [<Full$($protocol)+>] {
                ethernet: Ethernet,
                $(
                    [<$protocol:lower>]:  $protocol,
                )*
            }
        }
    };
}

FullEthernetPacket!(Ipv4, Tcp);
FullEthernetPacket!(Ipv6, Tcp);
FullEthernetPacket!(Ipv4, Udp);
FullEthernetPacket!(Ipv6, Udp);
FullEthernetPacket!(Arp);
FullEthernetPacket!(Ipv4);
FullEthernetPacket!(Ipv6);

#[derive(Debug, Clone, Display)]
pub enum FullPacket {
    FullIpv4Tcp(FullIpv4Tcp),
    FullIpv4Udp(FullIpv4Udp),
    FullIpv6Tcp(FullIpv6Tcp),
    FullIpv6Udp(FullIpv6Udp),
    FullArp(FullArp),
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

                        let tcp = TcpPacket::new(ipv4.payload())
                            .expect("Couldn't Create Tcp Packet");

                        return FullPacket::FullIpv4Tcp(FullIpv4Tcp {
                            ethernet: ethernet_header,
                            ipv4: ipv4_header,
                            tcp: tcp.into_header_with_payload(),
                        });
                    }

                    IpNextHeaderProtocols::Udp => {

                        let udp = UdpPacket::new(ipv4.payload())
                            .expect("Coudln't Create udp Packet");

                        return FullPacket::FullIpv4Udp(FullIpv4Udp {
                            ethernet: ethernet_header,
                            ipv4: ipv4_header,
                            udp: udp.into_header_with_payload()
                        });

                    }

                    _ => FullPacket::FullIpv4(FullIpv4 {
                        ethernet: ethernet_header,
                        ipv4: ipv4.into_header_with_payload(),
                    }),
                }
            }

            EtherTypes::Ipv6 => {

                let ipv6 = Ipv6Packet::new(ethernet_packet.payload())
                    .expect("Coudln't Create ipv6 packet");
                let ipv6_header = ipv6.into_header();
                
                match ipv6_header.next_header {


                    IpNextHeaderProtocols::Tcp => {

                        let tcp = TcpPacket::new(ipv6.payload())
                            .expect("Couldn't Create Tcp Packet");

                        return FullPacket::FullIpv6Tcp(FullIpv6Tcp {
                            ethernet: ethernet_header,
                            ipv6: ipv6_header,
                            tcp: tcp.into_header_with_payload(),
                        });
                    }

                    IpNextHeaderProtocols::Udp => {

                        let udp = UdpPacket::new(ipv6.payload())
                            .expect("Coudln't Create udp Packet");

                        return FullPacket::FullIpv6Udp(FullIpv6Udp {
                            ethernet: ethernet_header,
                            ipv6: ipv6_header.clone(),
                            udp: udp.into_header_with_payload()
                        }); 

                    }

                    _ => FullPacket::FullIpv6(FullIpv6 {
                        ethernet: ethernet_header,
                        ipv6: ipv6.into_header_with_payload(),
                    }),
                    
                }

            }

            EtherTypes::Arp => {

                let arp = ArpPacket::new(ethernet_packet.payload()).expect("Couldn't Create arp packet");

                return FullPacket::FullArp(FullArp { ethernet: ethernet_header, arp:  arp.into_header_with_payload()})

            }

            _ => FullPacket::Ethernet(ethernet_header),
        }
    }
}
