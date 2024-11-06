use pnet::packet::arp::{Arp, ArpPacket};
use pnet::packet::dns::{Dns, DnsPacket};
use pnet::packet::ethernet::{EtherTypes, Ethernet, EthernetPacket};
use pnet::packet::icmp::{Icmp, IcmpPacket};
use pnet::packet::icmpv6::{Icmpv6, Icmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4, Ipv4Packet};
use pnet::packet::ipv6::{Ipv6, Ipv6Packet};
use pnet::packet::tcp::{Tcp, TcpPacket};
use pnet::packet::udp::{Udp, UdpPacket};
// use pnet::packet::dhcp::{Dhcp, DhcpPacket};
use crate::protocol_utils::*;
use chrono::{DateTime, Local};
use paste::paste;
use pnet::packet::Packet;
use strum_macros::Display;

macro_rules! FullEthernetPacket {

    ($( $protocol:ident ),*) => {
        paste! {
            #[derive(Debug, Clone)]
            #[allow(dead_code)]
            pub struct [<Full$($protocol)+>] {
                timestamp: DateTime<Local>,
                ethernet: Ethernet,
                $(
                    [<$protocol:lower>]:  $protocol,
                )*
            }

            impl Timestamp for [<Full$($protocol)+>] {
                fn get_timestamp(&self) -> DateTime<Local> {
                    self.timestamp
                }
            }

        }
    };
}

pub trait Timestamp {
    fn get_timestamp(&self) -> DateTime<Local>;
}

#[derive(Debug, Clone)]
pub struct FullEthernet {
    timestamp: DateTime<Local>,
    ethernet: Ethernet,
}

impl Timestamp for FullEthernet {
    fn get_timestamp(&self) -> DateTime<Local> {
        self.timestamp
    }
}

FullEthernetPacket!(Ipv4, Tcp);
FullEthernetPacket!(Ipv6, Tcp);
FullEthernetPacket!(Ipv4, Udp);
FullEthernetPacket!(Ipv6, Udp);
FullEthernetPacket!(Arp);
FullEthernetPacket!(Ipv4);
FullEthernetPacket!(Ipv6);
FullEthernetPacket!(Ipv4, Dns);
FullEthernetPacket!(Ipv6, Dns);
FullEthernetPacket!(Ipv4, Icmp);
FullEthernetPacket!(Ipv6, Icmpv6);
// FullEthernetPacket!(Ipv4, Dhcp);
// FullEthernetPacket!(Ipv6, Dhcp);

#[derive(Debug, Clone, Display)]
pub enum FullPacket {
    FullIpv4Tcp(FullIpv4Tcp),
    FullIpv4Udp(FullIpv4Udp),
    FullIpv6Tcp(FullIpv6Tcp),
    FullIpv6Udp(FullIpv6Udp),
    FullArp(FullArp),
    FullEthernet(FullEthernet),
    FullIpv4(FullIpv4),
    FullIpv6(FullIpv6),
    FullIpv4Dns(FullIpv4Dns),
    FullIpv6Dns(FullIpv6Dns),
    FullIpv4Icmp(FullIpv4Icmp),
    FullIpv6Icmpv6(FullIpv6Icmpv6),
    // FullIpv4Dhcp(FullIpv4Dhcp),
    // FullIpv6Dhcp(FullIpv6Dhcp),
}

impl FullPacket {
    pub fn new(packet_bytes: &[u8], local_capture_time: DateTime<Local>) -> FullPacket {
        let ethernet_packet =
            EthernetPacket::new(packet_bytes).expect("Couldn't create Ethernet Packet");

        let ethernet_header = ethernet_packet.into_header();

        match ethernet_header.ethertype {
            EtherTypes::Ipv4 => {
                let ipv4 = Ipv4Packet::new(ethernet_packet.payload())
                    .expect("Couldn't Create ipv4 packet");
                let ipv4_header = ipv4.into_header();

                match ipv4_header.next_level_protocol {
                    IpNextHeaderProtocols::Tcp => {
                        if ipv4.payload().is_empty() {
                            return FullPacket::FullIpv4(FullIpv4 {
                                timestamp: local_capture_time,
                                ethernet: ethernet_header,
                                ipv4: ipv4.into_header_with_payload(),
                            });
                        }

                        let tcp = TcpPacket::new(ipv4.payload())
                            .expect("Couldn't Create Tcp Packet IPv4");

                        return FullPacket::FullIpv4Tcp(FullIpv4Tcp {
                            timestamp: local_capture_time,
                            ethernet: ethernet_header,
                            ipv4: ipv4_header,
                            tcp: tcp.into_header_with_payload(),
                        });
                    }

                    IpNextHeaderProtocols::Udp => {
                        let udp =
                            UdpPacket::new(ipv4.payload()).expect("Couldn't Create udp Packet");
                        return FullPacket::FullIpv4Udp(FullIpv4Udp {
                            timestamp: local_capture_time,
                            ethernet: ethernet_header,
                            ipv4: ipv4_header,
                            udp: udp.into_header_with_payload(),
                        });
                    }

                    IpNextHeaderProtocols::Icmp => {
                        let icmp =
                            IcmpPacket::new(ipv4.payload()).expect("Couldn't Create ICMP Packet");
                        return FullPacket::FullIpv4Icmp(FullIpv4Icmp {
                            timestamp: local_capture_time,
                            ethernet: ethernet_header,
                            ipv4: ipv4_header,
                            icmp: icmp.into_header_with_payload(),
                        });
                    }

                    _ => FullPacket::FullIpv4(FullIpv4 {
                        timestamp: local_capture_time,
                        ethernet: ethernet_header,
                        ipv4: ipv4.into_header_with_payload(),
                    }),
                }
            }

            EtherTypes::Ipv6 => {
                let ipv6 = Ipv6Packet::new(ethernet_packet.payload())
                    .expect("Couldn't Create ipv6 packet");
                let ipv6_header = ipv6.into_header();

                match ipv6_header.next_header {
                    IpNextHeaderProtocols::Tcp => {
                        if ipv6.payload().is_empty() {
                            return FullPacket::FullIpv6(FullIpv6 {
                                timestamp: local_capture_time,
                                ethernet: ethernet_header,
                                ipv6: ipv6.into_header_with_payload(),
                            });
                        }

                        let tcp = TcpPacket::new(ipv6.payload())
                            .expect("Couldn't Create Tcp Packet IPv6");
                        return FullPacket::FullIpv6Tcp(FullIpv6Tcp {
                            timestamp: local_capture_time,
                            ethernet: ethernet_header,
                            ipv6: ipv6_header,
                            tcp: tcp.into_header_with_payload(),
                        });
                    }

                    IpNextHeaderProtocols::Udp => {
                        let udp =
                            UdpPacket::new(ipv6.payload()).expect("Couldn't Create udp Packet");
                        return FullPacket::FullIpv6Udp(FullIpv6Udp {
                            timestamp: local_capture_time,
                            ethernet: ethernet_header,
                            ipv6: ipv6_header.clone(),
                            udp: udp.into_header_with_payload(),
                        });
                    }

                    IpNextHeaderProtocols::Icmp => {
                        let icmp = Icmpv6Packet::new(ipv6.payload())
                            .expect("Couldn't Create ICMPv6 Packet");
                        return FullPacket::FullIpv6Icmpv6(FullIpv6Icmpv6 {
                            timestamp: local_capture_time,
                            ethernet: ethernet_header,
                            ipv6: ipv6_header,
                            icmpv6: icmp.into_header_with_payload(),
                        });
                    }

                    _ => FullPacket::FullIpv6(FullIpv6 {
                        timestamp: local_capture_time,
                        ethernet: ethernet_header,
                        ipv6: ipv6.into_header_with_payload(),
                    }),
                }
            }

            EtherTypes::Arp => {
                let arp =
                    ArpPacket::new(ethernet_packet.payload()).expect("Couldn't Create arp packet");
                return FullPacket::FullArp(FullArp {
                    timestamp: local_capture_time,
                    ethernet: ethernet_header,
                    arp: arp.into_header_with_payload(),
                });
            }

            _ => FullPacket::FullEthernet(FullEthernet {
                ethernet: ethernet_header,
                timestamp: local_capture_time,
            }),
        }
    }

    pub fn get_timestamp(&self) -> DateTime<Local> {
        match self {
            FullPacket::FullIpv4Tcp(packet) => packet.get_timestamp(),
            FullPacket::FullIpv4Udp(packet) => packet.get_timestamp(),
            FullPacket::FullIpv6Tcp(packet) => packet.get_timestamp(),
            FullPacket::FullIpv6Udp(packet) => packet.get_timestamp(),
            FullPacket::FullArp(packet) => packet.get_timestamp(),
            FullPacket::FullEthernet(packet) => packet.get_timestamp(),
            FullPacket::FullIpv4(packet) => packet.get_timestamp(),
            FullPacket::FullIpv6(packet) => packet.get_timestamp(),
            FullPacket::FullIpv4Dns(packet) => packet.get_timestamp(),
            FullPacket::FullIpv6Dns(packet) => packet.get_timestamp(),
            FullPacket::FullIpv4Icmp(packet) => packet.get_timestamp(),
            FullPacket::FullIpv6Icmpv6(packet) => packet.get_timestamp(),
            // Uncomment and add similar lines if you have DHCP variants
            // FullPacket::FullIpv4Dhcp(packet) => packet.get_timestamp(),
            // FullPacket::FullIpv6Dhcp(packet) => packet.get_timestamp(),
        }
    }
}
