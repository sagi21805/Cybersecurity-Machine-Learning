use pnet::datalink;
use pnet::datalink::NetworkInterface;
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperation, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{
    EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket,
};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;


pub fn get_local_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    for interface in interfaces {
        if !interface.is_loopback() {
            return Some(interface);
        }
    }
    return None;
}

pub fn get_local_ip() -> Option<Ipv4Addr> {
    // Iterate over the available network interfaces.
    let interface = get_local_interface().expect("Can't find local interface");
    for ip_network in interface.ips {
        if let std::net::IpAddr::V4(ipv4) = ip_network.ip() {
            // Return the first non-loopback IPv4 address found.
            if !ipv4.is_loopback() {
                return Some(ipv4);
            }
        }
    }
    
    // Return None if no valid IP address is found.
    None
}

pub fn get__local_network(interface: &NetworkInterface) -> Option<Ipv4Network> {
    for net in &interface.ips {
        if let IpNetwork::V4(net_v4) = net {
            if !net.ip().is_loopback() {
                return Some(net_v4.clone());
            }
        }
    }
    None
}

pub fn get_interface_ip(interface: &NetworkInterface) -> Option<Ipv4Addr> {
    for address in &interface.ips {
        if let std::net::IpAddr::V4(ipv4) = address.ip() {
            // Return the first non-loopback IPv4 address found.
            if !ipv4.is_loopback() {
                return Some(ipv4);
            }
        }
    }
    None
}

pub fn get_interface(interface_name: &str) -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    for interface in interfaces {
        if interface.name == interface_name {
            return Some(interface);
        }
    }
    return None;
}

pub fn create_ethernet<'p>(
    buffer: &'p mut [u8],
    source_mac: MacAddr,
    destination_mac: MacAddr,
    proto: EtherType,
    payload: &'p [u8],
) -> EthernetPacket<'p> {
    let mut packet = MutableEthernetPacket::new(buffer).expect("Can't create Ethernet packet");
    packet.set_destination(destination_mac);
    packet.set_source(source_mac);
    packet.set_ethertype(proto);
    packet.set_payload(&payload);
    packet.consume_to_immutable()
}

pub fn create_arp<'p>(
    buffer: &'p mut [u8],
    source_mac: MacAddr,
    target_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    operation: ArpOperation,
) -> ArpPacket<'p> {
    let mut packet = MutableArpPacket::new(
        buffer
    ).expect("Can't create Arp packet");
    packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    packet.set_protocol_type(EtherTypes::Ipv4);
    packet.set_hw_addr_len(6);
    packet.set_proto_addr_len(4);
    packet.set_operation(operation);
    packet.set_sender_hw_addr(source_mac);
    packet.set_sender_proto_addr(source_ip);
    packet.set_target_hw_addr(target_mac);
    packet.set_target_proto_addr(target_ip);
    packet.consume_to_immutable()
}
