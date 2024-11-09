use pnet::datalink;
use pnet::datalink::NetworkInterface;
use pnet::packet::arp::{Arp, ArpHardwareTypes, ArpOperation, ArpOperations};
use pnet::packet::ethernet::EtherTypes;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

pub fn get_local_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    for interface in interfaces {
        println!("interface: {}", interface);
        if !interface.is_loopback() {
            return Some(interface);
        }
    }
    return None;
}

fn get_local_ip() -> Option<Ipv4Addr> {
    // Iterate over the available network interfaces.
    let interfaces = datalink::interfaces();
    for interface in interfaces {
        for ip_network in interface.ips {
            // Check if the IP address is an IPv4 address.
            if let std::net::IpAddr::V4(ipv4) = ip_network.ip() {
                // Return the first non-loopback IPv4 address found.
                if !ipv4.is_loopback() {
                    return Some(ipv4);
                }
            }
        }
    }
    // Return None if no valid IP address is found.
    None
}

pub fn get_interface_ip(interface: &NetworkInterface) -> Option<Ipv4Addr> {
    for address in interface.ips.clone() {
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
        println!("interface: {}", interface);
        if interface.name == interface_name {
            return Some(interface);
        }
    }
    return None;
}

pub fn create_arp(
    source_mac: MacAddr,
    target_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    operation: ArpOperation
) -> Arp {
    Arp {
        hardware_type: ArpHardwareTypes::Ethernet,
        hw_addr_len: 6,    // MAC address is 6 bytes
        proto_addr_len: 4, // Ipv4 address is 4 bytes
        protocol_type: EtherTypes::Ipv4,
        operation: operation,
        sender_hw_addr: source_mac,
        sender_proto_addr: source_ip,
        target_hw_addr: target_mac,
        target_proto_addr: target_ip,
        payload: Vec::new(),
    }
}


