use pnet::datalink;
use pnet::datalink::{Channel, NetworkInterface};
use pnet::packet::arp::{Arp, ArpHardwareTypes, ArpOperations};
use pnet::packet::ethernet::{EtherTypes, Ethernet};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

fn get_local_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    for interface in interfaces {
        println!("interface: {}", interface);
        if !interface.is_loopback() {
            return Some(interface);
        }
    }
    return None;
}

pub fn arp_reply(
    source_mac: MacAddr,
    target_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Arp {
    Arp {
        hardware_type: ArpHardwareTypes::Ethernet,
        hw_addr_len: 6,    // MAC address is 6 bytes
        proto_addr_len: 4, // Ipv4 address is 4 bytes
        protocol_type: EtherTypes::Ipv4,
        operation: ArpOperations::Reply,
        sender_hw_addr: source_mac,
        sender_proto_addr: source_ip,
        target_hw_addr: target_mac,
        target_proto_addr: target_ip,
        payload: Vec::new(),
    }
}

pub fn arp_request(
    source_mac: MacAddr,
    target_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Arp {
    Arp {
        hardware_type: ArpHardwareTypes::Ethernet,
        hw_addr_len: 6,    // MAC address is 6 bytes
        proto_addr_len: 4, // Ipv4 address is 4 bytes
        protocol_type: EtherTypes::Ipv4,
        operation: ArpOperations::Request,
        sender_hw_addr: source_mac,
        sender_proto_addr: source_ip,
        target_hw_addr: target_mac,
        target_proto_addr: target_ip,
        payload: Vec::new(),
    }
}

pub fn arp_scan() {}
