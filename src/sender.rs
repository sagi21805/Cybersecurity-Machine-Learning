use std::net::{IpAddr, Ipv4Addr};

use crate::network_utils::{self, create_arp, get_interface_ip};
use crate::sniffer::Sniffer;
use crate::utils::struct_to_bytes;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use pnet::packet::arp::{ArpOperation, ArpOperations};
use pnet::packet::ethernet::{self, EtherType, EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use pnet::{self, datalink::DataLinkSender};

// In Bytes
const ETHERNET_HEADER_SIZE: usize = 14;
const ARP_HEADER_SIZE: usize = 28;


pub struct Sender {
    sender: Box<dyn DataLinkSender>,
    interface: NetworkInterface,
}

impl Sender {
    pub fn new(interface_name: &str) -> Sender {
        let interface =
            network_utils::get_interface(interface_name).expect("No interface avilable");

        let (sender, _) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(sender, receiver)) => (sender, receiver),

            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };

        Self { sender, interface }
    }

    pub fn send(&mut self, packet: &[u8]) {
        self.sender.send_to(packet, Some(self.interface.clone()));
    }

    pub fn send_ethernet(&mut self, destination_mac: MacAddr, proto: EtherType, payload: &[u8]) {
        let mut buffer = vec![0u8; ETHERNET_HEADER_SIZE + payload.len()];
        let ethernet = network_utils::create_ethernet(
            &mut buffer,
            self.interface.mac.expect("Interface has no MAC address"),
            destination_mac,
            proto,
            payload,
        );
        self.send(ethernet.packet());
    }

    pub fn send_arp(&mut self, target_mac: MacAddr, target_ip: Ipv4Addr, operation: ArpOperation) {
        let mut buffer = vec![0u8; ARP_HEADER_SIZE];
        let arp = network_utils::create_arp(
            &mut buffer,
            self.interface.mac.expect("Interface has no MAC address"),
            target_mac,
            get_interface_ip(&self.interface).expect("Can't get Interface IP address"),
            target_ip,
            operation,
        );
        self.send_ethernet(MacAddr::broadcast(), EtherTypes::Arp, arp.packet());
    }

    pub fn scan_arp(&mut self, network: Ipv4Network) {
        for address_num in 0..network.size() {
            let target_address = network.nth(address_num).expect("Address doesn't exist");
            self.send_arp(MacAddr::zero(), target_address, ArpOperations::Request);
        }

    }

    
}
