use crate::host::Host;
use crate::network_utils::{
    self, get_interface_ip, get_local_network, ARP_HEADER_SIZE, ETHERNET_HEADER_SIZE,
};
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpOperation, ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use pnet::{self, datalink::DataLinkSender};
use std::net::Ipv4Addr;

pub struct Sender {
    sender: Box<dyn DataLinkSender>,
    interface: NetworkInterface,
    pub host: Host,
}

impl Sender {
    pub fn new(interface_name: &str) -> Sender {
        let interface =
            network_utils::get_interface(interface_name).expect("No interface avilable");
        let host = Host::new(interface_name);
        let (sender, _) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(sender, receiver)) => (sender, receiver),

            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };

        Self {
            host,
            interface,
            sender,
        }
    }

    pub fn custom(interface_name: &str, host: Host) -> Self {
        let interface =
            network_utils::get_interface(interface_name).expect("No interface avilable");
        let (sender, _) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(sender, receiver)) => (sender, receiver),

            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };

        Self {
            host,
            interface,
            sender,
        }
    }

    pub fn send(&mut self, packet: &[u8]) {
        self.sender.send_to(packet, Some(self.interface.clone()));
    }

    pub fn send_ethernet(&mut self, destination_mac: MacAddr, proto: EtherType, payload: &[u8]) {
        self.send_custom_ethernet(destination_mac, self.host.mac, proto, payload);
    }

    pub fn send_custom_arp(
        &mut self,
        source_mac: MacAddr,
        destination_mac: MacAddr,
        arp: ArpPacket,
    ) {
        self.send_custom_ethernet(destination_mac, source_mac, EtherTypes::Arp, arp.packet());
    }

    pub fn send_custom_ethernet(
        &mut self,
        destination_mac: MacAddr,
        source_mac: MacAddr,
        proto: EtherType,
        payload: &[u8],
    ) {
        let mut buffer = vec![0u8; ETHERNET_HEADER_SIZE + payload.len()];
        let ethernet = network_utils::create_ethernet(
            &mut buffer,
            source_mac,
            destination_mac,
            proto,
            payload,
        );
        self.send(ethernet.packet());
    }

    pub fn send_broad_arp(
        &mut self,
        target_mac: MacAddr,
        target_ip: Ipv4Addr,
        operation: ArpOperation,
    ) {
        let mut buffer = vec![0u8; ARP_HEADER_SIZE];
        let arp = network_utils::create_arp(
            &mut buffer,
            self.host.mac,
            target_mac,
            self.host.ip,
            target_ip,
            operation,
        );
        self.send_ethernet(MacAddr::broadcast(), EtherTypes::Arp, arp.packet());
    }

    pub fn scan_arp(&mut self) {
        for address_num in 0..self.host.network.size() {
            let target_address = self
                .host.network
                .nth(address_num)
                .expect("Address doesn't exist");
            self.send_broad_arp(MacAddr::zero(), target_address, ArpOperations::Request);
        }
    }
}
