use std::net::{IpAddr, Ipv4Addr};

use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::ArpOperation;
use pnet::util::MacAddr;
use pnet::{self, datalink::DataLinkSender};
use crate::sniffer::Sniffer;
use crate::network_utils::{self, create_arp, get_interface_ip};
use crate::utils::struct_to_bytes;
pub struct Sender {
    sender: Box<dyn DataLinkSender>,
    interface: NetworkInterface
}

impl Sender {

    pub fn new(interface_name: &str) -> Sender {

        let interface = network_utils::get_interface(
            interface_name
        ).expect("No interface avilable");

        let (sender, _) = match datalink::channel(
            &interface, Default::default()) {
    
            Ok(Channel::Ethernet(
                sender, receiver
            )) => (sender, receiver),
    
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };

        Self {
            sender,
            interface
        }

    }

    pub fn send(&mut self, packet: &[u8]) {
        self.sender.send_to(packet, Some(self.interface.clone()));
    }

    pub fn send_arp(&mut self, target_mac: MacAddr, target_ip: Ipv4Addr, operation: ArpOperation) {
        let arp = network_utils::create_arp(
            self.interface.mac.expect("Interface has no MAC address"), 
            target_mac, 
            get_interface_ip(&self.interface).expect("Can't get Interface IP address"),
            target_ip, 
            operation
        );
        self.send(struct_to_bytes(&arp));
    }

}