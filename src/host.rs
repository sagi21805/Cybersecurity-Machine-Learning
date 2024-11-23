use crate::network_utils::{self, get_interface_ip, get_local_network};
use pnet::ipnetwork::Ipv4Network;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct Host {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    pub network: Ipv4Network,
}

impl Host {
    pub fn new(interface_name: &str) -> Self {
        let interface =
            network_utils::get_interface(interface_name).expect("No interface avilable");

        Self {
            mac: (&interface).mac.unwrap(),
            ip: get_interface_ip(&interface).expect("Can't obtain IPv4 Network"),
            network: get_local_network(&interface).expect("Can't obtain IPv4 Network"),
        }
    }

    pub fn custom(mac: MacAddr, ip: Ipv4Addr, net_prefix: u8) -> Self {
        Self { mac, ip, network: Ipv4Network::new(ip, net_prefix).expect("Invalid prefix") }
    }
}
