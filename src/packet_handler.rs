use pcap::Packet;
use pnet::ipnetwork::Ipv4Network;
use pnet::packet;
use pnet::packet::arp::ArpOperations;
use pnet::util::MacAddr;
use tokio::sync::watch;

use crate::network_utils::get_interface_ip;
use crate::sniffer::Sniffer;
use crate::sender::Sender;

pub struct PacketHandler {
    pub sender: Sender,
    pub sniffer: Sniffer 
}

impl PacketHandler {

    pub fn new(interface_name: &str, default_stream_size: usize) -> PacketHandler {

        Self {
            sender: Sender::new(interface_name),
            sniffer: Sniffer::new(interface_name, default_stream_size)
        }

    }

    pub async fn arp_scan(&mut self, network: Ipv4Network) {

        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let sniff_task = self.sniffer.sniff_until(shutdown_rx);

        for address_num in 0..=network.size() {
            let target_address = network.nth(address_num).expect("Address doesn't exist");
            self.sender.send_arp(
                MacAddr::zero(),
                target_address,
                ArpOperations::Request
            );

        }

        let _ = shutdown_tx.send(());
        sniff_task.await;

        self.sniffer.stream().iter().for_each(|packet_stream|{
            packet_stream.stream.iter().for_each(|packet|{
                println!("Packet: {}", packet)
            });
        });

    }

}