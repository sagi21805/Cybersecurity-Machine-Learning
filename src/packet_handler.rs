
use pcap::Packet;
use pnet::ipnetwork::Ipv4Network;
use pnet::packet;
use pnet::packet::arp::ArpOperations;
use pnet::util::MacAddr;
use tokio::sync::watch;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use crate::full_packet::{FullArp, FullPacket};
use crate::network_utils::get_interface_ip;
use crate::sniffer::Sniffer;
use crate::sender::Sender;

pub struct PacketHandler {
    pub sender: Arc<Mutex<Sender>>,
    pub sniffer: Arc<Mutex<Sniffer>>
}

impl PacketHandler {

    // pub fn new(interface_name: &str, default_stream_size: usize) -> PacketHandler {

    //     Self {
    //         sender: Sender::new(interface_name),
    //         sniffer: Sniffer::new(interface_name, default_stream_size)
    //     }

    // }

    pub fn arp_scan(&mut self, network: Ipv4Network) {

        let signal = Arc::new(AtomicBool::new(true));
        let signal_clone = Arc::clone(&signal);
        let handle = thread::spawn( move || {
            self.sniffer.get_mut().unwrap().sniff_until(signal_clone);
        });
        
        

        // self.sniffer.stream.iter().for_each(|packet_stream| {
        //     packet_stream.stream.iter().for_each(|packet| match packet {
        //         FullPacket::FullArp(arp) => {
        //             println!("Arp packet: {:?}", arp);
        //         }
        //         _ => {}
        //     });
        // });
    }

}