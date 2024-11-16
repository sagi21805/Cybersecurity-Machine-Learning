use crate::full_packet::FullPacket;
use crate::network_utils::{self, ARP_HEADER_SIZE, ETHERNET_HEADER_SIZE};
use crate::sender::Sender;
use crate::sniffer::Sniffer;
use pnet::packet::arp::ArpOperations;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use tokio::sync::Mutex;

pub struct PacketHandler {
    pub sniffer: Arc<Mutex<Sniffer>>,
    pub sender: Sender,
}

impl PacketHandler {
    pub fn new(interface_name: &str, default_stream_size: usize) -> PacketHandler {
        Self {
            sniffer: Arc::new(Mutex::new(Sniffer::new(
                interface_name,
                default_stream_size,
            ))),
            sender: Sender::new(interface_name),
        }
    }

    pub async fn arp_scan(&mut self) {
        let shutdown_signal = Arc::new(AtomicBool::new(true));

        // Spawn the sniffing task
        let sniffer_task = {
            let sniffer = Arc::clone(&self.sniffer);
            let shutdown_signal = Arc::clone(&shutdown_signal);
            tokio::spawn(async move {
                let mut sniffer = sniffer.lock().await;
                sniffer.sniff_until(shutdown_signal).await;
            })
        };

        // Perform ARP scan asynchronously and allow time for sniffing
        self.sender.scan_arp();
        sleep(Duration::from_millis(500));

        // Signal the sniffer to stop and wait for it to finish
        shutdown_signal.store(false, Ordering::Relaxed);
        sniffer_task.await.expect("Sniffer task failed");

        // Process the collected packets after sniffing completes
        let sniffer = self.sniffer.lock().await;
        sniffer.stream.iter().for_each(|packet_stream| {
            packet_stream.stream.iter().for_each(|packet| match packet {
                FullPacket::FullArp(arp) if arp.arp.operation == ArpOperations::Reply => {
                    println!(
                        "Mac: {:?}, IP: {:?}",
                        arp.arp.sender_hw_addr, arp.arp.sender_proto_addr
                    );
                }
                _ => {}
            });
        });
    }

    // Tell gateway I am the host
    // Tell the host I am the gateway
    pub async fn arp_spoof(
        &mut self,
        attacker_mac: MacAddr,
        attacker_ip: Ipv4Addr,
        host_mac: MacAddr,
        host_ip: Ipv4Addr,
        gateway_mac: MacAddr,
        gateway_ip: Ipv4Addr,
    ) {

        let mut buffer: Vec<u8> = vec![0u8; ARP_HEADER_SIZE];
        let gateway_arp_spoof = network_utils::create_arp(
            &mut buffer,
            host_mac,
            gateway_mac,
            host_ip,
            attacker_ip,
            ArpOperations::Reply,
        );

        let mut buffer: Vec<u8> = vec![0u8; ARP_HEADER_SIZE];
        let host_arp_spoof = network_utils::create_arp(
            &mut buffer,
            attacker_mac,
            host_mac,
            attacker_ip,
            host_ip,
            ArpOperations::Reply,
        );
    }

    pub fn man_in_the_middle() {
        todo!()
    }
}
