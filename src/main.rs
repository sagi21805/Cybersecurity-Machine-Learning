mod full_packet;
mod network_utils;
mod packet_stream;
mod protocol_utils;
mod sender;
mod sniffer;
mod utils;

use std::{net::Ipv4Addr, sync::{atomic::{AtomicBool, Ordering}, Arc}};
use pnet::{ipnetwork::Ipv4Network, packet::arp::ArpOperations};
use sender::Sender;
use tokio::sync::Notify;
use full_packet::FullPacket;
use sniffer::Sniffer;

#[tokio::main]
async fn main() {
    let t = std::time::Instant::now();
    // Wrap Sniffer in an Arc<Mutex> to allow shared ownership and mutability
    let sniffer = Arc::new(tokio::sync::Mutex::new(Sniffer::new("wlp0s20f3", 5000)));
    let shutdown_signal = Arc::new(AtomicBool::new(true));
    let shutdown_signal_clone = Arc::clone(&shutdown_signal);
    
    // Spawn the sniffing tasks, passing in the cloned sniffer wrapped in Arc<Mutex>
    let sniffer_task = tokio::spawn({
        let sniffer = Arc::clone(&sniffer);
        async move {
            let mut sniffer = sniffer.lock().await; // Lock the Sniffer to access it
            sniffer.sniff_until(shutdown_signal_clone).await;
        }
    });

    // Simulate some work and then trigger shutdown after a delay
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let mut sender = Sender::new("wlp0s20f3");
    sender.scan_arp(Ipv4Network::new(Ipv4Addr::new(192, 168, 239, 140), 24).unwrap());
    shutdown_signal.store(false, Ordering::Relaxed);  // Signal to stop sniffing

    // Wait for the sniffer task to finish
    sniffer_task.await.unwrap();

    // Access the sniffer and read the data after the task is complete
    let sniffer = sniffer.lock().await; // Lock the Sniffer to access it
    sniffer.stream.iter().for_each(|packet_stream| {
        packet_stream.stream.iter().for_each(|packet| match packet {
            FullPacket::FullArp(arp) => {
                match arp.arp.operation {
                    ArpOperations::Reply => {
                        println!("Arp: {:?}", arp)
                    }
                    _ => { }
                }
            }
            _ => {}
        });
    });

    println!("Time {}", t.elapsed().as_secs_f32());
}
