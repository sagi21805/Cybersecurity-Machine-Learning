mod full_packet;
mod network_utils;
mod packet_stream;
mod protocol_utils;
mod sniffer;
mod utils;
mod sender;
mod packet_handler;

use std::net::Ipv4Addr;

use packet_handler::PacketHandler;
use pnet::ipnetwork::Ipv4Network;
use sniffer::Sniffer;

fn main() {
    let interface_name = "eth0";
    
    let mut sniffer = Sniffer::new(
        &interface_name,
        100
    );

    let handler = PacketHandler::new(interface_name, 2048);

    let task = handler.arp_scan(Ipv4Network::new(
        Ipv4Addr::new(10, 100, 102, 7), 
        24
    ).expect("Can't create network")
    );
    // loop {
    //     let t = std::time::Instant::now();
    //     match sniffer.sniff() {
    //         Ok(packet) => {
    //             println!("Packet: {}", packet)
    //         }
    //         Err(e) => {
    //             eprintln!("Err: {}", e)
    //         }
    //     }
    //     println!("Sniff time: {}ns", t.elapsed().as_nanos());
    //     let s = sniffer.stream();
    //     println!("Stream: {}", s.len())
    // }


    
}
