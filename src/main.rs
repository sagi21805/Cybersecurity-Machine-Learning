mod full_packet;
mod network_utils;
mod packet_stream;
mod protocol_utils;
mod sniffer;
mod utils;
use sniffer::Sniffer;

fn main() {
    let interface_name = "eth0";
    
    let mut sniffer = Sniffer::new(
        &interface_name,
        100
    );

    loop {
        let t = std::time::Instant::now();
        match sniffer.sniff() {
            Ok(packet) => {
                println!("Packet: {}", packet)
            }
            Err(e) => {
                eprintln!("Err: {}", e)
            }
        }
        println!("Sniff time: {}ns", t.elapsed().as_nanos());
        let s = sniffer.stream();
        println!("Stream: {}", s.len())
    }


    
}
