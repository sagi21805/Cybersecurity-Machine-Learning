mod full_packet;
mod network_utils;
mod packet_stream;
mod protocol_utils;
mod sender;
mod sniffer;
mod utils;
mod packet_handler;

use packet_handler::PacketHandler;


#[tokio::main]
async fn main() {
    let start_time = std::time::Instant::now();

    let mut ph= PacketHandler::new("eth0", 2048);
    ph.arp_scan().await;

    println!("Elapsed Time: {:.2} seconds", start_time.elapsed().as_secs_f32());
}
