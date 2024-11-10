mod full_packet;
mod network_utils;
mod packet_stream;
mod protocol_utils;
mod sender;
mod sniffer;
mod utils;

use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use tokio::sync::Notify;
use full_packet::FullPacket;
use sniffer::Sniffer;

#[tokio::main]
async fn main() {
    // Wrap Sniffer in an Arc<Mutex> to allow shared ownership and mutability
    let sniffer = Arc::new(tokio::sync::Mutex::new(Sniffer::new("wlp0s20f3", 100)));
   
}

