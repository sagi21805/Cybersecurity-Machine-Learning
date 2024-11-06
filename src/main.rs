mod packet;
mod protocol_utils;
mod packet_stream;

use packet::FullPacket;
use packet_stream::PacketStream;
use pcap::{Capture, Device};
use libc::timeval;
use chrono::{DateTime, Local};


fn timeval_to_datetime(tv: timeval) -> DateTime<Local> {
    let seconds = tv.tv_sec as i64;
    let nanoseconds = (tv.tv_usec * 1000) as u32; // microseconds to nanoseconds
    DateTime::from_timestamp(seconds, nanoseconds).unwrap().with_timezone(&Local)
}
fn main() {
    let interface_name = "wlp0s20f3";
    let device = Device::list()
        .expect("Failed to list devices")
        .into_iter()
        .find(|dev| dev.name == interface_name)
        .expect("Failed to find specified device");

    // Initialize a capture with promiscuous mode and a larger buffer size
    let mut cap = Capture::from_device(device)
        .expect("Failed to create capture from device")
        .promisc(true)
        .buffer_size(65536) // Increase the buffer size
        .timeout(1) // Set a small timeout for non-blocking behavior
        .open()
        .expect("Failed to open capture");

    println!("Starting packet capture on interface {}", interface_name);
    let mut packet_stream = PacketStream::new(2048);
    while let Ok(packet) = cap.next_packet() {
        let full_packet = FullPacket::new(&packet.data, timeval_to_datetime(packet.header.ts));
        packet_stream.add_packet(full_packet);
        packet_stream.get_statistics();
    }
}
