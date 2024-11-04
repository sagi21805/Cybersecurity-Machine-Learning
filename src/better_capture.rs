use pcap::Capture;
use pnet::packet::ethernet::EthernetPacket;
use libc::timeval;
use chrono::{DateTime, NaiveDateTime, Local};

fn timeval_to_datetime(tv: timeval) -> DateTime<Local> {
    let seconds = tv.tv_sec as i64;
    let nanoseconds = (tv.tv_usec * 1000) as u32; // microseconds to nanoseconds
    DateTime::from_timestamp(seconds, nanoseconds).unwrap().with_timezone(&Local)
}
fn main() {
    let mut cap = Capture::from_device("wlp0s20f3").unwrap()
                    .promisc(true)
                    .open().unwrap();

    while let Ok(packet) = cap.next_packet() {
        println!("received packet! {:?} at {:?}", EthernetPacket::new(packet.data), timeval_to_datetime(packet.header.ts));
}
}
