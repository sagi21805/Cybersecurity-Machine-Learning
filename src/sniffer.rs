use crate::{full_packet::FullPacket, packet_stream::PacketStream, utils};
use pcap::{Active, Capture, Device};
use tokio::task;
use std::{collections::LinkedList, net::Shutdown};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

pub struct Sniffer {
    cap: Capture<Active>,
    pub stream: LinkedList<PacketStream>,
    default_stream_size: usize,
}

impl Sniffer {
    pub fn new(interface_name: &str, default_stream_size: usize) -> Self {
        let device = Device::list()
            .expect("Failed to list devices")
            .into_iter()
            .find(|dev| dev.name == interface_name)
            .expect("Failed to find specified device");

        // Initialize a capture with promiscuous mode and a larger buffer size
        let cap = Capture::from_device(device)
            .expect("Failed to create capture from device")
            .promisc(true)
            .timeout(1)
            .open()
            .expect("Failed to open capture");

        let mut stream = LinkedList::<PacketStream>::new();
        stream.push_front(PacketStream::new(default_stream_size));

        Self {
            cap,
            stream,
            default_stream_size,
        }
    }

    pub fn current_stream(&mut self) -> &mut PacketStream {
        self.stream.front_mut().expect("Sniffer stream is empty")
    }

    pub fn sniff(&mut self) -> Result<&FullPacket, pcap::Error> {
        match self.cap.next_packet() {
            Ok(packet) => {
                let packet =
                    FullPacket::new(&packet.data, utils::timeval_to_datetime(packet.header.ts));
                if self.current_stream().stream.len() >= self.default_stream_size {
                    self.stream
                        .push_front(PacketStream::new(self.default_stream_size));
                }
                self.current_stream().add_packet(packet);
                Ok(self
                    .current_stream()
                    .stream
                    .last()
                    .expect("Current packet stream is empty"))
            }
            Err(e) => {
                Err(e) // propagate the error
            }
        }
    }

    pub fn silent_sniff(&mut self) {
        match self.cap.next_packet() {
            Ok(packet) => {
                let packet =
                    FullPacket::new(&packet.data, utils::timeval_to_datetime(packet.header.ts));
                if self.current_stream().stream.len() >= self.default_stream_size {
                    self.stream
                        .push_front(PacketStream::new(self.default_stream_size));
                }
                self.current_stream().add_packet(packet);
            }
            Err(_) => {}
        }
        println!("Sniff");
    }

    // Make sniff_until async and use Notify for shutdown signal
    pub async fn sniff_until(&mut self, shutdown_signal: Arc<AtomicBool>) {
        println!("Started Sniffing");

        while shutdown_signal.load(Ordering::Relaxed) {
        
            // Perform sniffing in a non-blocking way
            self.silent_sniff();
            println!("Sniffing");
        }

        println!("Signal Received");
    }

    pub fn sniff_stream(&mut self) {
        self.stream
            .push_front(PacketStream::new(self.default_stream_size));
        let mut packet_pushed = 0;

        while packet_pushed < self.default_stream_size {
            match self.cap.next_packet() {
                Ok(packet) => {
                    let packet =
                        FullPacket::new(&packet.data, utils::timeval_to_datetime(packet.header.ts));
                    self.current_stream().add_packet(packet);
                    packet_pushed += 1;
                }
                Err(_) => {}
            }
        }
    }
}
