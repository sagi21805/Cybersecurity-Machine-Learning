use crate::utils::timeval_to_datetime;
use crate::{full_packet::FullPacket, utils};
use pcap::{Active, Capture, Device};
use std::collections::LinkedList;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct Sniffer {
    pub cap: Capture<Active>,
    pub file: pcap::Savefile,
    pub stream: LinkedList<FullPacket>
}

impl Sniffer {
    pub fn new(interface_name: &str) -> Self {
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



        Self {
            file: cap.savefile("recording.pcap").unwrap(),
            cap,
            stream: LinkedList::new()
        }
    }


    pub fn silent_sniff(&mut self) {
        match self.cap.next_packet() {
            Ok(packet) => {
                self.file.write(&packet);
                self.stream.push_back(FullPacket::new(
                    packet.data,
                    timeval_to_datetime(packet.header.ts)
                ));
            }
            Err(_) => {}
        }
    }

    pub fn sniff_raw(&mut self) -> Result<Vec<u8>, pcap::Error> {
        match self.cap.next_packet() {
            Ok(packet) => {
                self.file.write(&packet);                
                Ok(packet.data.to_vec())
            }
            Err(e) => {
                Err(e) // propagate the error
            }
        }
    }

    pub fn sniff(&mut self) -> Result<FullPacket, pcap::Error> {
        match self.cap.next_packet() {
            Ok(packet) => {
                self.file.write(&packet);
                let full = FullPacket::new(
                    packet.data,
                    timeval_to_datetime(packet.header.ts)
                );
                self.stream.push_back(full.clone());
                Ok(full)
            }
            Err(e) => {
                Err(e) // propagate the error
            }
        }
    }


    // Make sniff_until async and use Notify for shutdown signal
    pub async fn sniff_until(&mut self, shutdown_signal: Arc<AtomicBool>) {
        while shutdown_signal.load(Ordering::Relaxed) {
            // Perform sniffing in a non-blocking way
            self.silent_sniff();
        }
    }

}
