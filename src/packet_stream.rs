use crate::packet::{FullPacket, Timestamp};

pub struct PacketStream {
    stream: Vec<FullPacket>
}

impl PacketStream {

    pub fn new(stream_size: usize) -> Self {
        Self { stream: Vec::<FullPacket>::with_capacity(stream_size) }
    }

    pub fn add_packet(&mut self, packet: FullPacket) {
        self.stream.push(packet);
    }

    pub fn get_statistics(&self) {
        let last = self.stream.last().expect("PacketStream is empty");
        let first = self.stream.first().expect("PacketStream is empty");
        let time = last.get_timestamp() - first.get_timestamp();    
        println!("Packet per second: {}", time.num_seconds() as usize / self.stream.len())
    }

}



