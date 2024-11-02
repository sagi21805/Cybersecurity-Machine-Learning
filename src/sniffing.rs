use pnet::datalink::Channel::Ethernet;
use pnet::datalink;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use pnet::packet::FromPacket;

pub fn capture_packets(interface: datalink::NetworkInterface) {
    let (_, mut rx) = match datalink::channel(&interface, 
                                                                    Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type: {}",&interface),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    println!("Start reading packet: ");
    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    println!("New packet on {}", interface.name);
                    println!("{} => {}: {}",
                        ethernet_packet.get_destination(),
                        ethernet_packet.get_source(),
                        ethernet_packet.get_ethertype());
                    let packet = ethernet_packet.packet();
                    let payload = ethernet_packet.payload();
                    let from_packet = ethernet_packet.from_packet();
                    //println!("---");
                    println!("packet: {:?}", packet);
                    // print the full packet as an array of u8
                    println!("payload: {:?}", payload);
                    // print the payload as an array of u8
                    println!("from_packet: {:?}", from_packet);
                    // print the hearder infos: mac address, ethertype, ...
                    // and the payload as an array of u8
                    println!("---");
                    
                }
            }
            Err(e)=> {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}