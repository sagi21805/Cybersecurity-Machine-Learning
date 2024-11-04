use paste::paste;
use pnet::packet::arp::{Arp, ArpPacket};
use pnet::packet::ethernet::{Ethernet, EthernetPacket};
use pnet::packet::ipv4::{Ipv4, Ipv4Packet};
use pnet::packet::ipv6::{Ipv6, Ipv6Packet};
use pnet::packet::tcp::{Tcp, TcpPacket};
use pnet::packet::udp::{Udp, UdpPacket};
use pnet::packet::Packet;

macro_rules! into_header {
    ($header_type:ident, $( $field_name:ident ),*) => {
        paste! {
            pub trait [<$header_type Packet To $header_type Header>] {
                fn into_header(&self) -> $header_type;
            }

            impl<'p> [<$header_type Packet To $header_type Header>] for [<$header_type Packet>]<'p> {
                fn into_header(&self) -> $header_type {
                    $header_type {
                        $(
                            $field_name: self.[<get_ $field_name>](),
                        )*
                        payload: self.payload().to_vec(),
                    }
                }
            }
        }
    };
}

into_header! { Ethernet, destination, source, ethertype }
into_header! { Ipv4, version, header_length, dscp, ecn, total_length, identification, flags, fragment_offset, ttl, next_level_protocol, checksum, source, destination, options}
into_header! { Ipv6, version, traffic_class, flow_label, payload_length, next_header, hop_limit, source, destination }
into_header! { Tcp, source, destination, sequence, acknowledgement, data_offset, reserved, flags, window, checksum, urgent_ptr, options }
into_header! { Udp, source, destination, length, checksum }
into_header! { Arp, hardware_type, protocol_type, hw_addr_len, operation, proto_addr_len, sender_hw_addr, sender_proto_addr, target_hw_addr, target_proto_addr}