mod sniffing;

use pnet::datalink;
use std::thread;
use sniffing::capture_packets;

fn main() {
    let interfaces = datalink::interfaces();
    let mut handles = vec![];

    for interface in interfaces {
        let handle = thread::spawn(move || {
            capture_packets(interface);
        });
        handles.push(handle);
    }
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
}
