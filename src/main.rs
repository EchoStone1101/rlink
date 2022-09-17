#![allow(dead_code)]
#![allow(unused)]

/// A CLI utility showcasing the functionality of the frame capturing
/// library.

use pcap::{Device, Capture};
use rlink::{DeviceHandle, EtherType};


fn main() {
    let mut device = DeviceHandle::new("lo", 0).unwrap();

    device.send_packet([0u8].as_ref(), 
        EtherType::IPv4,
        [0x11u8, 0x22u8, 0x33u8, 0x44u8, 0x55u8, 0x66u8],
        true
    );

    println!("{}", device);

    device.set_callback(Box::new(|p, addr| {
        println!("{:?}", p);
        None
    }));
    device.next_packet();

}
