#![allow(dead_code)]
#![allow(unused)]

//! Expect a packet from given device. 

use rlink::{DeviceHandle, EtherType};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: receiver [dev name]\n");
        return;
    }
    let mut device = DeviceHandle::new(args[1].as_ref(), 50, false).unwrap();

    let packet = device.next_packet().unwrap().unwrap();
    let parsed_packet = packet.parse_eth(false).unwrap();
    println!("Received packet:\n{}", parsed_packet);
}
