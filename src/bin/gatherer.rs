#![allow(dead_code)]
#![allow(unused)]

//! Multi-thread to gather packets from multiple devices.

use rlink::{DeviceHandle, EtherType, DevicePool, Packet};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: gatherer [dev name..]\n");
        return;
    }

    let pool = DevicePool::new(
        args[1..].iter().map(|s| s.clone()).collect(),
        50
    ).unwrap();


    loop {
        let packet = pool.select().unwrap();
        let parsed_packet = packet.parse_eth(false).unwrap();
        println!("Received Packet:\n{}", parsed_packet);
    }
}
