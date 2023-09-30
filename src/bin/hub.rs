#![allow(dead_code)]
#![allow(unused)]

//! Relay packets on the network. Do make sure that the network contains
//! no loop!

use rlink::{DeviceHandle, EtherType, DevicePool};
use pcap::Direction;
use std::{thread, time};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: hub [dev name..]");
        return;
    }

    let names: Vec<String> = args[1..].iter().map(|s| s.clone()).collect();
    let pool = DevicePool::new(names.clone(),50).unwrap();
    let mut devices: Vec<DeviceHandle> = names.iter().map(|name| {
        let handle = DeviceHandle::new(name, 50, false).unwrap();
        handle.direction(Direction::Out);
        handle
    }).collect();

    // Relay packets to other devices
    loop {
        let parsed_packet = pool.select().unwrap().parse_eth(false).unwrap();
        
        println!("Relayed packet...");

        for device in devices.iter_mut() {
            // Avoid sending packets back to sender
            if !device.mac_address().eq(&parsed_packet.mac_address) {
                device.send_packet(
                    parsed_packet.data(),
                    parsed_packet.ethtype(), 
                    parsed_packet.dst_addr(),
                    false);
            }
        }
    }
}
