#![allow(dead_code)]
#![allow(unused)]

use pcap::{Device, Capture};
use std::thread;

fn main() {
    for dev in Device::list().unwrap() {
        // println!("{:?}", dev);
        if dev.name.starts_with("veth") {
            let name = dev.name.clone();
            match Capture::from_device(dev) {
                Ok(cap) => match cap.open() {
                    Ok(mut cap) => {
                        println!("success openning {}", name);
                        loop {
                            match cap.next_packet() {
                                Ok(_) => println!("received packet"),
                                Err(e) => println!("error: {}", e),
                            }
                            thread::sleep(std::time::Duration::from_secs(1));
                        }
                    },
                    Err(_) => println!("error opening {}", name),
                },
                Err(_) => println!("error opening {}", name),
            }
        }
    }

    
}