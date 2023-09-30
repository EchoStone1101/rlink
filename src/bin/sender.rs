#![allow(dead_code)]
#![allow(unused)]

//! Inject a packet to given device. 

use rlink::{DeviceHandle, EtherType};
use std::env;

fn cvt(char: char) -> u8 {
    match char {
        '0' => 0u8,
        '1' => 1u8,
        '2' => 2u8,
        '3' => 3u8,
        '4' => 4u8,
        '5' => 5u8,
        '6' => 6u8,
        '7' => 7u8,
        '8' => 8u8,
        '9' => 9u8,
        'a' => 0xau8,
        'b' => 0xbu8,
        'c' => 0xcu8,
        'd' => 0xdu8,
        'e' => 0xeu8,
        'f' => 0xfu8,
        _ => 0x0u8,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!("Usage: sender [dst mac addr] [src dev name] [msg]\n");
        return;
    }

    let mut device = DeviceHandle::new(&args[2], 50, false).unwrap();

    device.send_packet(args[3].as_ref(), 
        EtherType::IPv4,
        args[1].split(":").into_iter().map(|b| {
            cvt(b.chars().nth(0).unwrap()) * 16 + cvt(b.chars().nth(1).unwrap())
        }).collect::<Vec<u8>>()[0..6].try_into().unwrap(),
        true
    );
}
