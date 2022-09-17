#![allow(dead_code)]
#![allow(unused)]

use rlink::{DeviceHandle, EtherType};

fn main() {
    let mut device = DeviceHandle::new("veth0-3", 0).unwrap();

    device.send_packet([0u8].as_ref(), 
        EtherType::IPv4,
        [0x0au8, 0x77u8, 0x45u8, 0xcfu8, 0xecu8, 0x55u8],
        true
    );

    println!("{}", device);
}
