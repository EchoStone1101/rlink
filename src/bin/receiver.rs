#![allow(dead_code)]
#![allow(unused)]

use rlink::{DeviceHandle, EtherType};

fn main() {
    let mut device = DeviceHandle::new("veth1-2", 10).unwrap();

    device.set_callback(Box::new(|p, addr| {
        println!("{:?}", p);
        None
    }));

    device.next_packet();
}
