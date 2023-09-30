#![allow(dead_code)]
#![allow(unused)]

pub mod device_pool {
    
    use pcap::{Device, Capture, Direction};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread;
    use crate::{DeviceHandle, RlinkError, Packet, Raw};
    use std::error::Error;

    /// A pool of DeviceHandles for group capturing. Internally contains 
    /// a thread pool for capturing packets from all DeviceHandles.
    pub struct DevicePool {
        /// Worker threads, one for each device.
        workers: Vec<thread::JoinHandle<()>>,
        /// Receiver of packets from all devices.
        rx: Option<mpsc::Receiver<Packet<Raw>>>,
    }

    impl DevicePool {
        /// Initiate a pool of handlers based on given names.
        /// Packets captured on these handlers are collected for centralized
        /// handling.
        pub fn new(names: Vec<String>, timeout: i32) -> Result<DevicePool, Box<dyn Error>> {
            let (tx, rx) = mpsc::channel();
            let workers = names
                .into_iter()
                .map(|name| {
                    let tx = tx.clone();
                    let thread = thread::spawn(move || {

                        let result = DeviceHandle::new(&name, timeout, false);
                        if let Err(e) = result {
                            return;
                        }
                        let mut device = result.unwrap();
                        device.direction(Direction::In);
                        loop {
                            // This is not so clean. next_packet() can be blocking when
                            // the device pool is already dropped, causing the worker
                            // thread to not join properly. In fact, if no new packets arrive,
                            // the workers can potentially be blocked forever.
                            let packet = device.next_packet();
                            match packet {
                                Ok(Some(packet)) => {
                                    match tx.send(packet) {
                                        Ok(_) => continue,
                                        Err(e) => break,
                                    }
                                }
                                Ok(None) => continue,
                                Err(e) => continue,
                            }
                        }
                        // println!("closing handle of {}\n", device.device.name);
                    });

                    thread
                    })
                .collect();
            Ok(DevicePool{ workers, rx: Some(rx) })
        }

        /// Block until packets arrive at any device in the pool.
        /// Returns error when all device handles in the pool are no longer 
        /// reading packets.
        pub fn select(&self) -> Result<Packet<Raw>, RlinkError> {
            match self.rx.as_ref().unwrap().recv() {
                Ok(packet) => Ok(packet),
                Err(e) => Err(RlinkError::BrokenDevicePool),
            }
        }
    }

    impl Drop for DevicePool {
        /// Explicitly drop `rx` to properly terminate worker threads.
        fn drop(&mut self) {
            drop(self.rx.take());

            // Drop the thread handles. Workers terminate once they realize 
            // `rx` is dropped.
        }
    }
}