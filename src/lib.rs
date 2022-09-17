#![allow(dead_code)]
#![allow(unused)]

//! This library manages NICs by name and provides the DeviceHandle 
//! abstraction, using the pcap crate. It further encapsulates I/O 
//! operations on the devices.
//! Note that DeviceHandle binds pcap::Device and pcap::Capture and
//! does not implement Sync, enforcing it not to be shared between
//! threads. In fact, the underlying `libpcap` does not guarantee 
//! thread safety on single `pcap_t` either.

pub mod ethtype;

use pcap::{Capture, Device, Active, Linktype, Direction, Packet, Stat};
use pcap::Error as PError;
use mac_address::MacAddress;
use crc::{Crc, CRC_32_CKSUM};
use std::fmt;
use std::error::Error;
use std::borrow::Borrow;
pub use ethtype::ethtype::EtherType;

type DeviceCallback = Box<dyn for <'a> Fn(Packet<'a>, &MacAddress)->Option<Packet<'a>>>;

/// An active network device to operate on.
pub struct DeviceHandle {
    /// Underlying network device
    device: Device,
    /// MAC address of the device
    mac_address: MacAddress,
    /// Active channel for receiving/sending packets
    cap: Capture<Active>,
    /// Callback function
    callback: Option<DeviceCallback>,
}

impl fmt::Display for DeviceHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "device: {:?}, mac_address: {:?}, id: {:p},", self.device, self.mac_address, &self)
    }
}

/// Errors beyond PcapError
#[derive(Debug)]
pub enum RlinkError {
    /// An invalid device name is requested
    InvalidDeviceName(&'static str),
    /// Payload exceeds maximum frame size
    PayloadTooLarge,
    /// Payload size mismatch with specified length
    PayloadLengthMismatch,
}

impl fmt::Display for RlinkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use RlinkError::*;
        match *self {
            InvalidDeviceName(name) => write!(f, "invalid device name: {:?}", name),
            PayloadTooLarge => write!(f, "payload too large"),
            PayloadLengthMismatch => write!(f, "payload size mismatch with ether type"),
        }
    }
}

impl Error for RlinkError {}

impl DeviceHandle {
    /// Create a new DeviceHandle by looking up given device name and 
    /// activating a Capture on it.
    /// 
    /// # Arguments
    ///
    /// * `name` - the name of target device.
    /// 
    /// Returns the newly created DeviceHandle or an Error.
    pub fn new(name: &str, timeout: i32) -> Result<Self, Box<dyn Error>> {
        match Device::list()?
            .iter()
            .find(|&x| x.name.eq(name)) {
            Some(device) => {
                let cap = Capture::from_device(device.name.as_str())?
                    .timeout(timeout)
                    .open()?;
                let mac_address = mac_address::mac_address_by_name(name)?.unwrap();
                Ok(DeviceHandle{
                    device: device.clone(), 
                    mac_address, 
                    cap,
                    callback: None,
                })
            },
            None => Err(Box::new(RlinkError::InvalidDeviceName("Invalid device name"))),
        }                         
    }

    /// Returns the associated device.
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// List the datalink types that this captured device supports.
    pub fn list_datalinks(&self) -> Result<Vec<Linktype>, PError> {
        self.cap.list_datalinks()
    }

    /// Set the datalink type for the current capture handle.
    pub fn set_datalink(&mut self, linktype: Linktype) -> Result<(), PError> {
        self.cap.set_datalink(linktype)
    }

    /// Get the current datalink type for this capture handle.
    pub fn get_datalink(&self) -> Linktype {
        self.cap.get_datalink()
    }

    /// Set the direction of the capture.
    pub fn direction(&self, direction: Direction) -> Result<(), PError> {
        self.cap.direction(direction)
    }

    /// Sets the filter on the capture using the given BPF program string. 
    /// Internally this is compiled using `pcap_compile()`. 
    /// `optimize` controls whether optimization on the resulting code is performed.
    pub fn filter(&mut self, program: &str, optimize: bool) -> Result<(), PError> {
        self.cap.filter(program, optimize)
    }

    /// Get capture statistics about this capture. The values represent packet 
    /// statistics from the start of the run to the time of the call.
    pub fn stats(&mut self) -> Result<Stat, PError> {
        self.cap.stats()
    }

    /// Set the capture to be non-blocking. When this is set, `Self::next_packet()` 
    /// may return an error indicating that there is no packet available to be read.
    pub fn setnonblock(self) -> Result<Self, PError> {
        match self.cap.setnonblock() {
            Ok(cap) => Ok(DeviceHandle {  cap, ..self }),
            Err(e) => Err(e),
        }
    }

    /// Sends a packet over this capture handle’s interface. Appropriate frame header
    /// (and trailer) is generated based on given ether type.
    /// 
    /// # Arguments
    /// 
    /// * `payload` - The packet payload data.
    /// * `ethtype` - The frame ether type.
    /// * `dest_mac` - The destination MAC address, in byte slice.
    pub fn send_packet<B: Borrow<[u8]>>(&mut self,
        payload: B,
        ethtype: EtherType,
        dest_mac: [u8; 6],
        checksum: bool,
    ) -> Result<(), Box<dyn Error>> {
        let payload = payload.borrow();
        let len = payload.len();
        if let EtherType::IEEE802_3(_len) = ethtype {
            if _len as usize != len {
                return Err(Box::new(RlinkError::PayloadLengthMismatch));
            }
        }
        if len >= 1500 {
            return Err(Box::new(RlinkError::PayloadTooLarge));
        }

        match ethtype {
            // IEEE 802.3 Frame is currently not supported
            EtherType::IEEE802_3(_) => Ok(()),
            // For other types, assume Ethernet II Frame format
            _ => {
                let mut frame = [
                    dest_mac.as_ref(),
                    self.mac_address.bytes().as_ref(),
                    <EtherType as Into<u16>>::into(ethtype).to_be_bytes().as_ref(),
                    payload.as_ref(),
                ].concat();

                // Pad frame to Minimum Frame Size
                frame.resize(std::cmp::max(frame.len(), 60usize), 0u8);

                if checksum {
                    let checksum = crc::Crc::<u32>::new(&CRC_32_CKSUM).checksum(frame.as_ref());
                    self.cap.sendpacket([
                        frame.as_ref(), 
                        checksum.to_be_bytes().as_ref()].concat())?;
                }
                else {
                    self.cap.sendpacket(frame.as_ref())?;
                }
                Ok(())
            }
        }
    }

    /// Set callback function on this capture handle. The callback is invoked each
    /// time `next_packet()` retrieves a packet from the device.
    pub fn set_callback(&mut self, callback: DeviceCallback) {
        self.callback = Some(callback);
    }

    /// Read a packet from this capture handle’s interface. May or may not block,
    /// based on the handle setting. A callback function, if registered, will be
    /// invoked on the packet first. 
    pub fn next_packet(&mut self) -> Result<Option<Packet>, PError> {
        let packet = self.cap.next_packet()?;
        if let Some(func) = &self.callback {
            Ok(func(packet, &self.mac_address))
        }
        else {
            Ok(Some(packet))
        }
    }
}