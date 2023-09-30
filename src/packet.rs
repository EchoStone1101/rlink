#![allow(dead_code)]
#![allow(unused)]

pub mod packet {
    use pcap::{Packet as _Packet, PacketHeader};
    use crate::{EtherType, RlinkError};
    use std::fmt::{self, write};
    use std::marker::PhantomData;
    use mac_address::MacAddress;
    use crc::{Crc, CRC_32_CKSUM};

    /// A rlink packet. The data is owned compared to pcap::Packet.
    #[derive(Clone, Debug)]
    pub struct Packet<T: Type + ?Sized> {
        /// Header of the packet
        pub header: PacketHeader,
        /// Packet content
        pub data: Vec<u8>,
        /// MAC address of the device that received this packet
        pub mac_address: MacAddress,
        _marker: PhantomData<T>,
    }

    impl Packet<Raw> {
        /// Parses packet as Ethernet II Frame. The minimum frame size and (optional)
        /// checksum is checked.
        pub fn parse_eth(self, checksum: bool) -> Result<Packet<Eth>, RlinkError> {
            if self.data.len() < 64 {
                return Err(RlinkError::InvalidPacket(self, "packet size too small"));
            }
            
            if checksum {
                let len = self.data.len();
                let checksum1 = &self.data[len-4..];
                let checksum2 = crc::Crc::<u32>::new(&CRC_32_CKSUM)
                    .checksum(self.data[..len-4].as_ref()).to_be_bytes();
                if !checksum1.eq(checksum2.as_ref()) {
                    return Err(RlinkError::InvalidPacket(self, "checksum mismatch"));
                }
            }

            Ok(Packet::<Eth> {
                header: self.header,
                data: self.data,
                mac_address: self.mac_address,
                _marker: PhantomData::<Eth>,
            })
        }

        pub fn from(packet: _Packet, addr: MacAddress) -> Packet<Raw> {
            Packet::<Raw> {
                header: packet.header.to_owned(),
                data: packet.data.to_owned(),
                mac_address: addr,
                _marker: PhantomData::<Raw>,
            }
        }
    }

    impl Packet<Eth> {
        pub fn dst_addr(&self) -> &[u8; 6] {
            self.data[0..6].try_into().unwrap()
        }

        pub fn src_addr(&self) -> &[u8; 6] {
            self.data[6..12].try_into().unwrap()
        }

        pub fn ethtype(&self) -> EtherType {
            let type_field = &self.data[12..14];
            // Big Endian
            let ethtype = type_field[0] as u16 * 256 + type_field[1] as u16;
            EtherType::from(ethtype)
        }

        pub fn data(&self) -> &[u8] {
            &self.data[14..self.data.len()-4]
        }
    }

    impl fmt::Display for Packet<Raw> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            
            write!(f, "{:?}\n", self.header);
            write!(f, "{:?}\n", self.mac_address);
            // Hex dump the data
            for (idx, byte) in self.data.iter().enumerate() {
                write!(f, "{:0>2X} ", byte);
                match idx % 12 {
                    5 => {write!(f, " ");},
                    11 => {write!(f, "\n");},
                    _ => {}
                };
            }

            Ok(())
        }
    }

    impl fmt::Display for Packet<Eth> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write! (f, "{:?}\n", self.header);
            write! (f, "{:?}\n", self.mac_address);

            let dst_addr = self.dst_addr();
            write! (f, "dst_addr: {:0>2X}:{:0>2X}:{:0>2X}:{:0>2X}:{:0>2X}:{:0>2X}\n", 
                dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3], dst_addr[4], dst_addr[5]);
            
            let src_addr = self.src_addr();
            write! (f, "src_addr: {:0>2X}:{:0>2X}:{:0>2X}:{:0>2X}:{:0>2X}:{:0>2X}\n", 
                src_addr[0], src_addr[1], src_addr[2], src_addr[3], src_addr[4], src_addr[5]);

            let ethtype = self.ethtype();
            write! (f, "ether type: 0x{:0>4X} ({})\n", <EtherType as Into<u16>>::into(ethtype), ethtype);
            
            // Hex dump the data
            for (idx, byte) in self.data().iter().enumerate() {
                write!(f, "{:0>2X} ", byte);
                match idx % 12 {
                    5 => {write!(f, " ");},
                    11 => {write!(f, "\n");},
                    _ => {}
                };
            }
            Ok(())
        }
    }

    pub trait Type {}

    /// Raw data captured from wire.
    #[derive(Debug)]
    pub enum Raw {}
    impl Type for Raw {}

    /// Parsed as Ethernet II Frame
    #[derive(Debug)]
    pub enum Eth {}
    impl Type for Eth {}
}