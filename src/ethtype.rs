#![allow(dead_code)]
#![allow(unused)]

pub mod ethtype {
    //! Collection of EtherType values for notable protocols.
    #[derive(Clone, Debug, Copy, PartialEq)]
    pub enum EtherType {
        IPv4,
        /// Neighbor Detection Protocol, part of Rip implementation.
        NDP,
        ARP,
        RARP,
        IPX,
        IPv6,
        EFC,
        IEEE802_3(u16),
        UNKNOWN(u16),
    }
    
    use super::ethtype::EtherType::*;
    impl std::fmt::Display for EtherType {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match *self {
                IPv4 => write!(f, "Internet Protocol version 4"),
                NDP => write!(f, "Neighbor Detection Protocol"),
                ARP => write!(f, "Address Resolution Protocol"),
                RARP => write!(f, "Reverse Address Resolution Protocol"),
                IPX => write!(f, "Internetwork Packet Exchange"),
                IPv6 => write!(f, "Internet Protocol version 6"),
                EFC => write!(f, "Reverse Address Resolution Protocol"),
                IEEE802_3(len) => write!(f, "IEEE 802.3 length field ({})", len),
                UNKNOWN(value) => write!(f, "Unknown EtherType ({})", value),
            }
        }
    }
    
    use std::convert::From;
    impl From<u16> for EtherType {
        fn from(value: u16) -> Self {
            if value <= 1500 {
                IEEE802_3(value)
            }
            else {
                match value {
                    0x0800 => IPv4,
                    0x1101 => NDP,
                    0x0806 => ARP,
                    0x8035 => RARP,
                    0x8137 => IPX,
                    0x86DD => IPv6,
                    0x8808 => EFC,
                    _ => UNKNOWN(value),
                }
            }
        }
    }

    impl From<EtherType> for u16 {
        fn from(ethtype: EtherType) -> Self {
            match ethtype {
                IPv4 => 0x0800,
                /// Rip specific. The number is my birthday.
                NDP => 0x1101,
                ARP => 0x0806,
                RARP => 0x8035,
                IPX => 0x8137,
                IPv6 => 0x86DD,
                EFC => 0x8808,
                IEEE802_3(len) => len,
                UNKNOWN(value) => value,
            }
        }
    }
}