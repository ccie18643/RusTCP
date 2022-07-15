/*
############################################################################
#                                                                          #
#  RusTCP - Rust TCP/IP stack                                              #
#  Copyright (C) 2020-2022  Sebastian Majewski                             #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/RusTCP                  #
#                                                                          #
############################################################################
*/

//! MAC Address support library
//!
//! Provides abstraction over the MAC Address and various utility
//! functions that operate on MAC Addresses.

#![allow(dead_code)]

use crate::lib::ip6_address::Ip6Address;
use byteorder::{ByteOrder, NetworkEndian};
use regex::Regex;
use std::convert::TryInto;
use std::fmt;

#[derive(Debug)]
pub struct MacAddressParseError;

/// Convert MAC address format from string to u64
fn mac_str_to_u64(mac_str: &str) -> Result<u64, MacAddressParseError> {
    let re = Regex::new(
        "^([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):\
        ([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})$",
    )
    .unwrap();

    match re.captures(mac_str) {
        Some(cap) => {
            let mut bytes = [0u8; 8];
            for i in 0..6 {
                bytes[i + 2] = u8::from_str_radix(&cap[i + 1], 16).unwrap();
            }
            Ok(NetworkEndian::read_u64(&bytes))
        }
        None => Err(MacAddressParseError),
    }
}

/// Convert MAC address format from u64 to string
fn u64_to_mac_str(address: u64) -> String {
    let mut bytes = [0u8; 8];
    NetworkEndian::write_u64(&mut bytes, address);

    let mut mac_str = String::with_capacity(19);
    for byte in &bytes[2..8] {
        mac_str.push_str(&format!("{:02x}:", byte));
    }
    mac_str.pop();
    mac_str
}

/// MAC address structure
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddress {
    address: u64,
}

impl MacAddress {
    /// Create new MAC address
    pub fn new(string: &str) -> Self {
        string.into()
    }

    /// Convert MAC address into array of bytes
    pub fn to_bytes(self) -> [u8; 6] {
        let mut bytes = [0u8; 8];
        NetworkEndian::write_u64(&mut bytes, self.address);
        bytes[2..8].try_into().unwrap()
    }
}

/// Convert slice of bytes into MAC address
impl From<&[u8]> for MacAddress {
    fn from(bytes: &[u8]) -> Self {
        Self {
            address: NetworkEndian::read_u64(&[&[0u8; 2], bytes].concat()),
        }
    }
}

/// Convert string into MAC address
impl From<&str> for MacAddress {
    fn from(string: &str) -> Self {
        Self {
            address: mac_str_to_u64(string).expect("Bad MAC address format"),
        }
    }
}

/// Convert IPv6 multicast address into MAC address
impl From<Ip6Address> for MacAddress {
    fn from(ip6_address: Ip6Address) -> Self {
        assert!(ip6_address.is_multicast());
        Self {
            address: 0x33_33_00_00_00_00 | u128::from(ip6_address) as u32 as u64,
        }
    }
}

/// Display MAC address
impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", u64_to_mac_str(self.address))
    }
}

/// Debug display MAC address
impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MacAddress({})", u64_to_mac_str(self.address))
    }
}

/// Convert MAC address into u64
impl From<MacAddress> for u64 {
    fn from(mac_address: MacAddress) -> Self {
        mac_address.address
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    const CONVERSION_TEST_CASES: [(&str, u64); 3] = [
        ("00:00:00:00:00:00", 0x00_00_00_00_00_00),
        ("01:23:45:67:89:ab", 0x01_23_45_67_89_ab),
        ("ff:ff:ff:ff:ff:ff", 0xff_ff_ff_ff_ff_ff),
    ];

    const CONVERSION_FAIL_CASES: [&str; 10] = [
        "0000:00:00:00:00",
        "00:00:00:00:00:00:00",
        "00:00:00:00:00",
        "00.00:00:00:00:00",
        "x0:00:00:00:00:00",
        "0:00:00:00:00:00",
        "00:00:000:00:00:00",
        "0000.0000.0000",
        "00-00-00-00-00-00",
        "",
    ];

    #[test]
    #[allow(non_snake_case)]
    fn test__u64_to_mac_str() {
        for test_case in CONVERSION_TEST_CASES {
            assert_eq!(u64_to_mac_str(test_case.1), test_case.0);
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__mac_str_to_u64() {
        for test_case in CONVERSION_TEST_CASES {
            assert_eq!(mac_str_to_u64(test_case.0).unwrap(), test_case.1);
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__mac_str_to_u64__fail() {
        for test_case in CONVERSION_FAIL_CASES {
            assert!(mac_str_to_u64(test_case).is_err());
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__mac_address__new() {
        let mac_address = MacAddress::new("01:02:03:04:05:06");
        assert_eq!(mac_address.address, 0x00_00_01_02_03_04_05_06);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__mac_address__to_bytes() {
        let mac_address = MacAddress::new("01:23:45:67:89:ab");
        assert_eq!(
            mac_address.to_bytes(),
            [0x01u8, 0x23u8, 0x45u8, 0x67u8, 0x89u8, 0xabu8]
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__mac_address__from_u8() {
        let mac_address: MacAddress = [0x01u8, 0x23u8, 0x45u8, 0x67u8, 0x89u8, 0xabu8][..].into();
        assert_eq!(mac_address.address, 0x00_00_01_23_45_67_89_ab);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__mac_address__from_str() {
        let mac_address: MacAddress = "01:23:45:67:89:ab".into();
        assert_eq!(mac_address.address, 0x00_00_01_23_45_67_89_ab);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__mac_address__from_ip6_multicast() {
        let mac_address: MacAddress = Ip6Address::new("ff02::0123:4567:89ab:cdef").into();
        assert_eq!(mac_address.address, 0x00_00_33_33_89_ab_cd_ef);
    }

    #[test]
    #[allow(non_snake_case)]
    #[should_panic]
    fn test__mac_address__from_ip6_multicast__non_multicast_ip6_address() {
        let _mac_address: MacAddress = Ip6Address::new("fe80::0123:4567:89ab:cdef").into();
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__mac_address__fmt_display() {
        let mac_address = MacAddress::new("01:23:45:67:89:ab");
        assert_eq!(format!("{}", mac_address), "01:23:45:67:89:ab");
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__mac_address__fmt_debug() {
        let mac_address = MacAddress::new("01:23:45:67:89:ab");
        assert_eq!(
            format!("{:?}", mac_address),
            "MacAddress(01:23:45:67:89:ab)"
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__u64__from_mac_address() {
        let mac_address = MacAddress::new("01:23:45:67:89:ab");
        assert_eq!(u64::from(mac_address), 0x00_00_01_23_45_67_89_ab);
    }
}
