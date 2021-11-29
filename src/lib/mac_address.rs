#![allow(dead_code)]

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

use crate::lib::errors;
use crate::lib::ip6_address::Ip6Address;
use regex::Regex;
use std::convert::TryInto;
use std::fmt;

/// Helper converting MAC address format from string to bytes
fn mac_str_to_bytes(mac_str: &str) -> Result<[u8; 6], errors::ParseAddressError> {
    let re = Regex::new(
        "^([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):\
        ([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})$",
    )
    .unwrap();

    match re.captures(mac_str) {
        Some(cap) => {
            let mut bytes = [0u8; 6];
            for i in 0..6 {
                bytes[i] = u8::from_str_radix(&cap[i + 1], 16).unwrap();
            }
            Ok(bytes)
        }
        None => Err(errors::ParseAddressError),
    }
}

/// Helper converting MAC address format from bytes to string
fn bytes_to_mac_str(bytes: &[u8; 6]) -> String {
    let mut mac_str = String::with_capacity(19);
    for byte in bytes {
        mac_str.push_str(&format!("{:02x}:", byte));
    }
    mac_str.pop();
    mac_str
}

/// MAC address structure
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddress {
    bytes: [u8; 6],
}

impl MacAddress {
    /// Create all-zeros MAC address
    pub fn new() -> Self {
        MacAddress { bytes: [0u8; 6] }
    }

    /// Helper converting MAC address to array of bytes
    pub fn to_bytes(self) -> [u8; 6] {
        self.bytes
    }
}

/// Convert MAC address into array of  bytes
impl From<MacAddress> for [u8; 6] {
    fn from(mac_address: MacAddress) -> Self {
        mac_address.bytes
    }
}

/// Convert MAC address into reference to array of bytes
impl From<&MacAddress> for [u8; 6] {
    fn from(mac_address: &MacAddress) -> Self {
        mac_address.bytes
    }
}

/// Convert slice of bytes into MAC address
impl From<&[u8]> for MacAddress {
    fn from(bytes: &[u8]) -> Self {
        MacAddress {
            bytes: bytes.try_into().expect("Bad MAC address length"),
        }
    }
}

/// Convert array of bytes into MAC address
impl From<[u8; 6]> for MacAddress {
    fn from(bytes: [u8; 6]) -> Self {
        MacAddress { bytes }
    }
}

/// Convert string into MAC address
impl From<&str> for MacAddress {
    fn from(string: &str) -> Self {
        MacAddress {
            bytes: mac_str_to_bytes(string).expect("Bad MAC address format"),
        }
    }
}

/// Convert IPv6 multicast address into MAC address
impl From<Ip6Address> for MacAddress {
    fn from(ip6_address: Ip6Address) -> Self {
        // Need to assert here to make sure ip6_address is a multicast address
        let ip6_address_bytes: [u8; 16] = ip6_address.into();
        MacAddress {
            bytes: [
                0x33,
                0x33,
                ip6_address_bytes[12],
                ip6_address_bytes[13],
                ip6_address_bytes[14],
                ip6_address_bytes[15],
            ],
        }
    }
}

/// Display MAC address
impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bytes_to_mac_str(&self.bytes))
    }
}

/// Debug display MAC address
impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MacAddress({})", bytes_to_mac_str(&self.bytes))
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CASES: [(&str, [u8; 6]); 3] = [
        ("01:23:45:67:89:ab", [0x01, 0x23, 0x45, 0x67, 0x89, 0xab]),
        ("00:00:00:00:00:00", [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        ("ff:ff:ff:ff:ff:ff", [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
    ];

    #[test]
    #[allow(non_snake_case)]
    fn bytes_to_mac_str__assert() {
        for test_case in TEST_CASES {
            assert_eq!(bytes_to_mac_str(&test_case.1), test_case.0);
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn mac_str_to_bytes__assert() {
        for test_case in TEST_CASES {
            assert_eq!(mac_str_to_bytes(test_case.0).unwrap(), test_case.1);
        }
    }
}
