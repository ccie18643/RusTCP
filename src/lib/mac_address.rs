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
use byteorder::{ByteOrder, NetworkEndian};
use regex::Regex;
use std::convert::TryInto;
use std::fmt;

/// Convert MAC address format from string to u64
fn mac_str_to_u64(mac_str: &str) -> Result<u64, errors::ParseAddressError> {
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
        None => Err(errors::ParseAddressError),
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
    /// Convert MAC address into array of bytes
    pub fn to_bytes(self) -> [u8; 6] {
        let mut bytes = [0u8; 8];
        NetworkEndian::write_u64(&mut bytes, self.address);
        bytes[2..8].try_into().unwrap()
    }
}

/// Convert slice of bytes into MAC address
impl From<&[u8]> for MacAddress {
    fn from(bytes: &[u8]) -> MacAddress {
        MacAddress {
            address: NetworkEndian::read_u64(&[&[0u8; 2], bytes].concat()),
        }
    }
}

/// Convert string into MAC address
impl From<&str> for MacAddress {
    fn from(string: &str) -> MacAddress {
        MacAddress {
            address: mac_str_to_u64(string).expect("Bad MAC address format"),
        }
    }
}

/// Convert IPv6 multicast address into MAC address
impl From<Ip6Address> for MacAddress {
    fn from(ip6_address: Ip6Address) -> MacAddress {
        assert!(ip6_address.is_multicast());
        MacAddress {
            address: 0x3333_0000_0000 | u128::from(ip6_address) as u32 as u64,
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

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CASES: [(&str, u64); 3] = [
        ("01:23:45:67:89:ab", 0x0123_4567_89ab),
        ("00:00:00:00:00:00", 0x0000_0000_0000),
        ("ff:ff:ff:ff:ff:ff", 0xffff_ffff_ffff),
    ];

    #[test]
    #[allow(non_snake_case)]
    fn u64_to_mac_str__assert() {
        for test_case in TEST_CASES {
            assert_eq!(u64_to_mac_str(test_case.1), test_case.0);
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn mac_str_to_u64__assert() {
        for test_case in TEST_CASES {
            assert_eq!(mac_str_to_u64(test_case.0).unwrap(), test_case.1);
        }
    }
}
