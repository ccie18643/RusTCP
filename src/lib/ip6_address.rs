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
use byteorder::{ByteOrder, NetworkEndian};
use regex::Regex;
use std::fmt;

/// Convert IPv6 address format from string to u128
fn ip6_str_to_u128(ip6_str: &str) -> Result<u128, errors::ParseAddressError> {
    let mut bytes = [0u8; 16];

    let re = Regex::new(
        "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|\
        ([0-9a-fA-F]{1,4}:){1,7}:|\
        ([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|\
        ([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|\
        ([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|\
        ([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|\
        ([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|\
        [0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|\
        :((:[0-9a-fA-F]{1,4}){1,7}|:))$",
    )
    .unwrap();

    if !re.is_match(ip6_str) {
        return Err(errors::ParseAddressError);
    }

    let ip6_str_colon_count = ip6_str.matches(':').count();
    let mut ip6_word_number = 0;

    for (ip6_str_group_number, ip6_str_group) in ip6_str.split(':').enumerate() {
        if ip6_str_group.is_empty() {
            if ip6_str_group_number != 0 && ip6_str_group_number != ip6_str_colon_count {
                ip6_word_number += 7 - ip6_str_colon_count;
            }
        } else {
            NetworkEndian::write_u16(
                &mut bytes[ip6_word_number * 2..ip6_word_number * 2 + 2],
                u16::from_str_radix(ip6_str_group, 16).unwrap(),
            );
        };
        ip6_word_number += 1;
    }

    Ok(NetworkEndian::read_u128(&bytes))
}

/// Convert IPv6 address format from u128 to string
fn u128_to_ip6_str(address: u128) -> String {
    let mut ip6_str = String::with_capacity(40);

    let mut bytes = [0u8; 16];
    NetworkEndian::write_u128(&mut bytes, address);

    for ip6_word_number in 0..8 {
        ip6_str.push_str(&format!(
            ":{:x}",
            NetworkEndian::read_u16(&bytes[ip6_word_number * 2..ip6_word_number * 2 + 2])
        ));
    }

    let mut fold_str = ":0:0:0:0:0:0:0:0".to_string();

    for _ in 0..7 {
        if ip6_str.matches(&fold_str).count() > 0 {
            ip6_str = ip6_str.replacen(&fold_str, ":", 1);
            break;
        }
        fold_str.truncate(fold_str.len() - 2);
    }

    ip6_str.remove(0);

    if ip6_str.starts_with(':') {
        ip6_str = format!(":{}", ip6_str);
    }

    if ip6_str.ends_with(':') {
        ip6_str = format!("{}:", ip6_str);
    }

    if ip6_str.is_empty() {
        ip6_str = "::".to_string();
    }

    ip6_str
}

/// IPv6 address structure
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Ip6Address {
    address: u128,
}

impl Ip6Address {
    /// Helper converting IPv6 address to array of bytes
    pub fn to_bytes(self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        NetworkEndian::write_u128(&mut bytes, self.address);
        bytes
    }

    /// Check if address is unspecified
    pub fn is_unspecified(&self) -> bool {
        self.address == 0
    }

    /// Check if address is a solicited node multicast
    pub fn is_solicited_node_multicast(&self) -> bool {
        self.address & 0xffff_ffff_ffff_ffff_ffff_ffff_ff00_0000
            == 0xff02_0000_0000_0000_0000_0001_ff00_0000
    }
    /// Create coresponding Solicited Node Multicast address
    pub fn solicited_node_multicast(&self) -> Ip6Address {
        Ip6Address {
            address: self.address & 0x0000_0000_0000_0000_0000_0000_00ff_ffff
                | 0xff02_0000_0000_0000_0000_0001_ff00_0000,
        }
    }
}

/// Convert slice of bytes into IPv6 Address
impl From<&[u8]> for Ip6Address {
    fn from(bytes: &[u8]) -> Ip6Address {
        Ip6Address {
            address: NetworkEndian::read_u128(bytes),
        }
    }
}

/// Convert string into IPv6 address
impl From<&str> for Ip6Address {
    fn from(string: &str) -> Ip6Address {
        Ip6Address {
            address: ip6_str_to_u128(string).expect("Bad IPv6 address format"),
        }
    }
}

/// Display IPv6 address
impl fmt::Display for Ip6Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", u128_to_ip6_str(self.address))
    }
}

/// Debug display IPv6 address
impl fmt::Debug for Ip6Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ip6Address({})", u128_to_ip6_str(self.address))
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CASES: [(&str, u128); 8] = [
        ("fe80::7", 0xfe80_0000_0000_0000_0000_0000_0000_0007),
        (
            "1111:2222:3333:4444:5555:aabb:ccdd:eeff",
            0x1111_2222_3333_4444_5555_aabb_ccdd_eeff,
        ),
        ("0:0:7::7", 0x0000_0000_0007_0000_0000_0000_0000_0007),
        ("::7:0:0:7:0:0", 0x0000_0000_0007_0000_0000_0007_0000_0000),
        ("0:0:7::7:0", 0x0000_0000_0007_0000_0000_0000_0007_0000),
        ("::7", 0x0000_0000_0000_0000_0000_0000_0000_0007),
        ("7::", 0x0007_0000_0000_0000_0000_0000_0000_0000),
        ("::", 0x0000_0000_0000_0000_0000_0000_0000_0000),
    ];

    #[test]
    #[allow(non_snake_case)]
    fn u128_to_ip6_str__assert() {
        for test_case in TEST_CASES {
            assert_eq!(u128_to_ip6_str(test_case.1), test_case.0);
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn ip6_str_to_u128__assert() {
        for test_case in TEST_CASES {
            assert_eq!(ip6_str_to_u128(test_case.0).unwrap(), test_case.1);
        }
    }
}
