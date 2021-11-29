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
use std::convert::TryInto;
use std::fmt;

/// Helper converting IPv6 address format from string to bytes
fn ip6_str_to_bytes(ip6_str: &str) -> Result<[u8; 16], errors::ParseAddressError> {
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

    Ok(bytes)
}

/// Helper converting IPv6 address format from bytes to string
fn bytes_to_ip6_str(bytes: &[u8; 16]) -> String {
    let mut ip6_str = String::with_capacity(40);

    for ip6_word_number in 0..8 {
        ip6_str.push_str(&format!(
            "{:x}:",
            NetworkEndian::read_u16(&bytes[ip6_word_number * 2..ip6_word_number * 2 + 2])
        ));
    }
    ip6_str.pop();

    let mut fold_str = "0:0:0:0:0:0:0:0".to_string();

    for _ in 0..7 {
        if ip6_str.matches(&fold_str).count() > 0 {
            ip6_str = ip6_str.replacen(&fold_str, "", 1);
            break;
        }
        fold_str.truncate(fold_str.len() - 2);
    }

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
    bytes: [u8; 16],
}

impl Ip6Address {
    /// Create all-zeros IPv6 address
    pub fn new() -> Ip6Address {
        Ip6Address { bytes: [0u8; 16] }
    }

    /// Helper converting IPv6 address to array of bytes
    pub fn to_bytes(self) -> [u8; 16] {
        self.bytes
    }

    /// Create coresponding Solicited Node Multicast address
    pub fn solicited_node_multicast(&self) -> Ip6Address {
        Ip6Address {
            bytes: [
                0xFF,
                0x02,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01,
                0xFF,
                self.bytes[13],
                self.bytes[14],
                self.bytes[15],
            ],
        }
    }
}

/// Convert IPv6 address into array of bytes
impl From<Ip6Address> for [u8; 16] {
    fn from(ip6_address: Ip6Address) -> Self {
        ip6_address.bytes
    }
}

/// Convert IPv6 address into reference to array of bytes
impl From<&Ip6Address> for [u8; 16] {
    fn from(ip6_address: &Ip6Address) -> Self {
        ip6_address.bytes
    }
}

/// Convert slice of bytes into IPv6 Address
impl From<&[u8]> for Ip6Address {
    fn from(bytes: &[u8]) -> Self {
        Ip6Address {
            bytes: bytes.try_into().expect("Bad IPv6 address length"),
        }
    }
}

/// Convert array of bytes into IPv6 address
impl From<[u8; 16]> for Ip6Address {
    fn from(bytes: [u8; 16]) -> Self {
        Ip6Address { bytes }
    }
}

/// Convert string into IPv6 address
impl From<&str> for Ip6Address {
    fn from(string: &str) -> Self {
        Ip6Address {
            bytes: ip6_str_to_bytes(string).expect("Bad IPv6 address format"),
        }
    }
}

/// Display IPv6 address
impl fmt::Display for Ip6Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bytes_to_ip6_str(&self.bytes))
    }
}

/// Debug display IPv6 address
impl fmt::Debug for Ip6Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ip6Address({})", bytes_to_ip6_str(&self.bytes))
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CASES: [(&str, [u8; 16]); 7] = [
        (
            "11:2233:4455:6677:8899:aabb:ccdd:eeff",
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        ),
        (
            "0:0:7::7",
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x07,
            ],
        ),
        (
            "::7:0:0:7:0:0",
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00,
                0x00, 0x00,
            ],
        ),
        (
            "0:0:7::7:0",
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
                0x00, 0x00,
            ],
        ),
        (
            "::7",
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x07,
            ],
        ),
        (
            "7::",
            [
                0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
        ),
        (
            "::",
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
        ),
    ];

    #[test]
    #[allow(non_snake_case)]
    fn bytes_to_ip6_str__assert() {
        for test_case in TEST_CASES {
            assert_eq!(bytes_to_ip6_str(&test_case.1), test_case.0);
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn ip6_str_to_bytes__assert() {
        for test_case in TEST_CASES {
            assert_eq!(ip6_str_to_bytes(test_case.0).unwrap(), test_case.1);
        }
    }
}
