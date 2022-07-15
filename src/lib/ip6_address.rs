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

//! IPv6 Address support library
//!
//! Provides abstraction over the IPv6 Address and various utility
//! functions that operate on IPv6 Addresses.

#![allow(dead_code)]

use crate::lib::mac_address::MacAddress;
use byteorder::{ByteOrder, NetworkEndian};
use regex::Regex;
use std::fmt;

#[derive(Debug)]
pub struct Ip6AddressParseError;

#[derive(Debug)]
pub struct Ip6NonContiguousMaskError;

/// Convert IPv6 address format from string to u128
fn ip6_str_to_u128(ip6_str: &str) -> Result<(u128, u128), Ip6AddressParseError> {
    let ip6_str = ip6_str.trim();
    let mut bytes = [0u8; 16];

    let re = Regex::new(
        "^((([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|\
        ([0-9a-fA-F]{1,4}:){1,7}:|\
        ([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|\
        ([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|\
        ([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|\
        ([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|\
        ([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|\
        [0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|\
        :((:[0-9a-fA-F]{1,4}){1,7}|:)))\
        (/(([0-9])|([1-9][0-9])|(1[0-1][0-9])|(12[0-8])))?$",
    )
    .unwrap();

    if !re.is_match(ip6_str) {
        return Err(Ip6AddressParseError);
    }

    let mut split = ip6_str.split('/');
    let (address, prefix_len) = (split.next().unwrap(), split.next().unwrap_or("128"));
    let prefix_len = 128 - prefix_len.parse::<u32>().unwrap();

    let address_colon_count = address.matches(':').count();
    let mut ip6_word_number = 0;

    for (address_group_number, address_group) in address.split(':').enumerate() {
        if address_group.is_empty() {
            if address_group_number != 0 && address_group_number != address_colon_count {
                ip6_word_number += 7 - address_colon_count;
            }
        } else {
            NetworkEndian::write_u16(
                &mut bytes[ip6_word_number * 2..ip6_word_number * 2 + 2],
                u16::from_str_radix(address_group, 16).unwrap(),
            );
        };
        ip6_word_number += 1;
    }

    let address = NetworkEndian::read_u128(&bytes);
    let mask = u128::MAX.checked_shl(prefix_len).unwrap_or(0);

    Ok((address, mask))
}

/// Convert IPv6 address format from u128 to string
fn u128_to_ip6_str(address: u128, mask: u128) -> Result<String, Ip6NonContiguousMaskError> {
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

    if mask.count_zeros() != mask.trailing_zeros() {
        return Err(Ip6NonContiguousMaskError);
    }

    let prefix_len = mask.leading_ones();

    if prefix_len < 128 {
        ip6_str = format!("{}/{}", ip6_str, prefix_len);
    }

    Ok(ip6_str)
}

/// IPv6 address structure
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Ip6Address {
    address: u128,
    mask: u128,
}

impl Ip6Address {
    /// Create new IPv6 address
    pub fn new(string: &str) -> Self {
        string.into()
    }

    /// Create EUI64 based IPv6 address
    pub fn eui64(prefix: Ip6Address, mac_address: MacAddress) -> Self {
        assert!(prefix.address & 0x0000_0000_0000_0000_ffff_ffff_ffff_ffff == 0);
        assert!(prefix.mask == 0xffff_ffff_ffff_ffff_0000_0000_0000_0000);

        let mac64: u64 = mac_address.into();
        let mut address = ((mac64 & 0x00_00_ff_ff_ff_00_00_00) << 16) as u128;
        address |= (mac64 & 0x00_00_00_00_00_ff_ff_ff) as u128;
        address |= 0x00_00_00_ff_fe_00_00_00_u128;
        address ^= 0x02_00_00_00_00_00_00_00_u128;
        address |= prefix.address;

        Self {
            address,
            mask: prefix.mask,
        }
    }

    /// Convert IPv6 address to array of bytes
    pub fn to_bytes(self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        NetworkEndian::write_u128(&mut bytes, self.address);
        bytes
    }

    /// Convert to host address
    pub fn host(&self) -> Self {
        Self {
            address: self.address,
            mask: 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
        }
    }

    /// Convert to network address
    pub fn network(&self) -> Self {
        Self {
            address: self.address & self.mask,
            mask: self.mask,
        }
    }

    /// Check if provided address is part of this network
    pub fn contains(&self, other: Self) -> bool {
        self.address & self.mask == other.address & self.mask
    }

    /// Check if address is unspecified
    pub fn is_unspecified(&self) -> bool {
        self.address == 0
    }

    /// Check if address is a loopback
    pub fn is_loopback(&self) -> bool {
        self.address == 0x0000_0000_0000_0000_0000_0000_0000_0001
    }

    /// Check if address is global
    pub fn is_global(&self) -> bool {
        self.address & 0xE000_0000_0000_0000_0000_0000_0000_0000
            == 0x2000_0000_0000_0000_0000_0000_0000_0000
    }

    /// Check if address is private
    pub fn is_private(&self) -> bool {
        self.address & 0xfe00_0000_0000_0000_0000_0000_0000_0000
            == 0xfc00_0000_0000_0000_0000_0000_0000_0000
    }

    /// Check if address is link-local
    pub fn is_link_local(&self) -> bool {
        self.address & 0xFFC0_0000_0000_0000_0000_0000_0000_0000
            == 0xFE80_0000_0000_0000_0000_0000_0000_0000
    }

    /// Check if address is unicast
    pub fn is_unicast(&self) -> bool {
        self.address & 0xff00_0000_0000_0000_0000_0000_0000_0000
            != 0xff00_0000_0000_0000_0000_0000_0000_0000
    }

    /// Check if address is multicast
    pub fn is_multicast(&self) -> bool {
        self.address & 0xff00_0000_0000_0000_0000_0000_0000_0000
            == 0xff00_0000_0000_0000_0000_0000_0000_0000
    }

    /// Check if address is solicited node multicast
    pub fn is_solicited_node_multicast(&self) -> bool {
        self.address & 0xffff_ffff_ffff_ffff_ffff_ffff_ff00_0000
            == 0xff02_0000_0000_0000_0000_0001_ff00_0000
    }

    /// Create coresponding Solicited Node Multicast address
    pub fn solicited_node_multicast(&self) -> Self {
        Self {
            address: self.address & 0x0000_0000_0000_0000_0000_0000_00ff_ffff
                | 0xff02_0000_0000_0000_0000_0001_ff00_0000,
            mask: 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
        }
    }

    /// Get the prefix length
    pub fn get_prefix_len(&self) -> u8 {
        self.mask.leading_ones() as u8
    }

    /// Set prefix lenght
    pub fn set_prefix_len(&mut self, prefix_len: u8) {
        self.mask = u128::MAX.checked_shl(128 - prefix_len as u32).unwrap_or(0);
    }
}

/// Convert slice of bytes into IPv6 Address
impl From<&[u8]> for Ip6Address {
    fn from(bytes: &[u8]) -> Self {
        Self {
            address: NetworkEndian::read_u128(bytes),
            mask: 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
        }
    }
}

/// Convert string into IPv6 address
impl From<&str> for Ip6Address {
    fn from(string: &str) -> Self {
        let (address, mask) = ip6_str_to_u128(string).expect("Bad IPv6 address format");
        Self { address, mask }
    }
}

/// Display IPv6 address
impl fmt::Display for Ip6Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", u128_to_ip6_str(self.address, self.mask).unwrap())
    }
}

/// Debug display IPv6 address
impl fmt::Debug for Ip6Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Ip6Address({})",
            u128_to_ip6_str(self.address, self.mask).unwrap()
        )
    }
}

/// Convert IPv6 address into u128
impl From<Ip6Address> for u128 {
    fn from(ip6_address: Ip6Address) -> Self {
        ip6_address.address
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    const CONVERSION_TEST_CASES: [(&str, (u128, u128)); 9] = [
        (
            "fe80::7/64",
            (
                0xfe80_0000_0000_0000_0000_0000_0000_0007,
                0xffff_ffff_ffff_ffff_0000_0000_0000_0000,
            ),
        ),
        (
            "1111:2222:3333:4444:5555:aabb:ccdd:eeff/48",
            (
                0x1111_2222_3333_4444_5555_aabb_ccdd_eeff,
                0xffff_ffff_ffff_0000_0000_0000_0000_0000,
            ),
        ),
        (
            "0:0:7::7/24",
            (
                0x0000_0000_0007_0000_0000_0000_0000_0007,
                0xffff_ff00_0000_0000_0000_0000_0000_0000,
            ),
        ),
        (
            "::7:0:0:7:0:0/124",
            (
                0x0000_0000_0007_0000_0000_0007_0000_0000,
                0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fff0,
            ),
        ),
        (
            "0:0:7::7:0/1",
            (
                0x0000_0000_0007_0000_0000_0000_0007_0000,
                0x8000_0000_0000_0000_0000_0000_0000_0000,
            ),
        ),
        (
            "::7/80",
            (
                0x0000_0000_0000_0000_0000_0000_0000_0007,
                0xffff_ffff_ffff_ffff_ffff_0000_0000_0000,
            ),
        ),
        (
            "7::/96",
            (
                0x0007_0000_0000_0000_0000_0000_0000_0000,
                0xffff_ffff_ffff_ffff_ffff_ffff_0000_0000,
            ),
        ),
        (
            "::/0",
            (
                0x0000_0000_0000_0000_0000_0000_0000_0000,
                0x0000_0000_0000_0000_0000_0000_0000_0000,
            ),
        ),
        (
            "::",
            (
                0x0000_0000_0000_0000_0000_0000_0000_0000,
                0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
            ),
        ),
    ];

    const CONVERSION_FAIL_CASES: [&str; 7] = [
        "0000:0000:0000:0000:0000:0000:0000:0000:0000",
        "0000:0000:0000:0000:0000:0000:0000",
        "a::b::c",
        "fe80::1/129",
        "fe80::1//64",
        "fe80::1/",
        "",
    ];

    #[test]
    #[allow(non_snake_case)]
    fn test__u128_to_ip6_str() {
        for test_case in CONVERSION_TEST_CASES {
            assert_eq!(
                u128_to_ip6_str(test_case.1 .0, test_case.1 .1).unwrap(),
                test_case.0
            );
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_str_to_u128() {
        for test_case in CONVERSION_TEST_CASES {
            assert_eq!(ip6_str_to_u128(test_case.0).unwrap(), (test_case.1));
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_str_to_u128__fail() {
        for test_case in CONVERSION_FAIL_CASES {
            assert!(ip6_str_to_u128(test_case).is_err());
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__new() {
        let ip6_address = Ip6Address::new("0011:2233:4455:6677:8899:aabb:ccdd:eeff/64");
        assert_eq!(
            ip6_address.address,
            0x0011_2233_4455_6677_8899_aabb_ccdd_eeff
        );
        assert_eq!(ip6_address.mask, 0xffff_ffff_ffff_ffff_0000_0000_0000_0000);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__new__no_mask() {
        let ip6_address = Ip6Address::new("0011:2233:4455:6677:8899:aabb:ccdd:eeff");
        assert_eq!(
            ip6_address.address,
            0x0011_2233_4455_6677_8899_aabb_ccdd_eeff
        );
        assert_eq!(ip6_address.mask, 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__eui64() {
        let ip6_address = Ip6Address::eui64(
            Ip6Address::new("fe80::/64"),
            MacAddress::new("01:02:03:04:05:06"),
        );
        assert_eq!(ip6_address, Ip6Address::new("fe80::302:3FF:FE04:506/64"))
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__to_bytes() {
        let ip6_address = Ip6Address::new("0011:2233:4455:6677:8899:aabb:ccdd:eeff");
        assert_eq!(
            ip6_address.to_bytes(),
            [
                0x00u8, 0x11u8, 0x22u8, 0x33u8, 0x44u8, 0x55u8, 0x66u8, 0x77u8, 0x88u8, 0x99u8,
                0xaau8, 0xbbu8, 0xccu8, 0xddu8, 0xeeu8, 0xffu8,
            ]
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__host() {
        let ip6_address = Ip6Address::new("0011:2233:4455:6677:8899:aabb:ccdd:eeff/64").host();
        assert_eq!(
            ip6_address.address,
            0x0011_2233_4455_6677_8899_aabb_ccdd_eeff
        );
        assert_eq!(ip6_address.mask, 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__network() {
        let ip6_address = Ip6Address::new("0011:2233:4455:6677:8899:aabb:ccdd:eeff/64").network();
        assert_eq!(
            ip6_address.address,
            0x0011_2233_4455_6677_0000_0000_0000_0000
        );
        assert_eq!(ip6_address.mask, 0xffff_ffff_ffff_ffff_0000_0000_0000_0000);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__contains() {
        let ip6_network = Ip6Address::new("0011:2233:4455:6677::/64");
        assert!(ip6_network.contains(Ip6Address::new("0011:2233:4455:6677:8899:aabb:ccdd:eeff")));
        assert!(!ip6_network.contains(Ip6Address::new("fe80::1")));
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__is_unspecified() {
        assert!(Ip6Address::new("::").is_unspecified());
        assert!(!Ip6Address::new("0011:2233:4455:6677:8899:aabb:ccdd:eeff").is_unspecified());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__is_loopback() {
        assert!(Ip6Address::new("::1").is_loopback());
        assert!(!Ip6Address::new("0011:2233:4455:6677:8899:aabb:ccdd:eeff").is_loopback());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__is_global() {
        assert!(Ip6Address::new("2001::1").is_global());
        assert!(!Ip6Address::new("fe80::1").is_global());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__is_private() {
        assert!(Ip6Address::new("fc00::1").is_private());
        assert!(Ip6Address::new("fd00::1").is_private());
        assert!(!Ip6Address::new("fe80::1").is_private());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__is_link_local() {
        assert!(Ip6Address::new("fe80::1").is_link_local());
        assert!(!Ip6Address::new("2001::1").is_link_local());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__is_unicast() {
        assert!(Ip6Address::new("fe80::1").is_unicast());
        assert!(Ip6Address::new("2001::1").is_unicast());
        assert!(!Ip6Address::new("ff00::1").is_unicast());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__is_multicast() {
        assert!(Ip6Address::new("ff00::1").is_multicast());
        assert!(!Ip6Address::new("fe80::1").is_multicast());
        assert!(!Ip6Address::new("2001::1").is_multicast());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__is_solicited_node_multicast() {
        assert!(Ip6Address::new("ff02::1:ff00:0").is_solicited_node_multicast());
        assert!(!Ip6Address::new("ff00::1").is_solicited_node_multicast());
        assert!(!Ip6Address::new("fe80::1").is_solicited_node_multicast());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__solicited_node_multicast() {
        let ip6_address = Ip6Address::new("0011:2233:4455:6677:8899:aabb:ccdd:eeff/64");
        assert_eq!(
            ip6_address.solicited_node_multicast(),
            Ip6Address::new("ff02::1:ffdd:eeff")
        )
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__get_prefix_len() {
        let ip6_address = Ip6Address::new("0011:2233:4455::/48");
        assert_eq!(ip6_address.get_prefix_len(), 48);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__set_prefix_len() {
        let mut ip6_address = Ip6Address::new("0011:2233:4455::/48");
        ip6_address.set_prefix_len(32);
        assert_eq!(ip6_address.mask, 0xffff_ffff_0000_0000_0000_0000_0000_0000);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__from_u8() {
        let ip6_address: Ip6Address = [
            0x00u8, 0x11u8, 0x22u8, 0x33u8, 0x44u8, 0x55u8, 0x66u8, 0x77u8, 0x88u8, 0x99u8, 0xaau8,
            0xbbu8, 0xccu8, 0xddu8, 0xeeu8, 0xffu8,
        ][..]
            .into();
        assert_eq!(
            ip6_address.address,
            0x0011_2233_4455_6677_8899_aabb_ccdd_eeff
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__from_str() {
        let ip6_address: Ip6Address = "0011:2233:4455:6677:8899:aabb:ccdd:eeff/64".into();
        assert_eq!(
            ip6_address.address,
            0x0011_2233_4455_6677_8899_aabb_ccdd_eeff
        );
        assert_eq!(ip6_address.mask, 0xffff_ffff_ffff_ffff_0000_0000_0000_0000);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__from_str__no_mask() {
        let ip6_address: Ip6Address = "0011:2233:4455:6677:8899:aabb:ccdd:eeff".into();
        assert_eq!(
            ip6_address.address,
            0x0011_2233_4455_6677_8899_aabb_ccdd_eeff
        );
        assert_eq!(ip6_address.mask, 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__fmt_display() {
        let ip6_address = Ip6Address::new("0011:2233:4455:6677:8899:aabb:ccdd:eeff/128");
        assert_eq!(
            format!("{}", ip6_address),
            "11:2233:4455:6677:8899:aabb:ccdd:eeff"
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__ip6_address__fmt_debug() {
        let ip6_address = Ip6Address::new("0011:2233:4455:6677:8899:aabb:ccdd:eeff/128");
        assert_eq!(
            format!("{:?}", ip6_address),
            "Ip6Address(11:2233:4455:6677:8899:aabb:ccdd:eeff)"
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__u128__from_ip6_address() {
        let ip6_address = Ip6Address::new("0011:2233:4455:6677:8899:aabb:ccdd:eeff");
        assert_eq!(
            u128::from(ip6_address),
            0x0011_2233_4455_6677_8899_aabb_ccdd_eeff
        );
    }
}
