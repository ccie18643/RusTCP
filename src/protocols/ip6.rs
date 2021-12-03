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

use crate::lib::ip6_address::Ip6Address;
use byteorder::{ByteOrder, NetworkEndian};
use std::fmt;

pub const HEADER_LEN: usize = 40;
pub const NEXT__IP6_HOP_OPT: u8 = 0x00;
pub const NEXT__ICMP6: u8 = 0x3A;

/// IPv6 header
#[derive(Debug)]
pub struct Ip6 {
    _ver: u8,
    _dscp: u8,
    _ecn: u8,
    _flow: u32,
    _dlen: u16,
    _next: u8,
    _hop: u8,
    _src: Ip6Address,
    _dst: Ip6Address,
}

impl Ip6 {
    /// Create empty header
    pub fn new() -> Ip6 {
        Ip6 {
            _ver: 6,
            _dscp: 0,
            _ecn: 0,
            _flow: 0,
            _dlen: 0,
            _next: 0,
            _hop: 64,
            _src: Ip6Address::default(),
            _dst: Ip6Address::default(),
        }
    }

    /// Get the 'flow' header field
    pub fn get_flow(&self) -> u32 {
        self._flow
    }

    /// Set the 'flow' header field
    pub fn set_flow(mut self, _flow: u32) -> Ip6 {
        self._flow = _flow;
        self
    }

    /// Get the 'dlen' header field
    pub fn _dlen(&self) -> u16 {
        self._dlen
    }

    /// Set the 'dlen' header field
    pub fn set_dlen(mut self, _dlen: u16) -> Ip6 {
        self._dlen = _dlen;
        self
    }

    /// Get the 'next' header field
    pub fn get_next(&self) -> u8 {
        self._next
    }

    /// Set the 'next' header field
    pub fn set_next(mut self, _next: u8) -> Ip6 {
        self._next = _next;
        self
    }

    /// Get the 'hop' header field
    pub fn get_hop(&self) -> u8 {
        self._hop
    }

    /// Set the 'hop' header field
    pub fn set_hop(mut self, _hop: u8) -> Ip6 {
        self._hop = _hop;
        self
    }

    /// Get the source IPv6 address
    pub fn get_src(&self) -> Ip6Address {
        self._src
    }

    /// Set the source IPv6 address
    pub fn set_src(mut self, _src: Ip6Address) -> Ip6 {
        self._src = _src;
        self
    }

    /// Get the destination IPv6 address
    pub fn get_dst(&self) -> Ip6Address {
        self._dst
    }

    /// Set the destination IPv6 address
    pub fn set_dst(mut self, _dst: Ip6Address) -> Ip6 {
        self._dst = _dst;
        self
    }

    /// Generate pseudo header used for TCP/UDP/ICMPv6 checksum calculation
    pub fn phdr(&self) -> Vec<u8> {
        let mut phdr = Vec::with_capacity(40);
        phdr.extend_from_slice(&self._src.to_bytes());
        phdr.extend_from_slice(&self._dst.to_bytes());
        phdr.extend_from_slice(&[
            (self._dlen >> 8) as u8,
            self._dlen as u8,
            0,
            0,
            0,
            0,
            0,
            self._next,
        ]);
        phdr
    }

    /// Get header length
    pub fn len(&self) -> usize {
        HEADER_LEN
    }

    /// Parse header
    pub fn parse(mut self, frame_rx: &[u8]) -> Self {
        self._flow = (((frame_rx[1] & 0b00001111) as u32) << 16)
            | ((frame_rx[2] as u32) << 8)
            | (frame_rx[3] as u32);
        self._dlen = NetworkEndian::read_u16(&frame_rx[4..6]);
        self._next = frame_rx[6];
        self._hop = frame_rx[7];
        self._src = frame_rx[8..24].into();
        self._dst = frame_rx[24..40].into();
        self
    }

    /// Assemble header
    pub fn assemble(&self, frame_tx: &mut Vec<u8>) {
        frame_tx.extend_from_slice(&[
            self._ver << 4 | self._dscp >> 4,
            self._dscp & 0x03 << 6 | self._ecn << 4 | (self._flow & 0xF0000 >> 16) as u8,
            (self._flow >> 8) as u8,
            self._flow as u8,
            (self._dlen >> 8) as u8,
            self._dlen as u8,
            self._next,
            self._hop,
        ]);
        frame_tx.extend_from_slice(&self._src.to_bytes());
        frame_tx.extend_from_slice(&self._dst.to_bytes());
    }
}
impl fmt::Display for Ip6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IPv6 {} > {}, next {}, flow {}, dlen {}, hop {}",
            self._src, self._dst, self._next, self._flow, self._dlen, self._hop,
        )
    }
}
