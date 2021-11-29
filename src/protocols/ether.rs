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

use crate::lib::mac_address::MacAddress;
use byteorder::{ByteOrder, NetworkEndian};
use std::fmt;

pub const HEADER_LEN: usize = 14;
pub const TYPE__IP6: u16 = 0x86DD;

/// Ethernet header
#[derive(Debug)]
pub struct Ether {
    _dst: MacAddress,
    _src: MacAddress,
    _type: u16,
}

impl Ether {
    /// Create empty header
    pub fn new() -> Ether {
        Ether {
            _dst: MacAddress::default(),
            _src: MacAddress::default(),
            _type: 0,
        }
    }

    /// Get the destination MAC address
    pub fn get_dst(&self) -> MacAddress {
        self._dst
    }

    /// Set the destination MAC address
    pub fn set_dst(mut self, _dst: MacAddress) -> Ether {
        self._dst = _dst;
        self
    }

    /// Get the source MAC address
    pub fn get_src(&self) -> MacAddress {
        self._src
    }

    /// Set the source MAC address
    pub fn set_src(mut self, _src: MacAddress) -> Ether {
        self._src = _src;
        self
    }

    /// Get the value of 'type' header field
    pub fn get_type(&self) -> u16 {
        self._type
    }

    /// Set the value of 'type' header field
    pub fn set_type(mut self, _type: u16) -> Ether {
        self._type = _type;
        self
    }

    /// Get header length
    pub fn len(&self) -> usize {
        HEADER_LEN
    }

    /// Parse header
    pub fn parse(mut self, frame_rx: &[u8]) -> Self {
        self._dst = frame_rx[0..6].into();
        self._src = frame_rx[6..12].into();
        self._type = NetworkEndian::read_u16(&frame_rx[12..14]);
        self
    }

    /// Assemble header
    pub fn assemble(&self, frame_tx: &mut Vec<u8>) {
        frame_tx.extend_from_slice(&self._dst.to_bytes());
        frame_tx.extend_from_slice(&self._src.to_bytes());
        frame_tx.extend_from_slice(&self._type.to_be_bytes());
    }
}

impl fmt::Display for Ether {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ETHER {} > {}, type {:#04x}",
            self._src, self._dst, self._type,
        )
    }
}
