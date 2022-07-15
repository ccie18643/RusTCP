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

#![allow(dead_code)]

use crate::protocols::protocol::{self, Protocol};
use byteorder::{ByteOrder, NetworkEndian};
use internet_checksum::Checksum as InetCksum;
use std::fmt;

pub const HEADER_LEN: usize = 8;
pub const ECHO_REQUEST__TYPE: u8 = 128;
pub const ECHO_REQUEST__CODE: u8 = 0;
pub const ECHO_REPLY__TYPE: u8 = 129;
pub const ECHO_REPLY__CODE: u8 = 0;

/// ICMPv6 Echo Request message
#[derive(Default)]
pub struct EchoRequest {
    _id: u16,
    _seq: u16,
    data: Vec<u8>,
    phdr: Vec<u8>,
}

impl EchoRequest {
    /// Create empty message struct
    pub fn new() -> Self {
        Self {
            _id: 0,
            _seq: 0,
            data: Vec::default(),
            phdr: Vec::default(),
        }
    }

    /// Create message based on parsed bytes
    pub fn from(frame_rx: &[u8]) -> Self {
        let mut message = Self::new();
        message.parse(frame_rx);
        message
    }

    /// Get 'id' header field
    pub fn get_id(&self) -> u16 {
        self._id
    }

    /// Set 'id' header field
    pub fn set_id(mut self, _id: u16) -> Self {
        self._id = _id;
        self
    }

    /// Get 'seq' header field
    pub fn get_seq(&self) -> u16 {
        self._seq
    }

    /// Set 'seq' header field
    pub fn set_seq(mut self, _seq: u16) -> Self {
        self._seq = _seq;
        self
    }

    /// Get message data
    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    /// Set message data
    pub fn set_data(mut self, data: &[u8]) -> Self {
        self.data = data.to_vec();
        self
    }

    /// Provide IPv6 pseudo header used for checksum calculation
    pub fn phdr(&mut self, phdr: Vec<u8>) {
        self.phdr = phdr;
    }
}

impl protocol::Protocol for EchoRequest {
    /// Get message length
    fn len(&self) -> usize {
        HEADER_LEN + self.data.len()
    }

    /// Parse message
    fn parse(&mut self, frame_rx: &[u8]) {
        self._id = NetworkEndian::read_u16(&frame_rx[4..6]);
        self._seq = NetworkEndian::read_u16(&frame_rx[6..8]);
        self.data = (&frame_rx[HEADER_LEN..]).to_vec();
    }

    /// Assemble message
    fn assemble(&self, frame_tx: &mut Vec<u8>) {
        let header_ptr = frame_tx.len();
        frame_tx.extend_from_slice(&[
            ECHO_REQUEST__TYPE,
            ECHO_REQUEST__CODE,
            0,
            0,
            (self._id >> 8) as u8,
            self._id as u8,
            (self._seq >> 8) as u8,
            self._seq as u8,
        ]);
        frame_tx.extend_from_slice(&self.data);

        let mut cksum = InetCksum::new();
        cksum.add_bytes(&self.phdr);
        cksum.add_bytes(&frame_tx[header_ptr..]);
        NetworkEndian::write_u16(
            &mut frame_tx[header_ptr + 2..header_ptr + 4],
            cksum.checksum(),
        );
    }
}

impl fmt::Display for EchoRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ICMPv6 Echo Request - id {}, seq {}, dlen {}",
            self._id,
            self._seq,
            self.data.len(),
        )
    }
}

/// ICMPv6 Echo Reply message
#[derive(Default)]
pub struct EchoReply {
    _id: u16,
    _seq: u16,
    data: Vec<u8>,
    phdr: Vec<u8>,
}

impl EchoReply {
    /// Create empty message struct
    pub fn new() -> Self {
        Self {
            _id: 0,
            _seq: 0,
            data: Vec::default(),
            phdr: Vec::default(),
        }
    }

    /// Create message based on parsed bytes
    pub fn from(frame_rx: &[u8]) -> Self {
        let mut message = Self::new();
        message.parse(frame_rx);
        message
    }

    /// Get 'id' header field
    pub fn get_id(&self) -> u16 {
        self._id
    }

    /// Set 'id' header field
    pub fn set_id(mut self, _id: u16) -> Self {
        self._id = _id;
        self
    }

    /// Get 'seq' header field
    pub fn get_seq(&self) -> u16 {
        self._seq
    }

    /// Set 'seq' header field
    pub fn set_seq(mut self, _seq: u16) -> Self {
        self._seq = _seq;
        self
    }

    /// Get message data
    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    /// Set message data
    pub fn set_data(mut self, data: &[u8]) -> Self {
        self.data = data.to_vec();
        self
    }

    /// Provide IPv6 pseudo header for checksum calculation
    pub fn phdr(&mut self, phdr: Vec<u8>) {
        self.phdr = phdr;
    }
}

impl protocol::Protocol for EchoReply {
    /// Get message length
    fn len(&self) -> usize {
        HEADER_LEN + self.data.len()
    }

    /// Parse message
    fn parse(&mut self, frame_rx: &[u8]) {
        self._id = NetworkEndian::read_u16(&frame_rx[4..6]);
        self._seq = NetworkEndian::read_u16(&frame_rx[6..8]);
        self.data = (&frame_rx[HEADER_LEN..]).to_vec();
    }

    /// Assemble message
    fn assemble(&self, frame_tx: &mut Vec<u8>) {
        let header_ptr = frame_tx.len();
        frame_tx.extend_from_slice(&[
            ECHO_REPLY__TYPE,
            ECHO_REPLY__CODE,
            0,
            0,
            (self._id >> 8) as u8,
            self._id as u8,
            (self._seq >> 8) as u8,
            self._seq as u8,
        ]);
        frame_tx.extend_from_slice(&self.data);

        let mut cksum = InetCksum::new();
        cksum.add_bytes(&self.phdr);
        cksum.add_bytes(&frame_tx[header_ptr..]);
        NetworkEndian::write_u16(
            &mut frame_tx[header_ptr + 2..header_ptr + 4],
            cksum.checksum(),
        );
    }
}

impl fmt::Display for EchoReply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ICMPv6 Echo Reply - id {}, seq {}, dlen {}",
            self._id,
            self._seq,
            self.data.len(),
        )
    }
}
