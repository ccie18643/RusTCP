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

use crate::lib::ip6_address::Ip6Address;
use crate::lib::mac_address::MacAddress;
use crate::protocols::protocol::{self, Protocol};
use byteorder::{ByteOrder, NetworkEndian};
use internet_checksum::Checksum as InetCksum;
use std::collections::HashMap;
use std::fmt;

pub const ROUTER_SOLICITATION__TYPE: u8 = 133;
pub const ROUTER_SOLICITATION__CODE: u8 = 0;
pub const ROUTER_SOLICITATION__HEADER_LEN: usize = 8;

pub const ROUTER_ADVERTISEMENT__TYPE: u8 = 134;
pub const ROUTER_ADVERTISEMENT__CODE: u8 = 0;
pub const ROUTER_ADVERTISEMENT__HEADER_LEN: usize = 16;

pub const NEIGHBOR_SOLICITATION__TYPE: u8 = 135;
pub const NEIGHBOR_SOLICITATION__CODE: u8 = 0;
pub const NEIGHBOR_SOLICITATION__HEADER_LEN: usize = 24;

pub const NEIGHBOR_ADVERTISEMENT__TYPE: u8 = 136;
pub const NEIGHBOR_ADVERTISEMENT__CODE: u8 = 0;
pub const NEIGHBOR_ADVERTISEMENT__HEADER_LEN: usize = 24;

pub const OPT_SLLA__TYPE: u8 = 1;
pub const OPT_SLLA__LEN: usize = 8;

pub const OPT_TLLA__TYPE: u8 = 2;
pub const OPT_TLLA__LEN: usize = 8;

pub const OPT_PI__TYPE: u8 = 3;
pub const OPT_PI__LEN: usize = 32;

pub struct Ip6NdRaPrefixMetadata;

/// ICMPv6 ND RS message
#[derive(Default, Debug)]
pub struct RouterSolicitation {
    opts: Vec<NdOpt>,
    phdr: Vec<u8>,
}

impl RouterSolicitation {
    /// Create empty message
    pub fn new() -> Self {
        Self {
            opts: Vec::new(),
            phdr: Vec::new(),
        }
    }

    /// Create message based on parsed bytes
    pub fn from(frame_rx: &[u8]) -> Self {
        let mut message = Self::new();
        message.parse(frame_rx);
        message
    }

    /// Get the value of 'slla' nd option if present
    pub fn get_slla(&self) -> Option<MacAddress> {
        for opt in &self.opts {
            match opt {
                NdOpt::SLLA { _slla } => return Some(*_slla),
                _ => continue,
            }
        }
        None
    }

    /// Add the 'slla' nd option and set it's value
    pub fn set_slla(mut self, slla: MacAddress) -> Self {
        self.opts.push(NdOpt::SLLA { _slla: slla });
        self
    }

    /// Provide IPv6 pseudo header for checksum calculation
    pub fn phdr(&mut self, phdr: Vec<u8>) {
        self.phdr = phdr;
    }
}

impl protocol::Protocol for RouterSolicitation {
    /// Get length of the message
    fn len(&self) -> usize {
        let mut opts_len = 0;
        for opt in &self.opts {
            opts_len += opt.len();
        }
        ROUTER_SOLICITATION__HEADER_LEN + opts_len
    }

    /// Parse message
    fn parse(&mut self, frame_rx: &[u8]) {
        self.opts = parse_opts(&frame_rx[ROUTER_SOLICITATION__HEADER_LEN..]);
    }

    /// Assemble message
    fn assemble(&self, frame_tx: &mut Vec<u8>) {
        let header_ptr = frame_tx.len();
        frame_tx.extend_from_slice(&[
            ROUTER_SOLICITATION__TYPE,
            ROUTER_SOLICITATION__CODE,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);

        for opt in &self.opts {
            opt.assemble(frame_tx);
        }

        let mut cksum = InetCksum::new();
        cksum.add_bytes(&self.phdr);
        cksum.add_bytes(&frame_tx[header_ptr..]);
        NetworkEndian::write_u16(
            &mut frame_tx[header_ptr + 2..header_ptr + 4],
            cksum.checksum(),
        );
    }
}

impl fmt::Display for RouterSolicitation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = "ICMPv6 ND Router Solicitation".to_string();
        for opt in &self.opts {
            text = format!("{}{}", text, opt);
        }
        write!(f, "{}", text)
    }
}

/// ICMPv6 ND RA message
#[derive(Default, Debug)]
pub struct RouterAdvertisement {
    _hop: u8,
    _flag_m: bool,
    _flag_o: bool,
    _router_lifetime: u16,
    _reachable_time: u32,
    _retrans_timer: u32,
    opts: Vec<NdOpt>,
    phdr: Vec<u8>,
}

impl RouterAdvertisement {
    /// Create empty message
    pub fn new() -> Self {
        Self {
            _hop: 0,
            _flag_m: false,
            _flag_o: false,
            _router_lifetime: 0,
            _reachable_time: 0,
            _retrans_timer: 0,
            opts: Vec::new(),
            phdr: Vec::new(),
        }
    }

    /// Create message based on parsed bytes
    pub fn from(frame_rx: &[u8]) -> Self {
        let mut message = Self::new();
        message.parse(frame_rx);
        message
    }

    /// Get the state of 'M' header flag
    pub fn get_flag_m(&self) -> bool {
        self._flag_m
    }

    /// Set the state of 'M' header flag
    pub fn set_flag_m(mut self, _flag_m: bool) -> Self {
        self._flag_m = _flag_m;
        self
    }

    /// Get the state of 'O' header flag
    pub fn get_flag_o(&self) -> bool {
        self._flag_o
    }

    /// Set the state of 'O' header flag
    pub fn set_flag_o(mut self, _flag_o: bool) -> Self {
        self._flag_o = _flag_o;
        self
    }

    /// Get the value of 'router_lifetime' header field
    pub fn get_router_lifetime(&self) -> u16 {
        self._router_lifetime
    }

    /// Set the value of 'router_lifetime' header field
    pub fn set_router_lifetime(mut self, _router_lifetime: u16) -> Self {
        self._router_lifetime = _router_lifetime;
        self
    }

    /// Get the value of 'reachable_time' header field
    pub fn get_reachable_time(&self) -> u32 {
        self._reachable_time
    }

    /// Set the value of 'reachable_time' header field
    pub fn set_reachable_time(mut self, _reachable_time: u32) -> Self {
        self._reachable_time = _reachable_time;
        self
    }

    /// Get the value of 'retrans_timer' header field
    pub fn get_retrans_timer(&self) -> u32 {
        self._retrans_timer
    }

    /// Set the value of 'retrans_timer' header field
    pub fn set_retrans_timer(mut self, _retrans_timer: u32) -> Self {
        self._retrans_timer = _retrans_timer;
        self
    }

    /// Get the value of 'slla' nd option if present
    pub fn get_slla(&self) -> Option<MacAddress> {
        for opt in &self.opts {
            match opt {
                NdOpt::SLLA { _slla } => return Some(*_slla),
                _ => continue,
            }
        }
        None
    }

    /// Add the 'slla' nd option and set it's value
    pub fn set_slla(mut self, slla: MacAddress) -> Self {
        self.opts.push(NdOpt::SLLA { _slla: slla });
        self
    }

    /// Get the value of 'pi' nd option(s) if present
    pub fn get_pi(&self) -> HashMap<Ip6Address, Ip6NdRaPrefixMetadata> {
        let mut prefixes = HashMap::new();
        for opt in &self.opts {
            match opt {
                NdOpt::PI { _prefix, .. } => prefixes.insert(*_prefix, Ip6NdRaPrefixMetadata {}),
                _ => continue,
            };
        }
        prefixes
    }

    /// Provide IPv6 pseudo header for checksum calculation
    pub fn phdr(&mut self, phdr: Vec<u8>) {
        self.phdr = phdr;
    }
}

impl protocol::Protocol for RouterAdvertisement {
    /// Get length of the message
    fn len(&self) -> usize {
        let mut opts_len = 0;
        for opt in &self.opts {
            opts_len += opt.len();
        }
        NEIGHBOR_ADVERTISEMENT__HEADER_LEN + opts_len
    }

    /// Parse message
    fn parse(&mut self, frame_rx: &[u8]) {
        self._hop = frame_rx[4];
        self._flag_m = frame_rx[4] & 0b10000000 != 0;
        self._flag_o = frame_rx[4] & 0b01000000 != 0;
        self._router_lifetime = NetworkEndian::read_u16(&frame_rx[6..8]);
        self._reachable_time = NetworkEndian::read_u32(&frame_rx[8..12]);
        self._retrans_timer = NetworkEndian::read_u32(&frame_rx[12..16]);
        self.opts = parse_opts(&frame_rx[ROUTER_ADVERTISEMENT__HEADER_LEN..]);
    }

    /// Assemble message
    fn assemble(&self, frame_tx: &mut Vec<u8>) {
        let header_ptr = frame_tx.len();
        let flag_byte: u8 = ((self._flag_m as u8) << 7) | ((self._flag_o as u8) << 6);
        frame_tx.extend_from_slice(&[
            ROUTER_ADVERTISEMENT__TYPE,
            ROUTER_ADVERTISEMENT__CODE,
            0,
            0,
            flag_byte,
        ]);
        frame_tx.extend_from_slice(&self._router_lifetime.to_be_bytes());
        frame_tx.extend_from_slice(&self._reachable_time.to_be_bytes());
        frame_tx.extend_from_slice(&self._retrans_timer.to_be_bytes());

        for opt in &self.opts {
            opt.assemble(frame_tx);
        }

        let mut cksum = InetCksum::new();
        cksum.add_bytes(&self.phdr);
        cksum.add_bytes(&frame_tx[header_ptr..]);
        NetworkEndian::write_u16(
            &mut frame_tx[header_ptr + 2..header_ptr + 4],
            cksum.checksum(),
        );
    }
}

impl fmt::Display for RouterAdvertisement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = format!(
            "ICMPv6 ND Router Advertisement - hop limit {}, flags {}{}, router lifetime {}, reachable time {}, retrans timer {}",
            self._hop,
            if self._flag_m { 'M' } else { '-' },
            if self._flag_o { 'O' } else { '-' },
            self._router_lifetime,
            self._reachable_time,
            self._retrans_timer,
        );
        for opt in &self.opts {
            text = format!("{}{}", text, opt);
        }
        write!(f, "{}", text)
    }
}

/// ICMPv6 ND NS message
#[derive(Default, Debug)]
pub struct NeighborSolicitation {
    _tnla: Ip6Address,
    opts: Vec<NdOpt>,
    phdr: Vec<u8>,
}

impl NeighborSolicitation {
    /// Create empty message
    pub fn new() -> Self {
        Self {
            _tnla: Ip6Address::default(),
            opts: Vec::new(),
            phdr: Vec::new(),
        }
    }

    /// Create message based on parsed bytes
    pub fn from(frame_rx: &[u8]) -> Self {
        let mut message = Self::new();
        message.parse(frame_rx);
        message
    }

    /// Get the value of 'tnla' header field
    pub fn get_tnla(&self) -> Ip6Address {
        self._tnla
    }

    /// Set the value of 'tnla' header field
    pub fn set_tnla(mut self, _tnla: Ip6Address) -> Self {
        self._tnla = _tnla;
        self
    }

    /// Get the value of 'slla' nd option if present
    pub fn get_slla(&self) -> Option<MacAddress> {
        for opt in &self.opts {
            match opt {
                NdOpt::SLLA { _slla } => return Some(*_slla),
                _ => continue,
            }
        }
        None
    }

    /// Add the 'slla' nd option and set it's value
    pub fn set_slla(mut self, slla: MacAddress) -> Self {
        self.opts.push(NdOpt::SLLA { _slla: slla });
        self
    }

    /// Provide IPv6 pseudo header for checksum calculation
    pub fn phdr(&mut self, phdr: Vec<u8>) {
        self.phdr = phdr;
    }
}

impl protocol::Protocol for NeighborSolicitation {
    /// Get length of the message
    fn len(&self) -> usize {
        let mut opts_len = 0;
        for opt in &self.opts {
            opts_len += opt.len();
        }
        NEIGHBOR_SOLICITATION__HEADER_LEN + opts_len
    }

    /// Parse message
    fn parse(&mut self, frame_rx: &[u8]) {
        self._tnla = frame_rx[8..24].into();
        self.opts = parse_opts(&frame_rx[NEIGHBOR_SOLICITATION__HEADER_LEN..]);
    }

    /// Assemble message
    fn assemble(&self, frame_tx: &mut Vec<u8>) {
        let header_ptr = frame_tx.len();
        frame_tx.extend_from_slice(&[
            NEIGHBOR_SOLICITATION__TYPE,
            NEIGHBOR_SOLICITATION__CODE,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        frame_tx.extend_from_slice(&self._tnla.to_bytes());

        for opt in &self.opts {
            opt.assemble(frame_tx);
        }

        let mut cksum = InetCksum::new();
        cksum.add_bytes(&self.phdr);
        cksum.add_bytes(&frame_tx[header_ptr..]);
        NetworkEndian::write_u16(
            &mut frame_tx[header_ptr + 2..header_ptr + 4],
            cksum.checksum(),
        );
    }
}

impl fmt::Display for NeighborSolicitation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = format!("ICMPv6 ND Neighbor Solicitation - tnla {}", self._tnla,);
        for opt in &self.opts {
            text = format!("{}{}", text, opt);
        }
        write!(f, "{}", text)
    }
}

/// ICMPv6 ND NA message
#[derive(Default, Debug)]
pub struct NeighborAdvertisement {
    _flag_r: bool,
    _flag_s: bool,
    _flag_o: bool,
    _tnla: Ip6Address,
    opts: Vec<NdOpt>,
    phdr: Vec<u8>,
}

impl NeighborAdvertisement {
    /// Create empty message
    pub fn new() -> Self {
        Self {
            _flag_r: false,
            _flag_s: false,
            _flag_o: false,
            _tnla: Ip6Address::default(),
            opts: Vec::new(),
            phdr: Vec::new(),
        }
    }

    /// Create message based on parsed bytes
    pub fn from(frame_rx: &[u8]) -> Self {
        let mut message = Self::new();
        message.parse(frame_rx);
        message
    }

    /// Get the state of 'R' header flag
    pub fn get_flag_r(&self) -> bool {
        self._flag_r
    }

    /// Set the state of 'R' header flag
    pub fn set_flag_r(mut self, _flag_r: bool) -> Self {
        self._flag_r = _flag_r;
        self
    }

    /// Get the state of 'S' header flag
    pub fn get_flag_s(&self) -> bool {
        self._flag_s
    }

    /// Set the state of 'S' header flag
    pub fn set_flag_s(mut self, _flag_s: bool) -> Self {
        self._flag_s = _flag_s;
        self
    }

    /// Get the state of 'O' header flag
    pub fn get_flag_o(&self) -> bool {
        self._flag_o
    }

    /// Set the state of 'O' header flag
    pub fn set_flag_o(mut self, _flag_o: bool) -> Self {
        self._flag_o = _flag_o;
        self
    }

    /// Get the value of 'tnla' header field
    pub fn get_tnla(&self) -> Ip6Address {
        self._tnla
    }

    /// Set the value of 'tnla' header field
    pub fn set_tnla(mut self, _tnla: Ip6Address) -> Self {
        self._tnla = _tnla;
        self
    }

    /// Get the value of 'tlla' nd option if present
    pub fn get_tlla(&self) -> Option<MacAddress> {
        for opt in &self.opts {
            match opt {
                NdOpt::TLLA { _tlla } => return Some(*_tlla),
                _ => continue,
            }
        }
        None
    }

    /// Add the 'tlla' nd option and set it's value
    pub fn set_tlla(mut self, tlla: MacAddress) -> Self {
        self.opts.push(NdOpt::TLLA { _tlla: tlla });
        self
    }

    /// Provide IPv6 pseudo header for checksum calculation
    pub fn phdr(&mut self, phdr: Vec<u8>) {
        self.phdr = phdr;
    }
}

impl protocol::Protocol for NeighborAdvertisement {
    /// Get length of the message
    fn len(&self) -> usize {
        let mut opts_len = 0;
        for opt in &self.opts {
            opts_len += opt.len();
        }
        NEIGHBOR_ADVERTISEMENT__HEADER_LEN + opts_len
    }

    /// Parse message
    fn parse(&mut self, frame_rx: &[u8]) {
        self._flag_r = frame_rx[4] & 0b10000000 != 0;
        self._flag_s = frame_rx[4] & 0b01000000 != 0;
        self._flag_o = frame_rx[4] & 0b00100000 != 0;
        self._tnla = frame_rx[8..24].into();
        self.opts = parse_opts(&frame_rx[NEIGHBOR_ADVERTISEMENT__HEADER_LEN..]);
    }

    /// Assemble message
    fn assemble(&self, frame_tx: &mut Vec<u8>) {
        let header_ptr = frame_tx.len();
        let flag_byte: u8 =
            ((self._flag_r as u8) << 7) | ((self._flag_s as u8) << 6) | ((self._flag_o as u8) << 5);
        frame_tx.extend_from_slice(&[
            NEIGHBOR_ADVERTISEMENT__TYPE,
            NEIGHBOR_ADVERTISEMENT__CODE,
            0,
            0,
            flag_byte,
            0,
            0,
            0,
        ]);
        frame_tx.extend_from_slice(&self._tnla.to_bytes());

        for opt in &self.opts {
            opt.assemble(frame_tx);
        }

        let mut cksum = InetCksum::new();
        cksum.add_bytes(&self.phdr);
        cksum.add_bytes(&frame_tx[header_ptr..]);
        NetworkEndian::write_u16(
            &mut frame_tx[header_ptr + 2..header_ptr + 4],
            cksum.checksum(),
        );
    }
}

impl fmt::Display for NeighborAdvertisement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = format!(
            "ICMPv6 ND Neighbor Advertisement - flags {}{}{}, tnla {}",
            if self._flag_r { 'R' } else { '-' },
            if self._flag_s { 'S' } else { '-' },
            if self._flag_o { 'O' } else { '-' },
            self._tnla,
        );
        for opt in &self.opts {
            text = format!("{}{}", text, opt);
        }
        write!(f, "{}", text)
    }
}

//
// TODO: Not sure yet if using enum for ND options is right approach but it works for now
//

/// Parse ICMPv6 ND options and put them into the option vector
pub fn parse_opts(mut frame_rx: &[u8]) -> Vec<NdOpt> {
    let mut opts = Vec::<NdOpt>::new();
    while !frame_rx.is_empty() {
        let opt = NdOpt::parse(frame_rx);
        frame_rx = &frame_rx[opt.len()..];
        opts.push(opt);
    }
    opts
}

/// ICMPv6 ND options
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub enum NdOpt {
    SLLA {
        _slla: MacAddress,
    },
    TLLA {
        _tlla: MacAddress,
    },
    PI {
        _prefix: Ip6Address,
        _flag_l: bool,
        _flag_a: bool,
        _flag_r: bool,
        _valid_lifetime: u32,
        _prefer_lifetime: u32,
    },
    Unknown {
        _type: u8,
        _len: u8,
    },
}

impl NdOpt {
    /// Get option length
    pub fn len(&self) -> usize {
        match self {
            NdOpt::SLLA { .. } => OPT_SLLA__LEN,
            NdOpt::TLLA { .. } => OPT_TLLA__LEN,
            NdOpt::PI { .. } => OPT_PI__LEN,
            NdOpt::Unknown { _len, .. } => *_len as usize,
        }
    }

    /// Parse option
    fn parse(frame_rx: &[u8]) -> NdOpt {
        let opt_type = frame_rx[0];
        let opt_len = (frame_rx[1] << 3) as usize;
        match (opt_type, opt_len) {
            (OPT_SLLA__TYPE, OPT_SLLA__LEN) => NdOpt::SLLA {
                _slla: frame_rx[2..8].into(),
            },
            (OPT_TLLA__TYPE, OPT_TLLA__LEN) => NdOpt::TLLA {
                _tlla: frame_rx[2..8].into(),
            },
            (OPT_PI__TYPE, OPT_PI__LEN) => {
                let mut prefix: Ip6Address = frame_rx[16..32].into();
                prefix.set_prefix_len(frame_rx[2]);
                NdOpt::PI {
                    _prefix: prefix,
                    _flag_l: frame_rx[3] & 0b10000000 != 0,
                    _flag_a: frame_rx[3] & 0b01000000 != 0,
                    _flag_r: frame_rx[3] & 0b00100000 != 0,
                    _valid_lifetime: NetworkEndian::read_u32(&frame_rx[4..8]),
                    _prefer_lifetime: NetworkEndian::read_u32(&frame_rx[8..12]),
                }
            }
            _ => NdOpt::Unknown {
                _type: opt_type,
                _len: opt_len as u8,
            },
        }
    }

    /// Assemble option
    pub fn assemble(&self, frame_tx: &mut Vec<u8>) {
        match self {
            NdOpt::SLLA { _slla } => {
                frame_tx.extend_from_slice(&[OPT_SLLA__TYPE, self.len() as u8 >> 3]);
                frame_tx.extend_from_slice(&_slla.to_bytes());
            }
            NdOpt::TLLA { _tlla } => {
                frame_tx.extend_from_slice(&[OPT_TLLA__TYPE, self.len() as u8 >> 3]);
                frame_tx.extend_from_slice(&_tlla.to_bytes());
            }
            NdOpt::PI {
                _prefix,
                _flag_l,
                _flag_a,
                _flag_r,
                _valid_lifetime,
                _prefer_lifetime,
            } => {
                frame_tx.extend_from_slice(&[
                    OPT_PI__TYPE,
                    self.len() as u8 >> 3,
                    _prefix.get_prefix_len(),
                    ((*_flag_l as u8) << 7) | ((*_flag_a as u8) << 6) | ((*_flag_r as u8) << 5),
                    (*_valid_lifetime >> 24) as u8,
                    (*_valid_lifetime >> 16) as u8,
                    (*_valid_lifetime >> 8) as u8,
                    *_valid_lifetime as u8,
                    (*_prefer_lifetime >> 24) as u8,
                    (*_prefer_lifetime >> 16) as u8,
                    (*_prefer_lifetime >> 8) as u8,
                    *_prefer_lifetime as u8,
                    0,
                    0,
                    0,
                    0,
                ]);
                frame_tx.extend_from_slice(&_prefix.to_bytes());
            }
            NdOpt::Unknown { .. } => {}
        }
    }
}

impl fmt::Display for NdOpt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NdOpt::SLLA { _slla } => write!(f, ", SLLA-OPT [slla {_slla}]"),
            NdOpt::TLLA { _tlla } => write!(f, ", TLLA-OPT [tlla {_tlla}]"),
            NdOpt::PI {
                _prefix,
                _flag_l,
                _flag_a,
                _flag_r,
                _valid_lifetime,
                _prefer_lifetime,
            } => {
                write!(
                    f,
                    ", PI-OPT [prefix {}, flags {}{}{}, vlft {}, plft {}]",
                    _prefix,
                    if *_flag_l { 'L' } else { '-' },
                    if *_flag_a { 'A' } else { '-' },
                    if *_flag_r { 'R' } else { '-' },
                    _valid_lifetime,
                    _prefer_lifetime,
                )
            }
            NdOpt::Unknown { _type, _len } => {
                write!(f, ", UNK-OPT [_type {_type}, _len {_len}]")
            }
        }
    }
}
