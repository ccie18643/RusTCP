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
use crate::lib::mac_address::MacAddress;
use byteorder::{ByteOrder, NetworkEndian};
use internet_checksum::Checksum as InetCksum;
use std::fmt;

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

/// ICMPv6 ND NS message
#[derive(Default, Debug)]
pub struct NeighborSolicitation {
    _tnla: Ip6Address,
    opts: Vec<NdOpt>,
    phdr: Vec<u8>,
}

impl NeighborSolicitation {
    /// Create empty message
    pub fn new() -> NeighborSolicitation {
        NeighborSolicitation {
            _tnla: Ip6Address::default(),
            opts: vec![],
            phdr: Vec::default(),
        }
    }

    /// Get the value of 'tnla' header field
    pub fn get_tnla(&self) -> Ip6Address {
        self._tnla
    }

    /// Set the value of 'tnla' header field
    pub fn set_tnla(mut self, _tnla: Ip6Address) -> NeighborSolicitation {
        self._tnla = _tnla;
        self
    }

    /// Get the value of 'slla' nd option if present
    pub fn get_slla(&self) -> Option<&MacAddress> {
        for opt in &self.opts {
            match opt {
                NdOpt::SLLA(slla) => return Some(slla),
                _ => continue,
            }
        }
        None
    }

    /// Add the 'slla' nd option and set it's value
    pub fn set_slla(mut self, _slla: MacAddress) -> NeighborSolicitation {
        self.opts.push(NdOpt::SLLA(_slla));
        self
    }

    /// Provide IPv6 pseudo header for checksum calculation
    pub fn phdr(&mut self, phdr: Vec<u8>) {
        self.phdr = phdr;
    }

    /// Get length of the message
    pub fn len(&self) -> usize {
        let mut opts_len = 0;
        for opt in &self.opts {
            opts_len += opt.len();
        }
        NEIGHBOR_SOLICITATION__HEADER_LEN + opts_len
    }

    /// Parse message
    pub fn parse(mut self, frame_rx: &[u8]) -> Self {
        self._tnla = frame_rx[8..24].into();
        self.opts = parse_opts(&frame_rx[NEIGHBOR_SOLICITATION__HEADER_LEN..]);
        self
    }

    /// Assemble message
    pub fn assemble(&self, frame_tx: &mut Vec<u8>) {
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
    pub fn new() -> NeighborAdvertisement {
        Self {
            _flag_r: false,
            _flag_s: false,
            _flag_o: false,
            _tnla: Ip6Address::default(),
            opts: vec![],
            phdr: Vec::default(),
        }
    }

    /// Get the state of 'R' header flag
    pub fn get_flag_r(&self) -> bool {
        self._flag_r
    }

    /// Set the state of 'R' header flag
    pub fn set_flag_r(mut self, _flag_r: bool) -> NeighborAdvertisement {
        self._flag_r = _flag_r;
        self
    }

    /// Get the state of 'S' header flag
    pub fn get_flag_s(&self) -> bool {
        self._flag_s
    }

    /// Set the state of 'S' header flag
    pub fn set_flag_s(mut self, _flag_s: bool) -> NeighborAdvertisement {
        self._flag_s = _flag_s;
        self
    }

    /// Get the state of 'O' header flag
    pub fn get_flag_o(&self) -> bool {
        self._flag_o
    }

    /// Set the state of 'O' header flag
    pub fn set_flag_o(mut self, _flag_o: bool) -> NeighborAdvertisement {
        self._flag_o = _flag_o;
        self
    }

    /// Get the value of 'tnla' header field
    pub fn get_tnla(&self) -> Ip6Address {
        self._tnla
    }

    /// Set the value of 'tnla' header field
    pub fn set_tnla(mut self, _tnla: Ip6Address) -> NeighborAdvertisement {
        self._tnla = _tnla;
        self
    }

    /// Get the value of 'tlla' nd option if present
    pub fn get_tlla(&self) -> Option<&MacAddress> {
        for opt in &self.opts {
            match opt {
                NdOpt::TLLA(tlla) => return Some(tlla),
                _ => continue,
            }
        }
        None
    }

    /// Add the 'tlla' nd option and set it's value
    pub fn set_tlla(mut self, _tlla: MacAddress) -> NeighborAdvertisement {
        self.opts.push(NdOpt::TLLA(_tlla));
        self
    }

    /// Provide IPv6 pseudo header for checksum calculation
    pub fn phdr(&mut self, phdr: Vec<u8>) {
        self.phdr = phdr;
    }

    /// Get length of the message
    pub fn len(&self) -> usize {
        let mut opts_len = 0;
        for opt in &self.opts {
            opts_len += opt.len();
        }
        NEIGHBOR_ADVERTISEMENT__HEADER_LEN + opts_len
    }

    /// Parse message
    pub fn parse(mut self, frame_rx: &[u8]) -> Self {
        self._flag_r = frame_rx[4] & 0b10000000 != 0;
        self._flag_s = frame_rx[4] & 0b01000000 != 0;
        self._flag_o = frame_rx[4] & 0b00100000 != 0;
        self._tnla = frame_rx[8..24].into();
        self.opts = parse_opts(&frame_rx[NEIGHBOR_ADVERTISEMENT__HEADER_LEN..]);
        self
    }

    /// Assemble message
    pub fn assemble(&self, frame_tx: &mut Vec<u8>) {
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
pub fn parse_opts(bytes: &[u8]) -> Vec<NdOpt> {
    let mut opts = Vec::<NdOpt>::new();
    let mut bytes_offset = 0;
    while bytes_offset + 1 < bytes.len() {
        let opt_type = bytes[bytes_offset];
        let opt_len = (bytes[bytes_offset + 1] << 3) as usize;
        match (opt_type, opt_len) {
            (OPT_SLLA__TYPE, OPT_SLLA__LEN) => opts.push(NdOpt::SLLA(bytes[2..8].into())),
            (OPT_TLLA__TYPE, OPT_TLLA__LEN) => opts.push(NdOpt::TLLA(bytes[2..8].into())),
            _ => opts.push(NdOpt::Unknown(opt_type, opt_len as u8)),
        }
        bytes_offset += opt_len;
    }
    opts
}

/// ICMPv6 ND options
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub enum NdOpt {
    SLLA(MacAddress),
    TLLA(MacAddress),
    Unknown(u8, u8),
}

impl NdOpt {
    /// Get option length
    pub fn len(&self) -> usize {
        match self {
            NdOpt::SLLA(_) => OPT_SLLA__LEN,
            NdOpt::TLLA(_) => OPT_TLLA__LEN,
            NdOpt::Unknown(_, len) => *len as usize,
        }
    }

    /// Assemble option
    pub fn assemble(&self, frame_tx: &mut Vec<u8>) {
        match self {
            NdOpt::SLLA(slla) => {
                frame_tx.extend_from_slice(&[OPT_SLLA__TYPE, self.len() as u8 >> 3]);
                frame_tx.extend_from_slice(&slla.to_bytes());
            }
            NdOpt::TLLA(tlla) => {
                frame_tx.extend_from_slice(&[OPT_TLLA__TYPE, self.len() as u8 >> 3]);
                frame_tx.extend_from_slice(&tlla.to_bytes());
            }
            NdOpt::Unknown(_, _) => {}
        }
    }
}

impl fmt::Display for NdOpt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NdOpt::SLLA(slla) => write!(f, ", slla {}", slla),
            NdOpt::TLLA(tlla) => write!(f, ", tlla {}", tlla),
            NdOpt::Unknown(r#type, len) => {
                write!(f, ", unk-{}-{}", r#type, len)
            }
        }
    }
}
