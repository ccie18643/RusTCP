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

use crate::protocols::ether;
use crate::protocols::icmp6;
use crate::protocols::icmp6_nd;
use crate::protocols::ip6;
use crate::protocols::protocol::Protocol;

/// Enum containing all protocols supported by stack
pub enum ProtoKind {
    Ether(ether::Ether),
    Ip6(ip6::Ip6),
    Icmp6(Icmp6Kind),
    Unknown,
}

/// Enum containing the various types of ICMPv6 messages
pub enum Icmp6Kind {
    EchoRequest(icmp6::EchoRequest),
    EchoReply(icmp6::EchoReply),
    RouterSolicitation(icmp6_nd::RouterSolicitation),
    RouterAdvertisement(icmp6_nd::RouterAdvertisement),
    NeighborSolicitation(icmp6_nd::NeighborSolicitation),
    NeighborAdvertisement(icmp6_nd::NeighborAdvertisement),
    Unknown,
}

/// Struct used to parse and assemble packets
#[derive(Default)]
pub struct Packet {
    pub frame: Vec<u8>,
    pub tracker: String,
    protocols: Vec<ProtoKind>,
    data_offset: usize,
    phdr: Vec<u8>,
}

impl Packet {
    /// Constructor
    pub fn new(frame: Vec<u8>, tracker: String) -> Self {
        Self {
            frame,
            tracker,
            protocols: Vec::new(),
            data_offset: 0,
            phdr: Vec::default(),
        }
    }

    /// Parse packet
    pub fn parse(&mut self) {
        self.parse_ether();
    }

    /// Assemble packet
    pub fn assemble(&mut self) {
        for protocol in self.protocols.iter() {
            match protocol {
                ProtoKind::Ether(header) => {
                    header.assemble(&mut self.frame);
                }
                ProtoKind::Ip6(header) => {
                    header.assemble(&mut self.frame);
                }
                ProtoKind::Icmp6(Icmp6Kind::EchoRequest(message)) => {
                    message.assemble(&mut self.frame);
                }
                ProtoKind::Icmp6(Icmp6Kind::EchoReply(message)) => {
                    message.assemble(&mut self.frame);
                }
                ProtoKind::Icmp6(Icmp6Kind::RouterSolicitation(message)) => {
                    message.assemble(&mut self.frame);
                }
                ProtoKind::Icmp6(Icmp6Kind::RouterAdvertisement(message)) => {
                    message.assemble(&mut self.frame);
                }
                ProtoKind::Icmp6(Icmp6Kind::NeighborSolicitation(message)) => {
                    message.assemble(&mut self.frame);
                }
                ProtoKind::Icmp6(Icmp6Kind::NeighborAdvertisement(message)) => {
                    message.assemble(&mut self.frame);
                }
                _ => {}
            }
        }
    }

    /// Add protocol header to the protocol stack
    pub fn add_protocol(mut self, mut protocol: ProtoKind) -> Self {
        match protocol {
            ProtoKind::Ip6(ref header) => {
                self.phdr = header.phdr();
            }
            ProtoKind::Icmp6(Icmp6Kind::EchoRequest(ref mut message)) => {
                message.phdr(self.phdr.clone());
            }
            ProtoKind::Icmp6(Icmp6Kind::EchoReply(ref mut message)) => {
                message.phdr(self.phdr.clone());
            }
            ProtoKind::Icmp6(Icmp6Kind::RouterSolicitation(ref mut message)) => {
                message.phdr(self.phdr.clone());
            }
            ProtoKind::Icmp6(Icmp6Kind::RouterAdvertisement(ref mut message)) => {
                message.phdr(self.phdr.clone());
            }
            ProtoKind::Icmp6(Icmp6Kind::NeighborSolicitation(ref mut message)) => {
                message.phdr(self.phdr.clone());
            }
            ProtoKind::Icmp6(Icmp6Kind::NeighborAdvertisement(ref mut message)) => {
                message.phdr(self.phdr.clone());
            }
            _ => {}
        }
        self.protocols.push(protocol);
        self
    }

    /// Get the iterator for 'protocols' array
    pub fn protocols(&self) -> std::slice::Iter<ProtoKind> {
        self.protocols.iter()
    }

    /// Get the Ethernet header if present in the 'protocols' array
    pub fn ether(&self) -> Option<&ether::Ether> {
        for protocol in self.protocols.iter() {
            if let ProtoKind::Ether(header) = protocol {
                return Some(header);
            }
        }
        None
    }

    /// Get the IPv6 header if present in the 'protocols' array
    pub fn ip6(&self) -> Option<&ip6::Ip6> {
        for protocol in self.protocols.iter() {
            if let ProtoKind::Ip6(header) = protocol {
                return Some(header);
            }
        }
        None
    }

    /// Get the ICMPv6 Echo Request message if present in the 'protocols' array
    pub fn icmp6_echo_request(&self) -> Option<&icmp6::EchoRequest> {
        for protocol in self.protocols.iter() {
            if let ProtoKind::Icmp6(Icmp6Kind::EchoRequest(message)) = protocol {
                return Some(message);
            }
        }
        None
    }

    /// Get the ICMPv6 Echo Reply message if present in the 'protocols' array
    pub fn icmp6_echo_reply(&self) -> Option<&icmp6::EchoReply> {
        for protocol in self.protocols.iter() {
            if let ProtoKind::Icmp6(Icmp6Kind::EchoReply(message)) = protocol {
                return Some(message);
            }
        }
        None
    }

    /// Get the ICMPv6 Router Solicitation message if present in the 'protocols' array
    pub fn icmp6_router_solicitation(&self) -> Option<&icmp6_nd::RouterSolicitation> {
        for protocol in self.protocols.iter() {
            if let ProtoKind::Icmp6(Icmp6Kind::RouterSolicitation(message)) = protocol {
                return Some(message);
            }
        }
        None
    }

    /// Get the ICMPv6 Router Advertisement message if present in the 'protocols' array
    pub fn icmp6_router_advertisement(&self) -> Option<&icmp6_nd::RouterAdvertisement> {
        for protocol in self.protocols.iter() {
            if let ProtoKind::Icmp6(Icmp6Kind::RouterAdvertisement(message)) = protocol {
                return Some(message);
            }
        }
        None
    }

    /// Get the ICMPv6 Neighbor Solicitation message if present in the 'protocols' array
    pub fn icmp6_neighbor_solicitation(&self) -> Option<&icmp6_nd::NeighborSolicitation> {
        for protocol in self.protocols.iter() {
            if let ProtoKind::Icmp6(Icmp6Kind::NeighborSolicitation(message)) = protocol {
                return Some(message);
            }
        }
        None
    }

    /// Get the ICMPv6 Neighbor Advertisement message if present in the 'protocols' array
    pub fn icmp6_neighbor_advertisement(&self) -> Option<&icmp6_nd::NeighborAdvertisement> {
        for protocol in self.protocols.iter() {
            if let ProtoKind::Icmp6(Icmp6Kind::NeighborAdvertisement(message)) = protocol {
                return Some(message);
            }
        }
        None
    }

    /// Parse Ethernet header
    fn parse_ether(&mut self) {
        let ether = ether::Ether::from(&self.frame[self.data_offset..]);
        let ether_type = ether.get_type();
        self.data_offset += ether.len();
        self.protocols.push(ProtoKind::Ether(ether));
        match ether_type {
            ether::TYPE__IP6 => self.parse_ip6(),
            _ => self.protocols.push(ProtoKind::Unknown),
        }
    }

    /// Parse IPv6 header
    fn parse_ip6(&mut self) {
        let ip6 = ip6::Ip6::from(&self.frame[self.data_offset..]);
        let ip6_next = ip6.get_next();
        self.data_offset += ip6.len();
        self.protocols.push(ProtoKind::Ip6(ip6));
        match ip6_next {
            ip6::NEXT__ICMP6 => self.parse_icmp6(),
            _ => self.protocols.push(ProtoKind::Unknown),
        }
    }

    /// Parse ICMPv6 message
    fn parse_icmp6(&mut self) {
        match self.frame[self.data_offset] {
            icmp6::ECHO_REQUEST__TYPE => {
                let icmp6 = icmp6::EchoRequest::from(&self.frame[self.data_offset..]);
                self.data_offset += icmp6.len();
                self.protocols
                    .push(ProtoKind::Icmp6(Icmp6Kind::EchoRequest(icmp6)));
            }
            icmp6::ECHO_REPLY__TYPE => {
                let icmp6 = icmp6::EchoReply::from(&self.frame[self.data_offset..]);
                self.data_offset += icmp6.len();
                self.protocols
                    .push(ProtoKind::Icmp6(Icmp6Kind::EchoReply(icmp6)));
            }
            icmp6_nd::ROUTER_SOLICITATION__TYPE => {
                let icmp6 = icmp6_nd::RouterSolicitation::from(&self.frame[self.data_offset..]);
                self.data_offset += icmp6.len();
                self.protocols
                    .push(ProtoKind::Icmp6(Icmp6Kind::RouterSolicitation(icmp6)));
            }
            icmp6_nd::ROUTER_ADVERTISEMENT__TYPE => {
                let icmp6 = icmp6_nd::RouterAdvertisement::from(&self.frame[self.data_offset..]);
                self.data_offset += icmp6.len();
                self.protocols
                    .push(ProtoKind::Icmp6(Icmp6Kind::RouterAdvertisement(icmp6)));
            }
            icmp6_nd::NEIGHBOR_SOLICITATION__TYPE => {
                let icmp6 = icmp6_nd::NeighborSolicitation::from(&self.frame[self.data_offset..]);
                self.data_offset += icmp6.len();
                self.protocols
                    .push(ProtoKind::Icmp6(Icmp6Kind::NeighborSolicitation(icmp6)));
            }
            icmp6_nd::NEIGHBOR_ADVERTISEMENT__TYPE => {
                let icmp6 = icmp6_nd::NeighborAdvertisement::from(&self.frame[self.data_offset..]);
                self.data_offset += icmp6.len();
                self.protocols
                    .push(ProtoKind::Icmp6(Icmp6Kind::NeighborAdvertisement(icmp6)));
            }
            _ => self.protocols.push(ProtoKind::Icmp6(Icmp6Kind::Unknown)),
        }
    }
}
