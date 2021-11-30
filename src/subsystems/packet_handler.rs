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
use crate::lib::packet::{Icmp6Kind, Packet, ProtoKind};
use crate::lib::tap_io;
use crate::log_packet_handler as log;
use crate::protocols::ether;
use crate::protocols::icmp6;
use crate::protocols::icmp6_nd;
use crate::protocols::ip6;
use crate::subsystems::rx_ring;
use crate::subsystems::tx_ring;
use filedescriptor::FileDescriptor;
use std::collections::HashSet;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use std::time;

pub struct PacketDropError;

/// Packet handler structure
pub struct PacketHandler {
    nic_name: String,
    nic_mtu: usize,
    packet_sn: Arc<Mutex<usize>>,
    mpsc_from_rx_ring: mpsc::Receiver<Packet>,
    mpsc_to_tx_ring: mpsc::Sender<Packet>,
    mac_address_rx: HashSet<MacAddress>,
    mac_address_tx: MacAddress,
    ip6_address_rx: HashSet<Ip6Address>,
    ip6_address_tx: Ip6Address,
}

impl<'a> PacketHandler {
    /// Initialize packet handler for given interface
    pub fn new(nic_id: u8, nic_mtu: usize, mac_address: MacAddress) -> PacketHandler {
        // Initialize the TAP interface
        let (nic_name, nic_fd) = match tap_io::open(nic_id) {
            Ok((nic_name, nic_fd)) => (nic_name, nic_fd),
            Err(error) => {
                log!("<CRIT>TAP interface initialisation error: {}", error);
                panic!();
            }
        };

        // Initialize RX ring and the MPSC channel to comunicate with it
        let mpsc_from_rx_ring = rx_ring::RxRing::new(
            nic_name.clone(),
            FileDescriptor::dup(&nic_fd).unwrap(),
            nic_mtu,
        );

        // Initialize TX ring and the MPSC channel to comunicate with it
        let mpsc_to_tx_ring = tx_ring::TxRing::new(
            nic_name.clone(),
            FileDescriptor::dup(&nic_fd).unwrap(),
            nic_mtu,
        );

        // Initialize the L2 and L3 addressing
        let mut mac_address_rx = HashSet::new();
        let mut ip6_address_rx = HashSet::new();

        mac_address_rx.insert(mac_address);
        mac_address_rx.insert("ff:ff:ff:ff:ff:ff".into());

        mac_address_rx.insert("33:33:00:00:00:01".into());
        ip6_address_rx.insert("ff02::1".into());

        // Create PacketHandler structure, need to use mutex to make sure
        // the 'packet_sn' read and increment is an atomic operation
        #[allow(clippy::mutex_atomic)]
        PacketHandler {
            nic_name,
            nic_mtu,
            packet_sn: Arc::new(Mutex::new(0)),
            mpsc_from_rx_ring,
            mpsc_to_tx_ring,
            mac_address_rx,
            mac_address_tx: mac_address,
            ip6_address_rx,
            ip6_address_tx: Ip6Address::default(),
        }
    }

    /// Start the packet handdler thread
    pub fn run(mut self) {
        thread::spawn(move || {
            self.phrx_thread();
        });
    }

    /// Add IPv6 address to the interface configuration and start ICMPv6 ND DAD
    /// check for it in separate thread
    pub fn ip6_address(mut self, ip6_address: Ip6Address) -> PacketHandler {
        self.ip6_address_tx = ip6_address;
        self.ip6_address_rx.insert(ip6_address);
        self.ip6_address_rx
            .insert(ip6_address.solicited_node_multicast());
        self.mac_address_rx
            .insert(ip6_address.solicited_node_multicast().into());

        // Send out three ICMPv6 ND DAD messages over three seconds
        {
            let mpsc_to_tx_ring = self.mpsc_to_tx_ring.clone();
            let nic_name = self.nic_name.clone();
            let packet_sn = self.packet_sn.clone();

            thread::spawn(move || {
                log!("Thread spawned: 'icmp6_nd_dad - {}'", ip6_address);

                for _ in 0..3 {
                    log!("<B>Sending ICMPv6 ND DAD packet for {}</>", ip6_address);

                    let tracker = {
                        let mut packet_sn = packet_sn.lock().unwrap();
                        let tracker =
                            format!("<lr>[TX/{}/{:04X}]</>", nic_name.to_uppercase(), *packet_sn);
                        *packet_sn = (*packet_sn).wrapping_add(1);
                        tracker
                    };

                    let icmp6_tx = icmp6_nd::NeighborSolicitation::new().set_tnla(ip6_address);
                    log!("{} - {}", tracker, icmp6_tx);

                    let ip6_tx = ip6::Ip6::new()
                        .set_dst(ip6_address.solicited_node_multicast())
                        .set_hop(255)
                        .set_dlen(icmp6_tx.len() as u16)
                        .set_next(ip6::NEXT__ICMP6);
                    log!("{} - {}", tracker, ip6_tx);

                    let ether_tx = ether::Ether::new()
                        .set_src(self.mac_address_tx)
                        .set_dst(ip6_address.solicited_node_multicast().into())
                        .set_type(ether::TYPE__IP6);
                    log!("{} - {}", tracker, ether_tx);

                    let packet_tx = Packet::new(Vec::with_capacity(self.nic_mtu), tracker)
                        .add_protocol(ProtoKind::Ether(ether_tx))
                        .add_protocol(ProtoKind::Ip6(ip6_tx))
                        .add_protocol(ProtoKind::Icmp6(Icmp6Kind::NeighborSolicitation(icmp6_tx)));

                    if let Err(error) = mpsc_to_tx_ring.send(packet_tx) {
                        log!("<CRIT> MPSC channel error: '{}'</>", error);
                    }

                    thread::sleep(time::Duration::from_millis(1000));
                }
                log!("Thread ended: 'icmp6_nd_dad - {}'", ip6_address);
            });
        }

        self
    }

    /// Create tracker string to be used as packet identifier
    fn tracker(&mut self) -> String {
        let mut packet_sn = self.packet_sn.lock().unwrap();
        let tracker = format!(
            "<lr>[TX/{}/{:04X}]</>",
            self.nic_name.to_uppercase(),
            *packet_sn
        );
        *packet_sn = (*packet_sn).wrapping_add(1);
        tracker
    }

    /// Execute apropriate porotcol handler for each of the protocols in inbound packet
    fn phrx_thread(&mut self) {
        log!("Thread spawned: 'packet_handler - {}'", self.nic_name);
        log!("Listening on MAC addresses: {:?}", self.mac_address_rx);
        log!("Listening on IPv6 addresses: {:?}", self.ip6_address_rx);

        loop {
            let packet_rx = match self.mpsc_from_rx_ring.recv() {
                Ok(packet_rx) => packet_rx,
                Err(error) => {
                    log!("<CRIT> MPSC channel error: '{}'</>", error);
                    continue;
                }
            };

            for protocol in packet_rx.protocols() {
                match protocol {
                    ProtoKind::Ether(_) => {
                        if self.phrx_ether(&packet_rx).is_err() {
                            break;
                        }
                    }
                    ProtoKind::Ip6(_) => {
                        if self.phrx_ip6(&packet_rx).is_err() {
                            break;
                        }
                    }
                    ProtoKind::Icmp6(Icmp6Kind::NeighborSolicitation(_)) => {
                        if self.phrx_icmp6_neighbor_solicitation(&packet_rx).is_err() {
                            break;
                        }
                    }
                    ProtoKind::Icmp6(Icmp6Kind::NeighborAdvertisement(_)) => {
                        if self.phrx_icmp6_neighbor_advertisement(&packet_rx).is_err() {
                            break;
                        }
                    }
                    ProtoKind::Icmp6(Icmp6Kind::EchoRequest(_)) => {
                        if self.phrx_icmp6_echo_request(&packet_rx).is_err() {
                            break;
                        }
                    }
                    ProtoKind::Icmp6(Icmp6Kind::EchoReply(_)) => {
                        if self.phrx_icmp6_echo_request(&packet_rx).is_err() {
                            break;
                        }
                    }
                    ProtoKind::Icmp6(_) => {
                        log!("{} Unsupported ICMPv6 message", packet_rx.tracker);
                        break;
                    }
                    _ => {
                        log!("{} Unsupported protocol", packet_rx.tracker);
                        break;
                    }
                }
            }
        }
    }

    /// Process inbound Ethernet packet
    fn phrx_ether(&mut self, packet_rx: &'a Packet) -> Result<(), PacketDropError> {
        let ether_rx = packet_rx.ether().unwrap();

        if !self.mac_address_rx.contains(&ether_rx.get_dst()) {
            log!(
                "{} Unknown dst MAC address {}, dropping",
                packet_rx.tracker,
                ether_rx.get_dst(),
            );
            return Err(PacketDropError);
        }
        log!("{} - {}", packet_rx.tracker, ether_rx);

        Ok(())
    }

    /// Process inbound IPv6 packet
    fn phrx_ip6(&mut self, packet_rx: &'a Packet) -> Result<(), PacketDropError> {
        let ip6_rx = packet_rx.ip6().unwrap();

        if !self.ip6_address_rx.contains(&ip6_rx.get_dst()) {
            log!(
                "{} Unknown dst IPv6 address {}, dropping",
                packet_rx.tracker,
                ip6_rx.get_dst(),
            );
            return Err(PacketDropError);
        }
        log!("{} - {}", packet_rx.tracker, ip6_rx);

        Ok(())
    }

    /// Process inbound ICMPv6 Neighbor Solicitation message
    fn phrx_icmp6_neighbor_solicitation(
        &mut self,
        packet_rx: &'a Packet,
    ) -> Result<(), PacketDropError> {
        let ether_rx = packet_rx.ether().unwrap();
        let ip6_rx = packet_rx.ip6().unwrap();
        let icmp6_rx = packet_rx.icmp6_neighbor_solicitation().unwrap();
        log!("{} - {}", packet_rx.tracker, icmp6_rx);

        // Determine if packet is part of DAD request (src unspecified, no ssla option present)
        let ip6_nd_dad = matches!(
            (ip6_rx.get_src().is_unspecified(), icmp6_rx.get_slla()),
            (true, None)
        );

        log!(
            "{} - <B>Received ICMPv6 Neighbor Solicitation message from {}, sending reply</>",
            packet_rx.tracker,
            ip6_rx.get_src(),
        );

        // Send ICMPv6 ND Neighbor Advertisement
        {
            let tracker = self.tracker();

            let icmp6_tx = icmp6_nd::NeighborAdvertisement::new()
                .set_flag_s(!ip6_nd_dad)
                .set_flag_o(ip6_nd_dad)
                .set_tnla(icmp6_rx.get_tnla())
                .set_tlla(self.mac_address_tx);
            log!("{} - {}", tracker, icmp6_tx);

            let ip6_tx = ip6::Ip6::new()
                .set_src(icmp6_rx.get_tnla())
                .set_dst(if ip6_nd_dad {
                    Ip6Address::from("ff02::1") // use ff02::1 dst address when responding to DAD request
                } else {
                    ip6_rx.get_src() // use the rx dst address when responding to regular NS message
                })
                .set_hop(255)
                .set_dlen(icmp6_tx.len() as u16)
                .set_next(ip6::NEXT__ICMP6);
            log!("{} - {}", tracker, ip6_tx);

            let ether_tx = ether::Ether::new()
                .set_src(self.mac_address_tx)
                .set_dst(ether_rx.get_src())
                .set_type(ether::TYPE__IP6);
            log!("{} - {}", tracker, ether_tx);

            let packet_tx = Packet::new(Vec::with_capacity(self.nic_mtu), tracker)
                .add_protocol(ProtoKind::Ether(ether_tx))
                .add_protocol(ProtoKind::Ip6(ip6_tx))
                .add_protocol(ProtoKind::Icmp6(Icmp6Kind::NeighborAdvertisement(icmp6_tx)));

            if let Err(error) = self.mpsc_to_tx_ring.send(packet_tx) {
                log!("<CRIT> MPSC channel error: '{}'</>", error);
            }
        }

        Ok(())
    }

    /// Process inbound ICMPv6 Neighbor Advertisement message
    fn phrx_icmp6_neighbor_advertisement(
        &mut self,
        packet_rx: &'a Packet,
    ) -> Result<(), PacketDropError> {
        let _ether_rx = packet_rx.ether().unwrap();
        let ip6_rx = packet_rx.ip6().unwrap();
        let icmp6_rx = packet_rx.icmp6_neighbor_advertisement().unwrap();
        log!("{} - {}", packet_rx.tracker, icmp6_rx);
        log!(
            "{} - <B>Received ICMPv6 Neighbor Advertisement message from {}, not giving a single fuck about it</>",
            packet_rx.tracker,
            ip6_rx.get_src(),
        );

        Ok(())
    }

    /// Process inbound ICMPv6 Echo Request message
    fn phrx_icmp6_echo_request(&mut self, packet_rx: &'a Packet) -> Result<(), PacketDropError> {
        let ether_rx = packet_rx.ether().unwrap();
        let ip6_rx = packet_rx.ip6().unwrap();
        let icmp6_rx = packet_rx.icmp6_echo_request().unwrap();
        log!("{} - {}", packet_rx.tracker, icmp6_rx);
        log!(
            "{} - <B>Received ICMPv6 Echo Request message from {}, sending reply</>",
            packet_rx.tracker,
            ip6_rx.get_src(),
        );

        // Send ICMPv6 Echo Reply
        {
            let tracker = self.tracker();

            let icmp6_tx = icmp6::EchoReply::new()
                .set_id(icmp6_rx.get_id())
                .set_seq(icmp6_rx.get_seq())
                .set_data(icmp6_rx.get_data());
            log!("{} - {}", tracker, icmp6_tx);

            let ip6_tx = ip6::Ip6::new()
                .set_src(self.ip6_address_tx)
                .set_dst(ip6_rx.get_src())
                .set_dlen(icmp6_tx.len() as u16)
                .set_next(ip6::NEXT__ICMP6);
            log!("{} - {}", tracker, ip6_tx);

            let ether_tx = ether::Ether::new()
                .set_src(self.mac_address_tx)
                .set_dst(ether_rx.get_src())
                .set_type(ether::TYPE__IP6);
            log!("{} - {}", tracker, ether_tx);

            let packet_tx = Packet::new(Vec::with_capacity(self.nic_mtu), tracker)
                .add_protocol(ProtoKind::Ether(ether_tx))
                .add_protocol(ProtoKind::Ip6(ip6_tx))
                .add_protocol(ProtoKind::Icmp6(Icmp6Kind::EchoReply(icmp6_tx)));

            if let Err(error) = self.mpsc_to_tx_ring.send(packet_tx) {
                log!("<CRIT> MPSC channel error: '{}'</>", error);
            }
        }

        Ok(())
    }

    /// Process inbound ICMPv6 Echo Reply message
    fn phrx_icmp6_echo_reply(&mut self, packet_rx: &'a Packet) -> Result<(), PacketDropError> {
        let _ether_rx = packet_rx.ether().unwrap();
        let ip6_rx = packet_rx.ip6().unwrap();
        let icmp6_rx = packet_rx.icmp6_echo_reply().unwrap();
        log!("{} - {}", packet_rx.tracker, icmp6_rx);
        log!(
            "{} - <B>Received ICMPv6 Echo Reply message from {}, not giving a single fuck about it</>",
            packet_rx.tracker,
            ip6_rx.get_src(),
        );

        Ok(())
    }
}
