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

use crate::break_on_err;
use crate::config::{IP6_DAD_DELAY, IP6_DAD_RETRIES};
use crate::lib::ip6_address::Ip6Address;
use crate::lib::mac_address::MacAddress;
use crate::lib::packet::{Icmp6Kind, Packet, ProtoKind};
use crate::lib::tap_io;
use crate::lib::util;
use crate::log_packet_handler as log;
use crate::protocols::ether;
use crate::protocols::icmp6;
use crate::protocols::icmp6_nd;
use crate::protocols::ip6;
use crate::protocols::protocol::Protocol;
use crate::subsystems::nd_cache;
use crate::subsystems::rx_ring;
use crate::subsystems::tx_ring;
use filedescriptor::FileDescriptor;
use itertools;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time;

pub struct Ip6DadError;
pub struct PacketDropError;

/// Enum describing the IPv6 DAD states
#[derive(PartialEq, Debug)]
enum Ip6NdDadState {
    Tentative,
    Failure,
    Success,
}

/// Packet handler structure
#[derive(Clone)]
pub struct PacketHandler {
    nic_name: String,
    nic_mtu: usize,
    packet_sn: Arc<Mutex<usize>>,
    mpsc_from_rx_ring: Arc<Mutex<mpsc::Receiver<Packet>>>,
    mpsc_to_tx_ring: mpsc::Sender<Packet>,
    mac_address_rx: Arc<Mutex<HashSet<MacAddress>>>,
    mac_address_tx: MacAddress,
    ip6_address_rx: Arc<Mutex<HashSet<Ip6Address>>>,
    ip6_address_tx: Arc<Mutex<HashSet<Ip6Address>>>,
    nd_cache: nd_cache::NdCache,
    ip6_nd_dad_status: Arc<Mutex<HashMap<Ip6Address, Ip6NdDadState>>>,
    ip6_nd_ra_prefixes: Arc<Mutex<HashMap<Ip6Address, icmp6_nd::Ip6NdRaPrefixMetadata>>>,
}

impl<'a> PacketHandler {
    /// Initialize packet handler for given interface
    pub fn new(nic_id: u8, nic_mtu: usize, mac_address: MacAddress) -> Self {
        // Initialize packet serial number
        #[allow(clippy::mutex_atomic)]
        let packet_sn = Arc::new(Mutex::new(0));

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
            nic_mtu,
            FileDescriptor::dup(&nic_fd).unwrap(),
        );

        // Initialize TX ring and the MPSC channel to comunicate with it
        let mpsc_to_tx_ring = tx_ring::TxRing::new(
            nic_name.clone(),
            nic_mtu,
            FileDescriptor::dup(&nic_fd).unwrap(),
        );

        // Initialize basic L2 and L3 addressing
        let mac_address_rx = Arc::new(Mutex::new(HashSet::new()));
        (*mac_address_rx.lock().unwrap()).insert(mac_address);
        (*mac_address_rx.lock().unwrap()).insert("ff:ff:ff:ff:ff:ff".into());
        let mac_address_tx = mac_address;

        let ip6_address_rx = Arc::new(Mutex::new(HashSet::new()));
        (*mac_address_rx.lock().unwrap()).insert("33:33:00:00:00:01".into());
        (*ip6_address_rx.lock().unwrap()).insert("ff02::1".into());
        let ip6_address_tx = Arc::new(Mutex::new(HashSet::new()));

        // Initialize ND cache
        let nd_cache = nd_cache::NdCache::new(
            nic_name.clone(),
            nic_mtu,
            packet_sn.clone(),
            mpsc_to_tx_ring.clone(),
            mac_address_tx,
            ip6_address_tx.clone(),
        );

        #[allow(clippy::mutex_atomic)]
        let packet_handler = Self {
            nic_name,
            nic_mtu,
            packet_sn,
            mpsc_from_rx_ring: Arc::new(Mutex::new(mpsc_from_rx_ring)),
            mpsc_to_tx_ring,
            mac_address_rx,
            mac_address_tx,
            ip6_address_rx,
            ip6_address_tx,
            nd_cache,
            ip6_nd_dad_status: Arc::new(Mutex::new(HashMap::new())),
            ip6_nd_ra_prefixes: Arc::new(Mutex::new(HashMap::new())),
        };

        let mut packet_handler_clone = packet_handler.clone();

        thread::spawn(move || {
            packet_handler_clone.phrx_thread();
        });

        packet_handler
    }

    /// Wait till the IPv6 DAD process finishes and report the L2/L3 addressing that has been assigned
    pub fn log_addresses(self) -> Self {
        log!(
            "<B>INFO: {} mac_address_rx: {}",
            self.nic_name,
            itertools::join(&*self.mac_address_rx.lock().unwrap(), ", ")
        );
        log!(
            "<B>INFO: {} mac_address_tx: {}",
            self.nic_name,
            self.mac_address_tx
        );
        log!(
            "<B>INFO: {} ip6_address_rx: {}",
            self.nic_name,
            itertools::join(&*self.ip6_address_rx.lock().unwrap(), ", ")
        );
        log!(
            "<B>INFO: {} ip6_address_tx: {}",
            self.nic_name,
            itertools::join(&*self.ip6_address_tx.lock().unwrap(), ", ")
        );
        self
    }

    /// Assign IPv6 address to the interface configuration and start ICMPv6 ND DAD process
    pub fn set_ip6_address(&self, ip6_address_tentative: Ip6Address) -> Result<(), Ip6DadError> {
        let ip6_address_tentative_snm = ip6_address_tentative.solicited_node_multicast();
        let ip6_address_tentative_mac = MacAddress::from(ip6_address_tentative_snm);

        (*self.ip6_address_rx.lock().unwrap()).insert(ip6_address_tentative_snm);
        (*self.mac_address_rx.lock().unwrap()).insert(ip6_address_tentative_mac);
        (*self.ip6_nd_dad_status.lock().unwrap())
            .insert(ip6_address_tentative, Ip6NdDadState::Tentative);

        let mut ip6_dad_success = true;

        for _ in 0..IP6_DAD_RETRIES {
            log!(
                "<B>Sending ICMPv6 ND DAD packet for {}</>",
                ip6_address_tentative
            );

            let tracker = util::tracker("TX", &self.nic_name, &mut self.packet_sn.lock().unwrap());

            let icmp6_tx = icmp6_nd::NeighborSolicitation::new().set_tnla(ip6_address_tentative);
            log!("{} - {}", tracker, icmp6_tx);

            let ip6_tx = ip6::Ip6::new()
                .set_dst(ip6_address_tentative_snm)
                .set_hop(255)
                .set_dlen(icmp6_tx.len() as u16)
                .set_next(ip6::NEXT__ICMP6);
            log!("{} - {}", tracker, ip6_tx);

            let ether_tx = ether::Ether::new()
                .set_src(self.mac_address_tx)
                .set_dst(ip6_address_tentative_mac)
                .set_type(ether::TYPE__IP6);
            log!("{} - {}", tracker, ether_tx);

            let packet_tx = Packet::new(Vec::with_capacity(self.nic_mtu), tracker)
                .add_protocol(ProtoKind::Ether(ether_tx))
                .add_protocol(ProtoKind::Ip6(ip6_tx))
                .add_protocol(ProtoKind::Icmp6(Icmp6Kind::NeighborSolicitation(icmp6_tx)));

            if let Err(error) = self.mpsc_to_tx_ring.send(packet_tx) {
                log!("<CRIT> MPSC channel error: '{}'</>", error);
                panic!();
            }

            thread::sleep(time::Duration::from_millis(IP6_DAD_DELAY));

            if (*self.ip6_nd_dad_status.lock().unwrap())[&ip6_address_tentative]
                == Ip6NdDadState::Failure
            {
                ip6_dad_success = false;
                break;
            }
        }

        if ip6_dad_success {
            (*self.ip6_nd_dad_status.lock().unwrap())
                .insert(ip6_address_tentative, Ip6NdDadState::Success);
            (*self.ip6_address_rx.lock().unwrap()).insert(ip6_address_tentative.host());
            (*self.ip6_address_tx.lock().unwrap()).insert(ip6_address_tentative);
            log!("IPv6 DAD process succeeded for {}'", ip6_address_tentative);
            Ok(())
        } else {
            // Before removing solicited node multicast / multicast mac from RX check if
            // any other IPv6 address is using it
            let mut solicited_node_multicast_in_use = false;

            for (address, state) in (*self.ip6_nd_dad_status.lock().unwrap()).iter() {
                if *state != Ip6NdDadState::Failure
                    && address.solicited_node_multicast() == ip6_address_tentative_snm
                {
                    solicited_node_multicast_in_use = true;
                    break;
                }
            }

            if !solicited_node_multicast_in_use {
                (*self.ip6_address_rx.lock().unwrap()).remove(&ip6_address_tentative_snm);
                (*self.mac_address_rx.lock().unwrap()).remove(&ip6_address_tentative_mac);
            }

            log!("IPv6 DAD process failed for {}'", ip6_address_tentative);
            Err(Ip6DadError)
        }
    }

    /// Assign EUI64 based IPv6 Link Local address to the interface configuration
    pub fn set_ip6_lla_eui64(self) -> Self {
        let ip6_address = Ip6Address::eui64(Ip6Address::new("fe80::/64"), self.mac_address_tx);
        log!(
            "<B><y>Started IPv6 DAD process for LLA address - {} on {}</>",
            ip6_address,
            self.nic_name
        );
        if let Err(Ip6DadError) = self.set_ip6_address(ip6_address) {
            log!(
                "<CRIT>PANIC: Unable to assign the LLA address due to DAD error - {} on {}</>",
                ip6_address,
                self.nic_name
            );
            panic!();
        }
        log!(
            "<B><y>Completed IPv6 DAD process for LLA address - {} on {}</>",
            ip6_address,
            self.nic_name
        );

        // Send Router Solicitation message to initiate the process of discovering available network prefixes
        self.send_router_solicitation(ip6_address);

        self
    }

    /// Assign ND RA & EUI64 based IPv6 Global Unicast address to the interface configuration
    pub fn set_ip6_gua_eui64(self) -> Self {
        // Make sure we have the LLA address already assigned, panic if thats not the case
        let mut ip6_lla = None;
        for ip6_address in self.ip6_address_tx.lock().unwrap().iter() {
            if ip6_address.is_link_local() {
                ip6_lla = Some(*ip6_address);
            }
        }
        let ip6_lla = ip6_lla.unwrap_or_else(|| {
            log!(
                "<CRIT>PANIC: No LLA address found on {} interface while trying to assign GUA</>",
                self.nic_name
            );
            panic!();
        });

        // Wait for network prefix to be available, skip if none available in reasonable time
        let mut repeat_count = 6;
        while self.ip6_nd_ra_prefixes.lock().unwrap().is_empty() {
            if repeat_count == 0 {
                return self;
            }
            if repeat_count & 1 == 1 {
                self.send_router_solicitation(ip6_lla);
            }
            repeat_count -= 1;
            thread::sleep(time::Duration::from_millis(500));
        }

        for (prefix, _) in self.ip6_nd_ra_prefixes.lock().unwrap().iter() {
            let ip6_address = Ip6Address::eui64(*prefix, self.mac_address_tx);
            log!(
                "<B><y>Started IPv6 DAD process for GUA address - {} on {}</>",
                ip6_address,
                self.nic_name
            );
            if let Err(Ip6DadError) = self.set_ip6_address(ip6_address) {
                log!(
                    "<CRIT>PANIC: Unable to assign the GUA address due to DAD error - {} on {}</>",
                    ip6_address,
                    self.nic_name
                );
                panic!();
            }
            log!(
                "<B><y>Completed IPv6 DAD process for GUA address - {} on {}</>",
                ip6_address,
                self.nic_name
            );
        }

        self
    }

    /// Execute apropriate porotcol handler for each of the protocols in inbound packet
    fn phrx_thread(&mut self) {
        log!(
            "<lv>Thread spawned: 'packet_handler - {}'</>",
            self.nic_name
        );
        loop {
            let packet_rx = match self.mpsc_from_rx_ring.lock().unwrap().recv() {
                Ok(packet_rx) => packet_rx,
                Err(error) => {
                    log!("<CRIT> MPSC channel error: '{}'</>", error);
                    panic!();
                }
            };

            for protocol in packet_rx.protocols() {
                match protocol {
                    ProtoKind::Ether(_) => {
                        break_on_err!(self.phrx_ether(&packet_rx))
                    }
                    ProtoKind::Ip6(_) => {
                        break_on_err!(self.phrx_ip6(&packet_rx))
                    }
                    ProtoKind::Icmp6(Icmp6Kind::EchoRequest(_)) => {
                        break_on_err!(self.phrx_icmp6_echo_request(&packet_rx))
                    }
                    ProtoKind::Icmp6(Icmp6Kind::EchoReply(_)) => {
                        break_on_err!(self.phrx_icmp6_echo_request(&packet_rx))
                    }
                    ProtoKind::Icmp6(Icmp6Kind::RouterSolicitation(_)) => {
                        break_on_err!(self.phrx_icmp6_router_solicitation(&packet_rx))
                    }
                    ProtoKind::Icmp6(Icmp6Kind::RouterAdvertisement(_)) => {
                        break_on_err!(self.phrx_icmp6_router_advertisement(&packet_rx))
                    }
                    ProtoKind::Icmp6(Icmp6Kind::NeighborSolicitation(_)) => {
                        break_on_err!(self.phrx_icmp6_neighbor_solicitation(&packet_rx))
                    }
                    ProtoKind::Icmp6(Icmp6Kind::NeighborAdvertisement(_)) => {
                        break_on_err!(self.phrx_icmp6_neighbor_advertisement(&packet_rx))
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

        if !(*self.mac_address_rx.lock().unwrap()).contains(&ether_rx.get_dst()) {
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

        if !(*self.ip6_address_rx.lock().unwrap()).contains(&ip6_rx.get_dst()) {
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

        // Report upper layer inbound activity to ND cache
        self.nd_cache.report_inbound_activity(ip6_rx.get_src());

        // Send ICMPv6 Echo Reply
        {
            let mut ip6_tx_src = ip6_rx.get_dst();

            if ip6_rx.get_dst().is_multicast() {
                ip6_tx_src = util::ip6_select_src(ip6_rx.get_src(), &self.ip6_address_tx)
                    .expect("TODO: Unable to pick source address");
            }

            let tracker = util::tracker("TX", &self.nic_name, &mut self.packet_sn.lock().unwrap());

            let icmp6_tx = icmp6::EchoReply::new()
                .set_id(icmp6_rx.get_id())
                .set_seq(icmp6_rx.get_seq())
                .set_data(icmp6_rx.get_data());
            log!("{} - {}", tracker, icmp6_tx);

            let ip6_tx = ip6::Ip6::new()
                .set_src(ip6_tx_src)
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
                panic!();
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

    /// Process inbound ICMPv6 Router Solicitation message
    fn phrx_icmp6_router_solicitation(
        &mut self,
        packet_rx: &'a Packet,
    ) -> Result<(), PacketDropError> {
        let icmp6_rx = packet_rx.icmp6_router_solicitation().unwrap();
        log!("{} - {}", packet_rx.tracker, icmp6_rx);
        Ok(())
    }

    /// Process inbound ICMPv6 Router Advertisement message
    fn phrx_icmp6_router_advertisement(
        &mut self,
        packet_rx: &'a Packet,
    ) -> Result<(), PacketDropError> {
        let icmp6_rx = packet_rx.icmp6_router_advertisement().unwrap();
        log!("{} - {}", packet_rx.tracker, icmp6_rx);

        self.ip6_nd_ra_prefixes
            .lock()
            .unwrap()
            .extend(icmp6_rx.get_pi());

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

        // Report inbound NS message to ND cache
        self.nd_cache.report_ns(ip6_rx, icmp6_rx);

        // Determine if packet is part of DAD request (src unspecified, no ssla option present)
        let ip6_nd_dad = matches!(
            (ip6_rx.get_src().is_unspecified(), icmp6_rx.get_slla()),
            (true, None)
        );

        if ip6_nd_dad {
            log!(
                "{} - <B>Received ICMPv6 ND DAD message from {}, sending reply</>",
                packet_rx.tracker,
                ip6_rx.get_src(),
            );
        } else {
            log!(
                "{} - <B>Received ICMPv6 Neighbor Solicitation message from {}, sending reply</>",
                packet_rx.tracker,
                ip6_rx.get_src(),
            );
        }

        // Send ICMPv6 ND Neighbor Advertisement
        {
            let tracker = util::tracker("TX", &self.nic_name, &mut self.packet_sn.lock().unwrap());

            let icmp6_tx = icmp6_nd::NeighborAdvertisement::new()
                .set_flag_s(!ip6_nd_dad) // no S flag when responding to DAD request
                .set_flag_o(ip6_nd_dad) // O flag when respondidng to DAD request (this is not necessary but Linux uses it)
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
                panic!();
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
        let _ip6_rx = packet_rx.ip6().unwrap();
        let icmp6_rx = packet_rx.icmp6_neighbor_advertisement().unwrap();
        log!("{} - {}", packet_rx.tracker, icmp6_rx);

        // Report inbound NA message to ND cache
        self.nd_cache.report_na(icmp6_rx);

        // Take care of DAD process if apliccable
        if let std::collections::hash_map::Entry::Occupied(mut ip6_dad_status) =
            (*self.ip6_nd_dad_status.lock().unwrap()).entry(icmp6_rx.get_tnla())
        {
            ip6_dad_status.insert(Ip6NdDadState::Failure);
            log!(
                "{} - <B>Message matches ND DAD entry {}, reporting DAD failure</>",
                packet_rx.tracker,
                icmp6_rx.get_tnla(),
            )
        }

        Ok(())
    }

    /// Send Router Solicitation packet using given LLA address as source
    fn send_router_solicitation(&self, ip6_src: Ip6Address) {
        // Make sure given source address is LLA and belongs to stack
        assert!(ip6_src.is_link_local());
        assert!(self.ip6_address_tx.lock().unwrap().contains(&ip6_src));

        let tracker = util::tracker("TX", &self.nic_name, &mut self.packet_sn.lock().unwrap());

        let icmp6_tx = icmp6_nd::RouterSolicitation::new().set_slla(self.mac_address_tx);
        log!("{} - {}", tracker, icmp6_tx);

        let ip6_tx = ip6::Ip6::new()
            .set_src(ip6_src)
            .set_dst(Ip6Address::new("ff02::2"))
            .set_hop(255)
            .set_dlen(icmp6_tx.len() as u16)
            .set_next(ip6::NEXT__ICMP6);
        log!("{} - {}", tracker, ip6_tx);

        let ether_tx = ether::Ether::new()
            .set_src(self.mac_address_tx)
            .set_dst(MacAddress::from(Ip6Address::new("ff02::2")))
            .set_type(ether::TYPE__IP6);
        log!("{} - {}", tracker, ether_tx);

        let packet_tx = Packet::new(Vec::with_capacity(self.nic_mtu), tracker)
            .add_protocol(ProtoKind::Ether(ether_tx))
            .add_protocol(ProtoKind::Ip6(ip6_tx))
            .add_protocol(ProtoKind::Icmp6(Icmp6Kind::RouterSolicitation(icmp6_tx)));

        if let Err(error) = self.mpsc_to_tx_ring.send(packet_tx) {
            log!("<CRIT> MPSC channel error: '{}'</>", error);
            panic!();
        }
    }
}
