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
use crate::lib::packet::Packet;
use crate::lib::packet::{Icmp6Kind, ProtoKind};
use crate::lib::util;
use crate::log_nd_cache as log;
use crate::protocols::ether;
use crate::protocols::icmp6_nd;
use crate::protocols::ip6;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time;

const INCOMPLETE_RETRY_TIME: u64 = 1;
const INCOMPLETE_RETRY_LIMIT: usize = 2;
const REACHABLE_TIME: u64 = 45;
const DELAY_TIME: u64 = 5;
const PROBE_RETRY_TIME: u64 = 1;
const PROBE_RETRY_LIMIT: usize = 2;

pub enum NdCacheState {
    Incomplete(time::Instant, usize),
    Reachable(MacAddress, time::Instant),
    Stale(MacAddress, time::Instant),
    Delay(MacAddress, time::Instant),
    Probe(MacAddress, time::Instant, usize),
}

#[allow(clippy::mutex_atomic)]
#[derive(Clone)]
pub struct NdCache {
    state_table: Arc<Mutex<HashMap<Ip6Address, NdCacheState>>>,
    nic_name: String,
    nic_mtu: usize,
    packet_sn: Arc<Mutex<usize>>,
    mpsc_to_tx_ring: mpsc::Sender<Packet>,
    mac_address_tx: MacAddress,
    ip6_address_tx: Arc<Mutex<HashSet<Ip6Address>>>,
}

impl NdCache {
    pub fn new(
        nic_name: String,
        nic_mtu: usize,
        packet_sn: Arc<Mutex<usize>>,
        mpsc_to_tx_ring: mpsc::Sender<Packet>,
        mac_address_tx: MacAddress,
        ip6_address_tx: Arc<Mutex<HashSet<Ip6Address>>>,
    ) -> NdCache {
        let nd_cache = NdCache {
            state_table: Arc::new(Mutex::new(HashMap::with_capacity(256))),
            nic_name,
            nic_mtu,
            packet_sn,
            mpsc_to_tx_ring,
            mac_address_tx,
            ip6_address_tx,
        };

        let self_c = nd_cache.clone();
        thread::spawn(move || {
            log!("<lv>Thread spawned: 'nd_cache - {}'</>", self_c.nic_name);
            loop {
                for (nla, state) in (*self_c.state_table.lock().unwrap()).iter() {
                    match state {
                        NdCacheState::Incomplete(timestamp, attempt) => {
                            if timestamp.elapsed().as_secs() >= INCOMPLETE_RETRY_TIME {
                                // |white| timeout, retransmit limit reached
                                // INCOMPLETE -> NONEXISTENT, Send ICMPv6 error
                                if *attempt >= INCOMPLETE_RETRY_LIMIT {
                                    (*self_c.state_table.lock().unwrap()).remove(nla);
                                    log!("{} - INCOMPLETE -> NONEXISTENT", nla);
                                    // TODO: Send ICMPv6 error
                                    continue;
                                }
                                (*self_c.state_table.lock().unwrap()).insert(
                                    *nla,
                                    NdCacheState::Incomplete(time::Instant::now(), attempt + 1),
                                );
                                log!(
                                    "{} - Incomplete timer expired <lb>[INCOMPLETE -> INCOMPLETE]</>",
                                    nla
                                );
                                self_c.send_neighbor_solicitation(*nla);
                            }
                        }
                        NdCacheState::Reachable(lla, timestamp) => {
                            // |white| timeout
                            // REACHABLE -> STALE
                            if timestamp.elapsed().as_secs() >= REACHABLE_TIME {
                                (*self_c.state_table.lock().unwrap())
                                    .insert(*nla, NdCacheState::Stale(*lla, time::Instant::now()));
                                log!(
                                    "{} - Reachable timer expired <lb>[REACHABLE -> STALE]</>, lla {}",
                                    nla,
                                    lla
                                );
                            }
                        }
                        NdCacheState::Stale(_, _) => {}
                        NdCacheState::Delay(lla, timestamp) => {
                            // |white| timeout
                            // DELAY -> PROBE
                            if timestamp.elapsed().as_secs() >= DELAY_TIME {
                                (*self_c.state_table.lock().unwrap()).insert(
                                    *nla,
                                    NdCacheState::Probe(*lla, time::Instant::now(), 0),
                                );
                                log!(
                                    "{} - Delay timer expired <lb>[DELAY -> PROBE]</>, lla {}",
                                    nla,
                                    lla
                                );
                                self_c.send_neighbor_solicitation_unicast(*nla, *lla);
                            }
                        }
                        NdCacheState::Probe(lla, timestamp, attempt) => {
                            if timestamp.elapsed().as_secs() >= PROBE_RETRY_TIME {
                                // |white| timeout, retransmit limit reached
                                // INCOMPLETE -> NONEXISTENT
                                if *attempt == PROBE_RETRY_LIMIT {
                                    (*self_c.state_table.lock().unwrap()).remove(nla);
                                    log!("{} - PROBE -> NONEXISTENT", nla);
                                    continue;
                                }
                                (*self_c.state_table.lock().unwrap()).insert(
                                    *nla,
                                    NdCacheState::Probe(*lla, time::Instant::now(), attempt + 1),
                                );
                                log!("{} - Probe timer expired <lb>[PROBE -> PROBE]</>", nla);
                                self_c.send_neighbor_solicitation_unicast(*nla, *lla);
                            }
                        }
                    }
                }
                thread::sleep(time::Duration::from_millis(250));
            }
        });

        nd_cache
    }

    /// Find cache entry for given IPv6 address
    pub fn find(&self, nla: &Ip6Address) -> Option<MacAddress> {
        if let Some(state) = (*self.state_table.lock().unwrap()).get(nla) {
            match state {
                NdCacheState::Incomplete(_, _) => return None,
                NdCacheState::Reachable(lla, _) => return Some(*lla),
                NdCacheState::Stale(lla, _) => {
                    // |white| sending packet
                    (*self.state_table.lock().unwrap())
                        .insert(*nla, NdCacheState::Delay(*lla, time::Instant::now()));
                    log!(
                        "{} - Internal query <lb>[STALE -> DELAY]</>, lla {}",
                        nla,
                        lla
                    );
                    return Some(*lla);
                }
                NdCacheState::Delay(lla, _) => return Some(*lla),
                NdCacheState::Probe(lla, _, _) => return Some(*lla),
            }
        }

        // No state exists in state table for given IPv6 address
        (*self.state_table.lock().unwrap())
            .insert(*nla, NdCacheState::Incomplete(time::Instant::now(), 0));
        log!(
            "{} - Internal query <lb>[NONEXISTENT -> INCOMPLETE]</>",
            nla
        );
        self.send_neighbor_solicitation(*nla);

        None
    }

    /// Report upper layer reachability confirmation
    pub fn report_reachability(&self, nla_rx: Ip6Address) {
        if let Some(state) = (*self.state_table.lock().unwrap()).get(&nla_rx) {
            match state {
                NdCacheState::Incomplete(_, _) => {}
                NdCacheState::Reachable(_, _) => {}
                NdCacheState::Stale(lla, _) => {
                    // |blue| upper-layer reachability confirmation
                    // STALE -> REACHABLE
                    (*self.state_table.lock().unwrap())
                        .insert(nla_rx, NdCacheState::Reachable(*lla, time::Instant::now()));
                    log!(
                        "{} - Reachability reported <lb>[STALE -> REACHABLE]</>, lla {}",
                        nla_rx,
                        lla
                    );
                }
                NdCacheState::Delay(_, _) => {}
                NdCacheState::Probe(_, _, _) => {}
            }
        }
    }

    /// Report upper layer packet being sent towards nla
    pub fn report_activity(&self, nla_tx: Ip6Address) {
        if let Some(state) = (*self.state_table.lock().unwrap()).get(&nla_tx) {
            match state {
                NdCacheState::Incomplete(_, _) => {}
                NdCacheState::Reachable(_, _) => {}
                NdCacheState::Stale(lla, _) => {
                    (*self.state_table.lock().unwrap())
                        .insert(nla_tx, NdCacheState::Delay(*lla, time::Instant::now()));
                    log!(
                        "{} - Activity reported <lb>[STALE -> DELAY]</>, lla {}",
                        nla_tx,
                        lla
                    );
                }
                NdCacheState::Delay(_, _) => {}
                NdCacheState::Probe(_, _, _) => {}
            }
        }
    }

    /// Report inbound Network Solicitation message
    pub fn report_ns(&self, ip6_rx: &ip6::Ip6, icmp6_rx: &icmp6_nd::NeighborSolicitation) {
        let nla_rx = ip6_rx.get_src();
        if let Some(lla_rx) = icmp6_rx.get_slla() {
            if let Some(state) = (*self.state_table.lock().unwrap()).get(&nla_rx) {
                match state {
                    NdCacheState::Incomplete(_, _) => {
                        (*self.state_table.lock().unwrap())
                            .insert(nla_rx, NdCacheState::Stale(lla_rx, time::Instant::now()));
                        log!(
                            "{} - Received NS message <lb>[INCOMPLETE -> STALE]</>, lla {}",
                            nla_rx,
                            lla_rx
                        );
                        // TODO: Send queued packets
                    }
                    NdCacheState::Reachable(lla, _) => {
                        // |general| received NS[different lla]
                        // REACHABLE -> STALE, record lla
                        if lla_rx != *lla {
                            (*self.state_table.lock().unwrap())
                                .insert(nla_rx, NdCacheState::Stale(*lla, time::Instant::now()));
                            log!(
                                "{} - Received NS message <lb>[REACHABLE -> STALE]</>, lla {} -> {}",
                                nla_rx,
                                lla,
                                lla_rx
                            );
                        }
                    }
                    NdCacheState::Stale(lla, _) => {
                        // |general| received NS[different lla]
                        // STALE -> STALE, record lla
                        if lla_rx != *lla {
                            (*self.state_table.lock().unwrap())
                                .insert(nla_rx, NdCacheState::Stale(*lla, time::Instant::now()));
                            log!(
                                "{} - Received NS message <lb>[STALE -> STALE]</>, lla {} -> {}",
                                nla_rx,
                                lla,
                                lla_rx
                            );
                        }
                    }
                    NdCacheState::Delay(lla, _) => {
                        // |general| received NS[different lla]
                        // DELAY -> STALE, record lla
                        if lla_rx != *lla {
                            (*self.state_table.lock().unwrap())
                                .insert(nla_rx, NdCacheState::Stale(*lla, time::Instant::now()));
                            log!(
                                "{} - Received NS message <lb>[DELAY -> STALE]</>, lla {} -> {}",
                                nla_rx,
                                lla,
                                lla_rx
                            );
                        }
                    }
                    NdCacheState::Probe(lla, _, _) => {
                        // |general| received NS[different lla]
                        // PROBE -> STALE, record lla
                        if lla_rx != *lla {
                            (*self.state_table.lock().unwrap())
                                .insert(nla_rx, NdCacheState::Stale(*lla, time::Instant::now()));
                            log!(
                                "{} - Received NS message <lb>[PROBE -> STALE]</>, lla {} -> {}",
                                nla_rx,
                                lla,
                                lla_rx
                            );
                        }
                    }
                }
            }
        }
        // NS received
        // NONEXISTENT -> STALE
        if let Some(lla_rx) = icmp6_rx.get_slla() {
            (*self.state_table.lock().unwrap())
                .insert(nla_rx, NdCacheState::Stale(lla_rx, time::Instant::now()));
            log!(
                "{} - Received NS message <lb>[NONEXISTENT -> STALE]</>, lla {}",
                nla_rx,
                lla_rx
            );
        }
    }

    /// Report receiving Neighbor Advertisement message
    pub fn report_na(&self, icmp6_rx: &icmp6_nd::NeighborAdvertisement) {
        if let Some(lla_rx) = icmp6_rx.get_tlla() {
            let nla_rx = icmp6_rx.get_tnla();
            if let Some(state) = (*self.state_table.lock().unwrap()).get(&nla_rx) {
                match state {
                    NdCacheState::Incomplete(_, _) => {
                        // |blue| received NA[S=1, O=any]
                        // INCOMPLETE -> REACHABLE, record lla, send queued packets
                        if icmp6_rx.get_flag_s() {
                            (*self.state_table.lock().unwrap()).insert(
                                nla_rx,
                                NdCacheState::Reachable(lla_rx, time::Instant::now()),
                            );
                            log!(
                                "{} - Received NA message <lb>[INCOMPLETE -> REACHABLE]</>, lla {}",
                                nla_rx,
                                lla_rx
                            );
                            // TODO: Send queued packets
                        }
                        // |red| received NA[S=0, O=any]
                        // INCOMPLETE -> STALE, record lla, send queued packets
                        if !icmp6_rx.get_flag_s() {
                            (*self.state_table.lock().unwrap())
                                .insert(nla_rx, NdCacheState::Stale(lla_rx, time::Instant::now()));
                            log!(
                                "{} - Received NA message <lb>[INCOMPLETE -> STALE]</>, lla {}",
                                nla_rx,
                                lla_rx
                            );
                            // TODO: Send queued packets
                        }
                    }
                    NdCacheState::Reachable(lla, _) => {
                        // |yellow| received NA[S=1, O=0, lla different]
                        // REACHABLE -> STALE, ignore lla
                        if icmp6_rx.get_flag_s() && !icmp6_rx.get_flag_o() && lla_rx != *lla {
                            (*self.state_table.lock().unwrap())
                                .insert(nla_rx, NdCacheState::Stale(*lla, time::Instant::now()));
                            log!(
                                "{} - Received NA message <lb>[REACHABLE -> STALE]</>, lla {} -/> {}",
                                nla_rx,
                                lla,
                                lla_rx
                            );
                        }
                        // |red| received NA[S=0, O=1, lla different]
                        // REACHABLE -> STALE, record lla
                        if !icmp6_rx.get_flag_s() && icmp6_rx.get_flag_o() && lla_rx != *lla {
                            (*self.state_table.lock().unwrap())
                                .insert(nla_rx, NdCacheState::Stale(lla_rx, time::Instant::now()));
                            log!(
                                "{} -  Received NA message <lb>[REACHABLE -> STALE]</>, lla {} -> {}",
                                nla_rx,
                                lla,
                                lla_rx
                            );
                        }
                    }
                    NdCacheState::Stale(lla, _) => {
                        // |blue| received NA[S=1, O=1] (checking lla for logging)
                        // STALE -> REACHABLE, record lla if different
                        if icmp6_rx.get_flag_s() && icmp6_rx.get_flag_o() {
                            (*self.state_table.lock().unwrap()).insert(
                                nla_rx,
                                NdCacheState::Reachable(lla_rx, time::Instant::now()),
                            );
                            if lla_rx == *lla {
                                log!(
                                    "{} - Received NA message <lb>[STALE -> REACHABLE]</>, lla {}",
                                    nla_rx,
                                    lla
                                );
                            } else {
                                log!(
                                    "{} - Received NA message <lb>[STALE -> REACHABLE]</>, lla {} -> {}",
                                    nla_rx,
                                    lla,
                                    lla_rx
                                );
                            }
                        }
                        // |yellow| received NA[S=1, O=0, different lla]
                        // STALE->STALE, ignore lla
                        if icmp6_rx.get_flag_s() && !icmp6_rx.get_flag_o() && lla_rx != *lla {
                            (*self.state_table.lock().unwrap()).insert(
                                nla_rx,
                                NdCacheState::Reachable(*lla, time::Instant::now()),
                            );
                            log!(
                                "{} - Received NA message <lb>[STALE -> STALE]</>, lla {} -/> {}",
                                nla_rx,
                                lla,
                                lla_rx
                            );
                        }
                    }
                    NdCacheState::Delay(lla, _) => {
                        // |blue| received NA[S=1, O=1] (checking lla for logging)
                        // DELAY -> REACHABLE, record lla if different
                        if icmp6_rx.get_flag_s() && icmp6_rx.get_flag_o() {
                            (*self.state_table.lock().unwrap()).insert(
                                nla_rx,
                                NdCacheState::Reachable(lla_rx, time::Instant::now()),
                            );
                            if lla_rx == *lla {
                                log!(
                                    "{} - Received NA message <lb>[DELAY -> REACHABLE]</>, lla {}",
                                    nla_rx,
                                    lla
                                );
                            } else {
                                log!(
                                    "{} - Received NA message <lb>[DELAY -> REACHABLE]</>, lla {} -> {}",
                                    nla_rx,
                                    lla,
                                    lla_rx
                                );
                            }
                        }
                        // |yellow| received NA[S=1, O=0, different lla]
                        // DELAY -> DELAY, ignore lla
                        if icmp6_rx.get_flag_s() && !icmp6_rx.get_flag_o() && lla_rx != *lla {
                            (*self.state_table.lock().unwrap()).insert(
                                nla_rx,
                                NdCacheState::Reachable(*lla, time::Instant::now()),
                            );
                            log!(
                                "{} - Received NA message <lb>[DELAY -> DELAY]</>, lla {} -/> {}",
                                nla_rx,
                                lla,
                                lla_rx
                            );
                        }
                        // |red| received NA[S=0, O=1, different lla]
                        // DELAY -> STALE, record lla
                        if !icmp6_rx.get_flag_s() && icmp6_rx.get_flag_o() && lla_rx != *lla {
                            (*self.state_table.lock().unwrap())
                                .insert(nla_rx, NdCacheState::Stale(lla_rx, time::Instant::now()));
                            log!(
                                "{} - Received NA message <lb>[DELAY -> STALE]</>, lla {} -> {}",
                                nla_rx,
                                lla,
                                lla_rx
                            );
                        }
                    }
                    NdCacheState::Probe(lla, _, _) => {
                        // |blue| received NA[S=1, O=1] (checking lla for logging)
                        // PROBE -> REACHABLE, record lla if different
                        if icmp6_rx.get_flag_s() && icmp6_rx.get_flag_o() {
                            (*self.state_table.lock().unwrap()).insert(
                                nla_rx,
                                NdCacheState::Reachable(lla_rx, time::Instant::now()),
                            );
                            if lla_rx == *lla {
                                log!(
                                    "{} - Received NA message <lb>[PROBE -> REACHABLE]</>, lla {}",
                                    nla_rx,
                                    lla
                                );
                            } else {
                                log!(
                                    "{} - Received NA message <lb>[PROBE -> REACHABLE]</>, lla {} -> {}",
                                    nla_rx,
                                    lla,
                                    lla_rx
                                );
                            }
                        }
                        // |yellow| received NA[S=1, O=0, different lla]
                        // PROBE -> DELAY, ignore lla
                        if icmp6_rx.get_flag_s() && !icmp6_rx.get_flag_o() && lla_rx != *lla {
                            (*self.state_table.lock().unwrap()).insert(
                                nla_rx,
                                NdCacheState::Reachable(*lla, time::Instant::now()),
                            );
                            log!(
                                "{} - Received NA message <lb>[PROBE -> DELAY]</>, lla {} -/> {}",
                                nla_rx,
                                lla,
                                lla_rx
                            );
                        }
                        // |red| received NA[S=0, O=1, different lla]
                        // PROBE -> STALE, record lla
                        if !icmp6_rx.get_flag_s() && icmp6_rx.get_flag_o() && lla_rx != *lla {
                            (*self.state_table.lock().unwrap())
                                .insert(nla_rx, NdCacheState::Stale(lla_rx, time::Instant::now()));
                            log!(
                                "{} - Received NA message <lb>[PROBE -> STALE]</>, lla {} -> {}",
                                nla_rx,
                                lla,
                                lla_rx
                            );
                        }
                    }
                }
            }
        }
    }

    /// Send Neighbor Solicitation message
    fn send_neighbor_solicitation(&self, nla: Ip6Address) {
        let tracker = {
            let mut packet_sn = self.packet_sn.lock().unwrap();
            let tracker = format!(
                "<lr>[TX/{}/{:04X}]</>",
                self.nic_name.to_uppercase(),
                *packet_sn
            );
            *packet_sn = (*packet_sn).wrapping_add(1);
            tracker
        };

        let icmp6_tx = icmp6_nd::NeighborSolicitation::new()
            .set_tnla(nla)
            .set_slla(self.mac_address_tx);
        log!("{} - {}", tracker, icmp6_tx);

        let ip6_tx = ip6::Ip6::new()
            .set_src(
                util::ip6_select_src(&nla, &self.ip6_address_tx)
                    .expect("TODO: Unable to select src address"),
            )
            .set_dst(nla.solicited_node_multicast())
            .set_hop(255)
            .set_dlen(icmp6_tx.len() as u16)
            .set_next(ip6::NEXT__ICMP6);
        log!("{} - {}", tracker, ip6_tx);

        let ether_tx = ether::Ether::new()
            .set_src(self.mac_address_tx)
            .set_dst(nla.solicited_node_multicast().into())
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
    }

    /// Send Neighbor Solicitation message (unicast version)
    fn send_neighbor_solicitation_unicast(&self, nla: Ip6Address, lla: MacAddress) {
        let tracker = {
            let mut packet_sn = self.packet_sn.lock().unwrap();
            let tracker = format!(
                "<lr>[TX/{}/{:04X}]</>",
                self.nic_name.to_uppercase(),
                *packet_sn
            );
            *packet_sn = (*packet_sn).wrapping_add(1);
            tracker
        };

        let icmp6_tx = icmp6_nd::NeighborSolicitation::new()
            .set_tnla(nla)
            .set_slla(self.mac_address_tx);
        log!("{} - {}", tracker, icmp6_tx);

        let ip6_tx = ip6::Ip6::new()
            .set_src(
                util::ip6_select_src(&nla, &self.ip6_address_tx)
                    .expect("TODO: Unable to select src address"),
            )
            .set_dst(nla)
            .set_hop(255)
            .set_dlen(icmp6_tx.len() as u16)
            .set_next(ip6::NEXT__ICMP6);
        log!("{} - {}", tracker, ip6_tx);

        let ether_tx = ether::Ether::new()
            .set_src(self.mac_address_tx)
            .set_dst(lla)
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
    }
}
