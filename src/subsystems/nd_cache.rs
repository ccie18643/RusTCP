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

use crate::config::{
    ND_CACHE__DELAY_TIME, ND_CACHE__INCOMPLETE_RETRY_LIMIT, ND_CACHE__INCOMPLETE_RETRY_TIME,
    ND_CACHE__PROBE_RETRY_LIMIT, ND_CACHE__PROBE_RETRY_TIME, ND_CACHE__REACHABLE_TIME,
    ND_CACHE__TIME_LOOP_DELAY,
};
use crate::lib::ip6_address::Ip6Address;
use crate::lib::mac_address::MacAddress;
use crate::lib::packet::Packet;
use crate::lib::packet::{Icmp6Kind, ProtoKind};
use crate::lib::util;
use crate::log_nd_cache as log;
use crate::protocols::ether;
use crate::protocols::icmp6_nd;
use crate::protocols::ip6;
use crate::protocols::protocol::Protocol;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time;

#[derive(Debug)]
enum State {
    Incomplete {
        timestamp: time::Instant,
        attempt: usize,
    },
    Reachable {
        clla: MacAddress,
        timestamp: time::Instant,
    },
    Stale {
        clla: MacAddress,
    },
    Delay {
        clla: MacAddress,
        timestamp: time::Instant,
    },
    Probe {
        clla: MacAddress,
        timestamp: time::Instant,
        attempt: usize,
    },
}

#[allow(clippy::mutex_atomic)]
#[derive(Debug, Clone)]
pub struct NdCache {
    state_table: Arc<Mutex<HashMap<Ip6Address, State>>>,
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
    ) -> Self {
        let nd_cache = Self {
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
                {
                    let state_table = &mut *self_c.state_table.lock().unwrap();
                    let state_table_keys: Vec<Ip6Address> = state_table.keys().cloned().collect();
                    for cnla in state_table_keys {
                        match state_table[&cnla] {
                            State::Incomplete { timestamp, attempt } => {
                                if timestamp.elapsed().as_secs() >= ND_CACHE__INCOMPLETE_RETRY_TIME
                                {
                                    // |white| retransmit limit reached
                                    // INCOMPLETE -> NONEXISTENT, Send ICMPv6 error
                                    if attempt >= ND_CACHE__INCOMPLETE_RETRY_LIMIT {
                                        state_table.remove(&cnla);
                                        log!("{} - Incomplete retry limit reached <lb>[INCOMPLETE -> NONEXISTENT]", cnla);
                                        // TODO: Send ICMPv6 error
                                        continue;
                                    }
                                    // |white| retransmit limit not reached
                                    // INCOMPLETE -> INCOMPLETE, Send ICMPv6 error
                                    state_table.insert(
                                        cnla,
                                        State::Incomplete {
                                            timestamp: time::Instant::now(),
                                            attempt: attempt + 1,
                                        },
                                    );
                                    log!(
                                    "{} - Incomplete timer expired <lb>[INCOMPLETE -> INCOMPLETE]</>",
                                    cnla
                                );
                                    self_c.send_neighbor_solicitation_multicast(cnla);
                                }
                            }
                            State::Reachable { clla, timestamp } => {
                                // |white| timeout
                                // REACHABLE -> STALE
                                if timestamp.elapsed().as_secs() >= ND_CACHE__REACHABLE_TIME {
                                    state_table.insert(cnla, State::Stale { clla });
                                    log!(
                                        "{} - Reachable timer expired <lb>[REACHABLE -> STALE]</>, lla {}",
                                        cnla,
                                        clla
                                    );
                                }
                            }
                            State::Stale { .. } => (),
                            State::Delay { clla, timestamp } => {
                                // |white| timeout
                                // DELAY -> PROBE
                                if timestamp.elapsed().as_secs() >= ND_CACHE__DELAY_TIME {
                                    state_table.insert(
                                        cnla,
                                        State::Probe {
                                            clla,
                                            timestamp: time::Instant::now(),
                                            attempt: 0,
                                        },
                                    );
                                    log!(
                                        "{} - Delay timer expired <lb>[DELAY -> PROBE]</>, lla {}",
                                        cnla,
                                        clla
                                    );
                                    self_c.send_neighbor_solicitation_unicast(cnla, clla);
                                }
                            }
                            State::Probe {
                                clla,
                                timestamp,
                                attempt,
                            } => {
                                if timestamp.elapsed().as_secs() >= ND_CACHE__PROBE_RETRY_TIME {
                                    // |white| retransmit limit reached
                                    // PROBE -> NONEXISTENT
                                    if attempt >= ND_CACHE__PROBE_RETRY_LIMIT {
                                        state_table.remove(&cnla);
                                        log!("{} - Probe retry limit reached <lb>[PROBE -> NONEXISTENT]</>", cnla);
                                        continue;
                                    }
                                    // |white| retransmit limit not reached
                                    // PROBE -> PROBE
                                    state_table.insert(
                                        cnla,
                                        State::Probe {
                                            clla,
                                            timestamp: time::Instant::now(),
                                            attempt: attempt + 1,
                                        },
                                    );
                                    log!(
                                        "{} - Probe timer expired <lb>[PROBE -> PROBE], lla {}</>",
                                        cnla,
                                        clla
                                    );
                                    self_c.send_neighbor_solicitation_unicast(cnla, clla);
                                }
                            }
                        }
                    }
                }
                thread::sleep(time::Duration::from_millis(ND_CACHE__TIME_LOOP_DELAY));
            }
        });

        nd_cache
    }

    /// Find cache entry for given IPv6 address
    pub fn find(&self, nla: Ip6Address) -> Option<MacAddress> {
        // TODO: Some optimalization of time when state_table is locked needed here
        let state_table = &mut *self.state_table.lock().unwrap();
        match state_table.get(&nla) {
            // |white| packet to be sent out
            // NONEXTISTENT -> INCOMPLETE, send out multicast NS
            None => {
                state_table.insert(
                    nla,
                    State::Incomplete {
                        timestamp: time::Instant::now(),
                        attempt: 0,
                    },
                );
                log!(
                    "{} - Internal query <lb>[NONEXISTENT -> INCOMPLETE]</>",
                    nla
                );
                self.send_neighbor_solicitation_multicast(nla);
                None
            }
            Some(State::Incomplete { .. }) => None,
            Some(State::Reachable { clla, .. })
            | Some(State::Stale { clla, .. })
            | Some(State::Delay { clla, .. })
            | Some(State::Probe { clla, .. }) => Some(*clla),
        }
    }

    /// Report upper layer inbound activity (reachability confirmation)
    pub fn report_inbound_activity(&self, nla: Ip6Address) {
        let state_table = &mut *self.state_table.lock().unwrap();
        // |blue| upper-layer inbound activity
        // STALE -> REACHABLE
        if let Some(State::Stale { clla, .. }) = state_table.get(&nla) {
            let clla = *clla;
            state_table.insert(
                nla,
                State::Reachable {
                    clla,
                    timestamp: time::Instant::now(),
                },
            );
            log!(
                "{} - Reachability reported <lb>[STALE -> REACHABLE]</>, lla {}",
                nla,
                clla
            );
        }
    }

    /// Report upper layer packet being sent towards nla
    pub fn report_outbound_activity(&self, nla: Ip6Address) {
        let state_table = &mut *self.state_table.lock().unwrap();
        // |white| upper-layer outbound activity
        // STALE -> DELAY
        if let Some(State::Stale { clla, .. }) = state_table.get(&nla) {
            let clla = *clla;
            state_table.insert(
                nla,
                State::Delay {
                    clla,
                    timestamp: time::Instant::now(),
                },
            );
            log!(
                "{} - Activity reported <lb>[STALE -> DELAY]</>, lla {}",
                nla,
                clla
            );
        }
    }

    /// Report inbound Network Solicitation message
    pub fn report_ns(&self, ip6_rx: &ip6::Ip6, icmp6_rx: &icmp6_nd::NeighborSolicitation) {
        // Ignore NS packet without SLLA option
        if icmp6_rx.get_slla() == None {
            return;
        }
        let lla = icmp6_rx.get_slla().unwrap();
        let nla = ip6_rx.get_src();
        let state_table = &mut *self.state_table.lock().unwrap();
        match state_table.get(&nla) {
            // |white} received NS[]
            // NONEXISTENT -> STALE
            None => {
                state_table.insert(nla, State::Stale { clla: lla });
                log!(
                    "{} - Received NS message <lb>[NONEXISTENT -> STALE]</>, lla {}",
                    nla,
                    lla,
                );
            }
            // |general| received NS[]
            // INCOMPLETE -> STALE, record lla
            Some(State::Incomplete { .. }) => {
                state_table.insert(nla, State::Stale { clla: lla });
                log!(
                    "{} - Received NS message <lb>[INCOMPLETE -> STALE]</>, lla {}",
                    nla,
                    lla,
                );
                // TODO: Send queued packets
            }
            // |general| received NS[different lla]
            // REACHABLE -> STALE, record lla
            Some(State::Reachable { clla, .. }) if *clla != lla => {
                let clla = *clla;
                state_table.insert(nla, State::Stale { clla });
                log!(
                    "{} - Received NS message <lb>[REACHABLE -> STALE]</>, lla {} -> {}",
                    nla,
                    clla,
                    lla,
                );
            }
            // |general| received NS[different lla]
            // STALE -> STALE, record lla
            Some(State::Stale { clla, .. }) if *clla != lla => {
                let clla = *clla;
                state_table.insert(nla, State::Stale { clla });
                log!(
                    "{} - Received NS message <lb>[STALE -> STALE]</>, lla {} -> {}",
                    nla,
                    clla,
                    lla,
                );
            }
            // |general| received NS[different lla]
            // DELAY -> STALE, record lla
            Some(State::Delay { clla, .. }) if *clla != lla => {
                let clla = *clla;
                state_table.insert(nla, State::Stale { clla });
                log!(
                    "{} - Received NS message <lb>[DELAY -> STALE]</>, lla {} -> {}",
                    nla,
                    clla,
                    lla,
                );
            }
            // |general| received NS[different lla]
            // PROBE -> STALE, record lla
            Some(State::Probe { clla, .. }) if *clla != lla => {
                let clla = *clla;
                state_table.insert(nla, State::Stale { clla });
                log!(
                    "{} - Received NS message <lb>[PROBE -> STALE]</>, lla {} -> {}",
                    nla,
                    clla,
                    lla,
                );
            }
            _ => (),
        }
    }

    /// Report receiving Neighbor Advertisement message
    pub fn report_na(&self, icmp6_rx: &icmp6_nd::NeighborAdvertisement) {
        // Ignore NA packet without TLLA option
        if icmp6_rx.get_tlla() == None {
            return;
        }
        let lla = icmp6_rx.get_tlla().unwrap();
        let nla = icmp6_rx.get_tnla();
        let state_table = &mut *self.state_table.lock().unwrap();
        match (
            state_table.get(&nla),
            icmp6_rx.get_flag_s(),
            icmp6_rx.get_flag_o(),
        ) {
            // |blue| received NA[S=1, O=any]
            // INCOMPLETE -> REACHABLE, record lla, send queued packets
            (Some(State::Incomplete { .. }), true, _) => {
                state_table.insert(
                    nla,
                    State::Reachable {
                        clla: lla,
                        timestamp: time::Instant::now(),
                    },
                );
                log!(
                    "{} - Received NA message <lb>[INCOMPLETE -> REACHABLE]</>, lla {}",
                    nla,
                    lla,
                );
                // TODO: Send queued packets
            }
            // |red| received NA[S=0, O=any]
            // INCOMPLETE -> STALE, record lla, send queued packets
            (Some(State::Incomplete { .. }), false, _) => {
                state_table.insert(nla, State::Stale { clla: lla });
                log!(
                    "{} - Received NA message <lb>[INCOMPLETE -> STALE]</>, lla {}",
                    nla,
                    lla,
                );
                // TODO: Send queued packets
            }
            // |yellow| received NA[S=1, O=0, lla different]
            // REACHABLE -> STALE, ignore lla
            (Some(State::Reachable { clla, .. }), true, false) if *clla != lla => {
                let clla = *clla;
                state_table.insert(nla, State::Stale { clla });
                log!(
                    "{} - Received NA message <lb>[REACHABLE -> STALE]</>, lla {} -/> {}",
                    nla,
                    clla,
                    lla,
                );
            }
            // |red| received NA[S=0, O=1, lla different]
            // REACHABLE -> STALE, record lla
            (Some(State::Reachable { clla, .. }), false, true) if *clla != lla => {
                let clla = *clla;
                state_table.insert(nla, State::Stale { clla: lla });
                log!(
                    "{} -  Received NA message <lb>[REACHABLE -> STALE]</>, lla {} -> {}",
                    nla,
                    clla,
                    lla,
                );
            }
            // |blue| received NA[S=1, O=1]
            // STALE -> REACHABLE, record lla if different
            (Some(State::Stale { clla, .. }), true, true) => {
                let clla = *clla;
                state_table.insert(
                    nla,
                    State::Reachable {
                        clla: lla,
                        timestamp: time::Instant::now(),
                    },
                );
                log!(
                    "{} - Received NA message <lb>[STALE -> REACHABLE]</>, lla {} -> {}",
                    nla,
                    clla,
                    lla,
                );
            }
            // |yellow| received NA[S=1, O=0, different lla]
            // STALE->STALE, ignore lla
            (Some(State::Stale { clla, .. }), true, false) if *clla != lla => {
                let clla = *clla;
                state_table.insert(
                    nla,
                    State::Reachable {
                        clla,
                        timestamp: time::Instant::now(),
                    },
                );
                log!(
                    "{} - Received NA message <lb>[STALE -> STALE]</>, lla {} -/> {}",
                    nla,
                    clla,
                    lla,
                );
            }
            // |blue| received NA[S=1, O=1]
            // DELAY -> REACHABLE, record lla if different
            (Some(State::Delay { clla, .. }), true, true) => {
                let clla = *clla;
                state_table.insert(
                    nla,
                    State::Reachable {
                        clla: lla,
                        timestamp: time::Instant::now(),
                    },
                );
                log!(
                    "{} - Received NA message <lb>[DELAY -> REACHABLE]</>, lla {} -> {}",
                    nla,
                    clla,
                    lla,
                );
            }
            // |yellow| received NA[S=1, O=0, different lla]
            // DELAY -> DELAY, ignore lla
            (Some(State::Delay { clla, .. }), true, false) if *clla != lla => {
                let clla = *clla;
                state_table.insert(
                    nla,
                    State::Reachable {
                        clla,
                        timestamp: time::Instant::now(),
                    },
                );
                log!(
                    "{} - Received NA message <lb>[DELAY -> DELAY]</>, lla {} -/> {}",
                    nla,
                    clla,
                    lla,
                );
            }
            // |red| received NA[S=0, O=1, different lla]
            // DELAY -> STALE, record lla
            (Some(State::Delay { clla, .. }), false, true) if *clla != lla => {
                let clla = *clla;
                state_table.insert(nla, State::Stale { clla: lla });
                log!(
                    "{} - Received NA message <lb>[DELAY -> STALE]</>, lla {} -> {}",
                    nla,
                    clla,
                    lla
                );
            }
            // |blue| received NA[S=1, O=1]
            // PROBE -> REACHABLE, record lla if different
            (Some(State::Probe { clla, .. }), true, true) => {
                let clla = *clla;
                state_table.insert(
                    nla,
                    State::Reachable {
                        clla: lla,
                        timestamp: time::Instant::now(),
                    },
                );
                log!(
                    "{} - Received NA message <lb>[PROBE -> REACHABLE]</>, lla {} -> {}",
                    nla,
                    clla,
                    lla,
                );
            }
            // |yellow| received NA[S=1, O=0, different lla]
            // PROBE -> DELAY, ignore lla
            (Some(State::Probe { clla, .. }), true, false) if *clla != lla => {
                let clla = *clla;
                state_table.insert(
                    nla,
                    State::Reachable {
                        clla,
                        timestamp: time::Instant::now(),
                    },
                );
                log!(
                    "{} - Received NA message <lb>[PROBE -> DELAY]</>, lla {} -/> {}",
                    nla,
                    clla,
                    lla,
                );
            }
            // |red| received NA[S=0, O=1, different lla]
            // PROBE -> STALE, record lla
            (Some(State::Probe { clla, .. }), false, true) if *clla != lla => {
                let clla = *clla;
                state_table.insert(nla, State::Stale { clla: lla });
                log!(
                    "{} - Received NA message <lb>[PROBE -> STALE]</>, lla {} -> {}",
                    nla,
                    clla,
                    lla,
                );
            }
            _ => (),
        }
    }

    /// Send Neighbor Solicitation message (multicast version)
    fn send_neighbor_solicitation_multicast(&self, nla: Ip6Address) {
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
                util::ip6_select_src(nla, &self.ip6_address_tx)
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
                util::ip6_select_src(nla, &self.ip6_address_tx)
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
