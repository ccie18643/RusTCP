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
use crate::log_nd_cache as log;
use crate::protocols::ether;
use crate::protocols::icmp6_nd;
use crate::protocols::ip6;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time;

pub enum NdCacheState {
    Incomplete(time::Instant, usize),
    Reachable(MacAddress),
    Stale(MacAddress),
    Delay(MacAddress),
    Probe(MacAddress),
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
                            if timestamp.elapsed().as_secs() < 1 {
                                continue;
                            }
                            if *attempt == 2 {
                                (*self_c.state_table.lock().unwrap()).remove(nla);
                                continue;
                            }
                            self_c.send_neighbor_solicitation(*nla);
                            (*self_c.state_table.lock().unwrap()).insert(
                                *nla,
                                NdCacheState::Incomplete(time::Instant::now(), attempt + 1),
                            );
                        }
                        NdCacheState::Reachable(_) => {}
                        NdCacheState::Stale(_) => {}
                        NdCacheState::Delay(_) => {}
                        NdCacheState::Probe(_) => {}
                    }
                }
                thread::sleep(time::Duration::from_millis(250));
            }
        });

        nd_cache
    }

    pub fn find(&self, nla: Ip6Address) -> Option<MacAddress> {
        if let Some(state) = (*self.state_table.lock().unwrap()).get(&nla) {
            match state {
                NdCacheState::Incomplete(_, _) => return None,
                NdCacheState::Reachable(lla) => return Some(*lla),
                NdCacheState::Stale(lla) => return Some(*lla),
                NdCacheState::Delay(lla) => return Some(*lla),
                NdCacheState::Probe(lla) => return Some(*lla),
            }
        }

        self.send_neighbor_solicitation(nla);
        (*self.state_table.lock().unwrap())
            .insert(nla, NdCacheState::Incomplete(time::Instant::now(), 0));

        None
    }

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
            //
            // TODO: Need to set here the src address from same subnet that the tlna address is
            //
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
}
