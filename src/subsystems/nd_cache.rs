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
use crate::lib::packet::Packet;
use crate::log_nd_cache as log;
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time;

pub enum NdCacheState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
}

pub struct NdCache {
    state_table: Arc<Mutex<HashMap<Ip6Address, NdCacheState>>>,
}

impl NdCache {
    pub fn new(mpsc_to_tx_ring: mpsc::Sender<Packet>, nic_name: String) -> NdCache {
        let nd_cache = NdCache {
            state_table: Arc::new(Mutex::new(HashMap::with_capacity(256))),
        };

        {
            let state_table = nd_cache.state_table.clone();
            thread::spawn(move || nd_cache_thread(state_table, mpsc_to_tx_ring, nic_name));
        }

        nd_cache
    }
}

fn nd_cache_thread(
    _state_table: Arc<Mutex<HashMap<Ip6Address, NdCacheState>>>,
    _mpsc_to_tx_ring: mpsc::Sender<Packet>,
    nic_name: String,
) {
    log!("<lv>Thread spawned: 'nd_cache - {}'</>", nic_name);

    loop {
        thread::sleep(time::Duration::from_millis(1000));
    }
}
