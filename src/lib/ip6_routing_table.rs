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

use std::collections::HashMap;

struct RoutingTable {
    routing_table: HashMap<(u128, usize), usize>,
    prefix_len_table: Vec<usize>,
}

impl RoutingTable {
    fn new() -> RoutingTable {
        RoutingTable {
            routing_table: HashMap::new(),
            prefix_len_table: Vec::with_capacity(127),
        }
    }

    /// Add prefix to routing table
    fn add(mut self, prefix: u128, prefix_len: usize, next_hop_id: usize) -> RoutingTable {
        self.routing_table.insert((prefix, prefix_len), next_hop_id);
        if prefix_len != 0 {
            self.prefix_len_table.push(128 - prefix_len);
            self.prefix_len_table.sort_unstable();
        }
        self
    }

    /// Remove prefix from routing table
    fn remove(mut self, prefix: u128, prefix_len: usize) -> RoutingTable {
        self.routing_table.remove(&(prefix, prefix_len));
        self.prefix_len_table.clear();
        for (_, prefix_len) in self.routing_table.keys() {
            self.prefix_len_table.push(128 - prefix_len);
        }
        self.prefix_len_table.sort_unstable();
        self
    }

    /// Find the longest match for given address
    fn find(&self, address: u128) -> Option<&usize> {
        for n in self.prefix_len_table.iter() {
            if let Some(next_hop_id) = self.routing_table.get(&(address >> n << n, 128 - n)) {
                return Some(next_hop_id);
            }
        }
        self.routing_table.get(&(0u128, 0usize))
    }
}
