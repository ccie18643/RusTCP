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
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// Create tracker string to be used as packet identifier and increment the serial number
pub fn tracker(tag: &str, nic_name: &str, packet_sn: &mut usize) -> String {
    let color = match tag {
        "TX" => "lr",
        "RX" => "lg",
        _ => "/",
    };
    let tracker = format!(
        "<{}>[{}/{}/{:04X}]</>",
        color,
        tag,
        nic_name.to_uppercase(),
        packet_sn
    );
    *packet_sn = (*packet_sn).wrapping_add(1);
    tracker
}

/// Select IPv6 packet source address based on it's destination
pub fn ip6_select_src(
    dst: &Ip6Address,
    ip6_address_tx: &Arc<Mutex<HashSet<Ip6Address>>>,
) -> Option<Ip6Address> {
    for address in (*ip6_address_tx.lock().unwrap()).iter() {
        if address.contains(dst) {
            return Some(address.host());
        }
    }
    None
}
