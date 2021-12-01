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

mod lib;
mod protocols;
mod subsystems;

use std::thread;
use std::time::Duration;

use crate::subsystems::packet_handler;

fn main() {
    log_stack!(
        "<B>RusTCP</> - TCP/IP Stack written in <r>Rust</>, 2021 <B><y>Sebastian Majewski</>"
    );

    packet_handler::PacketHandler::new(7, 1514, "02:00:00:77:77:77".into())
        .set_ip6_address("fe80::7".into())
        .set_ip6_address("2007::7".into())
        .run();

    loop {
        thread::sleep(Duration::from_millis(1000));
    }
}
