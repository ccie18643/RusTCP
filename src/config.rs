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

pub const ND_CACHE__INCOMPLETE_RETRY_TIME: u64 = 1;
pub const ND_CACHE__INCOMPLETE_RETRY_LIMIT: usize = 2;
pub const ND_CACHE__REACHABLE_TIME: u64 = 45;
pub const ND_CACHE__DELAY_TIME: u64 = 5;
pub const ND_CACHE__PROBE_RETRY_TIME: u64 = 1;
pub const ND_CACHE__PROBE_RETRY_LIMIT: usize = 2;
pub const ND_CACHE__TIME_LOOP_DELAY: u64 = 100;
