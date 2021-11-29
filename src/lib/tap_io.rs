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

use filedescriptor::FileDescriptor;
use std::io::Error;
use std::io::Read;
use std::io::Write;
use utuntap::tap;

const MAX_FRAME_RX_LEN: usize = 2048;

/// Open TAP interface
pub fn open(num: u8) -> Result<(String, FileDescriptor), Error> {
    let (nic_fd, nic_name) = tap::OpenOptions::new()
        .packet_info(false)
        .number(num)
        .open()?;
    Ok((nic_name, FileDescriptor::dup(&nic_fd).unwrap()))
}

/// Read from TAP interface
pub fn read(fd: &mut FileDescriptor) -> Result<Vec<u8>, Error> {
    let mut frame_rx = vec![0u8; MAX_FRAME_RX_LEN];
    let frame_rx_len = fd.read(&mut frame_rx)?;
    frame_rx.truncate(frame_rx_len);
    Ok(frame_rx)
}

/// Write to TAP interface
pub fn write(fd: &mut FileDescriptor, frame_tx: &[u8]) -> Result<usize, Error> {
    fd.write(frame_tx)
}
