#![allow(dead_code)]

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

use crate::lib::packet::Packet;
use crate::lib::tap_io;
use crate::log_tx_ring as log;
use filedescriptor::FileDescriptor;
use std::sync::mpsc;
use std::thread;

/// TX ring structure
pub struct TxRing {
    nic_name: String,
    nic_fd: FileDescriptor,
    nic_mtu: usize,
    mpsc_from_packet_handler: mpsc::Receiver<Packet>,
}

impl TxRing {
    /// Initialize RX ring structure, spawn it in separate thread and return MPSC channel
    /// used to dequeue frames from packet_handler
    #[allow(clippy::new_ret_no_self)]
    pub fn new(nic_name: String, nic_fd: FileDescriptor, nic_mtu: usize) -> mpsc::Sender<Packet> {
        let (mpsc_to_tx_ring, mpsc_from_packet_handler) = mpsc::channel();

        thread::spawn(move || {
            TxRing {
                nic_name,
                nic_fd,
                nic_mtu,
                mpsc_from_packet_handler,
            }
            .thread();
        });

        mpsc_to_tx_ring
    }

    /// TX ring thread, dequeues packets from packet_handler and sends them to NIC device
    fn thread(&mut self) {
        log!("Thread spawned: 'tx_ring - {}'", self.nic_name);

        loop {
            let mut packet_tx = match self.mpsc_from_packet_handler.recv() {
                Ok(packet_tx) => packet_tx,
                Err(error) => {
                    log!("<CRIT> MPSC channel error: '{}'</>", error);
                    continue;
                }
            };

            packet_tx.assemble();

            if packet_tx.frame.len() > self.nic_mtu {
                log!(
                    "<CRIT>Frame send error: frame length of {} bytes exceed interface mtu {}",
                    packet_tx.frame.len(),
                    self.nic_mtu
                );
                continue;
            }

            match tap_io::write(&mut self.nic_fd, &packet_tx.frame) {
                Ok(bytes_sent) => {
                    if bytes_sent != packet_tx.frame.len() {
                        log!(
                            "<CRIT>Frame send error: {} out of {} bytes sent",
                            bytes_sent,
                            packet_tx.frame.len()
                        );
                        continue;
                    }
                    log!(
                        "<tx>[TX]</> {} - Sent frame, {} bytes",
                        packet_tx.tracker,
                        bytes_sent
                    );
                }
                Err(error) => log!("<CRIT>Frame send error: {}", error),
            }
        }
    }
}
