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

use crate::lib::packet::Packet;
use crate::lib::tap_io;
use crate::log_tx_ring as log;
use filedescriptor::FileDescriptor;
use std::sync::mpsc;
use std::thread;

/// TX ring structure
pub struct TxRing {
    nic_name: String,
    nic_mtu: usize,
    nic_fd: FileDescriptor,
    mpsc_from_packet_handler: mpsc::Receiver<Packet>,
}

impl TxRing {
    /// Initialize RX ring structure, spawn it in separate thread and return MPSC channel
    /// used to dequeue frames from packet_handler
    #[allow(clippy::new_ret_no_self)]
    pub fn new(nic_name: String, nic_mtu: usize, nic_fd: FileDescriptor) -> mpsc::Sender<Packet> {
        let (mpsc_to_tx_ring, mpsc_from_packet_handler) = mpsc::channel();

        thread::spawn(move || {
            TxRing {
                nic_name,
                nic_mtu,
                nic_fd,
                mpsc_from_packet_handler,
            }
            .tx_ring_thread();
        });

        mpsc_to_tx_ring
    }

    /// TX ring thread, dequeues packets from packet_handler and sends them to NIC device
    fn tx_ring_thread(&mut self) {
        log!("<lv>Thread spawned: 'tx_ring - {}'</>", self.nic_name);

        loop {
            let mut packet_tx = self
                .mpsc_from_packet_handler
                .recv()
                .unwrap_or_else(|error| {
                    log!("<CRIT>MPSC channel error: '{}'</>", error);
                    panic!();
                });

            packet_tx.assemble();

            if packet_tx.frame.len() > self.nic_mtu {
                log!(
                    "<CRIT>Frame send error: frame length of {} bytes exceed interface mtu {}</>",
                    packet_tx.frame.len(),
                    self.nic_mtu
                );
                panic!();
            }

            match tap_io::write(&mut self.nic_fd, &packet_tx.frame) {
                Ok(bytes_sent) => {
                    if bytes_sent != packet_tx.frame.len() {
                        log!(
                            "<CRIT>Frame send error: {} out of {} bytes sent</>",
                            bytes_sent,
                            packet_tx.frame.len()
                        );
                        panic!();
                    }
                    log!(
                        "<tx>[TX]</> {} - Sent frame, {} bytes",
                        packet_tx.tracker,
                        bytes_sent
                    );
                }
                Err(error) => {
                    log!("<CRIT>Frame send error: {}</>", error);
                    panic!();
                }
            }
        }
    }
}
