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
use crate::lib::util;
use crate::log_rx_ring as log;
use core::panic;
use filedescriptor::FileDescriptor;
use std::sync::mpsc;
use std::thread;

/// RX ring structure
pub struct RxRing {
    nic_name: String,
    nic_mtu: usize,
    nic_fd: FileDescriptor,
    packet_sn: usize,
    mpsc_to_packet_handler: mpsc::Sender<Packet>,
}

impl RxRing {
    /// Initialize RX ring structure, spawn it in separate thread
    /// and return MPSC channel used to enqueue frames to packet_handler
    #[allow(clippy::new_ret_no_self)]
    pub fn new(nic_name: String, nic_mtu: usize, nic_fd: FileDescriptor) -> mpsc::Receiver<Packet> {
        let (mpsc_to_packet_handler, mpsc_from_rx_ring) = mpsc::channel();

        thread::spawn(move || {
            RxRing {
                nic_name,
                nic_mtu,
                nic_fd,
                packet_sn: 0,
                mpsc_to_packet_handler,
            }
            .rx_ring_thread();
        });

        mpsc_from_rx_ring
    }

    /// Pick up packets from NIC device and enqueue them for packet_handler
    fn rx_ring_thread(&mut self) {
        log!("<lv>Thread spawned: 'rx_ring - {}'</>", self.nic_name);

        loop {
            match tap_io::read(&mut self.nic_fd) {
                Ok(frame_rx) => {
                    if frame_rx.len() > self.nic_mtu {
                        log!("<CRIT>Frame receive error: frame lenght of {} bytes exceeds interface mtu {}</>", frame_rx.len(), self.nic_mtu);
                        panic!();
                    }

                    let mut packet_rx = Packet::new(
                        frame_rx,
                        util::tracker("RX", &self.nic_name, &mut self.packet_sn),
                    );

                    packet_rx.parse();

                    log!(
                        "<rx>[RX]</> {} - Received frame, {} bytes",
                        packet_rx.tracker,
                        packet_rx.frame.len()
                    );

                    if let Err(error) = self.mpsc_to_packet_handler.send(packet_rx) {
                        log!("<CRIT>MPSC channel error: '{}'</>", error);
                        panic!();
                    }
                }
                Err(error) => {
                    log!("<CRIT>Frame receive error: '{}'</>", error);
                    panic!();
                }
            }
        }
    }
}
