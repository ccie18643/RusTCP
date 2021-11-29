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

use lazy_static::lazy_static;
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::SystemTime;

#[macro_export]
macro_rules! log {
    ($chanel:expr, $($arg:tt)*) => ($crate::lib::logger::LOGGER.log($chanel, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_stack {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::Stack, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_timer {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::Timer, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_rx_ring {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::RxRing, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_tx_ring {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::TxRing, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_arp_cache {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::ArpCache, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_nd_cache {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::NdCache, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_ether {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::Ether, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_ip4 {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::Ip4, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_ip6 {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::Ip6, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_icmp4 {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::Icmp4, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_icmp6 {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::Icmp6, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_udp {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::Udp, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_tcp {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::Tcp, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_socket {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::Socket, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_tcp_session {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::TcpSession, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_service {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::Service, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_client {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::Client, &format!("{}", std::format_args!($($arg)*))));
}

#[macro_export]
macro_rules! log_packet_handler {
    ($($arg:tt)*) => ($crate::lib::logger::LOGGER.log($crate::lib::logger::LogChanel::PacketHandler, &format!("{}", std::format_args!($($arg)*))));
}

lazy_static! {
    pub static ref LOGGER: Logger<'static> = Logger::new(&[
        LogChanel::Stack,
        LogChanel::Timer,
        LogChanel::RxRing,
        LogChanel::TxRing,
        LogChanel::ArpCache,
        LogChanel::NdCache,
        LogChanel::Ether,
        LogChanel::Arp,
        LogChanel::Ip4,
        LogChanel::Ip6,
        LogChanel::Icmp4,
        LogChanel::Icmp6,
        LogChanel::Udp,
        LogChanel::Tcp,
        LogChanel::Socket,
        LogChanel::TcpSession,
        LogChanel::Service,
        LogChanel::Client,
        LogChanel::PacketHandler,
    ]);
}

/// Structure defining various log channels
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum LogChanel {
    Stack,
    Timer,
    RxRing,
    TxRing,
    ArpCache,
    NdCache,
    Ether,
    Arp,
    Ip4,
    Ip6,
    Icmp4,
    Icmp6,
    Udp,
    Tcp,
    Socket,
    TcpSession,
    Service,
    Client,
    PacketHandler,
}

impl std::fmt::Display for LogChanel {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LogChanel::Stack => "stack".fmt(f),
            LogChanel::Timer => "timer".fmt(f),
            LogChanel::RxRing => "rx-ring".fmt(f),
            LogChanel::TxRing => "tx-ring".fmt(f),
            LogChanel::ArpCache => "arp-c".fmt(f),
            LogChanel::NdCache => "nd-c".fmt(f),
            LogChanel::Ether => "ether".fmt(f),
            LogChanel::Arp => "arp".fmt(f),
            LogChanel::Ip4 => "ip4".fmt(f),
            LogChanel::Ip6 => "ip6".fmt(f),
            LogChanel::Icmp4 => "icmp4".fmt(f),
            LogChanel::Icmp6 => "icmp6".fmt(f),
            LogChanel::Udp => "udp".fmt(f),
            LogChanel::Tcp => "tcp".fmt(f),
            LogChanel::Socket => "socket".fmt(f),
            LogChanel::TcpSession => "tcp-ss".fmt(f),
            LogChanel::Service => "service".fmt(f),
            LogChanel::Client => "client".fmt(f),
            LogChanel::PacketHandler => "p_hndlr".fmt(f),
        }
    }
}

/// Logger structure
pub struct Logger<'a> {
    styles: HashMap<&'a str, &'a str>,
    start_time: SystemTime,
    chanels: HashSet<LogChanel>,
}

impl Logger<'_> {
    pub fn new(chanels: &[LogChanel]) -> Logger<'static> {
        Logger {
            styles: [
                ("</>", "\x1b[0m"),
                ("<WARN>", "\x1b[1m\x1b[93m"),
                ("<CRIT>", "\x1b[1m\x1b[41m"),
                ("<INFO>", "\x1b[1m"),
                ("<B>", "\x1b[1m"),
                ("<I>", "\x1b[3m"),
                ("<U>", "\x1b[4m"),
                ("<r>", "\x1b[31m"),
                ("<lr>", "\x1b[91m"),
                ("<g>", "\x1b[32m"),
                ("<lg>", "\x1b[92m"),
                ("<y>", "\x1b[33m"),
                ("<ly>", "\x1b[93m"),
                ("<b>", "\x1b[34m"),
                ("<lb>", "\x1b[94m"),
                ("<c>", "\x1b[36m"),
                ("<lc>", "\x1b[96m"),
                ("<v>", "\x1b[35m"),
                ("<lv>", "\x1b[95m"),
                ("<rx>", "\x1b[1m\x1b[92m"),
                ("<tx>", "\x1b[1m\x1b[91m"),
            ]
            .iter()
            .cloned()
            .collect(),
            start_time: SystemTime::now(),
            chanels: chanels.iter().cloned().collect(),
        }
    }

    pub fn log(&self, chanel: LogChanel, message: &str) {
        if self.chanels.contains(&chanel) {
            let time = self.start_time.elapsed().expect("System time error");
            let mut message = format!(
                " <g>{:04}.{:02}</> | <b>{:7}</> | {}</>",
                time.as_secs(),
                time.subsec_nanos() as u64 / 10_000_000,
                chanel,
                message,
            );
            for (style, term) in self.styles.iter() {
                message = message.replace(style, term);
            }
            println!("{}", message);
        }
    }
}
