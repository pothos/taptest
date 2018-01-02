extern crate smoltcp;
extern crate env_logger;

use std::collections::BTreeMap;
use std::thread;
use std::io::{self, Write};
use std::time::{Instant, Duration};
use std::io::prelude::*;
use std::net::{TcpStream};
use std::os::unix::io::AsRawFd;
use smoltcp::phy::wait as phy_wait;
use smoltcp::phy::TapInterface;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};
use smoltcp::iface::{NeighborCache, EthernetInterfaceBuilder};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer, SocketSet};

/*
use smoltcp::phy::{PcapWriter, PcapSink, PcapMode, PcapLinkType};
use std::cell::RefCell;
use std::rc::Rc;
use std::fs::File;
*/


const AMOUNT: u64 = 10000000;

pub fn client() {
    thread::sleep(Duration::from_millis(199));
    let mut stream = TcpStream::connect("192.168.69.1:8080").unwrap();
    let mut inp = vec![0; 64];
    let mut read: u64 = 0;
    while read < AMOUNT {
           if read + 64u64 > AMOUNT {
                inp.resize((AMOUNT - read) as usize, 0);
            }
           match stream.read(&mut inp) {
                Ok(0) => {
                    break;
                }
                Ok(r) => {
                    read += r as u64;
                    print!("(R:{})", read);
                    io::stdout().flush().unwrap();
                }
                _ => {
                    break;
                }
            };
    }
    println!("Read {} bytes", read);
}

fn millis_since(startup_time: Instant) -> u64 {
    let duration = Instant::now().duration_since(startup_time);
    let duration_ms = (duration.as_secs() * 1000) + (duration.subsec_nanos() / 1000000) as u64;
    duration_ms
}

pub fn smoltcpserver() {
    let device = TapInterface::new("tap0").unwrap();
    let fd = device.as_raw_fd();
    let startup_time = Instant::now();
    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; 65535]);
    let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; 65535]);
    let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);
    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_addrs = [IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24)];

    /*
    let pcap_writer:Box<io::Write> = Box::new(File::create("pcapdump").expect("can not open pcapdump file"));
    let device = PcapWriter::new(device, Rc::new(RefCell::new(pcap_writer)) as Rc<PcapSink>, PcapMode::Both, PcapLinkType::Ethernet );
    */

    let mut iface = EthernetInterfaceBuilder::new(device)
            .ethernet_addr(ethernet_addr)
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();

    let mut sockets = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(tcp_socket);
    let mut tcp_active = false;

    let mut send: u64 = 0;
    let mut outp = vec![0; 64];

    loop {
        let timestamp = millis_since(startup_time);
        iface.poll(&mut sockets, timestamp).expect("poll error");

        {
            let mut socket = sockets.get::<TcpSocket>(tcp_handle);
            if !socket.is_open() {
                socket.listen(8080).unwrap();
                socket.set_keep_alive(Some(1000));
                socket.set_timeout(Some(2000));
            }

            if socket.is_active() && !tcp_active {
                println!("connection accepted");
                send = 0;
                outp.resize(64 as usize, 0);
            } else if !socket.is_active() && tcp_active {
                // is disconnected
                return;
            }
            tcp_active = socket.is_active();

            if socket.may_recv() {
                    loop {
                      if socket.can_send() && send < AMOUNT {
                            if send + 64u64 > AMOUNT {
                                outp.resize((AMOUNT - send) as usize, 0);
                            }
                            let write = socket.send_slice(&outp).unwrap();
                            send += write as u64;
                            // print!("(W:{})", send); // will sometimes let the bug disappear
                            //io::stdout().flush().unwrap();
                            if socket.can_send() {
                                if send >= AMOUNT {
                                        println!("Send {} bytes", send);
                                        break;
                                    }
                            } else { break; }
                        } else {
                          break;
                        }
                    }

            } else if socket.may_send() {
                println!("closing");
                socket.close();
            }
        }

        phy_wait(fd, iface.poll_delay(&sockets, timestamp)).expect("wait error");

    }
}

fn main() {
    env_logger::init().unwrap();
    thread::spawn(move || {
        client();
    });

    smoltcpserver();
}
