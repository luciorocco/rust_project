mod cli;

use std::any::Any;
use std::{process, result, time};
use std::borrow::{Borrow, BorrowMut};
use pcap::{Device, Capture, PacketCodec, PacketHeader, Packet, Address, Active};
use std::io::{stdin} ;
use std::ops::Deref;
use std::str::from_utf8;
use std::string::FromUtf8Error;
use chrono::prelude::*;
use clap::builder::Str;
use pktparse::*;
use pktparse::ipv4::{IPv4Header, parse_ipv4_header};
use pktparse::ipv6::parse_ipv6_header;
use pktparse::tcp::parse_tcp_header;
use pktparse::udp::parse_udp_header;
use etherparse::*;
use pktparse::arp::parse_arp_pkt;
use pktparse::ethernet::{EthernetFrame, parse_ethernet_frame, parse_vlan_ethernet_frame, VlanEthernetFrame};
use pktparse::icmp::parse_icmp_header;
use clap::Parser;
use pcap_parser::nom::IResult;
use std::collections::HashMap;
use std::path::PathBuf;
use std::ptr::null;
use std::fs::{File, OpenOptions};
use std::future::pending;
use dirs::desktop_dir;
use serde::{Serialize, Deserialize};
use serde_json::Result;
use serde_json_any_key::*;
use regex::Regex;
use std::thread;
use std::thread::Builder;
use std::sync::{Arc, Condvar, mpsc, Mutex, MutexGuard};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError};
use chrono::Duration;
use pcap_parser::nom::Err::Error;
use serde::de::Unexpected::Option;
use std::io::prelude::*;
use std::collections::hash_map::Entry::{Occupied, Vacant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppProtocol {
    /// File Transfer Protocol
    FTP,
    /// Secure Shell
    SSH,
    /// Telnet
    Telnet,
    /// Simple Mail Transfer Protocol
    SMTP,
    /// Terminal Access Controller Access-Control System
    TACACS,
    /// Domain Name System
    DNS,
    /// Dynamic Host Configuration Protocol
    DHCP,
    /// Trivial File Transfer Protocol
    TFTP,
    /// Hypertext Transfer Protocol
    HTTP,
    /// Post Office Protocol
    POP,
    /// Network Time Protocol
    NTP,
    /// NetBIOS
    NetBIOS,
    /// Post Office Protocol 3 over TLS/SSL
    POP3S,
    /// Internet Message Access Protocol
    IMAP,
    /// Simple Network Management Protocol
    SNMP,
    /// Border Gateway Protocol
    BGP,
    /// Lightweight Directory Access Protocol
    LDAP,
    ///Hypertext Transfer Protocol over TLS/SSL
    HTTPS,
    /// Lightweight Directory Access Protocol over TLS/SSL
    LDAPS,
    /// File Transfer Protocol over TLS/SSL
    FTPS,
    /// Multicast DNS
    #[allow(non_camel_case_types)]
    mDNS,
    ///Internet Message Access Protocol over TLS/SSL
    IMAPS,
    /// Simple Service Discovery Protocol
    SSDP,
    /// Extensible Messaging and Presence Protocol |
    XMPP,
    /// not identified
    Other,
}
pub fn from_port_to_application_protocol(port: u16) -> AppProtocol {
    match port {
        20..=21 => AppProtocol::FTP,
        22 => AppProtocol::SSH,
        23 => AppProtocol::Telnet,
        25 => AppProtocol::SMTP,
        49 => AppProtocol::TACACS,
        53 => AppProtocol::DNS,
        67..=68 => AppProtocol::DHCP,
        69 => AppProtocol::TFTP,
        80 | 8080 => AppProtocol::HTTP,
        109..=110 => AppProtocol::POP,
        123 => AppProtocol::NTP,
        137..=139 => AppProtocol::NetBIOS,
        143 | 220 => AppProtocol::IMAP,
        161..=162 | 199 => AppProtocol::SNMP,
        179 => AppProtocol::BGP,
        389 => AppProtocol::LDAP,
        443 => AppProtocol::HTTPS,
        636 => AppProtocol::LDAPS,
        989..=990 => AppProtocol::FTPS,
        993 => AppProtocol::IMAPS,
        995 => AppProtocol::POP3S,
        1900 => AppProtocol::SSDP,
        5222 => AppProtocol::XMPP,
        5353 => AppProtocol::mDNS,
        _ => AppProtocol::Other,
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct k{
    pub type_eth : String,
    pub source_address : String,
    pub destination_address: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub operation : String,
    pub protocol: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct summary{
    pub ts_i: String,
    pub ts_f: String,
    pub len: u32,
}


type Summary = HashMap<k, summary>;

/// Represents a owned packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketOwned {
    pub header: PacketHeader,
    pub data: Box<[u8]>,
}

/// Simple codec that tranform [`pcap::Packet`] into [`PacketOwned`]
pub struct Codec;

impl PacketCodec for Codec {
    type Item = PacketOwned;

    fn decode(&mut self, packet: Packet) -> Self::Item {
        PacketOwned {
            header: *packet.header,
            data: packet.data.into(),
        }
    }
}

fn ts_toDate(ts:i64)-> String{
    let naive = NaiveDateTime::from_timestamp_opt(ts,0).unwrap();
    let _datetime: DateTime<Utc> = DateTime::from_utc(naive,Utc);
    let datetime: DateTime<Local> = DateTime::from(_datetime);
    let newdate = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
    newdate
}

fn ethernetDecode(ethernet_u8: &[u8]) -> VlanEthernetFrame{
    let ethernet = match parse_vlan_ethernet_frame(ethernet_u8) {
        Ok(x) => {x.1}
        Err(e) => {
            println!("ERRORE");
            process::exit(0);
        }
    };

    //println!("{:x?}", ethernet);
    ethernet
}

fn ipv4Decode(ipv4_u8: &[u8], data: &[u8], src: &mut String, dst: &mut String, prot: &mut String, srp: &mut u16, dsp: &mut u16){
    let ipv4 = parse_ipv4_header(ipv4_u8).unwrap();
    *src = ipv4.1.source_addr.to_string();
    *dst = ipv4.1.dest_addr.to_string();
    //println!("{:?}",ipv4.1);

    match ipv4.1.protocol {
        pktparse::ip::IPProtocol::TCP => {
            let tcp_u8 = &data[(14 + (ipv4.1.ihl as usize) * 4)..];
            let tcp = parse_tcp_header(tcp_u8).unwrap();
            *prot = "TCP".to_string();
            *srp = tcp.1.source_port;
            *dsp = tcp.1.dest_port;
            //println!("{:?}", tcp.1);
        },
        pktparse::ip::IPProtocol::UDP => {
            let udp_u8 = &data[(14 + (ipv4.1.ihl as usize) * 4)..];
            let udp = parse_udp_header(udp_u8).unwrap();
            *prot = "UDP".to_string();
            *srp = udp.1.source_port;
            *dsp = udp.1.dest_port;
            // println!("{:?}", udp.1);
        }

        pktparse::ip::IPProtocol::IGMP =>{
            *prot = "IGMP".to_string();
            // println!("IGMP");
        },

        pktparse::ip::IPProtocol::ICMP => {
            let icmp_u8 = &data[(14 + (ipv4.1.ihl as usize) * 4)..];
            let icmp = parse_icmp_header(icmp_u8).unwrap();
            *prot = "ICMP".to_string();
            //println!("{:?}", icmp.1);
        },

        _=> *prot = "IPv4 PROTOCOL unknown".to_string()
    }
}

fn ipv6Decode(ipv6_u8: &[u8], data: &[u8], src: &mut String, dst: &mut String, prot: &mut String, srp: &mut u16, dsp: &mut u16){
    let ipv6 = parse_ipv6_header(ipv6_u8).unwrap();
    *src = ipv6.1.source_addr.to_string();
    *dst = ipv6.1.dest_addr.to_string();
    //println!("{:?}",ipv6.1);

    match ipv6.1.next_header {
        pktparse::ip::IPProtocol::TCP => {
            let tcp_u8 = &data[54..];
            let tcp = parse_tcp_header(tcp_u8).unwrap();
            *prot = "TCP".to_string();
            *srp = tcp.1.source_port;
            *dsp = tcp.1.dest_port;
            // println!("{:?}", tcp.1);
        },
        pktparse::ip::IPProtocol::UDP => {
            let udp_u8 = &data[54..];
            let udp = parse_udp_header(udp_u8).unwrap();
            *prot = "UDP".to_string();
            *srp = udp.1.source_port;
            *dsp = udp.1.dest_port;
            // println!("{:?}", udp.1);
        }

        pktparse::ip::IPProtocol::ICMP6 =>{
            *prot = "ICMP6".to_string();
           // println!("ICMP6");
        },

        _=> *prot = "IPv6 PROTOCOL unknown".to_string()
    }
}

fn arpDecode(arp_u8: &[u8], src: &mut String, dst: &mut String, operation :&mut String){
    let arp = parse_arp_pkt(arp_u8).unwrap();
    *src = arp.1.src_addr.to_string();
    *dst = arp.1.dest_addr.to_string();
    match arp.1.operation {
        pktparse::arp::Operation::Reply => *operation = "Reply".to_string(),
        pktparse::arp::Operation::Request => *operation ="Request".to_string(),
        pktparse::arp::Operation::Other(p) => *operation = "Other".to_string()
    }
}


fn try_toDecode(data : &[u8], sum: &mut Summary, newdate: String, i: u32){
    let ethernet = ethernetDecode( &data[..14]);
    let mut tpe: String = String::new();
    let mut src: String = String::new();
    let mut dst: String = String::new();
    let mut prot: String = String::new();
    let mut operation: String = "".to_string();
    let mut srp: u16 = 0;
    let mut dsp: u16 = 0;

    match ethernet.ethertype {
        pktparse::ethernet::EtherType::IPv4 => {
            tpe = "IPv4".to_string();
            ipv4Decode(&data[14..], data, &mut src, &mut dst, &mut prot, &mut srp, &mut dsp);
        },
        pktparse::ethernet::EtherType::IPv6 => {
            tpe = "IPv6".to_string();
            ipv6Decode(&data[14..], data,  &mut src, &mut dst, &mut prot, &mut srp, &mut dsp);
        },

        pktparse::ethernet::EtherType::ARP =>{
            tpe = "ARP".to_string();
            arpDecode(&data[14..],  &mut src, &mut dst, &mut operation);
        },
        _ => println!("ETHERNET TYPE unknown")
    }

    match sum.entry(k {
        type_eth: tpe.clone(),
        source_address: dst.clone(),
        destination_address: src.clone(),
        source_port: dsp.clone(),
        dest_port: srp.clone(),
        operation: operation.clone(),
        protocol: prot.clone()
    }) {
        Occupied(e) => {
            sum.entry(k {
                type_eth: tpe.clone(),
                source_address: dst.clone(),
                destination_address: src.clone(),
                source_port: dsp.clone(),
                dest_port: srp.clone(),
                operation: operation.clone(),
                protocol: prot.clone()
            }).and_modify(|x| {
                x.len += i;
                x.ts_f = newdate.clone();
            });
        },
        Vacant(e) => {
            sum.entry(k {
                type_eth: tpe.clone(),
                source_address: src.clone(),
                destination_address: dst.clone(),
                source_port: srp.clone(),
                dest_port: dsp.clone(),
                operation: operation.clone(),
                protocol: prot.clone()
            }).and_modify(|x| {
                x.len += i;
                x.ts_f = newdate.clone();
            }).or_insert(summary {
                ts_i: newdate.clone(),
                ts_f: newdate.clone(),
                len: i,
            });
        }
    }

   //sum.iter().for_each(|x|println!("{:?}",x));

}


fn parse_packet(mut sum: &mut Summary, cv1: &Arc<(Mutex<bool>, Condvar)>, atm: &Arc<AtomicBool>, file: &mut PathBuf, packet: &PacketOwned){

    let (lock1, cvar1) = &**cv1;
    //println!("k");

    if(atm.load(Ordering::Relaxed)){
        let mut started = lock1.lock().unwrap();
        while  !*started {
            started = cvar1.wait(started).unwrap();
        }
        println!("AGGIORNO FILE!");
        save_on_file(file, &sum);
        atm.store(false, Ordering::Relaxed);
        *started = false;
        cvar1.notify_all();
    }



    let newdate = ts_toDate(packet.header.ts.tv_sec as i64);
    try_toDecode(&packet.data, &mut sum, newdate, packet.header.len);
}



fn start_sniffing(atm2: &Arc<AtomicBool>, started: &mut MutexGuard<bool>, cap: &mut Capture<Active>, cv: &&Condvar, tx: &Sender<PacketOwned>, filter: &String){

    let lt = cap.get_datalink();
    //println!("{:?}", lt.0 );
    //println!("{:?}", lt.get_name().unwrap());
    //println!("{:?}", lt.get_description().unwrap());
    cap.filter(filter, true).unwrap();
    //let (lock, cvar) = &**cv;
    println!(" SNIFFING");
    while let packet = cap.next_packet() {

        if (atm2.load(Ordering::Relaxed)) {
            **started = false;
            cv.notify_all();
            break
        }

        match packet {
            Ok(p) => {
                let pa = Codec.decode(p);
                tx.send(pa);
            }
            Err(e) => {
                match e{
                    _ => {}
                }
            }
        }
    }

}

fn capturedevice(device: Device) -> Capture<Active>{
    println!("{:?}", device);
    let mut cap = Capture::from_device(device)
        .unwrap()

        .promisc(true)

        .immediate_mode(true)

        .open()

        .unwrap()
        ;
    cap
}

fn chose_device()-> Device{
    let mut s = String::new();
    let device = pcap::Device::list().unwrap();
    println!("Choose your device");
    device.iter().enumerate().for_each(|x|{
        if(x.1.flags.connection_status == pcap::ConnectionStatus::Connected){
            match x.1.addresses.first() {
                Some(y) => {println!("Num: {}, Desc: {:?},  Address = ( {:?} )", x.0 , x.1.desc.as_ref().unwrap(), x.1.addresses.first().unwrap().addr)},
                None => {println!("Num: {},  Desc: {:?},  Address = ( {:?} )", x.0 , x.1.desc.as_ref().unwrap(), x.1.addresses.first())}
            }
            ;
        }
    });

    loop{
        //TAKE INPUT
        stdin().read_line(&mut s).ok().expect("Failed to read line");
        //CHECK INPUT AND START SNIFFING
        match s.trim().parse::<usize>() {
            Ok(ok) => {
                let i = s.trim().parse::<usize>().ok().unwrap();
                if i <= device.len() -1 {
                    return device[i].clone();
                } else {
                    println!("Please insert a valid number!");
                    s.clear();
                    continue
                }
            },
            Err(e) => {
                println!("Please insert a number!");
                s.clear();
                continue
            }
        }
    }
}

fn create_file(p : PathBuf) -> File{
    let mut file = match File::create(p){
        Ok(p) => p,
        Err(e)=> {
            println!("{:?}", e);
            process::exit(1);
        }
    };
    file
}

fn save_on_file(file: &mut PathBuf, sum: &Summary){
    let mut file_op= OpenOptions::new()
        .write(true)
        .append(true)
        .open(&file)
        .unwrap();

    writeln!(&file_op, "--------------------------------------------------------------------------------------------------------------------------------------------------------------").unwrap();
    writeln!(&file_op, "--------------------------------------------------------------------------------------------------------------------------------------------------------------").unwrap();

    sum.iter().for_each(|x|{
        writeln!(&file_op,"\n");

        if x.0.type_eth.clone() == "ARP".to_string() {
            writeln!(&file_op, " Type Ethernet : {}, Initial Time Stamp : {}, Final Time Stamp : {}, Total Lenght :{} \n Source : {} -> Destination : {}, Operation : {}  ",
                     x.0.type_eth, x.1.ts_i, x.1.ts_f, x.1.len, x.0.source_address, x.0.destination_address, x.0.operation).unwrap();
        }else{
            let mut ap_protocol= match from_port_to_application_protocol(x.0.dest_port) {
                x if x != AppProtocol::Other =>{x},
                _ => {
                    from_port_to_application_protocol(x.0.source_port)
                }
            };
            writeln!(&file_op, " Type Ethernet : {}, Initial Time Stamp : {}, Final Time Stamp : {}, Total Lenght :{} \n Source : {}_{} -> Destination : {}_{}, Protocol : {}, Application Protocol : {:?}  ",
                     x.0.type_eth, x.1.ts_i, x.1.ts_f, x.1.len , x.0.source_address, x.0.source_port, x.0.destination_address, x.0.dest_port, x.0.protocol, ap_protocol).unwrap();
        }
    });
    println!("GENERATED REPORT...");
}

fn wait_pause(cv: Arc<(Mutex<bool>, Condvar)>, cv6: Arc<(Mutex<bool>, Condvar)>, atm: &Arc<AtomicBool>, ext: &Arc<AtomicBool>, sender: Sender<String>){
    let mut s = String::new();
    let (lock,cvar ) = &*cv;

    'outer: loop{
        println!("Press P for pause or E for exit and save on file");
        //TAKE INPUT
        stdin().read_line(&mut s).ok().expect("Failed to read line");
        //CHECK INPUT AND START SNIFFING
        match s.trim().to_ascii_lowercase().as_str() {
            "p" => {
                s.clear();
                atm.store(true, Ordering::Relaxed);
                let mut guard = cvar.wait_while(lock.lock().unwrap(),|pending|{
                    *pending
                }).unwrap();
                'inner : loop{
                    println!("Press R for resume or E to exit..");
                    stdin().read_line(&mut s).ok().expect("Failed to read line");
                    match s.trim().to_ascii_lowercase().as_str() {
                        "r" => {
                            s.clear();
                            atm.store(false, Ordering::Relaxed);
                            *guard = true;
                            cvar.notify_all();
                            break 'inner
                        },
                        "e" => {
                            ext.store(true, Ordering::Relaxed);
                            *guard = true;
                            cvar.notify_all();
                            let (lock1,cvar1 ) = &*cv6;
                            let mut started = lock1.lock().unwrap();
                            *started = false;
                            cvar1.notify_all();
                            break 'outer
                        }
                        _ => {
                            s.clear();
                            println!("Command Not Found...");
                            continue
                        }
                    }

                }
            },
            "e" => {
                ext.store(true, Ordering::Relaxed);
                atm.store(true, Ordering::Relaxed);
                let mut guard = cvar.wait_while(lock.lock().unwrap(),|pending|{
                    *pending
                }).unwrap();
                *guard = true;
                cvar.notify_all();
                break 'outer
            }
            _ => {
                s.clear();
                println!("Command Not Found...");
                continue
            }
        }
    }
    sender.send("e".to_string());
}



fn main() {
    let args = cli::RustArgs::parse();
    //PAUSE
    let cv = Arc::new((Mutex::new(true), Condvar::new()));
    let mut cv2 = cv.clone();
    let  atm3 = Arc::new(AtomicBool::new(false));
    let atm4 = Arc::clone(&atm3);
    //DURATION
    let cv3 = Arc::new((Mutex::new(false), Condvar::new()));
    let mut cv4 = cv3.clone();
    let mut cv6 = Arc::clone(&cv3);
    let atm = Arc::new(AtomicBool::new(false));
    let atm2 = Arc::clone(&atm);

    let (sender, receiver) = mpsc::channel();

    //EXIT
    let ext_atm = Arc::new(AtomicBool::new(false));
    let ext_atm1 = Arc::clone(&ext_atm);
    let ext_atm2 = Arc::clone(&ext_atm);
    let ext_atm3 = Arc::clone(&ext_atm);

    //FOR PARSE PACKET
    let (tx, rx) : (Sender<PacketOwned>, Receiver<PacketOwned>) = mpsc::channel();



    //SUMMARY PACKET
    let mut sum : Summary = HashMap::new();


    let mut  file = match args.path {
        Some(p) => {
            create_file(p.clone());
            p
        },
        None => {
            let mut x = dirs::desktop_dir().unwrap();
            x.push("sniff.txt");
            create_file(x.clone());
            x
        }
    };

    let duration = match args.duration{
        None  => {
            let mut x : u64 = 10;
            x
        }
        Some(s) => s as u64,

    };

    let filter = match args.filter{
        Some(s) => s,
        None => {
            let mut x = "".to_string();
            x
        }
    };

    let device = chose_device();
    let mut capture_device = capturedevice(device);

    let t1 = thread::Builder::new().name("t1".into()).spawn(move || loop {
        if !ext_atm.load(Ordering::Relaxed){
            let(lock, cvar) = &*cv2;
            let mut started = lock.lock().unwrap();
            while !*started {
                started = cvar.wait(started).unwrap();
            }
            if ext_atm.load(Ordering::Relaxed){println!("FINISH SNIFFING");break}
            println!("START SNIFFING");
            start_sniffing(&atm4, &mut started, &mut capture_device, &cvar, &tx ,&filter);
        }else {
            println!("FINISH SNIFFING");
            break;
        }
    }).unwrap();


    let t2 = thread::Builder::new().name("t2".into()).spawn(move || {
        wait_pause( cv, cv6, &atm3, &ext_atm1, sender);
        println!("FINISH WAIT COMMAND");
    }).unwrap();


    let t4 = thread::Builder::new().name("t4".into()).spawn(move || loop{
        if(!ext_atm3.load(Ordering::Relaxed)){
            match rx.try_recv(){
                Ok(packet) => {parse_packet( &mut sum ,&cv4, &atm2,  &mut file,  &packet)},
                Err(TryRecvError::Disconnected) => {println!("DISCONNESSO")},
                Err(TryRecvError::Empty) => {}
            }
        }else {
            println!("UPDATE FILE AND THEN EXIT!");
            save_on_file(&mut file, &sum);
            println!("FINISH PARSE PACKET AND UPDATE FILE");
            break
        }

    }).unwrap();


    let t3 = thread::Builder::new().name("t3".into()).spawn(move || loop {
        if !ext_atm2.load(Ordering::Relaxed){
            //thread::sleep(time::Duration::from_secs(duration));
            match receiver.recv_timeout(time::Duration::from_secs(duration)) {
                Err(RecvTimeoutError::Timeout) => {
                    let (lock,cvar ) = &*cv3;
                    let mut started = lock.lock().unwrap();
                    if ext_atm2.load(Ordering::Relaxed){println!("FINISH DURATION ");break};
                    println!("FINISH WAIT DURATION...");
                    atm.store(true,Ordering::Relaxed);
                    *started = true;
                    cvar.notify_all();
                    while *started {
                        started = cvar.wait(started).unwrap();
                    }
                    println!("PROVAAAA");
                }
                Err(RecvTimeoutError::Disconnected) => {
                    println!("DISCONNECTED");
                    break;
                }
                Ok(x) => {
                    println!("FINISH DURATION");
                    break;
                }
            }

        }else{
            println!("FINISH DURATION ");
            break
        }

    }).unwrap();

    t3.join().unwrap();
    t1.join().unwrap();
    t2.join().unwrap();
    t4.join().unwrap();

    println!("EXIT");

}