mod cli;
mod sniff;
mod wait_input;
mod parse;
mod savefile;
mod structs;

use std::any::Any;
use std::{fs, process, result, time};
use std::borrow::{Borrow, BorrowMut};
use pcap::{Device, Capture, PacketCodec, PacketHeader, Packet, Address, Active, DeviceFlags};
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
use std::path::{Path, PathBuf};
use std::ptr::null;
use std::fs::{create_dir_all, File, OpenOptions};
//use std::future::pending;
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
use std::rc::Rc;



fn capturedevice(device: Device) -> Capture<Active>{
    println!("{:?}", device.addresses.first().unwrap());
    let mut cap = Capture::from_device(device)
        .expect("Capture initialization error\n\r")

        .promisc(true)

        .immediate_mode(true)

        .open()
        ;

    let cap1 = match cap {
        Ok(x) => x,
        Err(e) => {
            println!("{:?}",e);
            process::exit(1);
        }
    };
    match cap1.get_datalink(){
        pcap::Linktype::ETHERNET =>{},
        _ => {
            println!("Please select a ethernet Linktypr");
            process::exit(1);

        }
    }
    cap1
}

fn chose_device()-> Device{
    let mut s = String::new();
    let device = pcap::Device::list().unwrap();
    println!("");
    println!("Please select your device by choosing among the following numbers:");
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


fn main() {
    //COMMAND RUST
    let args = cli::RustArgs::parse();
    //PAUSE
    let cv = Arc::new((Mutex::new(true), Condvar::new()));
    let mut cv2 = cv.clone();
    let  atm3 = Arc::new(AtomicBool::new(false));
    let atm4 = Arc::clone(&atm3);
    //DURATION
    let cv3 = Arc::new((Mutex::new(false), Condvar::new()));
    let mut cv6 = Arc::clone(&cv3);

    let (sender, receiver) = mpsc::channel();

    //EXIT
    let ext_atm = Arc::new(AtomicBool::new(false));
    let ext_atm1 = Arc::clone(&ext_atm);
    let ext_atm2 = Arc::clone(&ext_atm);
    let ext_atm3 = Arc::clone(&ext_atm);

    //FOR PARSE PACKET
    let (tx, rx) : (Sender<structs::packetow::PacketOwned>, Receiver<structs::packetow::PacketOwned>) = mpsc::channel();



    //SUMMARY PACKET
    let mut sum : Arc<Mutex<structs::summaryf::Summary>> = Arc::new(Mutex::new(HashMap::new()));
    let mut sum_save = Arc::clone(&sum);


    let mut file = match args.path {
        Some(p) => {
            create_file(p.clone());
            println!("CREATE FILE IN : {}", p.display());
            p
        },
        None => {
            let mut x = dirs::desktop_dir().unwrap();

            let mut string_path= x.to_str().unwrap().to_string();
            string_path.push_str(r"\sniffing");

            if !Path::exists(Path::new(&string_path)){
                println!("Create New Dir");
                create_dir_all(&string_path);
            }
            let mut p = PathBuf::from(&string_path);
            let date = chrono::offset::Local::now();
            let newdate = date.format("%Y-%m-%d_%H-%M-%S").to_string();
            p.push(format!("Sniffing{}.txt", newdate));
            create_file(p.clone());
            println!("CREATE FILE IN : {}", p.display());
            p
        }
    };

    let duration = match args.duration{
        None  => {
            let mut x : u64 = 10;
            println!("");
            println!("No value. Every {} seconds a report will be generated!", x);
            x
        }
        Some(s) => {
            if s == 0{
                let mut x : u64 = 10;
                println!("");
                println!("Every {} seconds a report will be generated!", s);
                x
            }else {
                println!("");
                println!("Every {} seconds a report will be generated!", s);
                s as u64
            }


        },

    };

    let filter = match args.filter{
        Some(s) => {
            println!("");
            println!("Sniff only {}", s);
            s
        },
        None => {
            let mut x = "".to_string();
            println!("");
            println!("NO FILTER, SNIFF ALL");
            x
        }
    };

    let device = chose_device();
    let mut capture_device = capturedevice(device.clone());

    let t1 = thread::Builder::new().name("t1".into()).spawn(move || loop {
        if !ext_atm.load(Ordering::Relaxed){
            let(lock, cvar) = &*cv2;
            let mut started = lock.lock().unwrap();
            while !*started {
                started = cvar.wait(started).unwrap();
            }
            if ext_atm.load(Ordering::Relaxed){println!("FINISH SNIFFING");break}
            //println!("START SNIFFING");
            sniff::start_sniffing(&atm4, &mut started, &mut capture_device, &cvar, &tx ,&filter);
            println!("");
            println!("--------------------------STOP SNIFFINFG---------------------------")
        }else {
            println!("FINISH SNIFFING");
            break;
        }
    }).unwrap();


    let t2 = thread::Builder::new().name("t2".into()).spawn(move || {
        wait_input::wait_pause( cv, cv6, &atm3, &ext_atm1, sender);
        println!("FINISH WAIT COMMAND");
    }).unwrap();


    let t4 = thread::Builder::new().name("t4".into()).spawn(move || loop{
        if(!ext_atm3.load(Ordering::Relaxed)){
            match rx.try_recv(){
                Ok(packet) => {
                    let mut sum1 = sum.lock().unwrap();
                    if(ext_atm3.load(Ordering::Relaxed)){println!("FINISH PARSE PACKET ");break}
                    parse::parse_packet(&mut sum1, &packet);
                },
                Err(TryRecvError::Disconnected) => {println!("DISCONNESSO")},
                Err(TryRecvError::Empty) => {}
            }
        }else {
            println!("FINISH PARSE PACKET ");
            break
        }

    }).unwrap();


    let t3 = thread::Builder::new().name("t3".into()).spawn(move || loop {
        if !ext_atm2.load(Ordering::Relaxed){
            match receiver.recv_timeout(time::Duration::from_secs(duration)) {
                Err(RecvTimeoutError::Timeout) => {
                    let (lock,cvar ) = &*cv3;
                    println!("FINISH WAIT DURATION GO TO UPDATE FILE");
                    let guard = cvar.wait_while(lock.lock().unwrap(), |pending| *pending);
                    if !ext_atm2.load(Ordering::Relaxed){
                        let mut sum1 = sum_save.lock().unwrap();
                        savefile::save_on_file(&mut file,&sum1);
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    println!("DISCONNECTED");
                    break;
                }
                Ok(x) => {
                    let mut sum1 = sum_save.lock().unwrap();
                    savefile::save_on_file(&mut file,&sum1);
                    println!("FINISH DURATION");
                    break;
                }
            }

        }else{
            let mut sum1 = sum_save.lock().unwrap();
            savefile::save_on_file(&mut file,&sum1);
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