mod cli;

use std::any::Any;
use std::{process, time};
use std::borrow::Borrow;
use pcap::{Device, Capture, PacketCodec, PacketHeader, Packet, Address};
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
use dirs::desktop_dir;
use serde::{Serialize, Deserialize};
use serde_json::Result;
use serde_json_any_key::*;
use regex::Regex;
use std::thread;
use std::thread::Builder;
use std::sync::{Arc, Condvar, mpsc, Mutex, MutexGuard};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use chrono::Duration;


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
    pub len: u32
}


type Summary = HashMap<k, summary>;



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
            process::exit(1);
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

        _=> println!("ERROR")
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
        _=> println!("ERROR")
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
    println!("{:?}", arp.1);
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
        _ => println!("ERROR")
    }

     sum.entry(k {
            type_eth: tpe.clone(),
            source_address: src.clone(),
            destination_address: dst.clone(),
            source_port: srp.clone(),
            dest_port: dsp.clone(),
            operation: operation,
            protocol: prot.clone()
        }).and_modify(|x| {
            x.len += i;
            x.ts_f = newdate.clone();
        }).or_insert(summary {
         ts_i: newdate.clone(),
         ts_f: newdate.clone(),
         len: i,
     });

   // sum.iter().for_each(|x|println!("{:?}",x));

}



fn start_sniffing(device: Device, filter: &String, cv: Arc<(Mutex<bool>, Condvar)>, cv1: Arc<(Mutex<bool>, Condvar)>, atm: &Arc<AtomicBool>, file: &mut File) -> Summary{
    println!("{:?}", device);
    let mut cap = Capture::from_device(device)
        .unwrap()

        .promisc(true)

        .timeout(1000)

        .open()

        .unwrap()
        ;

    let lt = cap.get_datalink();
    println!("{:?}", lt.0 );
    println!("{:?}", lt.get_name().unwrap());
    println!("{:?}", lt.get_description().unwrap());

    cap.filter(filter, true).unwrap();

    let mut sum : Summary = HashMap::new();
    let (lock, cvar) = &*cv;
    let (lock1, cvar1) = &*cv1;
    println!(" SNIFFING");
    while let packet = cap.next_packet() {


        let guard = cvar.wait_while(lock.lock().unwrap(), |pending| {
            println!("SNIFFING");
            *pending
        }).unwrap();

        println!("{:?}", guard);

        if(atm.load(Ordering::Relaxed)){
            if !*guard{
                let mut started = lock1.lock().unwrap();
                while  !*started {
                    started = cvar1.wait(started).unwrap();
                }
                println!("AGGIORNO FILE!");
                save_on_file(file, &sum);
                println!("RITORNO SNIFFING");
                atm.store(false, Ordering::Relaxed);
                *started = false;
                cvar1.notify_all();
            }

        }


        println!("packet");

        match packet {
            Ok(p) => {
                let newdate = ts_toDate(p.header.ts.tv_sec as i64);
                try_toDecode(p.data, &mut sum, newdate, p.header.len);
            }
            Err(e) => {}
        }
    }
    sum
}



fn chose_device()-> Device{
    let mut s = String::new();
    let device = pcap::Device::list().unwrap();
    println!("Choose your device");
    device.iter().enumerate().for_each(|x|{
        if(x.1.flags.connection_status == pcap::ConnectionStatus::Connected){
            println!("Num: {}  Desc: {:?}  Address{:?} ", x.0  , x.1.desc, x.1.addresses);
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

fn save_on_file(file: &mut File, sum: &Summary){
    //serde_json::to_writer(file, sum);

    let mut ser1 = sum.to_json_map().unwrap();
    println!("{:?}", ser1);
    let s1 = ser1.replace(r"\","");
    println!("{:?}", s1);
    serde_json::to_writer(file, &s1);
}

fn wait_pause(cv: Arc<(Mutex<bool>, Condvar)>){
    let mut s = String::new();
    let (lock,cvar ) = &*cv;

    loop{
        println!("Press P for pause or E for exit and save on file");
        //TAKE INPUT
        stdin().read_line(&mut s).ok().expect("Failed to read line");
        //CHECK INPUT AND START SNIFFING
        match s.trim().to_ascii_lowercase().as_str() {
            "p" => {
                s.clear();
                let mut started = lock.lock().unwrap();
                *started = true;
                loop{
                    println!("Press R for resume..");
                    stdin().read_line(&mut s).ok().expect("Failed to read line");
                    match s.trim().to_ascii_lowercase().as_str() {
                        "r" => {
                            s.clear();
                            *started = false;
                            cvar.notify_all();
                            break
                        }
                        _ => {
                            s.clear();
                            println!("cmd non riconosciuto");
                            continue
                        }
                    }

                }
            },
            "e" => {
                println!("EXIT");
                process::exit(1);
            }
            _ => {
                s.clear();
                println!("cmd non riconosciuto");
                continue
            }
        }
    }
}



fn main() {
    let args = cli::RustArgs::parse();
    //PAUSE
    let cv = Arc::new((Mutex::new(false), Condvar::new()));
    let mut cv2 = cv.clone();
    //DURATION
    let cv3 = Arc::new((Mutex::new(false), Condvar::new()));
    let mut cv4 = cv3.clone();
    let mut atm = Arc::new(AtomicBool::new(false));
    let atm2 = Arc::clone(&atm);

    let mut  file = match args.path {
        Some(p) => {
            create_file(p)
        },
        None => {
            let mut x = dirs::desktop_dir().unwrap();
            x.push("try.txt");
            create_file(x)
        }
    };

    let duration = match args.duration{
        Some(s) => s as u64,
        None => {
            let mut x : u64 = 0;
            x
        }
    };

    let filter = match args.filter{
        Some(s) => s,
        None => {
            let mut x = "".to_string();
            x
        }
    };


    let device = chose_device();

    let t1 = thread::Builder::new().name("t1".into()).spawn(move || {
         start_sniffing(device, &filter,cv2, cv4, &atm2,  &mut file);
        println!("Sono uscito");
        //save_on_file(&mut file, &sum );
    }).unwrap();


    let t2 = thread::Builder::new().name("t2".into()).spawn(move || {
        wait_pause( cv);
    }).unwrap();


    let t3 = thread::Builder::new().name("t3".into()).spawn(move || loop {
        let (lock,cvar ) = &*cv3;
        let mut started = lock.lock().unwrap();
        thread::sleep(time::Duration::from_secs(/*duration*/ 10));
        println!("ATTESA FINITA");
        atm.store(true,Ordering::Relaxed);
        println!("TIMER FINITO CAMBIO ATM {:?}",atm );
        *started = true;
        cvar.notify_all();
        while *started {
            started = cvar.wait(started).unwrap();
        }
        println!("FINITOOOO");
    }).unwrap();

        t1.join().unwrap();
        t2.join().unwrap();
        t3.join().unwrap();


}
