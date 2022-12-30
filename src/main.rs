mod cli;
use std::process;
use std::borrow::Borrow;
use pcap::{Device, Capture, PacketCodec, PacketHeader, Packet};
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
use std::fs::File;

#[derive(PartialEq, Eq, Hash,Debug)]
pub struct k{
    pub type_eth : String,
    pub source_address : String,
    pub destination_address: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub operation : String,
    pub protocol: String,
}

#[derive(Debug)]
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

    println!("{:x?}", ethernet);
    ethernet
}

fn ipv4Decode(ipv4_u8: &[u8], data: &[u8], src: &mut String, dst: &mut String, prot: &mut String, srp: &mut u16, dsp: &mut u16){
    let ipv4 = parse_ipv4_header(ipv4_u8).unwrap();
    *src = ipv4.1.source_addr.to_string();
    *dst = ipv4.1.dest_addr.to_string();
    println!("{:?}",ipv4.1);

    match ipv4.1.protocol {
        pktparse::ip::IPProtocol::TCP => {
            let tcp_u8 = &data[(14 + (ipv4.1.ihl as usize) * 4)..];
            let tcp = parse_tcp_header(tcp_u8).unwrap();
            *prot = "TCP".to_string();
            *srp = tcp.1.source_port;
            *dsp = tcp.1.dest_port;
            println!("{:?}", tcp.1);
        },
        pktparse::ip::IPProtocol::UDP => {
            let udp_u8 = &data[(14 + (ipv4.1.ihl as usize) * 4)..];
            let udp = parse_udp_header(udp_u8).unwrap();
            *prot = "UDP".to_string();
            *srp = udp.1.source_port;
            *dsp = udp.1.dest_port;
            println!("{:?}", udp.1);
        }

        pktparse::ip::IPProtocol::IGMP =>{
            *prot = "IGMP".to_string();
            println!("IGMP");
        },

        pktparse::ip::IPProtocol::ICMP => {
            let icmp_u8 = &data[(14 + (ipv4.1.ihl as usize) * 4)..];
            let icmp = parse_icmp_header(icmp_u8).unwrap();
            *prot = "ICMP".to_string();
            println!("{:?}", icmp.1);
        },

        _=> println!("ERROR")
    }
}

fn ipv6Decode(ipv6_u8: &[u8], data: &[u8], src: &mut String, dst: &mut String, prot: &mut String, srp: &mut u16, dsp: &mut u16){
    let ipv6 = parse_ipv6_header(ipv6_u8).unwrap();
    *src = ipv6.1.source_addr.to_string();
    *dst = ipv6.1.dest_addr.to_string();
    println!("{:?}",ipv6.1);

    match ipv6.1.next_header {
        pktparse::ip::IPProtocol::TCP => {
            let tcp_u8 = &data[54..];
            let tcp = parse_tcp_header(tcp_u8).unwrap();
            *prot = "TCP".to_string();
            *srp = tcp.1.source_port;
            *dsp = tcp.1.dest_port;
            println!("{:?}", tcp.1);
        },
        pktparse::ip::IPProtocol::UDP => {
            let udp_u8 = &data[54..];
            let udp = parse_udp_header(udp_u8).unwrap();
            *prot = "UDP".to_string();
            *srp = udp.1.source_port;
            *dsp = udp.1.dest_port;
            println!("{:?}", udp.1);
        }

        pktparse::ip::IPProtocol::ICMP6 =>{
            *prot = "ICMP6".to_string();
            println!("ICMP6");
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

    sum.iter().for_each(|x|println!("{:?}",x));

}

/*#[derive(Debug, Clone, PartialEq, Eq)]
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
}*/

fn start_sniffing(device: Device){
    println!("{:?}", device);
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .timeout(1000)
        //.buffer_size(3)
        .open()
        .unwrap()
        ;

    let lt = cap.get_datalink();
    println!("{:?}", lt.0 );
    println!("{:?}", lt.get_name().unwrap() );
    println!("{:?}", lt.get_description().unwrap() );



    cap.filter("", true).unwrap();


    let mut sum : Summary = HashMap::new();
    while let packet = cap.next_packet() {
        match packet {
            Ok(p) => {
                let newdate = ts_toDate(p.header.ts.tv_sec as i64);
                //println!("{:?}", packet.header.len);
                //println!("{:?}", newdate);
                try_toDecode(p.data, &mut sum, newdate, p.header.len);
            }
            Err(e) => eprintln!("{:?}", e)
        }

    }

    /*for packet in cap.iter(Codec) {
        let packet = packet.unwrap();

        println!("{:?}", packet);
    }*/

    //println!("{:?}", cap.next_packet());





}

fn chose_device(){
    let mut s = String::new();
    let device = pcap::Device::list().unwrap();
    println!("Choose your device");
    device.iter().enumerate().for_each(|x|{
        println!("Num: {}  Desc: {:?}  Address{:?} ", x.0  , x.1.desc, x.1.addresses)
    });

    loop{
        //TAKE INPUT
        stdin().read_line(&mut s).ok().expect("Failed to read line");
        //CHECK INPUT AND START SNIFFING
        match s.trim().parse::<usize>() {
            Ok(ok) => {
                let i = s.trim().parse::<usize>().ok().unwrap();
                if i <= device.len() -1 {
                    start_sniffing(device[i].clone());
                    break
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

fn create_file(p : PathBuf){
    let mut file = match File::create(p){
        Ok(p) => p,
        Err(e)=> {
            println!("{:?}", e);
            process::exit(1);
        }
    };
}

fn main() {
    let args = cli::RustArgs::parse();
    let x = match args.path {
        Some(p) => create_file(p),
        None => println!("None path")
    };
    //println!("{:?}",args);
    chose_device();
}
