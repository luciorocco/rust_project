mod cli;
use std::process;
use std::borrow::Borrow;
use pcap::{Device, Capture};
use std::io::{stdin} ;
use std::ops::Deref;
use chrono::prelude::*;
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


fn ts_toDate(ts:i64)-> String{
    let naive = NaiveDateTime::from_timestamp_opt(ts,0).unwrap();
    let _datetime: DateTime<Utc> = DateTime::from_utc(naive,Utc);
    let datetime: DateTime<Local> = DateTime::from(_datetime);
    let newdate = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
    newdate
}

fn ethernetDecode(ethernet_u8: &[u8])-> VlanEthernetFrame{
    let ethernet = match parse_vlan_ethernet_frame(ethernet_u8) {
        Ok(x) => {x.1}
        Err(e) => {println!("ERRORE")}
    };
    println!("{:x?}", ethernet);
    ethernet
}

fn ipv4Decode(ipv4_u8: &[u8]){
    let ipv4 = parse_ipv4_header(ipv4_u8).unwrap();
    println!("{:?}",ipv4.1);

    match ipv4.1.protocol {
        pktparse::ip::IPProtocol::TCP => {
            let tcp_u8 = &data[(14 + (ipv4.1.ihl as usize) * 4)..];
            let tcp = parse_tcp_header(tcp_u8).unwrap();
            println!("{:?}", tcp.1);
        },
        pktparse::ip::IPProtocol::UDP => {
            let udp_u8 = &data[(14 + (ipv4.1.ihl as usize) * 4)..];
            let udp = parse_udp_header(udp_u8).unwrap();
            println!("{:?}", udp.1);
        }

        pktparse::ip::IPProtocol::IGMP =>{
            println!("IGMP");
        },

        pktparse::ip::IPProtocol::ICMP => {
            let icmp_u8 = &data[(14 + (ipv4.1.ihl as usize) * 4)..];
            let icmp = parse_icmp_header(icmp_u8).unwrap();
            println!("{:?}", icmp.1);
        }
        _=> println!("ERROR")
    }
}

fn ipv6Decode(ipv6_u8: &[u8]){
    let ipv6 = parse_ipv6_header(ipv6_u8).unwrap();
    println!("{:?}",ipv4.1);

    match ipv6.1.next_header {
        pktparse::ip::IPProtocol::TCP => {
            let tcp_u8 = &data[54..];
            let tcp = parse_tcp_header(tcp_u8).unwrap();
            println!("{:?}", tcp.1);
        },
        pktparse::ip::IPProtocol::UDP => {
            let udp_u8 = &data[54..];
            let udp = parse_udp_header(udp_u8).unwrap();
            println!("{:?}", udp.1);
        }

        pktparse::ip::IPProtocol::ICMP6 =>{
            let icmp6_u8 = &data[54..];
            let icmp6 = Icmpv6Slice::from_slice(icmp6_u8).unwrap().header();
            println!("{:?}", icmp6);
        },
        _=> println!("ERROR")
    }
}

fn arpDecode(arp_u8: &[u8]){
    let arp = parse_arp_pkt(arp_u8).unwrap();
    println!("{:?}", arp.1);
}

fn try_toDecode(data : &[u8]){
    let ethernet = ethernetDecode( &data[..14]);

    match ethernet.ethertype {
        pktparse::ethernet::EtherType::IPv4 => {
            ipv4Decode(&data[14..]);
        } ,
        pktparse::ethernet::EtherType::IPv6 => {
            ipv6Decode(&data[14..]);
        },

        pktparse::ethernet::EtherType::ARP =>{
            arpDecode(&data[14..]);
        },
        _ => println!("ERROR")
    }

}

fn start_sniffing(device: Device){
    println!("{:?}", device);
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .open()
        .unwrap()
        ;

    let lt = cap.get_datalink();
    println!("{:?}", lt.0 );
    println!("{:?}", lt.get_name().unwrap() );
    println!("{:?}", lt.get_description().unwrap() );



    cap.filter("", true).unwrap();
    while let Ok(packet) = cap.next_packet() {
        let newdate = ts_toDate(packet.header.ts.tv_sec as i64);
        try_toDecode(packet.data);
    }
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



fn main() {
    let args = cli::RustArgs::parse();
    println!("{:?}",args);
    chose_device();
}
