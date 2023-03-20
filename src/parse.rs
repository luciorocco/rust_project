use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::process;
use chrono::{DateTime, Duration, Local, NaiveDateTime, Utc};
use pktparse::arp::parse_arp_pkt;
use pktparse::ethernet::{parse_vlan_ethernet_frame, VlanEthernetFrame};
use pktparse::icmp::parse_icmp_header;
use pktparse::ipv4::{IPv4Header, parse_ipv4_header};
use pktparse::ipv6::parse_ipv6_header;
use pktparse::tcp::parse_tcp_header;
use pktparse::udp::parse_udp_header;


use crate::structs;


fn ts_toDate(ts_sec: i64, ts_usec: u32) -> String{
    let naive = NaiveDateTime::from_timestamp_opt(ts_sec,ts_usec*1000).unwrap();
    let _datetime: DateTime<Utc> = DateTime::from_utc(naive,Utc);
    let datetime: DateTime<Local> = DateTime::from(_datetime);
    let newdate = datetime.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
    newdate
}

fn ethernetDecode(ethernet_u8: &[u8]) -> VlanEthernetFrame{
    let ethernet = match parse_vlan_ethernet_frame(ethernet_u8) {
        Ok(x) => {x.1}
        Err(_) => {
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
            *prot = "ICMP".to_string();
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


fn try_toDecode(data : &[u8], sum: &mut structs::summaryf::Summary, newdate: String, i: u32){
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

    match sum.entry(structs::summaryf::k {
        type_eth: tpe.clone(),
        source_address: dst.clone(),
        destination_address: src.clone(),
        source_port: dsp.clone(),
        dest_port: srp.clone(),
        operation: operation.clone(),
        protocol: prot.clone()
    }) {
        Occupied(e) => {
            sum.entry(structs::summaryf::k {
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
            sum.entry(structs::summaryf::k {
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
            }).or_insert(structs::summaryf::summary {
                ts_i: newdate.clone(),
                ts_f: newdate.clone(),
                len: i,
            });
        }
    }


}


pub(crate) fn parse_packet(mut sum: &mut structs::summaryf::Summary, packet: &structs::packetow::PacketOwned){
    let newdate = ts_toDate(packet.header.ts.tv_sec as i64, packet.header.ts.tv_usec as u32);
    try_toDecode(&packet.data, &mut sum, newdate, packet.header.len);
}