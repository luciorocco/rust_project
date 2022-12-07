use std::any::Any;
use pcap::{Device, Capture, BpfProgram, Linktype};
use std::io::{stdin} ;
use std::process;
use chrono::Duration;
use chrono::prelude::*;
use pcap_sys::{bpf_u_int32,u_char, u_int, u_short};
use pktparse::*;
use pktparse::ipv4::parse_ipv4_header;
use pktparse::ipv6::parse_ipv6_header;
use pktparse::tcp::parse_tcp_header;
use pktparse::udp::parse_udp_header;

/* Ethernet addresses are 6 bytes */
pub const ETHER_ADDR_LEN : usize = 6;

struct Pcap_Pkthdr {
    ts : String, /* time stamp */
    caplen : bpf_u_int32,  /* length of portion present */
    len : bpf_u_int32 /* length this packet (off wire) */
}



/*struct Sniff_Ethernet {
    ether_dhost: u_char, /* Destination host address */
    ether_shost : u_char, /* Source host address */
    ether_type : u_short /* IP? ARP? RARP? etc */
}

struct Sniff_Ip {
    ip_vhl: u_char,		/* version << 4 | header length >> 2 */
    ip_tos: u_char ,		/* type of service */
    ip_len: u_short ,		/* total length */
    ip_id: u_short ,		/* identification */
    ip_off: u_short ,		/* fragment offset field */
    ip_ttl: u_char ,		/* time to live */
    ip_p: u_char ,		/* protocol */
    ip_sum: u_short,		/* checksum */
    //struct {in_addr, ip_src,ip_dst}
}

impl Sniff_Ip{
    const IP_RF: u32 =  0x8000;		/* reserved fragment flag */
    const IP_DF: u32 =  0x4000;		/* don't fragment flag */
    const IP_MF: u32 =  0x2000;		/* more fragments flag */
    const IP_OFFMASK: u32 =  0x1fff;	/* mask for fragmenting bits */
}

/* TCP header */
type  tcp_seq = u_int;

struct Sniff_Tcp {
    th_sport: u_short,	/* source port */
    th_dport : u_short,	/* destination port */
    th_seq: tcp_seq,		/* sequence number */
    th_ack : tcp_seq,		/* acknowledgement number */
    th_offx2 : u_char,	/* data offset, rsvd */
    //#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) > 4)
    th_flags : u_char,
    //#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    th_win : u_short,		/* window */
    th_sum : u_short,		/* checksum */
    th_urp : u_short		/* urgent pointer */
}

impl Sniff_Tcp{
    const TH_FIN : u32 = 0x01;
    const TH_SYN : u32 =  0x02;
    const TH_RST : u32 =  0x04;
    const TH_PUSH : u32 =  0x08;
    const TH_ACK : u32 =  0x10;
    const TH_URG : u32 =  0x20;
    const TH_ECE : u32 =  0x40;
    const TH_CWR : u32 =  0x80;
}*/
/*4 byte ip address*/
/*struct IP_ADDRESS{
    byte1 : u_char,
    byte2 : u_char,
    byte3 : u_char,
    byte4 : u_char
}

/* IPv4 header */
struct IP_HEADER{
    ver_ihl: u_char, // Version (4 bits) + IP header length (4 bits)
    tos: u_char,     // Type of service
    tlen: u_short,    // Total length
    identification: u_short,  // Identification
    flags_fo: u_short, // Flags (3 bits) + Fragment offset (13 bits)
    ttl: u_char,      // Time to live
    proto: u_char  ,    // Protocol
    crc: u_short,      // Header checksum
    saddr: ip_address , // Source address
    daddr: ip_address, // Destination address
    op_pad: u_int  ,     // Option + Padding
}

/* UDP header*/
struct UDP_HEADER{
    sport: u_short,  // Source port
    dport : u_short, // Destination port
    len: u_short,   // Datagram length
    crc : u_short  // Checksum
}*/





fn ts_toDate(ts:i64)-> String{
    let naive = NaiveDateTime::from_timestamp_opt(ts,0).unwrap();
    let _datetime: DateTime<Utc> = DateTime::from_utc(naive,Utc);
    let datetime: DateTime<Local> = DateTime::from(_datetime);
    let newdate = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
    newdate
}

fn try_toDecode<'a>(data : &'a [u8]){
    /*let ih = *IP_HEADER;
    let uh = *UDP_HEADER;
    let ip_len:u_int;
    let sPort : u_short;
    let dPort : u_short;

    /* retireve the position of the ip header */
    ih = (ip_header *) (data +
        14); //length of ethernet header
*/
    let data_clone = data.clone();
    let y = parse_ipv4_header(data_clone).unwrap();
    let w = parse_ipv6_header(data_clone).unwrap();
    let x = parse_tcp_header(data_clone).unwrap();
    let z = parse_udp_header(data_clone).unwrap();
    //println!("{:?}", x.0);

    println!("{:?}", y.1);
    println!("{:?}", w.1);
    println!("{:?}", x.1);
    println!("{:?}", z.1);

}

fn start_sniffing(device: Device){
    println!("{:?}", device);
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)

        .open()

        .unwrap()


        ;

    /*let lt = cap.get_datalink();
    println!("{:?}", lt.get_description());
    let capture = Capture::dead(lt).unwrap();
    let pr: BpfProgram = match capture.compile("port 23", true) {
        Ok(p) =>p,
        Err(e) => {
            println!("{:?}", e);
            process::exit(1);
        }
    };


    let instructions = pr.get_instructions();
    let def: String = instructions
        .iter()
        .map(|ref op| format!("{}", op))
        .collect::<Vec<_>>()
        .join(",");
    println!("{},{}", instructions.len(), def);*/

    //cap.filter("udp", true);
    let mut x = Pcap_Pkthdr{
        ts: "".to_string(),
        caplen: 0,
        len: 0,
    };

    cap.filter("udp", true).unwrap();
    while let Ok(packet) = cap.next_packet() {
        let newdate = ts_toDate(packet.header.ts.tv_sec as i64);
        //println!("received packet! {:?}", packet);
        x.ts = newdate;
        x.len = packet.header.len;
        x.caplen = packet.header.caplen;
        println!("{:?}", x.ts);

        try_toDecode(packet.data);

    }


}


fn main() {
    let mut s = String::new();
    let mut i : usize = 0;
    let device = pcap::Device::list().unwrap();

    println!("Choose your device");

    device.iter().enumerate().for_each(|x|{
        println!("Num: {}  Desc: {:?} ", x.0  , x.1.desc)
    });

    loop{
        //TAKE INPUT
        stdin().read_line(&mut s).ok().expect("Failed to read line");
        //CHECK INPUT AND START SNIFFING
        match s.trim().parse::<usize>() {
            Ok(ok) => {
                i = s.trim().parse::<usize>().ok().unwrap();
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
