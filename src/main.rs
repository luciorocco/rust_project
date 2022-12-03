use std::any::Any;
use pcap::{Device, Capture, BpfProgram, Linktype};
use std::io::{stdin} ;
use std::env;
use std::process;
use chrono::Duration;
use chrono::prelude::*;
use pcap_sys::{pcap_open_live, pcap_setfilter};

fn ts_toDate(ts:i64)-> String{
    let naive = NaiveDateTime::from_timestamp_opt(ts,0).unwrap();
    let _datetime: DateTime<Utc> = DateTime::from_utc(naive,Utc);
    let datetime: DateTime<Local> = DateTime::from(_datetime);
    let newdate = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
    newdate
}

fn start_sniffing(device: Device){
    println!("{:?}", device);
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .open()
        .unwrap();

    /*let lt = cap.get_datalink();
    let capture = Capture::dead(lt).unwrap();
    let pr: BpfProgram = match capture.compile("ip", true) {
        Ok(p) => p,
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

    while let Ok(packet) = cap.next_packet() {
        let newdate = ts_toDate(packet.header.ts.tv_sec as i64);
        println!("received packet! {:?}", packet);

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
