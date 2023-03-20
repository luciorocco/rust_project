use std::process;
use std::sync::{Arc, Condvar, MutexGuard};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use pcap::{Active, Capture, PacketCodec};

use crate::structs;

pub(crate) fn start_sniffing(atm2: &Arc<AtomicBool>, started: &mut MutexGuard<bool>, cap: &mut Capture<Active>, cv: &&Condvar, tx: &Sender<structs::packetow::PacketOwned>, filter: &String){

    let lt = cap.get_datalink();

    match cap.filter(filter, true){
        Ok(_) => {println!("APPLIED FILTER")},
        Err(e) => {
            println!("WRONG USAGE OF FILTER! PLEASE INSERT A VALID FILTER");
            process::exit(1);
        }
    }
    println!("");
    println!("--------------------------SNIFFING------------------------------");
    while let packet = cap.next_packet() {

        if atm2.load(Ordering::Relaxed) {
            **started = false;
            cv.notify_all();
            break
        }


        match packet {
            Ok(p) => {
                let pa = structs::packetow::Codec.decode(p);
                tx.send(pa);
            }
            Err(e) => {
                continue
            }
        }
    }

}