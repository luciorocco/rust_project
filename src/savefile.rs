use std::fs::OpenOptions;
use std::path::PathBuf;
use regex::internal::Input;
use std::io::Write;

use crate::structs;

pub(crate) fn save_on_file(file: &mut PathBuf, sum: &structs::summaryf::Summary){
    if sum.len() != 0{
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
                let mut ap_protocol= match structs::application_layer::from_port_to_application_protocol(x.0.dest_port) {
                    x if x != structs::application_layer::AppProtocol::Other =>{
                        x
                    },
                    _ => {
                        structs::application_layer::from_port_to_application_protocol(x.0.source_port)
                    }
                };
                writeln!(&file_op, " Type Ethernet : {}, Initial Time Stamp : {}, Final Time Stamp : {}, Total Lenght :{} \n Source : {}_{} -> Destination : {}_{}, Protocol : {}, Application Protocol : {:?}  ",
                         x.0.type_eth, x.1.ts_i, x.1.ts_f, x.1.len , x.0.source_address, x.0.source_port, x.0.destination_address, x.0.dest_port, x.0.protocol, ap_protocol).unwrap();
            }
        });
        println!("GENERATED REPORT...");
    }else{
        println!("No packet Found...");
    }

}