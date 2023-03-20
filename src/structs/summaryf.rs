use std::collections::{HashMap};
use crate::Serialize;
use crate::Deserialize;

#[derive(PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Clone )]
pub struct k{
    pub type_eth : String,
    pub source_address : String,
    pub destination_address: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub operation : String,
    pub protocol: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct summary{
    pub ts_i: String,
    pub ts_f: String,
    pub len: u32,
}

pub type Summary = HashMap<k, summary>;