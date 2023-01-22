use clap::{Args,Parser};

#[derive(Debug,Parser)]
#[command(author, version, about, long_about = None)]
pub struct RustArgs{

    /// output file to be generated example: "C:\Users\name\Desktop\..\nameFile". DEFAULT = IN DESKTOP CREATE A FOLDER Sniffing and inside a file with a date
    #[arg(short, long)]
    pub path: Option<std::path::PathBuf>,

    ///the interval after which a new report is to be generated in second. DEFAULT = 10
    #[arg(short, long)]
    pub duration: Option<usize>,

    /// a filter to apply to captured data. DEFAULT = NONE
    #[arg(short , long)]
    pub filter: Option<String>
}

