use clap::{Args,Parser};

#[derive(Debug,Parser)]
#[command(author, version, about, long_about = None)]
pub struct RustArgs{

    /// output file to be generated
    #[arg(short, long)]
    pub path: Option<std::path::PathBuf>,

    ///the interval after which a new report is to be generated in second
    #[arg(short, long)]
    pub duration: Option<usize>,

    /// a filter to apply to captured data
    #[arg(short , long)]
    pub filter: Option<String>
}

