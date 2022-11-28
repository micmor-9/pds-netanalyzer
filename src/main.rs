use clap::Parser;
use pds_netanalyzer::args::Args;

fn main() {
    let args = Args::parse();
    let interface_name = args.interface;

    println!("Interface: {}", interface_name);
    
}