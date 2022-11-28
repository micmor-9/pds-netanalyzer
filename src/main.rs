use clap::Parser;
use pds_netanalyzer::args::Args;

fn main() {
    let args = Args::parse();
    let interface_name = args.list;

    println!("Interface: {}", interface_name);
    

    // let settings = menu();
}