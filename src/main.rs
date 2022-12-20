use clap::Parser;
use netanalyzer::args::Args;
use pcap::Device;

use ::netanalyzer::menu::print_menu;

fn main() {
    let args = Args::parse();
    let interface_name = args.interface;
    let list_mode = args.list;
    let option = args.commands;
    let filters = args.filters;
    let interfaces = Device::list().unwrap();

    print_menu(interface_name, list_mode, option, interfaces, filters);
}


