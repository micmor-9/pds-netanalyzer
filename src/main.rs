use clap::Parser;
use pcap::Device;
use netanalyzer::args::Args;
use std::process;
use colored::*;

fn main() {
    let args = Args::parse();
    let interface_name = args.interface;
    let list_mode = args.list;
    let option = args.commands;

    let interfaces = Device::list().unwrap();

    print_menu(interface_name, list_mode, option, interfaces);
    
}

fn print_menu (interface_name: String, list_mode: bool, option: bool, interfaces: Vec<Device>) {
    if list_mode && interface_name == "listview__".to_string() {
        println!("\n{}", "THE AVAILABLE NET INTERFACE ARE".bold().green());
        println!("\n{0: <10} | {1: <20}", "Name", "Status");
        println!("--------------------------");
        interfaces.into_iter().for_each(
            |i| println!("{0: <10} | {1: <20}", i.name.green(), i.desc.unwrap_or("Available".to_string()))
        );
        println!("\n");
    }
    if !list_mode && interface_name == "listview__".to_string() && !option {
        // TODO -> first af all search for a configuration file and then ask to choose the parameters
        eprintln!("\n{}", "No configuration file found".bold().red());
        eprintln!("{}", "\t-i, --interface\t\tName of the interface to be used for the sniffing".red());
        eprintln!("{}", "\t-l, --list:\t\tShow the net interfaces present in the system without launching the sniffing".red());
        eprintln!("{}", "\t-c, --commands\t\tShow all possible commands\n".red());
        process::exit(1);
    }
    if option {
        println!("\n{}", "MENU".green().bold());
        println!("{0: <2}  {1: <10}  {2: <10}", "1.", "Choose an interface to start sniffing:", "\t-- -i <interface_name>".bold().green());
        println!("{0: <2}  {1: <10}  {2: <10}", "2.", "List all interfaces", "\t\t\t-- -l".bold().green());
        println!("{0: <2}  {1: <10}  {2: <10}", "3.", "Set report file name", "\t\t\t-- -n ".bold().green());
        println!("{0: <2}  {1: <10}  {2: <10}", "4.", "Set report file type to txt", "\t\t-- -t".bold().green());
        println!("{0: <2}  {1: <10}  {2: <10}", "5.", "Set report file type to csv", "\t\t-- -c\n".bold().green());
    }
}

