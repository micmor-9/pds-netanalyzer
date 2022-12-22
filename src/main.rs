use clap::Parser;
use pcap::Device;
use netanalyzer::args::Args;
use std::process;
use colored::*;
use std::io::{self, BufRead};
use std::path::Path;
use std::fs::File;
use std::io::Write;
use std::io::prelude;



fn main() {
    let args = Args::parse();
    let interface_name = args.interface;
    let list_mode = args.list;
    let option = args.commands;

    let interfaces = Device::list().unwrap();

    print_menu(interface_name, list_mode, option, interfaces);
    //create_conf_file();
    
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

pub fn create_conf_file() -> std::io::Result<()>{
    let args = Args::parse();
    let interfaccia = args.interface;
    let tempo = args.timeout;
    let nome = args.filename;
    let tipo = match args.acsv {
    true => "1",
    false => "0"
    };
    let mut f = File::create("ConfigurationFile.txt")?;
    f.write_all(interfaccia.as_bytes())?;
    f.write_all(&tempo.to_be_bytes())?;
    f.write_all(nome.as_bytes())?;
    f.write_all(tipo.as_bytes())?;
    Ok(()) 
    
    //.to_string() + b"{}\n", args.csv +b"{}\n",args.timeout + b"{}\n", args.filename)?;
}

#[derive(Debug)]
pub struct Settings {
    pub interface: Option<String>,
    pub csv: Option<bool>,
    pub timeout: Option<i64>,
    pub filename: Option<String>,
}
impl Settings {
    pub fn new() -> Self {
        if let Ok(lines) = read_lines("./ConfigurationFile.txt") {
            let mut vec = vec![];
            // Consumes the iterator, returns an (Optional) String
            for line in lines {
                if let Ok(info) = line {
                    vec.push(info.to_string());
                }
            }
            let mut tipo = true;
            if vec[1] == "1" {
                tipo = true;
            }
            else if vec[1] == "0" {
                tipo = false;
            }
            let timeoutint: i64 = vec[2].parse().unwrap();
                    return Settings {
                        interface: Some(vec[0].to_string()),
                        csv: Some(tipo),
                        timeout: Some(timeoutint),
                        filename:Some(vec[3].to_string()),
                        }



        } else {
            return Settings {
                interface: None,
                csv: None,
                timeout: None,
                filename: None,
            }
        }
    }
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())

}



