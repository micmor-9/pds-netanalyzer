use std::io;

use crate::args::Args;
use clap::Parser;
use pcap::Device;
use std::process;

use colored::{ColoredString, Colorize};

#[derive(Debug)]
pub struct Settings {
    pub filters: String,
    pub csv: Option<bool>,
    pub timeout: Option<i64>,
    pub filename: Option<String>,
}
impl Settings {
    pub fn new() -> Self {
        return Settings {
            filters: String::new(),
            csv: None,
            timeout: None,
            filename: None,
        };
    }
}

pub struct Filter {
    pub ip_source: String,
    pub ip_dest: String,
    pub port_source: String,
    pub port_dest: String,
    pub transport_protocol: String,
}
impl Filter {
    pub fn new() -> Self {
        return Filter {
            ip_source: String::new(),
            ip_dest: String::new(),
            port_source: String::new(),
            port_dest: String::new(),
            transport_protocol: String::new(),
        };
    }
}

// Only the list of settings
pub fn filter_list() -> () {
    println!("\n{}", "FILTER OPTION:".bold().green());
    println!("1. \t Filter by {}", "source IP".green());
    println!("2. \t Filter by {}", "destination IP".green());
    println!("3. \t Filter by {}", "source port".green());
    println!("4. \t Filter by {}", "destination port".green());
    println!("5. \t Filter by {}", "transport protocol".green());
    println!("0. \t Back to menu\n");
}

// pub fn menu() -> Settings {}
pub fn print_filters() -> () {
    let args = Args::parse();
    // let mut conditional_settings = Vec::<String>::new();

    // TODO: aggiungere tutta la parte per aggiungere le varie opzioni in conditional settings

    // let mut filters = Filter::new();
    let filters = args.filters;
    let err_msg = "Failed to read line".red();

    let mut ip_source: Vec<String> = Vec::new();
    let mut ip_destination: Vec<String> = Vec::new();
    let mut source_port: Vec<String> = Vec::new();
    let mut destination_port: Vec<String> = Vec::new();
    let mut transport_protocol: Vec<String> = Vec::new();

    // match sulla scelta del filtro
    if filters {
        loop {
            filter_list();
            let mut buffer = String::new();
            buffer.clear();
            io::stdin().read_line(&mut buffer).expect(&err_msg);
            match buffer.as_str().trim() {
                "1" => {
                    println!("{}", "\nFilter by source IP".bold());
                    ip_source.push(filter_ip());
                    buffer.clear();
                }
                "2" => {
                    println!("{}", "\nFilter by destination IP".bold());
                    ip_destination.push(filter_ip());
                    buffer.clear();
                }
                "3" => {}
                "4" => {}
                "5" => {}
                "0" => {}
                _ => {
                    println!("\n{}", "Wrong command.".red());
                }
            }
        }
    }
}

pub fn filter_ip() -> String {
    let err_msg = "Failed to read line".red();
    let mut ip = String::new();
    loop {
        println!("\nInsert IP: ");
        ip.clear();
        io::stdin().read_line(&mut ip).expect(&err_msg);
        if check_validity_ip(&ip) {
            break;
        }
    }
    return "src host".to_owned() + &ip.trim().to_string();
}

pub fn check_validity_ip(ip: &String) -> bool {
    let splitted_ip: Vec<&str> = ip.trim().split(".").collect();

    // check ipv4 or ipv6
    match splitted_ip.len() {
        // 4 => check = check_validity_ipv4(&splitted_ip),
        4 => {
            if check_validity_ipv4(&splitted_ip) {
                println!("{}", "The ipv4 address inserted is valid".green());
                return true;
            } else {
                println!("{}", "The ipv4 address inserted is invalid".red());
                return false;
            }
        }
        8 => {
            if check_validity_ipv6(&splitted_ip) {
                println!("{}", "The ipv6 address inserted is valid".green());
                return true;
            } else {
                println!("{}", "The ipv6 address inserted is invalid".red());
                return false;
            }
        }
        _ => {
            println!("Ip not valid");
            return false;
        }
    }
}

pub fn check_validity_ipv4(splitted_ip: &Vec<&str>) -> bool {
    let mut check = true;
    for elem in splitted_ip {
        let number = elem.parse::<i32>();
        if number.is_ok() {
            if number.as_ref().unwrap() > &255 || number.unwrap() < 0 {
                check = false;
            }
        } else {
            check = true;
        }
    }
    return check;
}

pub fn check_validity_ipv6(splitted_ip: &Vec<&str>) -> bool {
    let mut check = true;

    for elem in splitted_ip {
        let number = elem.parse::<i32>();
        if number.is_ok() {
            if number.as_ref().unwrap() > &65535 || number.unwrap() < 0 {
                check = false;
            }
        } else {
            check = true;
        }
    }

    return check;
}
pub fn print_menu(
    interface_name: String,
    list_mode: bool,
    option: bool,
    interfaces: Vec<Device>,
    filters: bool,
) {
    if list_mode && interface_name == "listview__".to_string() {
        println!("\n{}", "THE AVAILABLE NET INTERFACE ARE".bold().green());
        println!("\n{0: <10} | {1: <20}", "Name", "Status");
        println!("--------------------------");
        interfaces.into_iter().for_each(|i| {
            println!(
                "{0: <10} | {1: <20}",
                i.name.green(),
                i.desc.unwrap_or("Available".to_string())
            )
        });
        println!("\n");
    }
    if !list_mode && interface_name == "listview__".to_string() && !option && !filters {
        // TODO -> first af all search for a configuration file and then ask to choose the parameters
        eprintln!("\n{}", "No configuration file found".bold().red());
        eprintln!(
            "{}",
            "\t-i, --interface\t\tName of the interface to be used for the sniffing".red()
        );
        eprintln!("{}", "\t-l, --list:\t\tShow the net interfaces present in the system without launching the sniffing".red());
        eprintln!(
            "{}",
            "\t-c, --commands\t\tShow all possible commands\n".red()
        );
        process::exit(1);
    }
    if option {
        println!("\n{}", "MENU".green().bold());
        println!(
            "{0: <2}  {1: <10}  {2: <10}",
            "1.",
            "Choose an interface to start sniffing:",
            "\t-- -i <interface_name>".bold().green()
        );
        println!(
            "{0: <2}  {1: <10}  {2: <10}",
            "2.",
            "List all interfaces",
            "\t\t\t-- -l".bold().green()
        );
        println!(
            "{0: <2}  {1: <10}  {2: <10}",
            "3.",
            "Set sniffing filters",
            "\t\t\t-- -f ".bold().green()
        );
        println!(
            "{0: <2}  {1: <10}  {2: <10}",
            "4.",
            "Set report file name",
            "\t\t\t-- -n ".bold().green()
        );
        println!(
            "{0: <2}  {1: <10}  {2: <10}",
            "5.",
            "Set report file type to txt",
            "\t\t-- -t".bold().green()
        );
        println!(
            "{0: <2}  {1: <10}  {2: <10}",
            "6.",
            "Set report file type to csv",
            "\t\t-- -c\n".bold().green()
        );
    }

    if filters {
        let _settings: () = print_filters();
    }
}
