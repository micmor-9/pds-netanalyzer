use std::io;

use crate::args::Args;
use clap::Parser;
use pcap::Device;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    if filters == true {
        loop {
            filter_list();
            let mut buffer = String::new();
            buffer.clear();
            io::stdin().read_line(&mut buffer).expect(&err_msg);
            match buffer.as_str().trim() {
                "1" => {
                    ip_source.push(filter_ip_source());
                }
                "2" => {}
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

pub fn filter_ip_source() -> String {
    let err_msg = "Failed to read line".red();
    let mut ip = String::new();
    loop {
        println!("Insert source IP: ");
        ip.clear();
        io::stdin().read_line(&mut ip).expect(&err_msg);
        // let ip2 = Ipv4Addr::new();
        check_ip_validity(&ip);

        println!("{}", "Check over".red());
    }
}

pub fn check_ip_validity(ip: &String) -> bool {
    let mut check = false;
    let ip_splitted: Vec<&str> = ip.trim().split(".").collect();

    println!("IP LEN: {}", ip_splitted.len());

    // check the ipv4 validity
    if ip_splitted.len() == 4 {}

    match ip_splitted.len() {
        4 => {
            let localhost_v4 = IpAddr::V4(Ipv4Addr::new(
                ip_splitted[0].parse::<u8>().unwrap(),
                ip_splitted[1].parse::<u8>().unwrap(),
                ip_splitted[2].parse::<u8>().unwrap(),
                ip_splitted[3].parse::<u8>().unwrap(),
            ));
            if localhost_v4.is_ipv4() {
                println!("{}", "The inserted ip is a valid ipv4 address".green());
                return true;
            } else {
                eprintln!("{}", "The inserted ip in not valid");
            }
        }
        8 => {
            let localhost_v6 = IpAddr::V6(Ipv6Addr::new(
                ip_splitted[0].parse::<u16>().unwrap(),
                ip_splitted[1].parse::<u16>().unwrap(),
                ip_splitted[2].parse::<u16>().unwrap(),
                ip_splitted[3].parse::<u16>().unwrap(),
                ip_splitted[4].parse::<u16>().unwrap(),
                ip_splitted[5].parse::<u16>().unwrap(),
                ip_splitted[6].parse::<u16>().unwrap(),
                ip_splitted[7].parse::<u16>().unwrap(),
            ));
            if localhost_v6.is_ipv6() {
                println!("{}", "The inserted ip is a valid ipv6 address".green());
                return true;
            } else {
                println!("porcodio");
            }
        
            
        }
        _ => {
            println!("Invalid IP");
        }
    }

    // let localhost_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // let localhost_v6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));

    // assert_eq!("127.0.0.1".parse(), Ok(localhost_v4));
    // assert_eq!("::1".parse(), Ok(localhost_v6));

    // assert_eq!(localhost_v4.is_ipv6(), false);
    // assert_eq!(localhost_v4.is_ipv4(), true);

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
