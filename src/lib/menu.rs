use crate::args::Args;
use crate::settings::{check_file, create_conf_file, Settings};
use clap::Parser;
use pcap::Device;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;
use std::process;

use colored::Colorize;

#[derive(Debug, Serialize, Deserialize)]
pub struct Filter {
    pub ip_source: String,
    pub ip_destination: String,
    pub source_port: String,
    pub destination_port: String,
    pub transport_protocol: String,
}
impl Filter {
    pub fn new() -> Self {
        return Filter {
            ip_source: String::new(),
            ip_destination: String::new(),
            source_port: String::new(),
            destination_port: String::new(),
            transport_protocol: String::new(),
        };
    }
    pub fn with_args(
        ip_source: String,
        ip_destination: String,
        source_port: String,
        destination_port: String,
        transport_protocol: String,
    ) -> Self {
        return Filter {
            ip_source,
            ip_destination,
            source_port,
            destination_port,
            transport_protocol,
        };
    }

    pub fn get_filter_string(&self) -> String {
        let mut options = Vec::<String>::new();
        if self.ip_source != "" {
            options.push(self.ip_source.to_string())
        }
        if self.ip_destination != "" {
            options.push(self.ip_destination.to_string())
        }
        if self.source_port != "" {
            options.push(self.source_port.to_string())
        }
        if self.destination_port != "" {
            options.push(self.destination_port.to_string())
        }
        if self.transport_protocol != "" {
            options.push(self.transport_protocol.to_string())
        }
        return options.join(" and ");
    }
}

// Only the list of settings
pub fn filter_list() -> () {
    println!("\n{}", "FILTER OPTION:".bold().green());
    println!("1.  Filter by {}", "source IP".green());
    println!("2.  Filter by {}", "destination IP".green());
    println!("3.  Filter by {}", "source port".green());
    println!("4.  Filter by {}", "destination port".green());
    println!("5.  Filter by {}", "transport protocol".green());
    println!("0.  Back to menu\n");
}

pub fn print_filters() -> Filter {
    let args = Args::parse();
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
                    ip_source.push(filter_ip(1));
                    buffer.clear();
                }
                "2" => {
                    println!("{}", "\nFilter by destination IP".bold());
                    ip_destination.push(filter_ip(2));
                    buffer.clear();
                }
                "3" => {
                    println!("{}", "\nFilter by source port".bold());
                    source_port.push(filter_port(1));
                    buffer.clear();
                }
                "4" => {
                    println!("{}", "\nFilter by destination port".bold());
                    destination_port.push(filter_port(2));
                    buffer.clear();
                }
                "5" => {
                    println!("{}", "\nFilter by transport protocol".bold());
                    transport_protocol.push(filter_transport_protocol());
                    buffer.clear();
                }
                "0" => {
                    let ip_source_ret = ip_source.join(" or ");
                    let ip_destination_ret = ip_destination.join(" or ");
                    let source_port_ret = source_port.join(" or ");
                    let destination_port_ret = destination_port.join(" or ");
                    let transport_protocol_ret = transport_protocol.join(" or ");
                    // let f = Filter::with_args(
                    //     ip_source_ret,
                    //     ip_destination_ret,
                    //     source_port_ret,
                    //     destination_port_ret,
                    //     transport_protocol_ret,
                    // );
                    let mut f = Settings::read_from_file().unwrap().filters.unwrap();
                    if ip_source_ret != "" {
                        f.ip_source = ip_source_ret;
                    }
                    if ip_destination_ret != "" {
                        f.ip_destination = ip_destination_ret;
                    }
                    if source_port_ret != "" {
                        f.source_port = source_port_ret;
                    }
                    if destination_port_ret != "" {
                        f.destination_port = destination_port_ret;
                    }
                    if transport_protocol_ret != "" {
                        f.transport_protocol = transport_protocol_ret;
                    }

                    let set_check = Settings::read_from_file();

                    if !set_check.is_ok() {
                        create_conf_file().unwrap();
                    }

                    let set = Settings::read_from_file();

                    let mut settings = set.unwrap();
                    settings.filters = Some(f);
                    settings.write_to_file().unwrap_or_else(|_| {
                        eprintln!("Error while writing filters on file...");
                        process::exit(1);
                    });
                    return settings.filters.unwrap();
                }
                _ => {
                    println!("\n{}", "Wrong command.".red());
                }
            }
        }
    }
    let f2 = Filter::new();
    let set = Settings::read_from_file();
    if set.is_ok() {
        let mut settings = set.unwrap();
        settings.filters = Some(f2);
        settings.write_to_file().unwrap_or_else(|_| {
            eprintln!("Error while writing filters on file...");
            process::exit(1);
        });
        return settings.filters.unwrap();
    } else {
        eprintln!("Error in conf file");
        return f2;
    }
}

pub fn filter_transport_protocol() -> String {
    let mut transport_protocol = String::new();
    let err_msg = "Failed to read line".red();
    loop {
        println!("Insert transport protocol");
        transport_protocol.clear();
        io::stdin()
            .read_line(&mut transport_protocol)
            .expect(&err_msg);
        if transport_protocol_validity(&transport_protocol) {
            transport_protocol = "\\".to_owned() + &transport_protocol;
            break;
        } else {
            println!("{}", "Invalid transport protocol".red());
            println!("The options are: icmp, arp, udp, tcp");
        }
    }

    return "ip proto ".to_owned() + &transport_protocol.trim().to_string();
}

pub fn transport_protocol_validity(transport_protocol: &String) -> bool {
    let possible_protocol = vec![
        String::from("icmp\n"),
        String::from("arp\n"),
        String::from("udp\n"),
        String::from("tcp\n"),
    ];

    return possible_protocol.contains(transport_protocol);
}

pub fn filter_port(mode: u8) -> String {
    let mut port_number = String::new();
    let err_msg = "Failed to read line".red();

    loop {
        println!("Inser port number");
        port_number.clear();
        io::stdin().read_line(&mut port_number).expect(&err_msg);
        if check_port_number(&port_number) {
            println!("{}", "Wrong port number\n".red());
        } else {
            println!("{}", "The port number inserted is valid".green());
            break;
        }
    }

    // difference between source port or destination port
    match mode {
        1 => return "src port ".to_owned() + &port_number.trim().to_string(),
        2 => return "dst port ".to_owned() + &port_number.trim().to_string(),
        _ => return "error".to_owned(),
    }
}

pub fn check_port_number(port_number: &String) -> bool {
    let number = port_number.trim().parse::<i32>();
    if number.is_ok() {
        if number.as_ref().unwrap() > &0 && number.unwrap() < 65535 {
            return false;
        }
    }
    return true;
}

pub fn filter_ip(mode: u8) -> String {
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

    // difference between source ip and destination ip
    match mode {
        1 => return "src host ".to_owned() + &ip.trim().to_string(),
        2 => return "dst host ".to_owned() + &ip.trim().to_string(),
        _ => return "error".to_owned(),
    }
}

pub fn check_validity_ip(ip: &String) -> bool {
    let splitted_ip: Vec<&str> = ip.trim().split(".").collect();

    // check ipv4 or ipv6
    match splitted_ip.len() {
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
    _interface_name: String,
    list_mode: bool,
    option: bool,
    interfaces: Vec<Device>,
    filters: bool,
    reset_filters: bool
) {
    let args = Args::parse();
    let interface = args.interface;
    let timeout = args.timeout;
    let file_name = args.reportname;
    let tipo = match args.output_type.as_str() {
        "csv" => true,
        "txt" => false,
        _ => false,
    };

    dbg!(reset_filters);

    if reset_filters {
        let mut cur_set = Settings::read_from_file().unwrap_or_else(|_|{
            eprintln!("{}", "Cannot reset filters. Configuration file doesn't exist! Exiting...".bold().red());
            process::exit(1);
        });
        cur_set.filters = Some(Filter::new());
        cur_set.write_to_file().unwrap();
        println!("{}", "Previous filters have been reset. Exiting...".bold().bright_green());
        process::exit(0);
    }

    if list_mode {
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
        process::exit(0);
    }
    if !list_mode && !option && !filters && !Path::new("./ConfigurationFile.txt").exists() {
        eprintln!("\n{}", "No configuration file found".bold().red());
        eprintln!(
            "{}",
            "\t-i, --interface\t\tName of the interface to be used for the sniffing".red()
        );
        eprintln!("{}", "\t-l, --list:\t\tShow the net interfaces present in the system without launching the sniffing".red());

        eprintln!(
            "{}",
            "\t-f, --filters: \t\tSet the filters for the sniffing".red()
        );
        eprintln!(
            "\n{}",
            "\t-c, --commands\t\tShow all possible commands".red()
        );

        eprint!(
            "\n\t{}",
            "If you want to create a default configuration file press (Y/y): ".bold()
        );

        let mut buf = String::new();
        buf.clear();
        io::stdin().read_line(&mut buf).expect("errore");

        match buf.as_str().trim() {
            "Y" | "y" => {
                check_file(&interface, &tipo, &timeout, &file_name);
            }
            _ => {}
        }
        println!("");

        process::exit(0);
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
            "\t\t\t-- -r <filename>".bold().green()
        );
        println!(
            "{0: <2}  {1: <10}  {2: <10}",
            "5.",
            "Set report file type",
            "\t\t\t-- -o <csv/txt>".bold().green()
        );
        println!(
            "{0: <2}  {1: <10}  {2: <10}",
            "6.",
            "Set timeout",
            "\t\t\t\t-- -t <value (in s)>".bold().green()
        );
        println!(
            "{0: <2}  {1: <10}  {2: <10}",
            "7.",
            "Reset filters",
            "\t\t\t\t-- -w \n".bold().green()
        );
        process::exit(0);
    }

    if filters {
        let _settings = print_filters();
    }
}
