use std::io;

use crate::args::Args;
use crate::settings::check_file;
use clap::Parser;
use pcap::Device;
use std::path::Path;
use std::process;

use colored::Colorize;

#[derive(Debug)]
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

pub fn print_filters() -> Option<Filter> {
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

                    return Some(Filter::with_args(
                        ip_source_ret,
                        ip_destination_ret,
                        source_port_ret,
                        destination_port_ret,
                        transport_protocol_ret,
                    ));
                }
                _ => {
                    println!("\n{}", "Wrong command.".red());
                }
            }
        }
    }
    return None;
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
    _option: bool,
    interfaces: Vec<Device>,
    _filters: bool,
) {
    let args = Args::parse();
    let interface = args.interface;
    let timeout = args.timeout;
    let file_name = args.reportname;
<<<<<<< HEAD
    let tipo = args.acsv;
    let mut option = _option.clone();
    let mut filters = _filters.clone();
=======
    let tipo = match args.output_type.as_str() {
        "csv" => true,
        "txt" => false,
        _ => false
    };

    if list_mode && interface_name == "en0".to_string() {
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
>>>>>>> dev
    if !list_mode && !option && !filters && !Path::new("./ConfigurationFile.txt").exists() {
        // TODO -> first af all search for a configuration file and then ask to choose the parameters
        eprintln!("\n{}", "No configuration file found\n".bold().red());

        eprintln!(
            "{}",
            "\t-i, --interface\t\tName of the interface to be used for the sniffing".red()
        );

        eprintln!("{}", 
        "\t-l, --list:\t\tShow the net interfaces present in the system without launching the sniffing".red()
        );

        eprintln!(
            "{}",
            "\t-f, --filters: \t\tSet the filters for the sniffing".red()
        );

        eprintln!("\n{}", "\t-c, --commands\t\tShow all possible commands".red());

        eprint!(
            "\n\t{}",
            "If you want to create a default configuration file press Yes (Y/y): ".bold()
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

<<<<<<< HEAD
        
    }
while (list_mode || filters || option) == true{
    
    if list_mode && interface_name == "eth0".to_string() {
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
=======
        println!("");

>>>>>>> dev
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
            "\t\t\t-- -r ".bold().green()
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
            "\t\t\t\t-- -t <value (in ms)>\n".bold().green()
        );
        
        process::exit(0);
    }

    if filters {
        let _settings = print_filters();
        if _settings.is_some()  {
            filters = false;
            option = true;
            println!("a");
        }
    }
}
}
