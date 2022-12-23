use clap::Parser;
use colored::*;
use pcap::{Capture, Device};
use std::fs::File;
use std::io::Write;
use std::process;
use std::sync::mpsc::channel;
use std::thread;

use netanalyzer::args::Args;
use netanalyzer::parser;
use netanalyzer::settings::Settings;

fn main() {
    let args = Args::parse();
    let interface_name = args.interface;
    let a = &interface_name;
    let list_mode = args.list;
    let option = args.commands;
    let tipo = args.acsv;
    let timeout = args.timeout;
    let filen = args.filename;
    let interfaces = Device::list().unwrap();

    // Select first interface available temporarly to start sniffing
    let interface = interfaces.first().unwrap().clone();
    let interface_bis = interface.clone();

    /*let s = Settings {
        interface: Some(a.to_string()),
        csv: Some(tipo),
        timeout: Some(timeout),
        filename: Some(filen),
    };
    println!("{:?}", s.new());*/
    //print_menu(interface_name, list_mode, option, interfaces);

    //Set up pcap capture in promisc mode
    let mut capture = Capture::from_device(interface)
        .unwrap() //get Ok() from result
        .promisc(true) // set promiscous mode on
        .immediate_mode(true) // set immediate mode to not buffer packets
        .open() // pass from inactive to active
        .unwrap(); // get Ok() from result

    let (tx_snif_pars, rx_snif_pars) = channel::<Vec<u8>>();
    let (tx_pars_report, rx_pars_report) = channel::<parser::Packet>();

    // Thread for sniffing the packets on the network via pcap
    let sniffing_thread = thread::spawn(move || {
        // TODO implement filters
        while let Ok(packet) = capture.next_packet() {
            let packet_to_send = packet.clone();
            tx_snif_pars.send(packet_to_send.to_vec()).unwrap();
        }
    });

    // Thread that receives a Vec<u8> from sniffing_thread and attempts to parse via the parser module of the lib
    let parsing_thread = thread::spawn(move || {
        while let Ok(packet) = rx_snif_pars.recv() {
            let parsed_packet = parser::ethernet_frame(&interface_bis, &packet);
            match parsed_packet {
                Ok(res) => {
                    println!("{}", res);
                    tx_pars_report.send(res).unwrap();
                }
                Err(err) => println!(
                    "{0} {1}",
                    "Error:".bold().yellow(),
                    err.to_string().bold().yellow()
                ),
            }
        }
    });

    let report_thread = thread::spawn(move || {
        while let Ok(_packet) = rx_pars_report.recv() {
            // TODO add packet to report queue
        }
    });

    /*let conf_file = create_conf_file();
    match conf_file {
        Ok(_) => println!("Configuration file created successfully!"),
        Err(err) => println!(
            "{} {}",
            "Error in configuration file creation".bold().red(),
            err.to_string().bold().red()
        ),
    }*/

    //Join the threads
    sniffing_thread.join().unwrap();
    parsing_thread.join().unwrap();
    report_thread.join().unwrap();
}

fn print_menu(interface_name: String, list_mode: bool, option: bool, interfaces: Vec<Device>) {
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
    if !list_mode && interface_name == "listview__".to_string() && !option {
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
            "Set report file name",
            "\t\t\t-- -n ".bold().green()
        );
        println!(
            "{0: <2}  {1: <10}  {2: <10}",
            "4.",
            "Set report file type to txt",
            "\t\t-- -t".bold().green()
        );
        println!(
            "{0: <2}  {1: <10}  {2: <10}",
            "5.",
            "Set report file type to csv",
            "\t\t-- -c\n".bold().green()
        );
    }
}

pub fn create_conf_file() -> std::io::Result<()> {
    let args = Args::parse();
    let interfaccia = format!("{}\n", args.interface);
    let tempo = format!("{}\n", args.timeout);
    let nome = format!("{}\n", args.filename);
    let tipo = match args.acsv {
        true => "1",
        false => "0",
    };
    let mut f = File::create("ConfigurationFile.txt")?;
    f.write_all(interfaccia.as_bytes())?;
    f.write_all(tempo.as_bytes())?;
    f.write_all(nome.as_bytes())?;
    f.write_all(tipo.as_bytes())?;
    Ok(())
    //.to_string() + b"{}\n", args.csv +b"{}\n",args.timeout + b"{}\n", args.filename)?;
}
