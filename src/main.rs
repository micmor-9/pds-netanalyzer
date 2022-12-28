use clap::Parser;
use colored::*;
use netanalyzer::error::ParserError;
use pcap::{Capture, Device};
use std::fs::File;
use std::io;
use std::io::Write;
use std::process;
use std::sync::mpsc::channel;
use std::sync::{Arc, RwLock, Mutex};
use std::thread;
use std::time::Duration;

use netanalyzer::args::Args;
use netanalyzer::parser;
use netanalyzer::report;
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

    println!(
        "{}",
        "Press ENTER to pause/resume the sniffing.".bold().cyan()
    );
    println!("{}", "Press q and ENTER to stop the sniffing".bold().blue());

    let (tx_snif_pars, rx_snif_pars) = channel::<Vec<u8>>();
    let (tx_pars_report, rx_parse_report) = channel::<parser::Packet>();

    let rwlock = Arc::new(RwLock::new(false));
    let pause_handler = Arc::clone(&rwlock);
    let pause_handler_snif = Arc::clone(&rwlock);
    let pause_handler_parse = Arc::clone(&rwlock);
    let pause_handler_rep = Arc::clone(&rwlock);
    let pause_handler_wrep = Arc::clone(&rwlock);

    // Thread for sniffing the packets on the network via pcap
    let sniffing_thread = thread::spawn(move || {
        let lock = &*pause_handler_snif;
        // TODO: implement filters
        while let Ok(packet) = capture.next_packet() {
            let pause = lock.read().unwrap();
            if !*pause {
                let packet_to_send = packet.clone();
                tx_snif_pars.send(packet_to_send.to_vec()).unwrap();
            }
            drop(pause);
        }
    });

    // Thread that receives a Vec<u8> from sniffing_thread and attempts to parse via the parser module of the lib
    let parsing_thread = thread::spawn(move || {
        let lock = &*pause_handler_parse;
        while let Ok(packet) = rx_snif_pars.recv() {
            let parsed_packet = parser::ethernet_frame(&interface_bis, &packet);
            let pause = lock.read().unwrap();
            if !*pause {
                match parsed_packet {
                    Ok(res) => {
                        println!("{}", res);
                        tx_pars_report.send(res).unwrap();
                    }
                    Err(err) => match err {
                        ParserError::EthernetPacketUnrecognized => {}
                        _ => println!(
                            "{0} {1}",
                            "Error:".bold().yellow(),
                            err.to_string().bold().yellow()
                        ),
                    },
                }
            }
            drop(pause);
        }
    });

    // Thread used to pause/resume
    let pause_resume_thread = thread::spawn(move || {
        let lock = &*pause_handler;
        let mut buffer = String::new();
        loop {
            buffer.clear();
            io::stdin()
                .read_line(&mut buffer)
                .expect("Failed to read line");
            match buffer.as_str().trim() {
                "" => {
                    let mut pause = lock.write().unwrap();
                    if *pause == true {
                        *pause = false;
                        println!("{}", "Sniffing resumed!".bold().green());
                    } else {
                        *pause = true;
                        println!("{}", "Sniffing paused!".bold().green());
                    }
                    io::stdout().flush().unwrap();
                    drop(pause);
                }
                "q" | "Q" => {
                    // TODO: implement the stop of all threads and the safe exit from the program
                }
                _ => {}
            }
        }
    });

    let report_queue_lock = Arc::new(Mutex::new(Vec::<parser::Packet>::new()));
    let report_queue_clone = Arc::clone(&report_queue_lock);

    // Thread used to fill the queue of packets waiting to be written in the report
    let report_thread = thread::spawn(move || {
        let lock = &*pause_handler_rep;
        let queue_lock = &*report_queue_lock;
        while let Ok(packet) = rx_parse_report.recv() {
            let pause = lock.read().unwrap();
            if !*pause {
                let mut queue_l = queue_lock.lock().unwrap();
                queue_l.push(packet);
            }
        }
    });

    let write_report_thread = thread::spawn(move || {
        let lock = &*&pause_handler_wrep;
        let queue_lock = &*report_queue_clone;

        //let report_path = report::create_directory(filename)
        loop {
            let pause = lock.read().unwrap();
            if !*pause {
                let mut queue_l = queue_lock.lock().unwrap();

            }
            thread::sleep(Duration::from_secs(timeout.unsigned_abs()));
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
    pause_resume_thread.join().unwrap();
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
