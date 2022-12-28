use clap::Parser;
use colored::*;
use netanalyzer::error::ParserError;
use pcap::{Capture, Device};
use std::fs::File;
use std::io;
use std::io::Write;
use std::sync::mpsc::channel;
use std::sync::{Arc, RwLock};
use std::thread;

use netanalyzer::args::Args;
use netanalyzer::parser;
use netanalyzer::settings::Settings;

use ::netanalyzer::menu::print_menu;
// use std::io::prelude;
use std::fs;
use std::path::Path;

fn main() {
    let args = Args::parse();
    let interface_name = args.interface;
    let list_mode = args.list;
    let option = args.commands;

    let interface = Device::list().unwrap();
    let filters = args.filters;

    let inter = interface_name.clone();
    print_menu(inter, list_mode, option, interface, filters);

    // let a = &interface_name;
    let tipo = args.acsv;
    let timeout = args.timeout;
    let filename = args.reportname;
    // let  mò = args.name;

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
    let (tx_pars_report, rx_pars_report) = channel::<parser::Packet>();

    let rwlock = Arc::new(RwLock::new(false));
    let pause_handler = Arc::clone(&rwlock);
    let pause_handler_snif = Arc::clone(&rwlock);
    let pause_handler_parse = Arc::clone(&rwlock);
    // let pause_handler_rep = Arc::clone(&rwlock);

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

    let report_thread = thread::spawn(move || {
        // let lock = &*pause_handler_rep;
        while let Ok(_packet) = rx_pars_report.recv() {
            // TODO: add packet to report queue
        }
    });

    
    let rs = Path::new("ConfigurationFile.txt").exists();
    if rs == true && interface_name == "listview__" && tipo == false && timeout == 10 && filename == "report" {
        println!(" Configuration File exsist ");
    }
    else if rs == false && interface_name == "listview__" && tipo == false && timeout == 10 && filename == "report" {
        create_conf_file().unwrap();
        println!("Default Configuration File created with default configs (interface name = listview, tipo = txt, timeout = 10, filename = report");
    }
    else if rs == true && (interface_name != "listview__" || tipo != false || timeout != 10 || filename != "report") {
        fs::remove_file("ConfigurationFile.txt").expect("File delete failed");

        create_conf_file().unwrap();
        println!("Customed Configuration File updated");
    }
    else if rs == false && (interface_name != "listview__" || tipo != false || timeout != 10 || filename != "report") {
        fs::remove_file("ConfigurationFile.txt").expect("File delete failed");
        create_conf_file().unwrap();
        println!("Customed Configuration File created");
    }
    let set = Settings::new();
    println!("{:?}", set);

    //Join the threads
    sniffing_thread.join().unwrap();
    parsing_thread.join().unwrap();
    report_thread.join().unwrap();
    pause_resume_thread.join().unwrap();
}
    

pub fn create_conf_file() -> std::io::Result<()> {
    let args = Args::parse();
    let interfaccia = format!("{}\n", args.interface);
    let tempo = format!("{}\n", args.timeout);
    let nome = format!("{}\n", args.reportname);
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




