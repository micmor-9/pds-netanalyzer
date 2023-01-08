use clap::Parser;
use colored::*;
use netanalyzer::error::ParserError;
use pcap::{Capture, Device};
use std::io::Write;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::{io, process};

use netanalyzer::args::Args;
use netanalyzer::parser;
use netanalyzer::report::ReportWriter;

use netanalyzer::menu::print_menu;
use netanalyzer::settings::check_file;

fn main() {
    let args = Args::parse();
    let interface_name = args.interface;
    let list_mode = args.list;
    let option = args.commands;

    let interface = Device::list().unwrap();
    let filters = args.filters;

    let inter = interface_name.clone();
    print_menu(inter, list_mode, option, interface, filters);

    let tipo = match args.output_type.as_str() {
        "csv" => true,
        "txt" => false,
        _ => false,
    };
    let filename = args.reportname;
    let timeout = args.timeout;

    let interfaces = Device::list().unwrap();

    let set = check_file(&interface_name, &tipo, &timeout, &filename);
    let interface_name_bis = set.interface.unwrap().clone();
    let filename_bis = set.filename.unwrap().clone();

    let interface = interfaces
        .into_iter()
        .find(|i| i.name == interface_name_bis)
        .unwrap_or_else(|| {
            println!("{}", "No such network interface!".bold().red());
            process::exit(1);
        });

    let interface_bis = interface.clone();
    let filters = set.filters.unwrap().get_filter_string();

    //Set up pcap capture in promisc mode
    let mut capture = Capture::from_device(interface)
        .unwrap() //get Ok() from result
        .promisc(true) // set promiscous mode on
        .immediate_mode(true) // set immediate mode to not buffer packets
        .open() // pass from inactive to active
        .unwrap_or_else(|_| {
            println!(
                "{}",
                "Error opening network socket in promiscous mode. Exiting..."
                    .bold()
                    .red()
            );
            process::exit(1);
        }); // get Ok() from result

    println!(
        "{}",
        "Press ENTER to pause/resume the sniffing.".bold().cyan()
    );
    println!(
        "{}",
        "Press q and ENTER (while sniffing is paused) to stop the sniffing"
            .bold()
            .blue()
    );

    let (tx_snif_pars, rx_snif_pars) = channel::<Vec<u8>>();
    let (tx_parse_report, rx_parse_report) = channel::<parser::Packet>();

    let rwlock = Arc::new(RwLock::new(false));
    let pause_handler = Arc::clone(&rwlock);
    let pause_handler_snif = Arc::clone(&rwlock);
    let pause_handler_parse = Arc::clone(&rwlock);
    let pause_handler_rep = Arc::clone(&rwlock);

    // Thread for sniffing the packets on the network via pcap
    let sniffing_thread = thread::spawn(move || {
        let lock = &*pause_handler_snif;
        // TODO: implement filters
        dbg!(&filters);
        if filters != "" {
            capture.filter(&filters, false).unwrap_or_else(|_| {
                println!("{}", "Filters not valid! Exiting...".bold().red());
                process::exit(1);
            });
            println!(
                "{} {}",
                filters.bold().red(),
                " set correctly!".bold().red()
            );
        }

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
                        tx_parse_report.send(res).unwrap();
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
                    let pause = lock.read().unwrap();
                    if *pause {
                        println!("{}", "Sniffing stopped. Exiting...".bold().bright_red());
                        process::exit(0);
                    }
                    drop(pause);
                }
                _ => {}
            }
        }
    });

    let timer_flag = Arc::new(Mutex::new(false));

    let report_thread = thread::spawn(move || {
        let timer = timer::Timer::new();
        let timer_flag_clone = timer_flag.clone();
        let fname = filename_bis.clone();
        let mut index = 0;

        let _timer_guard =
            timer.schedule_repeating(chrono::Duration::seconds(set.timeout.unwrap()), move || {
                let lock = &*&pause_handler_rep;
                let pause = lock.read().unwrap();

                if !*pause {
                    let mut flag = timer_flag_clone.lock().unwrap();
                    *flag = true;
                    drop(flag);
                }

                drop(pause);
            });

        loop {
            let mut queue = Vec::<parser::Packet>::new();

            while let Ok(packet) = rx_parse_report.recv() {
                queue.push(packet);
                let mut flag = timer_flag.lock().unwrap();
                if *flag {
                    *flag = false;
                    drop(flag);
                    break;
                }
                drop(flag);
            }

            index += 1;
            let mut report_handle = ReportWriter::new(set.csv.unwrap(), &fname, index);
            report_handle.init_report();

            for packet in queue {
                report_handle.write_report_line(packet);
            }

            println!(
                "{}{}{} {} {}{} {}",
                "[".bold().cyan(),
                chrono::offset::Local::now()
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string()
                    .bold()
                    .cyan(),
                "]".bold().cyan(),
                "Report".bold().cyan(),
                "#".bold().cyan(),
                index.to_string().bold().cyan(),
                "generated".bold().cyan()
            );
            report_handle.close_report();
        }
    });

    //Join the threads
    sniffing_thread.join().unwrap();
    parsing_thread.join().unwrap();
    report_thread.join().unwrap();
    pause_resume_thread.join().unwrap();
}
