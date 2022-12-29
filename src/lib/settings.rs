use crate::args::Args;
use clap::Parser;
use colored::*;
use pcap::Device;
use std::fs::{self, File};
use std::io::BufRead;
use std::io::{self, Write};
use std::path::Path;

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
            if vec[3] == "1" {
                tipo = true;
            } else if vec[3] == "0" {
                tipo = false;
            }
            println!("{}", vec[2]);
            let timeoutint: i64 = vec[1].parse().unwrap();
            return Settings {
                interface: Some(vec[0].to_string()),
                csv: Some(tipo),
                timeout: Some(timeoutint),
                filename: Some(vec[2].to_string()),
            };
        } else {
            return Settings {
                interface: None,
                csv: None,
                timeout: None,
                filename: None,
            };
        }
    }
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn check_file(interface_name: &String, tipo: &bool, timeout: &i64, filename: &String) -> () {
    let rs = Path::new("ConfigurationFile.txt").exists();
    let default_interface = Device::list().unwrap().first().unwrap().clone().name;
    if rs == true
        // && *interface_name == default_interface
        && *tipo == false
        && *timeout == 10
        && *filename == "report"
    {
        println!(" Configuration File exists ");
    } else if rs == false
        // && *interface_name == default_interface
        && *tipo == false
        && *timeout == 10
        && *filename == "report"
    {
        create_conf_file();
        println!("Default Configuration File created with default configs (interface name = eth0, tipo = txt, timeout = 10, filename = report");
    } else if rs == true
        && (/* *interface_name != default_interface ||*/*tipo != false || *timeout != 10 || *filename != "report")
    {
        fs::remove_file("ConfigurationFile.txt").expect("File delete failed");
        create_conf_file();
        println!("Customized Configuration File updated");
    } else if rs == false
        && (*interface_name != default_interface
            || *tipo != false
            || *timeout != 10
            || *filename != "report")
    {
        create_conf_file();
        println!("Customized Configuration File created");
    }
}

pub fn create_conf_file() -> () {
    let args = Args::parse();
    let interfaccia = format!(
        "{}\n",
        Device::list().unwrap().first().unwrap().clone().name
    );
    let tempo = format!("{}\n", args.timeout);
    let nome = format!("{}\n", args.reportname);
    let tipo = match args.acsv {
        true => "1",
        false => "0",
    };
    let mut f = File::create("ConfigurationFile.txt").unwrap();
    f.write_all(interfaccia.as_bytes())
        .expect("File writing error");
    f.write_all(tempo.as_bytes()).expect("File writing error");
    f.write_all(nome.as_bytes()).expect("File writing error");
    f.write_all(tipo.as_bytes()).expect("File writing error");
}

pub fn read_conf_file() -> String {
    let err_msg = "Error reading from file <ConfigurationFile.txt".red();

    let rs = Path::new("ConfigurationFile.txt").exists();

    if rs {
        let contents = fs::read_to_string("ConfigurationFile.txt").expect(&err_msg);

        let interface = contents.split_whitespace().next().unwrap_or("");
        return interface.to_string();
    } else {
        return "nu cazzu".to_string();
    }

}
