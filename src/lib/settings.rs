use crate::args::Args;
use crate::menu::Filter;
use clap::Parser;
use colored::Colorize;
use pcap::Device;
use std::fs::{self, File, OpenOptions};
use std::io::BufRead;
use std::io::{self, Write};
use std::path::Path;

#[derive(Debug)]
pub struct Settings {
    pub interface: Option<String>,
    pub csv: Option<bool>,
    pub timeout: Option<i64>,
    pub filename: Option<String>,
    pub filters: Option<Filter>,
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
            let mut i = 0;
            for elem in &vec {
                i = i + 1;
                match i {
                    1 => print!("{}{} ", "Interface: ".bold(), elem.cyan().bold()),
                    2 => print!("{}{} ", " - Timeout: ".bold(), elem.cyan().bold()),
                    3 => print!("{}{} ", " - Filename: ".bold(), elem.cyan().bold()),
                    4 => {
                        match elem.as_str() {
                            "0" => println!("{}{} ", " - FileType: ".bold(), "txt".cyan().bold()),
                            "1" => println!("{}{} ", " - FileType: ".bold(), "csv".cyan().bold()),
                            _ => {},
                        }
                    },
                    _ => {},
                }
            }

            let filter = Filter::with_args(vec[4].to_string(),vec[5].to_string(),vec[6].to_string(), vec[7].to_string(),vec[8].to_string());
            let mut tipo = true;
            if vec[3] == "csv" {
                tipo = true;
            } else if vec[3] == "txt" {            
                tipo = false;
            }
            let timeoutint: i64 = vec[1].parse().unwrap();
            return Settings {
                interface: Some(vec[0].to_string()),
                csv: Some(tipo),
                timeout: Some(timeoutint),
                filename: Some(vec[2].to_string()),
                filters: Some(filter),
            };
        } else {
            return Settings {
                interface: None,
                csv: None,
                timeout: None,
                filename: None,
                filters: None,
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

pub fn check_file(interface_name: &String, tipo: &bool, timeout: &i64, filename: &String) -> Settings {
    let args = Args::parse();
    let tipologia = args.output_type;
    let rs = Path::new("ConfigurationFile.txt").exists();

    if rs == true
        && *interface_name == ""
        && *tipo == false
        && *timeout == 10
        && *filename == "report"
        && tipologia == ""
    {
        println!(" Configuration File exists ");
    } else if rs == false
        && *interface_name == ""
        && *tipo == false
        && *timeout == 10
        && *filename == "report"
    {
        create_conf_file().unwrap();
        print!(
            "\n\t{}",
            "Default Configuration File created with default configs: ".green()
        );
    } else if rs == true
        && (*interface_name != "" || *tipo != false || *timeout != 10 || *filename != "report" || tipologia == "txt")
    {
        fs::remove_file("ConfigurationFile.txt").expect("File delete failed");
        create_conf_file().unwrap();
        println!("Customized Configuration File updated");
    } else if rs == false
        && (*interface_name != "" || *tipo != false || *timeout != 10 || *filename != "report")
    {
        create_conf_file().unwrap();
        println!("Customized Configuration File created");
    }
    let set = Settings::new();
    return set;
}

pub fn create_conf_file() -> std::io::Result<()> {
    let interfaces = Device::list().unwrap();
    let args = Args::parse();
    let interfaccia = format!("{}\n", args.interface);
    let interfaccia_standard = format!("{}\n", interfaces.first().unwrap().clone().name);
    let tempo = format!("{}\n", args.timeout);
    let nome = format!("{}\n", args.reportname);
    let tipo = format!("{}\n",match args.output_type.as_str() {
        "csv" => "1",
        "txt" => "0",
        _ => "0"
    });
    let mut f = File::create("ConfigurationFile.txt")?;

    if args.interface == "" {
        f.write_all(interfaccia.as_bytes()).unwrap();
    }
    f.write_all(tempo.as_bytes())?;
    f.write_all(nome.as_bytes())?;
    f.write_all(tipo.as_bytes())?;
    let f2 = Filter::new();
    let mut file = OpenOptions::new()
                    .write(true)
                    .append(true)
                    .open("ConfigurationFile.txt")
                    .unwrap();
                    file.write_all(format!("{}\n", f2.ip_source).as_bytes()).unwrap();
                    file.write_all(format!("{}\n", f2.ip_destination).as_bytes()).unwrap();
                    file.write_all(format!("{}\n", f2.source_port).as_bytes()).unwrap();
                    file.write_all(format!("{}\n", f2.destination_port).as_bytes()).unwrap();
                    file.write_all(format!("{}\n", f2.transport_protocol).as_bytes()).unwrap();
                    
    Ok(())
}



