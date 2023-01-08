use crate::args::Args;
use crate::menu::Filter;
use clap::Parser;
use colored::Colorize;
use pcap::Device;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::{self, File};
use std::io;
use std::io::BufRead;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct Settings {
    pub interface: Option<String>,
    pub csv: Option<bool>,
    pub timeout: Option<i64>,
    pub filename: Option<String>,
    pub filters: Option<Filter>,
}
impl Settings {
    pub fn new_empty() -> Self {
        return Settings {
            interface: None,
            csv: None,
            timeout: None,
            filename: None,
            filters: None,
        };
    }

    fn with_args(
        interface: String,
        csv: bool,
        timeout: i64,
        filename: String,
        filters: Filter,
    ) -> Self {
        return Settings {
            interface: Some(interface),
            csv: Some(csv),
            timeout: Some(timeout),
            filename: Some(filename),
            filters: Some(filters),
        };
    }

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
                    4 => match elem.as_str() {
                        "0" => println!("{}{} ", " - FileType: ".bold(), "txt".cyan().bold()),
                        "1" => println!("{}{} ", " - FileType: ".bold(), "csv".cyan().bold()),
                        _ => {}
                    },
                    _ => {}
                }
            }

            let filter = Filter::with_args(
                vec[4].to_string(),
                vec[5].to_string(),
                vec[6].to_string(),
                vec[7].to_string(),
                vec[8].to_string(),
            );
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

    pub fn write_to_file(&self) -> Result<(), std::io::Error> {
        let serialized_settings = serde_json::to_string(self).unwrap();
        std::fs::write("ConfigurationFile.txt", serialized_settings)
    }

    pub fn read_from_file() -> Result<Settings, std::io::Error> {
        let input_path = Path::new("ConfigurationFile.txt");
        let unserialized_settings = std::fs::read_to_string(input_path);
        if unserialized_settings.is_ok() {
            Ok(serde_json::from_str::<Settings>(&unserialized_settings.unwrap()).unwrap())
        } else {
            Err(unserialized_settings.unwrap_err())
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

pub fn check_file(
    interface_name: &String,
    tipo: &bool,
    timeout: &i64,
    filename: &String,
) -> Settings {
    let args = Args::parse();
    let tipologia = args.output_type;
    let rs = Settings::read_from_file();

    if rs.is_ok()
        && *interface_name == ""
        && *tipo == false
        && *timeout == 10
        && *filename == "report"
        && tipologia == ""
    {
        println!(" Configuration File exists ");
    } else if rs.is_err()
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
    } else if rs.is_ok()
        && (*interface_name != ""
            || *tipo != false
            || *timeout != 10
            || *filename != "report"
            || tipologia == "txt")
    {
        fs::remove_file("ConfigurationFile.txt").expect("File delete failed");
        create_conf_file().unwrap();
        println!("Customized Configuration File updated");
    } else if rs.is_err()
        && (*interface_name != "" || *tipo != false || *timeout != 10 || *filename != "report")
    {
        create_conf_file().unwrap();
        println!("Customized Configuration File created");
    }
    let set = Settings::read_from_file();
    if set.is_ok() {
        return set.unwrap();
    } else {
        return Settings::new_empty();
    }
}

pub fn create_conf_file() -> std::io::Result<()> {
    let interfaces = Device::list().unwrap();
    let args = Args::parse();
    let mut interface = args.interface;
    let interfaccia_standard = interfaces.first().unwrap().clone().name;
    let time = args.timeout;
    let name = args.reportname;
    let r_type = match args.output_type.as_str() {
        "csv" => true,
        "txt" => false,
        _ => false,
    };

    if interface == "" {
        interface = interfaccia_standard;
    }

    let filter_to_write = Filter::new();

    dbg!(&filter_to_write);

    let settings_to_write = Settings::with_args(interface, r_type, time, name, filter_to_write);

    settings_to_write.write_to_file()

    /*let mut f = File::create("ConfigurationFile.txt")?;

    f.write_all(time.as_bytes())?;
    f.write_all(name.as_bytes())?;
    f.write_all(r_type.as_bytes())?;
    let f2 = Filter::new();
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open("ConfigurationFile.txt")
        .unwrap();
    file.write_all(format!("{}\n", f2.ip_source).as_bytes())
        .unwrap();
    file.write_all(format!("{}\n", f2.ip_destination).as_bytes())
        .unwrap();
    file.write_all(format!("{}\n", f2.source_port).as_bytes())
        .unwrap();
    file.write_all(format!("{}\n", f2.destination_port).as_bytes())
        .unwrap();
    file.write_all(format!("{}\n", f2.transport_protocol).as_bytes())
        .unwrap();

    Ok(())*/
}
