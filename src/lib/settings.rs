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
    let mut file_exist = true;
    let rs = Settings::read_from_file().unwrap_or_else(|_| {
        file_exist = false;
        Settings::new_empty()
    });

    if file_exist
        && *interface_name == ""
        && *tipo == false
        && *timeout == 10
        && *filename == "report"
        && tipologia == ""
    {
        println!("\n{}", "\tConfiguration File exists".bold());
        print!(
            "\n{}",
            "\tLaunching the sniffer with previous Configurations\n\n"
                .green()
                .bold()
        );
        println!("\t{}{}", "Interface: ", rs.interface.as_ref().unwrap());
        println!(
            "\t{}{}",
            "Output Type: ",
            match rs.csv.as_ref().unwrap() {
                true => "CSV",
                false => "TXT",
            }
        );
        println!("\t{}{}", "Timeout: ", rs.timeout.as_ref().unwrap());
        println!("\t{}{}", "Filename: ", rs.filename.as_ref().unwrap());
        println!(
            "\t{}{}",
            "Filters: ",
            rs.filters.as_ref().unwrap().get_filter_string()
        );
    } else if !file_exist
        && *interface_name == ""
        && *tipo == false
        && *timeout == 10
        && *filename == "report"
    {
        create_conf_file().unwrap();
        print!(
            "\n\t{}",
            "Default Configuration File created with default configs: ".green(),
        );
        print!(
            "{}{}{}{}{}{}{}{}",
            "Interface: ".bold(),
            "en0".cyan(),
            " - Type output: ".bold(),
            "txt".cyan(),
            " - Timeout ".bold(),
            "10sec".cyan(),
            " - Filename ".bold(),
            "report\n".cyan()
        );
    } else if file_exist
        && (*interface_name != ""
            || *tipo != false
            || *timeout != 10
            || *filename != "report"
            || tipologia == "txt")
    {
        fs::remove_file("ConfigurationFile.txt").expect("File delete failed");
        create_conf_file().unwrap();
        println!("Customized Configuration File updated");
    } else if !file_exist
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
    let interfaces = Device::list().unwrap(); //da decommentare
    let args = Args::parse();
    let mut interface = args.interface;
    let standard_interface = interfaces.first().unwrap().clone().name;
    // let standard_interface = String::from("en0");
    let time = args.timeout;
    let name = args.reportname;
    let r_type = match args.output_type.as_str() {
        "csv" => true,
        "txt" => false,
        _ => false,
    };

    if interface == "" {
        interface = standard_interface;
    }

    let filter_to_write = Filter::new();

    let settings_to_write = Settings::with_args(interface, r_type, time, name, filter_to_write);

    settings_to_write.write_to_file()
}
