use crate::args::Args;
use crate::menu::Filter;
use clap::Parser;
use colored::Colorize;
use pcap::Device;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs;
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
    pub fn new() -> Self {
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

    pub fn write_to_file(&self) -> Result<(), std::io::Error> {
        let serialized_settings = serde_json::to_string(self).unwrap();
        fs::write("settings.conf", serialized_settings)
    }

    pub fn read_from_file() -> Result<Settings, std::io::Error> {
        let input_path = Path::new("settings.conf");
        let unserialized_settings = fs::read_to_string(input_path);
        if unserialized_settings.is_ok() {
            Ok(serde_json::from_str::<Settings>(&unserialized_settings.unwrap()).unwrap())
        } else {
            Err(unserialized_settings.unwrap_err())
        }
    }
}

pub fn check_file(
    interface_name: &String,
    tipo: &bool,
    timeout: &i64,
    filename: &String,
) -> Settings {
    let args = Args::parse();
    let tipologia = args.output_type;
    let mut file_exists = true;
    let mut rs = Settings::read_from_file().unwrap_or_else(|_| {
        file_exists = false;
        Settings::new()
    });

    if tipologia != "" {
        rs.csv = Some(*tipo);
    }

    if file_exists
        && *interface_name == ""
        && *tipo == false
        && *timeout == 10
        && *filename == "report"
        && tipologia == ""
    {
        println!("\n{}", "\tConfiguration File exists".bold());
        print!(
            "\n{}",
            "\tLaunching the sniffer with previous Configuration\n\n"
                .green()
                .bold()
        );
        println!(
            "\t{}{}",
            "Interface: ".bold(),
            rs.interface.as_ref().unwrap()
        );
        println!(
            "\t{}{}",
            "Output Type: ".bold(),
            match rs.csv.as_ref().unwrap() {
                true => "CSV",
                false => "TXT",
            }
        );
        println!("\t{}{}", "Timeout: ".bold(), rs.timeout.as_ref().unwrap());
        println!("\t{}{}", "Filename: ".bold(), rs.filename.as_ref().unwrap());
        println!(
            "\t{}{}",
            "Filters: ".bold(),
            rs.filters.as_ref().unwrap().get_filter_string()
        );
    } else if !file_exists
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
    } else if file_exists
        && (*interface_name != ""
            || *tipo != false
            || *timeout != 10
            || *filename != "report"
            || tipologia == "txt")
    {
        if *tipo != rs.csv.unwrap() {
            rs.csv = Some(*tipo);
        }
        if *filename != "report" && filename != rs.filename.as_ref().unwrap() {
            rs.filename = Some(filename.clone());
        }
        if *timeout != 10 && *timeout != rs.timeout.unwrap() {
            rs.timeout = Some(*timeout)
        }
        if *interface_name != "" && interface_name != rs.interface.as_ref().unwrap() {
            rs.interface = Some(interface_name.clone());
        }

        rs.write_to_file().unwrap_or_else(|_| {
            eprintln!("Error while writing filters on file...");
            std::process::exit(1);
        });
        println!("\n\t{}", "Customized Configuration File updated".bold());
    } else if !file_exists
        && (*interface_name != "" || *tipo != false || *timeout != 10 || *filename != "report")
    {
        create_conf_file().unwrap();
        println!("\n\t{}", "Customized Configuration File created".bold());
    }
    let set = Settings::read_from_file();
    return if set.is_ok() {
        set.unwrap()
    } else {
        Settings::new()
    };
}

pub fn create_conf_file() -> std::io::Result<()> {
    let interfaces = Device::list().unwrap();
    let args = Args::parse();
    let mut interface = args.interface;
    let standard_interface = interfaces.first().unwrap().clone().name;
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
