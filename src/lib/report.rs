use crate::parser::Packet;
use csv::{Writer, WriterBuilder};
use std::io::Write;

use std::fs::{create_dir, set_permissions, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub enum WriterType<'a> {
    CSV(&'a mut Writer<File>),
    TXT(&'a mut File),
}

pub struct ReportWriter {
    pub csv_or_txt: bool,
    pub filename: String,
    num : i32,
    csv_writer: Option<Box<Writer<File>>>,
    txt_writer: Option<Box<File>>,
}

impl ReportWriter {
    pub fn new(csv_or_txt: bool, filename: &str, num: i32) -> Self {
        let dirname = create_directory(&filename);
        let file_name = get_file_name(filename);
        match csv_or_txt {
            true => {
                let filecsv = WriterBuilder::new()
                    .from_path(format!("{}/{}_{}.csv", dirname, file_name, num));
                return Self {
                    csv_or_txt,
                    filename: file_name.to_string(),
                    num: num,
                    csv_writer: Some(Box::new(filecsv.unwrap())),
                    txt_writer: None,
                };
            }
            false => {
                let filetxt = File::create(format!("{}/{}_{}.txt", dirname, file_name, num));
                return Self {
                    csv_or_txt,
                    filename: file_name.to_string(),
                    num: num,
                    csv_writer: None,
                    txt_writer: Some(Box::new(filetxt.unwrap())),
                };
            }
        }
    }

    pub fn get_file_handle(&mut self) -> WriterType {
        match &mut self.csv_writer {
            Some(thing) => WriterType::CSV(&mut **thing),
            None => match &mut self.txt_writer {
                Some(thing) => WriterType::TXT(&mut **thing),
                _ => panic!("Impossible"),
            },
        }
    }

    pub fn init_report(&mut self) -> () {
        let report_number = self.num;
        let writer = self.get_file_handle();
        match writer {
            WriterType::CSV(csv) => csv
                .write_record(&[
                    "Interface",
                    "Source IP",
                    "Destination IP",
                    "Source Port",
                    "Destination Port",
                    "Bytes",
                    "Transport Protocol",
                    "Application Protocol",
                    "Timestamp"
                ])
                .unwrap(),
            WriterType::TXT(file) => {
                writeln!(file, "Report # {} generated at {}", report_number, chrono::offset::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()).unwrap();
                writeln!(file,"| Int.  | Source IP	            | Destination IP    	| Source Port	| Dest. Port	| Bytes | Transport Protocol	    | Application Protocol 	| Timestamp		|").unwrap();
            }
        }
    }

    pub fn write_report_line(&mut self, report: Packet) -> () {
        let writer = self.get_file_handle();
        match writer {
            WriterType::CSV(csv) => csv.serialize(report).unwrap(),
            WriterType::TXT(file) => {
                writeln!(file, "{}", report).unwrap();
            }
        }
    }

    pub fn close_report(&mut self) -> () {
        let writer = self.get_file_handle();
        match writer {
            WriterType::CSV(csv) => csv.flush().unwrap(),
            _ => (),
        }
    }
}

pub fn create_directory(filename: &str) -> String {
    let mut folder = format!(
        "{}_{}",
        filename,
        chrono::offset::Local::now().format("%Y-%m-%d").to_string()
    );
    folder = folder.to_string();
    folder = folder.replace(" ", "_").replace("-", "").replace(":", "_");

    if !Path::new(folder.as_str()).exists() {
        match create_dir(&folder) {
            Ok(()) => (),
            Err(why) => panic!("{}", why),
        }
        match set_permissions(&folder, PermissionsExt::from_mode(0o777)) {
            Err(why) => panic!("{}", why),
            Ok(_) => {}
        }
    }
    
    folder
}

pub fn get_file_name(filename: &str) -> String {
    let file_name = format!(
        "{}_{}",
        filename,
        chrono::offset::Local::now().format("%H_%M_%S").to_string()
    );
    file_name
}
