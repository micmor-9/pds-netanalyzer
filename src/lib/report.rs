use std::net::IpAddr;
use std::io::Write;
use csv::{Writer, WriterBuilder};
use crate::report::Reporter::{CSV, TXT};
use std::path::Path;
use serde::Serialize;
use std::fs::{create_dir, File, set_permissions};
use std::os::unix::fs::PermissionsExt;
use std::collections::HashMap;


#[derive(PartialEq, Eq, Hash)]
pub struct ReportHeader {
    pub source_address: IpAddr,
    pub destination_address: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>
}
#[derive(Serialize)]
pub struct Report {
    pub packet: Packet,
    pub total_bytes: u64,
    pub init_time: String,
    pub finish_time: String
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //        "Interface\t| Source IP address\t| Source Port\t| Dest IP address \t| Dest Port\t| Timestamp\t|  Bytes\t| Transport \t| Application \n"
        write!(f, "|{0: <1}\t| {}\t| {2: <5}\t| {3: <25} ({4}) \t| {5: <5}\t| {6: <3}\t| {7: <4} \t| {8: <4}\t| {9: <15}\t| {10: <15}", self.packet.interface, self.packet.src_addr, self.packet.src_port.unwrap_or(0), self.packet.dest_addr, self.packet.res_name, self.packet.dest_port.unwrap_or(0), self.total_bytes, self.packet.transport, self.packet.application, self.start_time, self.stop_time )
    }
}

pub enum WriterType <'a> {
    CSV(&'a mut Writer<File>),
    TXT(&'a mut File)
}

pub struct ReportWriter {
    pub csv_or_txt: bool,
    pub filename: String,
    csv_writer: Option<Box<Writer<File>>>,
    txt_writer: Option<Box<File>>
}

impl ReportWriter {
    pub fn new(csv_or_txt: bool, filename: &str, num: i32) -> Self {
        match csv_or_txt {
            true => {
                let filecsv = WriterBuilder::new().from_path(format!("{}-{}.csv", filename, num));
                return Self {
                    csv_or_txt,
                    filename: filename.to_string(),
                    csv_writer: Some(Box::new(filecsv)),
                    txt_writer: None
                }
            },
            false => {
                let path = Path::new(format!("{}-{}.txt", filename, num));
                let filetxt = File::create(&path);
                return Self {
                    csv_or_txt,
                    filename: filename.to_string(),
                    csv_writer: None,
                    txt_writer: Some(Box::new(filetxt))
                }
            }
        }
    }


    pub fn get_where_to_write(&mut self) -> WriterType {
        match &mut self.csv_writer{
            Some(thing) => CSV(&mut **thing),
            None =>{
                match &mut self.txt_writer {
                    Some(thing) => TXT(&mut **thing),
                    _ => panic!("Impossible")
                }
            }
        }
    }

    pub fn start_report(&mut self) -> (){
        let writer = self.get_where_to_write();
        match writer {
            WriterType::CSV(csv) => csv.write_record(
                &["Interface","Source_Address","Source_Port","Destination_Address",
                "Destination_port","Transport","Application","Bytes","Init_Time","Finish_Time"]
            ).unwrap(),
            WriterType::TXT(file)=>{
                writeln!(file,"| Interface\t| Source IP\t| Source Port\t| Destination IP\t| Destination Port\t| Bytes\t| Transport \t| Application \t| Init Time\t| Finish time\n").unwrap();
            }
        }
    }

    pub fn write_report(&mut self, report: Report) ->() {
        let writer = self.get_where_to_write();
        match writer {
            WriterType::CSV(csv) => csv.serialize(report).unwrap(),
            WriterType::TXT(file)=>{
                writeln!(file,"{}", report).unwrap();
            }
        }
    }

    pub fn close_report(&mut self) -> () {
        let writer = self.get_where_to_write();
        match writer {
            WriterType::CSV(csv) => csv.flush().unwrap(),
            _ => ()
        }
    }
}

pub fn create_directory(filename: &str) -> String {
    let mut folder = format!("{}_{}",
    filename,
    chrono::offset::Local::now().naive_local()
    );
    folder = folder.to_string();
    folder = folder.replace(" ", "_").replace("-","").replace(":","_");

    match create_dir(&folder){
        Ok(()) => (),
        Err(why) => panic!("{}",why)
    }
    match set_permissions(&folder, PermissionsExt::from_mode(0o777)) {
        Err(why) => panic!("{}", why),
        Ok(_) =>{},
    }
    folder
}

pub fn create_hashmap(buffer: Vec<Packet>) -> HashMap<ReportHeader, Report> {
    let mut report = HashMap::new();
    for l in buffer {
        let bytes = l.length;

        let p_header = ReportHeader {
            source_address: l.source_address,
            destination_address: l.destination_address,
            source_port: l.source_port,
            destination_port: l.destination_port
        };
        if report.contains_key(&p_header) {
            let mut update: &mut Report = report.get_mut(&p_header).unwrap();
            update.total_bytes += bytes as u64;
            update.stop_time = l.timestamp;
        } else {

            report.insert(p_header, {
                let time = l.timestamp.clone();
                let time2 = l.timestamp.clone();

                Report {
                    packet: s,
                    total_bytes: bytes as u64,
                    init_time: time,
                    finish_time: time2
                }
            });
        }
        //writeln!(&mut file, "{}", s).unwrap();
    }

    report
}

