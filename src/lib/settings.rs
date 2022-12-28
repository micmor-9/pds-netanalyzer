use std::fs::File;
use std::io;
use std::io::BufRead;
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
            }
            else if vec[3] == "0" {
                tipo = false;
            }
            println!("{}",vec[2]);
            let timeoutint: i64 = vec[1].parse().unwrap();
                    return Settings {
                        interface: Some(vec[0].to_string()),
                        csv: Some(tipo),
                        timeout: Some(timeoutint),
                        filename:Some(vec[2].to_string()),
                        }
                        
                        


        } else {
            return Settings {
                interface: None,
                csv: None,
                timeout: None,
                filename: None,
            }
        }
        

    }
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())

}

