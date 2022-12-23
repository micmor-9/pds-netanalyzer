use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    // name of interface to be used for the sniffing
    #[arg(short, long, default_value = "10")]
    pub timeout: i64,
    #[arg(short, long, default_value = "report")]
    pub filename: String,
    #[arg(short, long, default_value = "listview__")]
    pub interface: String,

    // view the interfaces whitout start the sniffing
    #[arg(short, long, action)]
    pub list: bool,

    #[arg(short, long, action)]
    pub commands: bool,
    #[arg(short, long, action)]
    pub acsv: bool,
}
