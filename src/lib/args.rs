use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    // name of interface to be used for the sniffing
    #[arg(short, long, default_value = "10")]
    pub timeout: i64,

    #[arg(short, long, default_value = "report")]
    pub reportname: String,

    // #[arg(short, long, default_value = "eth0")]  //cercare un valore di default 
    #[arg(short, long, default_value = "")]
    pub interface: String,

    // view the interfaces without start the sniffing
    #[arg(short, long, action)]
    pub list: bool,

    // view all possible commads without start sniffing
    #[arg(short, long, action)]
    pub commands: bool,

    // view all filters
    #[arg(short, long, action, default_value = "false")]
    pub filters: bool,

    #[arg(short, long, action)]
    pub acsv: bool,
}
