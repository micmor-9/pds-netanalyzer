use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {

    // name of interface to be used for the sniffing
    #[arg(short, long, default_value = "listview__")]
    pub interface: String,

    // view the interfaces whitout start the sniffing
    #[arg(short, long, action)]
    pub list: bool,

    #[arg(short, long, action)]
    pub commands: bool,

}