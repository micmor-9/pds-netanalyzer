use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {

    #[arg(short, long, default_value = "listview__")]
    pub interface: String,
    // view the interfaces
    #[arg(short, long, action)]
    pub list: String,
    
}