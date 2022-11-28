use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {

    // view the interfaces
    #[arg(short, long, action)]
    pub interface: String,
    
}