use clap::Parser;

#[derive(Parser)]

pub struct Arguments {
  pub filename: String,
  pub interface: String,
  pub list: bool
}