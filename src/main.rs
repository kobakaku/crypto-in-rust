use clap::{Parser, Subcommand};
mod sdes;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    SDES,
}

fn main() {
    let args = Args::parse();

    let key: u16 = 0b1010000010;
    let (key1, key2) = sdes::generate_key(key);
    println!("key1: {:08b}", key1);
    println!("key2: {:08b}", key2);

    let plain_text: u8 = 0b10010111;
    println!("original text: {:08b}", plain_text);

    match args.command {
        Commands::SDES => {
            let encrypted_text = sdes::encrypt(key1, key2, plain_text);
            println!("encrypted text: {:08b}", encrypted_text);
        }
    }
}
