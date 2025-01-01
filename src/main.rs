use clap::{Parser, Subcommand};
use rand::Rng;

mod aes;
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
    AES,
}

fn main() {
    let args = Args::parse();
    let mut rng = rand::thread_rng();

    let key: u16 = 0b1010000010;
    let (key1, key2) = sdes::generate_key(key);
    println!("key1: {:08b}", key1);
    println!("key2: {:08b}", key2);

    match args.command {
        Commands::SDES => {
            let input = rng.gen();
            println!("original input: {:08b}", input);
            let encrypted_text = sdes::encrypt(key1, key2, input);
            println!("encrypted text: {:08b}", encrypted_text);
        }
        Commands::AES => {
            let input = rng.gen();
            println!("original input: {:?}", input);
            let encrypted_text = aes::encrypt(input, 1);
            println!("encrypted text: {:?}", encrypted_text);
        }
    }
}
