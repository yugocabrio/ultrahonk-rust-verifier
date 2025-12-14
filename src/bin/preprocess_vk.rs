use std::env;
use std::fs;
use std::process;

use ultrahonk_soroban_contract::preprocess_vk_json;

fn main() {
    let mut args = env::args().skip(1);
    let input = match args.next() {
        Some(path) => path,
        None => {
            eprintln!("usage: preprocess_vk <vk_json_path> <output_path>");
            process::exit(1);
        }
    };
    let output = match args.next() {
        Some(path) => path,
        None => {
            eprintln!("usage: preprocess_vk <vk_json_path> <output_path>");
            process::exit(1);
        }
    };

    if args.next().is_some() {
        eprintln!("usage: preprocess_vk <vk_json_path> <output_path>");
        process::exit(1);
    }

    let contents = match fs::read_to_string(&input) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("failed to read {input}: {err}");
            process::exit(1);
        }
    };

    let bytes = match preprocess_vk_json(&contents) {
        Ok(result) => result,
        Err(_) => {
            eprintln!("failed to parse verification key JSON");
            process::exit(1);
        }
    };

    if let Err(err) = fs::write(&output, &bytes) {
        eprintln!("failed to write {output}: {err}");
        process::exit(1);
    }
}
