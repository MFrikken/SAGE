pub mod command_line_reader;
pub mod file_reader;
pub mod json_parser;
pub mod vulnerability;

use command_line_reader::{get_file_path, read_argument};
use json_parser::convert_to_vulnerability;
use vulnerability::Vulnerability;

fn main() {
    let arg = read_argument();
    let file_path: String = get_file_path(arg);
    let json_data = file_reader::read_file(&file_path);

    let result = json_parser::extract_vulnerabilities(&json_data);

    match result {
        Ok(vulnerabilities) => for vuln in vulnerabilities {
            let vulnerability: Vulnerability = convert_to_vulnerability(vuln);
            println!("{:?}", vulnerability);
        },
        Err(error) => println!("{}", error),
    }

    println!("{}", file_path);
}
