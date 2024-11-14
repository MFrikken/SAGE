pub mod command_line_reader;
pub mod file_reader;
pub mod json_parser;
pub mod vulnerability;

use command_line_reader::{get_file_path, read_argument};
use vulnerability::{Location, Vulnerability, Weakness};

fn main() {
    let arg = read_argument();
    let file_path: String = get_file_path(arg);
    let json_data = file_reader::read_file(&file_path);

    let result = json_parser::extract_vulnerabilities(&json_data);

    match result {
        Ok(vulnerabilities) => {
            for vuln in vulnerabilities {
                let weaknesses: Vec<Weakness> = Vulnerability::create_weaknesses(&vuln);
                let location: Location = Location::new(&vuln);
                let vulnerability: Vulnerability =
                    Vulnerability::new(1, &vuln, location, weaknesses);

                println!("{:?}", vulnerability);
                println!("-------------------------------------------------------------------------------------");
            }
        }
        Err(error) => println!("{}", error),
    }

    println!("{}", file_path);
}
