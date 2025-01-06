pub mod command_line_reader;
pub mod file_reader;
pub mod json_parser;
pub mod database_connector;
pub mod vulnerability;
pub mod pretty_table;

use command_line_reader::{get_file_path, read_argument};
use database_connector::DatabaseConnector;
use vulnerability::{Location, Vulnerability, Weakness};

fn main() {
    let arg = read_argument();
    let file_path: String = get_file_path(arg);
    let json_data = file_reader::read_file(&file_path);
    let database_connector = DatabaseConnector::new();

    let result = json_parser::extract_vulnerabilities(&json_data);

    match result {
        Ok(vulnerabilities) => {
            let mut vuln_id: u32 = 1;
            for vuln in vulnerabilities {
                let weaknesses: Vec<Weakness> = Vulnerability::create_weaknesses(&vuln);
                let location: Location = Location::new(&vuln);
                let vulnerability: Vulnerability =
                    Vulnerability::new(vuln_id, &vuln, location, weaknesses);

                let _ = database_connector.write_vulnerability(&vulnerability);

                for weakn in vulnerability.weaknesses {
                    let _ = database_connector.write_weakness(&vuln_id, &weakn);
                }

                vuln_id += 1;
            }

            match database_connector.read_all_vulnerabilities() {
                Ok(vulnerabilities) => {
                    let mut vuln_rows: Vec<Vec<String>> = Vec::new();
                    for vulnerability in vulnerabilities {
                        vuln_rows.push(vulnerability.to_table());
                    }

                    let _ = pretty_table::write_vulnerabilities_table(&mut vuln_rows);
                }
                Err(e) => {
                    println!("Failed to read database entries: {:?}", e)
                }
            }
        }
        Err(error) => println!("{}", error),
    }


    println!("{}", file_path);
}
