pub mod command_line_reader;
pub mod database_connector;
pub mod file_reader;
pub mod json_parser;
pub mod pretty_table;
pub mod vulnerability;

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

            // Add user interaction system:
            // Print general "statistic" (Found vulnerabilities: 0 Low, 5 Medium, 2 High)
            // Choose action:
            // 1. List all vulnerabilities
            // 2. List vulnerabilities by filter
            // 3. List all weaknesses
            // 4. List weaknesses by filter
            // 5. Exit

            let id = "1"; // read from user input
            match database_connector.get_vulnerability_by_id(id) {
                Ok(vulnerability) => {
                    let mut vuln_row: Vec<Vec<String>> = vec![vulnerability.to_table()];
                    pretty_table::write_vulnerabilities_table(&mut vuln_row);
                }
                Err(e) => {
                    println!("Could not find vulnerability with id = ({}): {:?}", id, e)
                }
            }
        }
        Err(error) => println!("{}", error),
    }

    let severity = "Low";
    match database_connector.get_vulnerability_by_severity(severity) {
        Ok(vulnerabilities) => {
            let mut vuln_rows = Vec::new();
            for vulnerability in vulnerabilities {
                vuln_rows.push(vulnerability.to_table());
            }
            // consider printing message if result is empty (instead of empty table)
            pretty_table::write_vulnerabilities_table(&mut vuln_rows);
        }
        Err(e) => {
            print!(
                "Could not find vulnerability with severity = ({}): {:?}",
                severity, e
            )
        }
    }

    let vuln_id = "2";
    match database_connector.get_weaknesses_by_vulnerability_id(vuln_id) {
        Ok(weaknesses) => {
            let mut weakn_rows = Vec::new();
            for weakness in weaknesses {
                weakn_rows.push(weakness.to_table());
            }
            // consider printing message if result is empty (instead of empty table)
            pretty_table::write_weaknesses_table(&mut weakn_rows);
        }
        Err(e) => {
            println!("No weakness found with vulnerability_id = ({}): {:?}", vuln_id, e)
        }
    }

    println!("Analyzed file: {}", file_path);
}
