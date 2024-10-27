use serde_json::{Result, Value};

use crate::vulnerability::{create_vulnerability, create_location, create_weaknesses, Vulnerability, Location, Weakness};

pub fn extract_vulnerabilities(json_data: &String) -> Result<Vec<Value>> {
    let scan_result: Value = serde_json::from_str(&json_data)?;
    let mut vulnerability_list: Vec<Value> = Vec::new();

    if let Some(vulnerabilities) = scan_result["vulnerabilities"].as_array() {
        for vuln in vulnerabilities {
            vulnerability_list.push(vuln.clone());
        }
    }

    Ok(vulnerability_list)
}

pub fn convert_to_vulnerability(vulnerability: Value) -> Vulnerability {
    let weaknesses: Vec<Weakness> = create_weaknesses(&vulnerability);
    let location: Location = create_location(&vulnerability);
    create_vulnerability(1, &vulnerability, location, weaknesses)
}
