use rusqlite::{Connection, Result, Error, params};
use std::fs;

use crate::vulnerability::{Vulnerability, Weakness, Location};

pub struct DatabaseConnector {
    connection: Connection
}

impl DatabaseConnector {

    pub fn new(database_scheme_path: &String) -> Self {
        let connection: Connection = DatabaseConnector::open_connection(&database_scheme_path).unwrap();
        DatabaseConnector {
            connection
        }
    }

    pub fn open_connection(database_scheme_path: &String) -> Result<Connection, Error> {
        match Connection::open_in_memory() {
            Ok(connection) => {
                let schema = fs::read_to_string(database_scheme_path);
                if let Ok(schema) = schema {
                    if let Err(e) = DatabaseConnector::create_database(&connection, &schema) {
                        println!("Failed to create databse from schema: {:?}", e);
                        return Err(e);
                    } 
                    Ok(connection)
                } else {
                    println!("Could not load database schema from: {}", database_scheme_path);
                    Err(Error::InvalidQuery)
                }
            },
            Err(error) => {
                println!("Error while connecting to database: {:?}", error);
                Err(error)
            }
        }
    }
    
    fn create_database(connection: &Connection, schema: &String) -> Result<()>{
        connection.execute_batch(schema)
    }
    
    pub fn write_vulnerability(&self, vulnerability: &Vulnerability) -> Result<()> {
        match self.connection.execute("INSERT INTO vulnerabilities (id, category, name, description, type, cve, severity, file, start_line, end_line) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);", 
        params![
            vulnerability.id,
            vulnerability.category, 
            vulnerability.name,
            vulnerability.description,
            vulnerability.r#type,
            vulnerability.cve,
            vulnerability.severity,
            vulnerability.location.file,
            vulnerability.location.start_line,
            vulnerability.location.end_line
        ]) {
            Ok(_) => {
                println!("Vulnerability successfully inserted!");
                Ok(())
            },
            Err(e) => {
                println!("Error while writing vulnerability: {:?}", e);
                Err(e)
            }
        }
    }

    pub fn write_weakness(&self, vulnerability_id: &u32, weakness: &Weakness) -> Result<()> {
        match self.connection.execute("INSERT INTO weaknesses (vulnerability_id, type, name, value, url) VALUES (?1, ?2, ?3, ?4, ?5);", 
        params![
            vulnerability_id,
            weakness.r#type,
            weakness.name,
            weakness.value,
            weakness.url
        ]) {
            Ok(_) => {
                println!("Weakness successfully inserted!");
                Ok(())
            },
            Err(e) => {
                println!("Error while writing weakness: {:?}", e);
                Err(e)
            }
        }
    }

    pub fn read_all_vulnerabilities(&self) -> Result<Vec<Vulnerability>, Error> {
        let mut stmt = self.connection.prepare("SELECT * FROM vulnerabilities")?;
        let vulnerabilities = stmt.query_map([], |row| {
            Ok(Vulnerability {
                id: row.get(0)?,
                category: row.get(1)?,
                name: row.get(2)?,
                description: row.get(3)?,
                r#type: row.get(4)?,
                cve: row.get(5)?,
                severity: row.get(6)?,
                location: Location {
                    file: row.get(7)?,
                    start_line: row.get(8)?,
                    end_line: row.get(9)?,
                },
                weaknesses: Vec::new()
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

        for vulnerability in &vulnerabilities {
            println!("{:?}", vulnerability);
        }

        Ok(vulnerabilities)
    }
}
