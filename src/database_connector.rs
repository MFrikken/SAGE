use rusqlite::{Connection, Result, Error, params};

use crate::vulnerability::{Vulnerability, Weakness, Location};

const DATABSE_SCHEMA: &str = include_str!("./resources/database/database.sql");

pub struct DatabaseConnector {
    connection: Connection
}

impl DatabaseConnector {

    pub fn new() -> Self {
        let connection: Connection = DatabaseConnector::open_connection().unwrap();
        DatabaseConnector {
            connection
        }
    }

    pub fn open_connection() -> Result<Connection, Error> {
        match Connection::open_in_memory() {
            Ok(connection) => {
                if let Err(e) = DatabaseConnector::create_database(&connection, DATABSE_SCHEMA) {
                    println!("Failed to create databse from schema: {:?}", e);
                    return Err(e);
                } 
                Ok(connection)
            },
            Err(error) => {
                println!("Error while connecting to database: {:?}", error);
                Err(error)
            }
        }
    }
    
    fn create_database(connection: &Connection, schema: &str) -> Result<()>{
        connection.execute_batch(schema)
    }
    
    pub fn write_vulnerability(&self, vulnerability: &Vulnerability) -> Result<()> {
        match self.connection.execute("INSERT INTO vulnerabilities (id, category, name, description, cve, severity, file, start_line, end_line) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);", 
        params![
            vulnerability.id,
            vulnerability.category, 
            vulnerability.name,
            vulnerability.description,
            vulnerability.cve,
            vulnerability.severity,
            vulnerability.location.file,
            vulnerability.location.start_line,
            vulnerability.location.end_line
        ]) {
            Ok(_) => {
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
                cve: row.get(4)?,
                severity: row.get(5)?,
                location: Location {
                    file: row.get(6)?,
                    start_line: row.get(7)?,
                    end_line: row.get(8)?,
                },
                weaknesses: Vec::new()
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

        Ok(vulnerabilities)
    }
}
