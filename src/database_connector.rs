use rusqlite::{params, Connection, Error, Result, Row};

use crate::vulnerability::{Location, Severity, Vulnerability, Weakness};

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
            vulnerability.severity.display(),
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
        self.find_all(
            "SELECT * FROM vulnerabilities",
            &[],
            |row| Self::map_vulnerability(row)
        )
    }

    pub fn get_all_weaknesses(&self) -> Result<Vec<Weakness>> {
        self.find_all(
            "SELECT * FROM weaknesses",
            &[],
            |row| Self::map_weakness(row)
        )
    }

    pub fn get_vulnerability_by_id(&self, id: &str) -> Result<Vulnerability> {
        self.find_one(
            "SELECT * FROM vulnerabilities  WHERE id = ?1",
            &[&id],
            Self::map_vulnerability
        )
            
        }

        pub fn get_weakness_by_id(&self, id: &str) -> Result<Weakness> {
            self.find_one(
                "SELECT * FROM weaknesses WHERE id = ?1",
                &[&id],
                Self::map_weakness
            )
        }

        pub fn get_weaknesses_by_vulnerability_id(&self, vulnerability_id: &str) -> Result<Vec<Weakness>> {
            self.find_all(
                "SELECT * FROM weaknesses WHERE vulnerability_id = ?1",
                &[&vulnerability_id],
                |row| Self::map_weakness(row)
            )
        }

        pub fn get_vulnerability_by_severity(&self, severity: &str) -> Result<Vec<Vulnerability>> {
    self.find_all(
        "SELECT * FROM vulnerabilities WHERE severity = ?1",
        &[&severity],
        |row| Self::map_vulnerability(row)
    )
        }

        
        fn find_one<T, F>(&self, query: &str, params: &[&dyn rusqlite::ToSql], mapper: F) -> Result<T> 
        where 
        F: Fn(&Row) -> Result<T, Error>,
        {
            let mut stmt = self.connection.prepare(query)?;
            stmt.query_row(params, mapper)
        }

        fn find_all<T, F>(&self, query: &str, params: &[&dyn rusqlite::ToSql], mapper: F) -> Result<Vec<T>>
        where 
            F: Fn(&Row) -> Result<T, Error>,
            {
                let mut stmt = self.connection.prepare(query)?;
                let rows = stmt.query_map(params, mapper)?;
                rows.collect::<Result<Vec<_>, _>>()
            }

            fn map_vulnerability(row: &Row) -> Result<Vulnerability, Error> {
                Ok(Vulnerability {
                    id: row.get(0)?,
                    category: row.get(1)?,
                    name: row.get(2)?,
                    description: row.get(3)?,
                    cve: row.get(4)?,
                    severity: match row.get::<_, String>(5)?.as_str() {
                        "Low" => Severity::Low,
                        "Medium" => Severity::Medium,
                        "High" => Severity::High,
                        _ => Severity::Unknown
                    },
                    location: Location {
                        file: row.get(6)?,
                        start_line: row.get(7)?,
                        end_line: row.get(8)?
                    },
                    weaknesses: Vec::new()
                })
            }

            fn map_weakness(row: &Row) -> Result<Weakness, Error> {
                Ok(Weakness {
                    id: row.get(0)?,
                    r#type: row.get(2)?,
                    name: row.get(3)?,
                    value: row.get(4)?,
                    url: row.get(5)?
                })
            }
        }

