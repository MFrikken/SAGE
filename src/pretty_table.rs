use comfy_table::{ColumnConstraint::{UpperBoundary, LowerBoundary}, Width::*, modifiers::{UTF8_ROUND_CORNERS, UTF8_SOLID_INNER_BORDERS}, presets::UTF8_FULL, ContentArrangement, Table, Cell, Color};


pub fn write_vulnerabilities_table (vulnerabilities: &mut Vec<Vec<String>>) {
    let mut table: Table = Table::new();

    table
    .load_preset(UTF8_FULL)
    .apply_modifier(UTF8_ROUND_CORNERS)
    .apply_modifier(UTF8_SOLID_INNER_BORDERS)
    .set_content_arrangement(ContentArrangement::Dynamic)
    .set_header(vec![
        "ID",
        "Category",
        "Name",
        "Discription",
        "CVE",
        "Severity",
        "File",
        "Start Line",
        "End Line",
    ]);

    table.column_mut(2)
    .expect("This should be 'Category'")
    .set_constraint(UpperBoundary(Fixed(30)));
    table.column_mut(3)
    .expect("This should be 'Description'")
    .set_constraint(LowerBoundary(Fixed(80)));
    table.column_mut(4)
    .expect("This should be 'CVE'")
    .set_constraint(UpperBoundary(Fixed(40)));
    table.column_mut(6)
    .expect("This should be 'File'")
    .set_constraint(UpperBoundary(Fixed(20)));

    for vulnerability in vulnerabilities {

        let severity = &vulnerability[5];
        let mut severity_cell = Cell::new(severity);
        severity_cell = match severity.as_str() {
            "Low" => severity_cell.fg(Color::Green),
            "Medium" => severity_cell.fg(Color::Yellow),
            "High" => severity_cell.fg(Color::Red),
            _ => severity_cell,
        };

        table.add_row(vec![
            Cell::new(&vulnerability[0]),
            Cell::new(&vulnerability[1]),
            Cell::new(&vulnerability[2]),
            Cell::new(&vulnerability[3]),
            Cell::new(&vulnerability[4]),
            severity_cell,
            Cell::new(&vulnerability[6]),
            Cell::new(&vulnerability[7]),
            Cell::new(&vulnerability[8]),
            ]);
    }

    println!("{table}");
}

pub fn write_weaknesses_table (weaknesses: &mut Vec<Vec<String>>) {
    let mut table: Table = Table::new();

    table
    .load_preset(UTF8_FULL)
    .apply_modifier(UTF8_ROUND_CORNERS)
    .apply_modifier(UTF8_SOLID_INNER_BORDERS)
    .set_content_arrangement(ContentArrangement::Dynamic)
    .set_header(vec![
        "ID",
        "Type",
        "Name",
        "Value",
        "References"
    ]);

    for weakness in weaknesses {
        table.add_row(weakness);
    }

    println!("{table}");
}