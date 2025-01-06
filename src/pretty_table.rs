use comfy_table::{ColumnConstraint::{UpperBoundary, LowerBoundary}, Width::*, modifiers::{UTF8_ROUND_CORNERS, UTF8_SOLID_INNER_BORDERS}, presets::UTF8_FULL, ContentArrangement, Table};


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
        table.add_row(vulnerability);
    }

    println!("{table}");
}