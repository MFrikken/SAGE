use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Arg {
    file_path: String
}

pub fn read_argument() -> Arg {
    let arg = Arg ::parse();
    return arg;
}

pub fn get_file_path(arg : Arg) -> String {
    return arg.file_path;
}