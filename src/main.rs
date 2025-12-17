use clap::{Arg, Command};
use std::error::Error;

mod joman;

fn cli() -> Command {
    clap::Command::new("joman")
        .about("A journal management system CLI")
        .version("0.3.7")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("init")
                .about("initializes an encrypted journal inside the current directory"),
        )
        .subcommand(
            Command::new("add")
                .about("adds a new entry to directory")
                .arg(
                    Arg::new("file")
                        .help("Path of the entry file to add")
                        .required(true)
                        .value_name("FILE"),
                ),
        )
        .subcommand(
            Command::new("load")
                .about("loads a directory of entries into the journal")
                .arg(
                    Arg::new("directory")
                        .help("Path of the directory to load")
                        .required(true)
                        .value_name("DIRECTORY"),
                ),
        )
        .subcommand(
            Command::new("read")
                .about("read an entry in the directory")
                .arg(
                    Arg::new("file")
                        .required(true)
                        .help("name of the entry file")
                        .value_name("FILE"),
                )
                .arg(
                    Arg::new("pem")
                        .required(true)
                        .help("the private key of the file")
                        .value_name("PEM"),
                ),
        )
        .subcommand(
            Command::new("new")
                .about("creates a new journal entry")
                .arg(
                    Arg::new("title")
                        .help("Title of the journal entry")
                        .value_name("TITLE"),
                ),
        )
        .subcommand(
            Command::new("zip")
                .about("creates a zip archive of the journal directory"),
        )
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("init", _sub_matches)) => {
            joman::initialize()?;

            println!("Journal directory initialized! key saved as ./private.pem");
        }
        Some(("add", sub_matches)) => {
            let file_path = sub_matches
                .get_one::<String>("file")
                .expect("<FILE> argument missing");

            joman::add_file(file_path)?;
        }
        Some(("load", sub_matches)) => {
            let dir_path = sub_matches
                .get_one::<String>("directory")
                .expect("<DIRECTORY> argument missing");

            joman::add_directory(dir_path)?;
        }
        Some(("read", sub_matches)) => {
            let file_path = sub_matches
                .get_one::<String>("file")
                .expect("<FILE> argument missing");

            let key = match sub_matches.get_one::<String>("pem").map(|s| s.as_str()) {
                Some(k) => k,
                None => {
                    eprintln!("private.pem is required to read an entry.");
                    return Ok(());
                }
            };

            let content = joman::read_file(file_path, key)?;
            println!("{}", content);
        }
        Some(("new", sub_matches)) => {
            let title = sub_matches.get_one::<String>("title").map(|s| s.as_str());

            joman::file_creation::new_file(title)?;
        }
        Some(("zip", _sub_matches)) => {
            joman::zip_file()?;
            println!("Journal directory zipped to Journal.zip");
        }
        _ => unreachable!(),
    }

    Ok(())
}
