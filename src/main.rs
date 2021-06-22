#[macro_use]
extern crate log;

use anyhow::Result;
use clap::{App, Arg, SubCommand};
use std::env;

static LOG_ENV_VAR: &str = "REGDB_LOG";

mod firmware;
mod signing;

fn main() {
    if let Err(e) = app() {
        println!("failed: {}", e);
        std::process::exit(1);
    }
}

fn app() -> Result<()> {
    if env::var(LOG_ENV_VAR).is_err() {
        env::set_var(LOG_ENV_VAR, "info");
    }
    pretty_env_logger::init_custom_env(LOG_ENV_VAR);
    trace!("logger started");

    let mut app = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .setting(clap::AppSettings::ColorAuto)
        .setting(clap::AppSettings::ColoredHelp)
        .subcommand(
            firmware::app()
        );

    if cfg!(feature = "completion") {
        app = app.subcommand(
            SubCommand::with_name("completion")
                .about("create completions")
                .version("0.1.0")
                .author(env!("CARGO_PKG_AUTHORS"))
                .arg(
                    Arg::with_name("shell")
                        .help("set the shell to create for. Tries to identify with env variable")
                        .index(1)
                        .required(false)
                        .value_name("SHELL")
                        .possible_value("fish")
                        .possible_value("bash")
                        .possible_value("zsh")
                        .possible_value("powershell")
                        .possible_value("elvish"),
                )
                .arg(
                    Arg::with_name("out")
                        .help("sets output file")
                        .value_name("FILE")
                        .short("o")
                        .long("output"),
                )
                .setting(clap::AppSettings::ColorAuto)
                .setting(clap::AppSettings::ColoredHelp),
        );
    }

    let matches = app.clone().get_matches();

    if cfg!(feature = "completion") {
        if let Some(matches) = matches.subcommand_matches("completion") {
            trace!("gernerate completion");
            completion(&matches, &mut app);
            std::process::exit(0);
        }
    }
    drop(app); // remove arguemnt parser

    if let Some(matches) = matches.subcommand_matches("firmware") {
        trace!("running firmware");
        firmware::run(matches)?;
    }

    Ok(())
}

/// create completion
#[cfg(feature = "completion")]
fn completion(args: &clap::ArgMatches, app: &mut App) {
    let shell: String = match args.value_of("shell") {
        Some(shell) => shell.to_string(),
        None => shell(),
    };

    use clap::Shell;
    let shell_l = shell.to_lowercase();
    let shell: Shell;
    if shell_l == "fish" {
        shell = Shell::Fish;
    } else if shell_l == "zsh" {
        shell = Shell::Zsh;
    } else if shell_l == "powershell" {
        shell = Shell::PowerShell;
    } else if shell_l == "elvish" {
        shell = Shell::Elvish;
    } else {
        shell = Shell::Bash;
    }

    use std::fs::File;
    use std::io::BufWriter;
    use std::io::Write;

    let mut path = BufWriter::new(match args.value_of("out") {
        Some(x) => Box::new(
            File::create(&std::path::Path::new(x)).unwrap_or_else(|err| {
                eprintln!("Error opening file: {}", err);
                std::process::exit(1);
            }),
        ) as Box<dyn Write>,
        None => Box::new(std::io::stdout()) as Box<dyn Write>,
    });

    app.gen_completions_to(env!("CARGO_PKG_NAME"), shell, &mut path);
}

#[cfg(all(feature = "completion", not(windows)))]
fn shell() -> String {
    let shell: String = match std::env::var("SHELL") {
        Ok(shell) => shell,
        Err(_) => "/bin/bash".to_string(),
    };
    let shell = std::path::Path::new(&shell);
    match shell.file_name() {
        Some(shell) => shell.to_os_string().to_string_lossy().to_string(),
        None => "bash".to_string(),
    }
}

#[cfg(all(feature = "completion", windows))]
fn shell() -> String {
    "powershell".to_string() // always default to powershell on windows
}

#[cfg(not(feature = "completion"))]
fn completion(_: &clap::ArgMatches, _: &mut App) {
    eprintln!("Completion command fired but completion not included in features");
    std::process::exit(-1);
}
