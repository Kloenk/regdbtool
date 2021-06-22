use clap::{App, Arg, SubCommand};

use anyhow::{Result, Context};

use crate::signing::SignInfo;

pub(crate) fn app() -> App<'static, 'static> {
    SubCommand::with_name("firmware")
        .alias("f")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("create firmware file")
        .setting(clap::AppSettings::ColorAuto)
        .setting(clap::AppSettings::ColoredHelp)
        .args(&args())
        .subcommand(
            SubCommand::with_name("sign")
                .version(env!("CARGO_PKG_VERSION"))
                .author(env!("CARGO_PKG_AUTHORS"))
                .about("sign firmware file")
                .setting(clap::AppSettings::ColorAuto)
                .setting(clap::AppSettings::ColoredHelp)
                .arg(
                    Arg::with_name("input")
                        .help("input file to sign")
                        .takes_value(true)
                        .value_name("REGDB")
                        .required(true)
                        .env("REGDB_FILE")
                )
                .arg(
                    Arg::with_name("output")
                        .help("signature file, defaults to <REGDB>.p7s")
                        .takes_value(true)
                        .value_name("SIGNATURE")
                        .env("REGDB_OUT")
                )
        )
        .subcommand(
            SubCommand::with_name("generate")
                .alias("gen")
                .alias("g")
                .version(env!("CARGO_PKG_VERSION"))
                .author(env!("CARGO_PKG_AUTHORS"))
                .about("generate firmware file")
                .setting(clap::AppSettings::ColorAuto)
                .setting(clap::AppSettings::ColoredHelp)
                .arg(
                    Arg::with_name("input")
                        .help("input file")
                        .takes_value(true)
                        .default_value("db.txt")
                        .env("REGDB_FILE")
                )
                .arg(
                    Arg::with_name("output")
                        .help("output file")
                        .takes_value(true)
                        .default_value("regulatory.db")
                        .env("REGDB_OUT")
                )
        )
}

fn args() -> Vec<Arg<'static, 'static>> {
    let mut ret = Vec::new();

    ret.append(&mut crate::signing::args_sign());

    ret
}


pub(crate) fn run(matches: &clap::ArgMatches) -> Result<()>{

    if cfg!(feature = "sign") {
        let info = SignInfo::from_matches(matches)?;
        let keyfile = matches.value_of("keyfile");
        if let Some(sub_matches) = matches.subcommand_matches("sign") {
            //info!("sign zone {} with key {}", matches.value_of("input").unwrap(), keyfile);//matches.value_of("keyfile").unwrap());
            sign(
                sub_matches.value_of("input").unwrap(),
                sub_matches.value_of("output"),
                matches.value_of("keyfile").unwrap(), // FIXME: check if it's set
                matches.value_of("cert"),
                matches.value_of("password"),
            )?;
        }
    }

    if let Some(sub_matches) = matches.subcommand_matches("generate") {
        trace!("generate firmware");
        generate(sub_matches.value_of("input").unwrap(), sub_matches.value_of("output").unwrap())?;
    }
    Ok(())
}


#[cfg(feature = "sign")]
fn sign(input: &str, output: Option<&str>, keyfile: &str, cert: Option<&str>, passphrase: Option<&str>) -> Result<()> {
    let output = if let Some(output) = output {
        output.to_string()
    } else {
        format!("{}.p7s", input)
    };

    let cert = if let Some(cert) = cert {
        cert.to_string()
    } else {
        todo!("create a cert from the key")
    };

    use std::io::Read;
    let mut file = std::fs::File::open(&cert)?;
    let mut signcert = Vec::new();
    file.read_to_end(&mut signcert)?;

    let signcert = openssl::x509::X509::from_pem(&signcert).context("could not read signcert")?;

    let mut file = std::fs::File::open(&keyfile)?;
    let mut pkey = Vec::new();
    file.read_to_end(&mut pkey)?;

    let passphrase = if let Some(passphrase) = passphrase {
        passphrase.to_string()
    } else {
        use dialoguer::Password;
        let password = Password::new().with_prompt("private key password").interact()?;
        password
    };

    println!("found password {}", passphrase);

    let pkey = openssl::pkey::PKey::private_key_from_pem_passphrase(&pkey, passphrase.as_bytes()).context("decrpyt pkey")?;

    let mut db = wireless_regdb::Binary::load(input)?;

    db.sign(&signcert, &pkey)?;
    db.write_signature_file(output)?;

    Ok(())
}


fn generate(input: &str, output: &str ) -> Result<()> { // TODO: signInfo struct
    trace!("running lexer");
    let lexer = wireless_regdb::lexer::TokType::parse(input)?;
    trace!("converting to regdb");
    let db = wireless_regdb::RegDB::from_lexer(lexer)?;

    trace!("converting to binary");
    let db = wireless_regdb::Binary::from_regdb(&db)?;

    // TODO: sign
    debug!("writing to {}", output);
    db.write_file(output)?;

    Ok(())
}
