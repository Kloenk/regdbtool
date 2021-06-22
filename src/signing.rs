use std::fs::File;
use std::io::Read;

use std::rc::Rc;

use anyhow::{Result, Context, bail};
use clap::Arg;

#[cfg(feature = "sign")]
pub struct SignInfo {
    //pub keyfile: String,
    //pub cert: String,

    pub key: Rc<Vec<u8>>,
    pub cert: Rc<Vec<u8>>,
    pub encrypted: bool,

    pub sign: bool,

    pub s_key: Option<openssl::pkey::PKey<openssl::pkey::Private>>,
    pub x509: Option<openssl::x509::X509>,
}

#[cfg(feature = "sign")]
impl SignInfo {
    pub fn new(keyfile: &str, certificate: &str) -> Result<Self> {

        let mut key_file = File::open(keyfile).with_context(|| format!("failed to open private key at {}", keyfile))?;
        let mut key = String::new();
        key_file.read_to_string(&mut key).with_context(|| format!("failed to read private key from {}", keyfile))?;
        let encrypted = key.contains("ENCRYPTED");

        let mut cert = File::open(certificate).with_context(|| format!("failed to open certificat at {}", certificate))?;
        let mut cert_buf = Vec::new();
        cert.read_to_end(&mut cert_buf).with_context(|| format!("failed to read certificate from {}", certificate))?;
        let cert = Rc::new(cert_buf);

        let key = Rc::new(key.into_bytes());

        let s_key = match encrypted {
            false => {
                let pkey = openssl::pkey::PKey::private_key_from_pem(&key).with_context(|| format!("could not parse key from {}", keyfile))?;

                Some(pkey)
            },
            true => None,
        };

        let x509 = openssl::x509::X509::from_pem(&cert).with_context(|| format!("could not parse cert from {}", certificate)).ok();

        Ok(Self {
            key,
            cert,
            encrypted,

            sign: true,

            s_key,
            x509
        })
    }

    pub fn from_matches(matches: &clap::ArgMatches) -> Result<Option<Self>> {
        if matches.is_present("no-sign") {
            Ok(Some(Self {
                key: Rc::new(Vec::new()),
                cert: Rc::new(Vec::new()),

                encrypted: false,

                sign: false,

                s_key: None,
                x509: None,
            }))
        } else if let Some(keyfile) = matches.value_of("keyfile") {
            todo!("create valid Info")
        } else {
            bail!("missing keyfile");
        }
    }

    pub fn has_key(&self) -> bool {
        self.s_key.is_some()
    }

    pub fn open_key(&mut self, password: &str) -> Result<()> {
        let pkey = openssl::pkey::PKey::private_key_from_pem_passphrase(&self.key, password.as_bytes()).with_context(|| format!("open private key with password"))?;
        self.s_key = Some(pkey);

        Ok(())
    }

    pub fn has_cert(&self) -> bool {
        self.x509.is_some()
    }

    pub fn gen_cert(&mut self, cn: &str) -> Result<()> {
        if !self.has_key() {
            bail!("no private key to generate certificate");
        }
        if self.cert.len() != 0 {
            bail!("cert data already set")
        }

        let mut certificate = openssl::x509::X509Builder::new()?;
        //certificate.set_serial_number(&openssl::asn1::Asn1Integer::from_bn(&openssl::bn::BigNum::from_u32(1)?)?)?;

        let mut name = openssl::x509::X509Name::builder()?;
        name.append_entry_by_text("CN", cn)?;
        let name = name.build();
        certificate.set_issuer_name(&name)?;

        certificate.set_not_before(openssl::asn1::Asn1Time::days_from_now(0)?.as_ref())?;
        certificate.set_not_before(openssl::asn1::Asn1Time::days_from_now(36500)?.as_ref())?;

        // unwrap arleady checked
        certificate.sign(self.s_key.as_ref().unwrap(), openssl::hash::MessageDigest::md5())?;
        let certificate = certificate.build();

        let cert = certificate.to_pem()?;

        self.x509 = Some(certificate);
        self.cert = Rc::new(cert.into());
        Ok(())
    }
}

#[cfg(feature = "sign")]
pub fn args_sign() -> Vec<Arg<'static, 'static>> {
    let mut ret = Vec::new();

        ret.push(
            Arg::with_name("keyfile")
                .help("file containing the secret key")
                .long("keyfile")
                .short("k")
                .takes_value(true)
                .value_name("PEM")
                .env("REGDB_KEYFILE")
                .global(true)
        );
        ret.push(
            Arg::with_name("cert")
                .help("certificate file for signing")
                .long("cert")
                .short("c")
                .takes_value(true)
                .value_name("CERT")
                .env("REGDB_CERT")
                .global(true)
        );
        ret.push(
            Arg::with_name("password")
                .help("password for the secret key")
                .long("password")
                .short("p")
                .takes_value(true)
                .value_name("PASSWORD")
                .env("REGDB_PASSWORD")
                .global(true)
        );
    ret.push(
        Arg::with_name("no-sign")
            .help("wether to sign the databes")
            .long("no-sign")
            .env("REGDB_NOSIGN")
            .global(true)
            .takes_value(false)
    );

    ret
}

#[cfg(not(feature = "sign"))]
pub fn args_sign() -> Vec<Arg<'static, 'static>> {
    Vec::new()
}
