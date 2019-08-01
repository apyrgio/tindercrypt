//! # Tindercrypt CLI
//!
//! The Tindercrypt CLI allows the user to encrypt/decrypt a file using a
//! passphrase. The user can also tweak some encryption parameters, such as
//! the encryption algorithm or the number of key derivation iterations.
//!
//! As is, the CLI offers just a subset of the Tindercrypt library's
//! functionality. For symmetric key encryption or more control over the
//! encryption process, you are encouraged to use the library directly.

#![deny(
    warnings,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications,
    unused_extern_crates,
    unused_must_use,
    unused_results,
    variant_size_differences
)]

use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::{env, fmt, fs};

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use dialoguer::PasswordInput;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate clap;

use tindercrypt::{cryptors, errors, metadata};

const PASSPHRASE_ENVVAR: &'static str = "TINDERCRYPT_PASSPHRASE";
const AES_ALGO: &'static str = "AES256-GCM";
const CHACHA_ALGO: &'static str = "CHACHA20-POLY1305";

lazy_static! {
    static ref AFTER_HELP: String = {
        format!(
            "A passphrase is required and can be provided via the {} \
             environment variable. Else, you will be prompted to type it.",
            PASSPHRASE_ENVVAR
        )
    };
    static ref PBKDF2_DEFAULT_ITERATIONS: String =
        { metadata::PBKDF2_DEFAULT_ITERATIONS.to_string() };
}

#[derive(Debug)]
enum CLIError {
    IOError {
        msg: String,
        io_error: io::Error,
    },
    TCError {
        msg: String,
        tc_error: errors::Error,
    },
    Error {
        msg: String,
    },
}

impl CLIError {
    fn from_io_error(msg: String, io_error: io::Error) -> Self {
        CLIError::IOError { msg, io_error }
    }

    fn from_tc_error(msg: String, tc_error: errors::Error) -> Self {
        CLIError::TCError { msg, tc_error }
    }
    fn new(msg: String) -> Self {
        CLIError::Error { msg }
    }
}

impl fmt::Display for CLIError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CLIError::IOError { msg, io_error } => {
                write!(f, "{}.\nReason: {}", msg, io_error)
            }
            CLIError::TCError { msg, tc_error } => {
                write!(f, "{}.\nReason: {}", msg, tc_error)
            }
            CLIError::Error { msg } => write!(f, "{}", msg),
        }
    }
}

/// Convert the iterations argument from a string to an integer.
fn _parse_iterations(iter_arg: &str) -> Result<usize, CLIError> {
    let err_msg = "The number of iterations must be an integer greater than 0";
    match iter_arg.parse::<usize>() {
        Ok(num) => {
            if num == 0 {
                return Err(CLIError::new(err_msg.to_string()));
            }
            Ok(num)
        }
        Err(_) => Err(CLIError::new(err_msg.to_string())),
    }
}

/// Validate the number of iterations, by attempting to parse them.
fn _validate_iterations(iter_arg: String) -> Result<(), String> {
    match _parse_iterations(iter_arg.as_str()) {
        Ok(_) => Ok(()),
        Err(cli_error) => Err(format!("{}", cli_error)),
    }
}

/// Read file contents into a buffer.
fn _read_file(name: &str) -> Result<Vec<u8>, CLIError> {
    match fs::read(name) {
        Ok(buf) => Ok(buf),
        Err(io_error) => Err(CLIError::from_io_error(
            format!("Could not read file: {}", name),
            io_error,
        )),
    }
}

/// Read buffer from stdin.
///
/// Read buffer from stdin, until EOF.
fn _read_stdin() -> Result<Vec<u8>, CLIError> {
    let mut buf = Vec::new();
    match io::stdin().read_to_end(&mut buf) {
        Ok(_) => Ok(buf),
        Err(io_error) => Err(CLIError::from_io_error(
            "Could not read from stdin".to_string(),
            io_error,
        )),
    }
}

/// Create a file and write a buffer to it.
///
/// The file will be created with read-write rights by the owner only.
fn _write_file(name: &str, buf: &[u8]) -> Result<(), CLIError> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(name);

    let mut file = match file {
        Ok(f) => f,
        Err(e) => {
            return Err(CLIError::from_io_error(
                format!("Could not create file: {}", name),
                e,
            ))
        }
    };

    match file.write_all(buf) {
        Ok(_) => Ok(()),
        Err(e) => Err(CLIError::from_io_error(
            format!("Could not write to file: {}", name),
            e,
        )),
    }
}

/// Write buffer to stdout.
fn _write_stdout(buf: &[u8]) -> Result<(), CLIError> {
    match io::stdout().write_all(buf) {
        Ok(_) => Ok(()),
        Err(e) => Err(CLIError::from_io_error(
            "Could not write to stdout".to_string(),
            e,
        )),
    }
}

/// Read a buffer from a file or stdin.
fn read_file_contents(ifile: &Option<&str>) -> Result<Vec<u8>, CLIError> {
    match ifile {
        Some(name) => _read_file(&name),
        None => _read_stdin(),
    }
}

/// Write a buffer to a file or stdout.
fn write_file_contents(
    ofile: &Option<&str>,
    buf: &[u8],
) -> Result<(), CLIError> {
    match ofile {
        Some(name) => _write_file(name, buf),
        None => _write_stdout(buf),
    }
}

/// Read passphrase from TTY or environment variable.
fn get_passphrase() -> Result<String, CLIError> {
    // Get the passphrase first from the environment variable.
    match env::var(PASSPHRASE_ENVVAR) {
        Ok(pass) => return Ok(pass),
        Err(_) => (),
    }

    // If not provided, prompt the user to type it.
    let pass = PasswordInput::new()
        .with_prompt("Enter password")
        .with_confirmation("Confirm password", "Passwords mismatch")
        .interact();

    match pass {
        Ok(pass) => return Ok(pass),
        Err(e) => Err(CLIError::from_io_error(
            "Could not read passphrase from TTY".to_string(),
            e,
        )),
    }
}

/// Encrypt plaintext with a passphrase, and return the ciphertext.
fn _seal<'a>(
    buf: &[u8],
    passphrase: &[u8],
    iterations: usize,
    algo: &'a str,
) -> Result<Vec<u8>, CLIError> {
    let cryptor = cryptors::RingCryptor::new();

    // Generate the metadata for the PBKDF2 key derivation algorithm and
    // explicitly set the number of iterations.
    let mut key_meta = metadata::KeyDerivationMetadata::generate();
    key_meta.iterations = iterations;
    let key_algo = metadata::KeyDerivationAlgorithm::PBKDF2(key_meta);

    // Generate the metadata for the encryption algorithm of the user's choice.
    let enc_meta = metadata::EncryptionMetadata::generate();
    let enc_algo = match algo {
        AES_ALGO => metadata::EncryptionAlgorithm::AES256GCM(enc_meta),
        CHACHA_ALGO => {
            metadata::EncryptionAlgorithm::ChaCha20Poly1305(enc_meta)
        }
        _ => unreachable!(),
    };

    let meta = metadata::Metadata::new(key_algo, enc_algo, buf.len());

    // Encrypt the plaintext with the created metadata.
    match cryptor.seal_with_meta(&meta, passphrase, &buf) {
        Ok(buf) => Ok(buf),
        Err(tc_error) => Err(CLIError::from_tc_error(
            "Unexpected error during encryption".to_string(),
            tc_error,
        )),
    }
}

/// Decrypt ciphertext with a passphrase, and return the plaintext.
fn _open(buf: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, CLIError> {
    let cryptor = cryptors::RingCryptor::new();
    match cryptor.open(passphrase, buf) {
        Ok(buf) => Ok(buf),
        Err(tc_error) => Err(CLIError::from_tc_error(
            "Error during decryption".to_string(),
            tc_error,
        )),
    }
}

fn encrypt<'a>(m: &ArgMatches<'a>) -> Result<(), CLIError> {
    // NOTE: We can always unwrap the `iterations` and `algo` arguments, since
    // they have default values.
    let iterations = _parse_iterations(m.value_of("iterations").unwrap())?;
    let algo = m.value_of("enc_algo").unwrap();

    let ifile = m.value_of("in_file");
    let ofile = m.value_of("out_file");
    let contents = read_file_contents(&ifile)?;

    let passphrase = get_passphrase()?;
    let buf = _seal(&contents, passphrase.as_bytes(), iterations, algo)?;

    let _ = write_file_contents(&ofile, &buf)?;
    Ok(())
}

fn decrypt<'a>(m: &ArgMatches<'a>) -> Result<(), CLIError> {
    let ifile = m.value_of("in_file");
    let ofile = m.value_of("out_file");
    let contents = read_file_contents(&ifile)?;

    let passphrase = get_passphrase()?;
    let buf = _open(&contents, passphrase.as_bytes())?;

    let _ = write_file_contents(&ofile, &buf)?;
    Ok(())
}

fn create_encrypt_parser<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("encrypt")
        .about("Encrypt a file with a passphrase")
        .after_help(AFTER_HELP.as_str())
        .arg(
            Arg::with_name("in_file")
                .short("i")
                .long("in-file")
                .takes_value(true)
                .help(
                    "The name of the file to be encrypted. If left blank, \
                     the file will be read from stdin",
                ),
        )
        .arg(
            Arg::with_name("out_file")
                .short("o")
                .long("out-file")
                .takes_value(true)
                .help(
                    "The name of the file to store the encrypted contents. If \
                     left blank, the encrypted contents will be written to \
                     stdout",
                ),
        )
        .arg(
            Arg::with_name("iterations")
                .short("I")
                .long("iterations")
                .validator(_validate_iterations)
                .takes_value(true)
                .default_value(PBKDF2_DEFAULT_ITERATIONS.as_str())
                .help(
                    "The number of iterations for the PBKDF2 key derivation \
                    algorithm",
                ),
        )
        .arg(
            Arg::with_name("enc_algo")
                .short("e")
                .long("encryption-algorithm")
                .takes_value(true)
                .possible_values(&[AES_ALGO, CHACHA_ALGO])
                .default_value(AES_ALGO)
                .help("The algorithm that will be used for the encryption"),
        )
}

fn create_decrypt_parser<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("decrypt")
        .about("Decrypt a file with a passphrase")
        .after_help(AFTER_HELP.as_str())
        .arg(
            Arg::with_name("in_file")
                .short("i")
                .long("in-file")
                .takes_value(true)
                .help(
                    "The name of the file to be decrypt. If left blank, \
                     the file will be read from stdin",
                ),
        )
        .arg(
            Arg::with_name("out_file")
                .short("o")
                .long("out-file")
                .takes_value(true)
                .help(
                    "The name of the file to store the decrypted contents. If \
                     left blank, the decrypted contents will be written to \
                     stdout",
                ),
        )
}

fn create_parser<'a, 'b>() -> App<'a, 'b> {
    App::new("Tindecrypt: File encryption tool")
        .version(crate_version!())
        .after_help(AFTER_HELP.as_str())
        .setting(AppSettings::SubcommandRequired)
        .subcommand(create_encrypt_parser())
        .subcommand(create_decrypt_parser())
}

fn main() {
    let parser = create_parser();
    let matches = parser.get_matches();

    let res = match matches.subcommand() {
        ("encrypt", Some(m)) => encrypt(&m),
        ("decrypt", Some(m)) => decrypt(&m),
        _ => unreachable!(),
    };

    match res {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1)
        }
    }
}
