use assert_fs::prelude::*;
use predicates::prelude::*;

use assert_cmd::Command;

fn cli() -> Command {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    cmd.env_clear();
    cmd.env("TINDERCRYPT_PASSPHRASE", "password1234");
    cmd
}

fn encrypt() -> Command {
    let mut cmd = cli();
    cmd.args(&["encrypt", "--iterations", "1"]);
    cmd
}

fn decrypt() -> Command {
    let mut cmd = cli();
    cmd.arg("decrypt");
    cmd
}

#[test]
fn test_encrypt_decrypt() {
    // Test that encryption/decryption works properly with files.
    let temp_dir = assert_fs::TempDir::new().unwrap();
    temp_dir.child("plaintext").write_str("secret").unwrap();
    encrypt()
        .args(&["-i", "plaintext", "-o", "ciphertext"])
        .current_dir(temp_dir.path())
        .assert()
        .success();

    decrypt()
        .args(&["-i", "ciphertext", "-o", "plaintext2"])
        .current_dir(temp_dir.path())
        .assert()
        .success();
    temp_dir.child("plaintext2").assert("secret");

    // Test that encryption/decryption works properly with stdin/stdout.
    let output = encrypt()
        .args(&["-e", "CHACHA20-POLY1305"])
        .write_stdin("secret")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    decrypt()
        .write_stdin(output.clone())
        .assert()
        .success()
        .stdout("secret");

    // Test that invalid ciphertexts return the appropriate error.
    decrypt()
        .write_stdin("secret")
        .assert()
        .failure()
        .stderr(predicate::str::starts_with("Error during decryption"))
        .stderr(predicate::str::ends_with("invalid metadata header\n"));

    // Test that a wrong password results to an error.
    decrypt()
        .env("TINDERCRYPT_PASSPHRASE", "wrongpass")
        .write_stdin(output.clone())
        .assert()
        .failure()
        .stderr(predicate::str::starts_with("Error during decryption"))
        .stderr(predicate::str::ends_with(
            "Could not decrypt the ciphertext\n",
        ));
}

#[test]
fn test_invalid_args() {
    // Test that errors in file I/O are reported properly.
    let temp_dir = assert_fs::TempDir::new().unwrap();
    encrypt()
        .args(&["-i", "plaintext"])
        .current_dir(temp_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::starts_with("Could not read file"));

    temp_dir.child("plaintext").write_str("secret").unwrap();
    encrypt()
        .args(&["-i", "plaintext", "-o", "bad/dir"])
        .current_dir(temp_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::starts_with("Could not create file"));

    // Test that invalid arguments for iterations are detected.
    encrypt()
        .args(&["-i", "plaintext", "-o", "ciphertext", "-I", "wrong"])
        .current_dir(temp_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("integer greater than 0"));

    encrypt()
        .args(&["-i", "plaintext", "-o", "ciphertext", "-I", "0"])
        .current_dir(temp_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("integer greater than 0"));

    // Test that an invalid encryption algorithm is reported properly.
    encrypt()
        .args(&["-i", "plaintext", "-o", "ciphertext", "-e", "wrong"])
        .current_dir(temp_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("isn't a valid value for"));
}
