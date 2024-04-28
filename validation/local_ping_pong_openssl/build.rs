use std::fs::metadata;
use std::path::Path;
use std::process::Command;
use std::time::SystemTime;
//TODO: use library eventually
//use openssl::rsa::Rsa;

fn main() {
    check_gen_certs();
}

fn cargo_target_dir() -> String {
    match std::env::var("CARGO_MANIFEST_DIR").as_deref() {
        Ok(target_dir) => target_dir.into(),
        _ => panic!("CARGO_MANIFEST_DIR required for build."),
    }
    /* TODO: use target directory when generating w/o shell
    match std::env::var("OUT_DIR").as_deref() {
        Ok(target_dir) => target_dir.into(),
        _ => panic!("OUT_DIR required for build."),
    }
    */
}

fn check_gen_certs() {
    let out_dir_str = cargo_target_dir();
    let out_dir = Path::new(&out_dir_str).join("certs");

    let ca_crt_path = out_dir.join("ca.rsa4096.crt");

    let mut generate = true;

    if ca_crt_path.exists() {
        let now = SystemTime::now();
        let meta = metadata(ca_crt_path).expect("fs metadata");
        let created = meta
            .created()
            .expect("fs no support to determine ctime from file?");
        let difference = now
            .duration_since(created)
            .expect("System clock gone backwards");

        if difference.as_secs() < 364 * 24 * 3600 {
            generate = false;
        }
    }

    if generate == true {
        Command::new("make")
            .arg("rsa4096")
            .current_dir(out_dir)
            .spawn()
            .expect("make rsa4096");
    }

    // public exponent will be 65537
    /* TODO: remove shell requirement:
    let rsa = Rsa::generate(4096).expect("openssl genrsa rsa");
    let ca_rsa = Rsa::generate(4096).expect("openssl genrsa ca_rsa");

    let rsa_pem = rsa.private_key_to_pem().expect("rsa private_key_to_pem");
    let ca_rsa_pem = ca_rsa.private_key_to_pem().expect("ca_rsa private_key_to_pem");
    */
}
