use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::string::String;

use clap::Parser;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use postcard::{from_bytes, to_allocvec};


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Options {
    /// data to encode
    #[arg(short, long, value_name = "INPUT_DATA")]
    input_data: Option<String>,

    /// file which contains data to encode
    #[clap(conflicts_with = "input_data")]
    #[arg(long, value_name = "INPUT_FILE")]
    input_file_dir: Option<PathBuf>,

    /// Path where output data shall be saved
    #[clap(default_value = "./encrypted_data")]
    #[arg(short, long, value_name = "OUTPUT_FILE")]
    output_file_dir: PathBuf,

    /// Path where private key shall be saved
    #[clap(default_value = "./privkey")]
    #[arg(long, value_name = "PRIVKEY")]
    priv_key_dir: PathBuf,

    /// signalizes if <PRIVKEY> shall be taken or overridden by new generated one!!
    #[arg(short, long, value_name = "REGENERATE")]
    regenerate_priv_key: bool,

    /// bit size to create the private key
    #[clap(default_value = "4096")]
    #[arg(long, value_name = "BITSIZE")]
    bit_size: usize,

    /// Path where public key shall be saved
    #[clap(default_value = "./pubkey")]
    #[arg(long, value_name = "PUBKEY")]
    pub_key_dir: PathBuf,
}

fn main() {
    let options = Options::parse();

    let input_data = if let Some(data) = options.input_data.as_deref() {
        data.as_bytes().to_vec()
    } else {
        read_file(options.input_file_dir.as_ref().expect("Parameter input_data or input_file missing")).to_vec()
    };

    let bits = options.bit_size;

    let mut rng = rand::thread_rng();
    let priv_key = if options.regenerate_priv_key{
        RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key")
    }else {
        load_priv_key(options.priv_key_dir.as_path())
    };

    let pub_key = RsaPublicKey::from(&priv_key);

    let mut rng = rand::thread_rng();
    let output_data = pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, &input_data[..])
        .expect("failed to encrypt");

    save(&options, &output_data, &priv_key, &pub_key);
    check(&options, &input_data);
}

fn save(options: &Options, data: &Vec<u8>, priv_key: &RsaPrivateKey, pub_key: &RsaPublicKey) {
    if options.regenerate_priv_key {
        priv_key
            .write_pkcs8_pem_file(&options.priv_key_dir, LineEnding::LF)
            .unwrap();
    }

    let priv_key_bin_dir = append_to_path(options.priv_key_dir.clone(), ".bin");
    let blob = serialize_to_bin(&priv_key);
    write_file(blob.as_slice(), &priv_key_bin_dir);

    pub_key
        .write_public_key_pem_file(&options.pub_key_dir, LineEnding::LF)
        .unwrap();

    write_file(data, options.output_file_dir.as_ref());
}

fn serialize_to_bin(priv_key: &RsaPrivateKey) -> Vec<u8>
{
    to_allocvec(priv_key).unwrap()
}

fn deserialize_from_bin(blob: &[u8]) -> RsaPrivateKey
{
    from_bytes(blob).unwrap()
}

fn append_to_path(p: PathBuf, s: &str) -> PathBuf {
    let mut p = p.into_os_string();
    p.push(s);
    p.into()
}
fn check(options: &Options, expected_data: &Vec<u8>) {
    let encrypted_data = read_file(options.output_file_dir.as_ref());
    let priv_key = load_priv_key(options.priv_key_dir.as_ref());
    let decrypted_data = priv_key.decrypt(Pkcs1v15Encrypt, &encrypted_data).unwrap();
    assert_eq!(expected_data, &decrypted_data);

    let priv_key_bin_dir = append_to_path(options.priv_key_dir.clone(), ".bin");
    let priv_key_bin = read_file(&priv_key_bin_dir);
    let priv_key_read_back = deserialize_from_bin(&priv_key_bin);
    assert_eq!(&priv_key, &priv_key_read_back);
}

fn read_file(file_dir: &Path) -> Vec<u8> {
    let mut file = File::open(file_dir).unwrap();
    let mut data = Vec::<u8>::new();
    file.read_to_end(&mut data).unwrap();
    data
}

fn write_file(data: &[u8], file_dir: &Path) {
    let mut file = File::create(file_dir).unwrap();
    file.write_all(&data).unwrap();
}

fn load_priv_key(path: &Path) -> RsaPrivateKey {
    DecodePrivateKey::read_pkcs8_pem_file(path).unwrap()
}
