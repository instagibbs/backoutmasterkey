use std::io::{self};
use std::process::{self};

extern crate bitcoin;
extern crate secp256k1;
extern crate core;
#[macro_use] extern crate hex_literal;
use bitcoin::util::bip32;
use bitcoin::util::base58::FromBase58;
use bitcoin::util::base58::ToBase58;
use std::io::Write;
use core::convert::From;

fn main() {
    println!("Enter: <xpub> <derivation_index> <privkey>");
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_) => {
        }
        Err(error) => {
            writeln!(::std::io::stderr(), "{}", error).ok();  // the `.ok()` means even if it fails, ignore it. We are exiting any way. I think it's a common pattern to abuse `ok()` like this?
            process::exit(1);
        }
    }
    let v: Vec<&str> = input.split(' ').collect();
    assert_eq!(v.len(), 3);
    let extpub_result = bip32::ExtendedPubKey::from_base58check(v[0]).unwrap();
    let index = v[1].parse::<u32>().unwrap();
    let network = bitcoin::network::constants::Network::Bitcoin;
    let ctx = secp256k1::Secp256k1::new();

    // Tweak to get to child privkey
    let child_tweak_and_chaincode = extpub_result.ckd_pub_tweak(&ctx, bip32::ChildNumber::Normal(index)).unwrap();
    let mut child_tweak = child_tweak_and_chaincode.0;
    // (curve order N)-1 aka -1
    let minusone : [u8; 32] = hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
    let minusone_key = secp256k1::key::SecretKey::from_slice(&ctx, &minusone).unwrap();
    child_tweak.mul_assign(&ctx, &minusone_key);

    // Now add to child key
    let child_key = bitcoin::util::address::Privkey::from_base58check(v[2].trim_right()).unwrap();
    let mut child_secret = child_key.secret_key().clone();
    child_secret.add_assign(&ctx, &child_tweak);

    // Re-construct master xprv
    let fingerprint : [u8; 4] = [0; 4];
    let finger = bip32::Fingerprint::from(&fingerprint[..]);
    let xprv = bip32::ExtendedPrivKey {chain_code: extpub_result.chain_code, child_number: bip32::ChildNumber::Normal(0), depth: 0, parent_fingerprint: finger, secret_key: child_secret, network: network};

    println!("{}", xprv.to_base58check());
}
