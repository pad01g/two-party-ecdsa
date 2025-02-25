use crate::curv::arithmetic::traits::*;
use crate::curv::arithmetic::BigInt;
use crate::*;

use crate::party_two::EphKeyGenFirstMsg as Party2EphKeyGenFirstMsg;
use crate::party_two::EphKeyGenSecondMsg as Party2EphKeyGenSecondMsg;
use crate::party_two::EphEcKeyPair as Party2EphEcKeyPair;
use crate::party_two::EcKeyPair as Party2EcKeyPair;
use crate::party_two::PartialSig;
use crate::party_two::EphCommWitness;

use crate::party_one::EphKeyGenFirstMsg as Party1EphKeyGenFirstMsg;
use crate::party_one::EphEcKeyPair as Party1EphEcKeyPair;
use crate::party_one::EcKeyPair as Party1EcKeyPair;
use crate::party_one::PaillierKeyPair;
use crate::party_one::Signature;

use serde_json;
use wasm_bindgen::prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct SignPartyOneFirstInput {
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignPartyOneFirstOutput {
    pub result: bool,
    pub eph_party_one_first_message: Party1EphKeyGenFirstMsg,
    pub eph_ec_key_pair_party1: Party1EphEcKeyPair,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignPartyTwoFirstInput {
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignPartyTwoFirstOutput {
    pub result: bool,
    pub eph_party_two_first_message: Party2EphKeyGenFirstMsg,
    pub eph_comm_witness: EphCommWitness,
    pub eph_ec_key_pair_party2: Party2EphEcKeyPair,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignPartyOneSecondInput {
    pub eph_party_two_first_message: Party2EphKeyGenFirstMsg,
    pub eph_party_two_second_message: Party2EphKeyGenSecondMsg,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignPartyOneSecondOutput {
    pub result: bool,
    // pub eph_party_one_second_message: Party1EphKeyGenSecondMsg,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignPartyTwoSecondInput {
    pub eph_comm_witness: EphCommWitness,
    pub eph_party_one_first_message: Party1EphKeyGenFirstMsg,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignPartyTwoSecondOutput {
    pub result: bool,
    pub eph_party_two_second_message: Party2EphKeyGenSecondMsg,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignPartyOneThirdInput {
    pub ec_key_pair_party1: Party1EcKeyPair,
    pub keypair: PaillierKeyPair,
    pub partial_sig_c3: BigInt,
    pub eph_ec_key_pair_party1: Party1EphEcKeyPair,
    pub witness_public_share: GE,
    pub public_share: GE,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignPartyOneThirdOutput {
    pub signature: Signature,
    pub result: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignPartyTwoThirdInput {
    pub ec_key_pair_party2: Party2EcKeyPair,
    // keygen result from party one
    pub ek: EncryptionKey,
    // keygen result from party one
    pub encrypted_share: BigInt,
    pub eph_ec_key_pair_party2: Party2EphEcKeyPair,
    pub eph_party_one_first_message: Party1EphKeyGenFirstMsg,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignPartyTwoThirdOutput {
    pub result: bool,
    pub partial_sig: PartialSig,
}

#[wasm_bindgen]
pub fn sign_party_two_first() -> String {
    // // assume party1 and party2 engaged with KeyGen in the past resulting in
    // // party1 owning private share and paillier key-pair
    // // party2 owning private share and paillier encryption of party1 share
    // let (_party_one_private_share_gen, _comm_witness, ec_key_pair_party1) =
    //     party_one::KeyGenFirstMsg::create_commitments();
    // let (party_two_private_share_gen, ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();

    // let keypair =
    //     party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

    // creating the ephemeral private shares:

    let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        party_two::EphKeyGenFirstMsg::create_commitments();

    return serde_json::to_string(&SignPartyTwoFirstOutput {
        eph_party_two_first_message,
        eph_comm_witness,
        eph_ec_key_pair_party2,
        result: true,
    }).unwrap();
}
#[wasm_bindgen]
pub fn sign_party_one_first() -> String {
    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
        party_one::EphKeyGenFirstMsg::create();

    return serde_json::to_string(&SignPartyOneFirstOutput {
        eph_party_one_first_message,
        eph_ec_key_pair_party1,
        result: true,
    }).unwrap();
}
#[wasm_bindgen]
pub fn sign_party_two_second(input: String) -> String {

    let party_two_second_input: SignPartyTwoSecondInput = serde_json::from_str(&input).unwrap();

    let eph_party_two_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
        party_two_second_input.eph_comm_witness,
        &party_two_second_input.eph_party_one_first_message,
    )
    .expect("party1 DLog proof failed");
    return serde_json::to_string(&SignPartyTwoSecondOutput {
        eph_party_two_second_message,
        result: true,
    }).unwrap();
}

#[wasm_bindgen]
pub fn sign_party_one_second(input: String) -> String {
    let party_one_second_input: SignPartyOneSecondInput = serde_json::from_str(&input).unwrap();

    let _eph_party_one_second_message =
        party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &party_one_second_input.eph_party_two_first_message,
            &party_one_second_input.eph_party_two_second_message,
        )
        .expect("failed to verify commitments and DLog proof");

    return serde_json::to_string(&SignPartyOneSecondOutput {
        // eph_party_one_second_message,
        result: true,
    }).unwrap();
}

#[wasm_bindgen]
pub fn sign_party_two_third(input: String) -> String {

    let party_two_third_input: SignPartyTwoThirdInput = serde_json::from_str(&input).unwrap();

    let party2_private = party_two::Party2Private::set_private_key(&party_two_third_input.ec_key_pair_party2);
    let partial_sig = party_two::PartialSig::compute(
        &party_two_third_input.ek,
        &party_two_third_input.encrypted_share,
        &party2_private,
        &party_two_third_input.eph_ec_key_pair_party2,
        &party_two_third_input.eph_party_one_first_message.public_share,
        &BigInt::from_hex(&party_two_third_input.message).unwrap(),
    );
    return serde_json::to_string(&SignPartyTwoThirdOutput {
        partial_sig,
        result: true,
    }).unwrap();
}

#[wasm_bindgen]
pub fn sign_party_one_third(input: String) -> String {

    let party_one_third_input: SignPartyOneThirdInput = serde_json::from_str(&input).unwrap();

    let party1_private =
        party_one::Party1Private::set_private_key(&party_one_third_input.ec_key_pair_party1, &party_one_third_input.keypair);

    let signature = party_one::Signature::compute(
        &party1_private,
        &party_one_third_input.partial_sig_c3,
        &party_one_third_input.eph_ec_key_pair_party1,
        &party_one_third_input.witness_public_share,
    );

    let pubkey =
        party_one::compute_pubkey(&party1_private, &party_one_third_input.public_share);
    party_one::verify(&signature, &pubkey, &BigInt::from_hex(&party_one_third_input.message).unwrap()).expect("Invalid signature");

    return serde_json::to_string(&SignPartyOneThirdOutput {
        signature,
        result: true,
    }).unwrap();
}