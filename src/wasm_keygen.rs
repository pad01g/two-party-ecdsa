use crate::curv::arithmetic::traits::Samplable;
use crate::curv::elliptic::curves::traits::*;
use crate::curv::arithmetic::BigInt;
use crate::*;

use serde_json;
use wasm_bindgen::prelude::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyOneFirstInput {
    pub secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyOneFirstOutput {
    pub party_one_first_message: KeyGenFirstMsg,
    pub comm_witness: CommWitness,
    pub ec_key_pair: EcKeyPair,
    pub result: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyTwoFirstInput {
    pub secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyTwoFirstOutput {
    pub party_two_first_message: KeyGenFirstMsg,
    pub ec_key_pair_party2: EcKeyPair,
    pub result: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyOneSecondInput {
    pub comm_witness: CommWitness,
    pub party_two_first_message: Party2FirstMessage,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyOneSecondOutput {
    pub party_one_second_message: KeyGenSecondMsg,
    pub result: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyTwoSecondInput {
    pub party_one_first_message: KeyGenFirstMsg,
    pub party_one_second_message: KeyGenSecondMsg,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyTwoSecondOutput {
    pub party_two_second_message: KeyGenSecondMsg,
    pub result: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyOneThirdInput {
    pub ec_key_pair_party1: EcKeyPair
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyOneThirdOutput {
    pub paillier_key_pair: PaillierKeyPair,
    pub party_one_private: Party1Private,
    pub correct_key_proof: NICorrectKeyProof,
    pub result: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyTwoThirdInput {
    pub paillier_key_pair: PaillierKeyPair,
    pub correct_key_proof: NICorrectKeyProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyTwoThirdOutput {
    pub party_two_paillier: PaillierPublic,
    pub result: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyOneFourthInput {
    pub paillier_key_pair: PaillierKeyPair,
    pub party_one_private: Party1Private,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyOneFourthOutput {
    pub range_proof: RangeProofNi,
    pub result: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyTwoFourthInput {
    pub party_two_paillier: PaillierPublic,
    pub range_proof: RangeProofNi,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenPartyTwoFourthOutput {
    pub result: bool,
}

#[wasm_bindgen]
pub fn keygen_party_one_first(input: String) -> String {
    let party_one_first_input: KeyGenPartyOneFirstInput = serde_json::from_str(input).unwrap();

    let (party_one_first_message, comm_witness, ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(ECScalar::from(
            party_one_first_input.secret,
        ));
    return serde_json::to_string(KeyGenPartyOneFirstResult {
        party_one_first_message,
        comm_witness,
        ec_key_pair_party1,
        result: true,
    })
}
#[wasm_bindgen]
pub fn keygen_party_two_first(input: String) -> String {
    let party_two_first_input: KeyGenPartyTwoFirstInput = serde_json::from_str(input).unwrap();

    let (party_two_first_message, ec_key_pair_party2) =
        party_two::KeyGenFirstMsg::create_with_fixed_secret_share(ECScalar::from(
            &party_two_first_input.secret,
        ));
    return serde_json::to_string(KeyGenPartyTwoFirstResult {
        party_two_first_message,
        ec_key_pair_party2,
        result: true,
    })
}
#[wasm_bindgen]
pub fn keygen_party_one_second(input: String) -> String{
    let party_one_second_input: KeyGenPartyOneSecondInput = serde_json::from_str(input).unwrap();

    let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
        party_one_second_input.comm_witness,
        &party_one_second_input.party_two_first_message.d_log_proof,
    )
    .expect("failed to verify and decommit");
    return serde_json::to_string(KeyGenPartyOneSecondOutput {
        party_one_second_message,
        result: true,
    });
}
#[wasm_bindgen]
pub fn keygen_party_two_second(input: String) -> String {
    let party_two_second_input: KeyGenPartyTwoSecondInput = serde_json::from_str(input).unwrap();

    let party_two_second_message =
        party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &party_two_second_input.party_one_first_message,
            &party_two_second_input.party_one_second_message,
        )
        .expect("failed to verify commitments and DLog proof");

    return serde_json::to_string(KeyGenPartyTwoSecondOutput {
        party_two_second_message,
        result: true,
    });
}

#[wasm_bindgen]
pub fn keygen_party_one_third(input: String) -> String {
    let party_one_third_input: KeyGenPartyOneThirdInput = serde_json::from_str(input).unwrap();
    
    // init paillier keypair:
    let paillier_key_pair =
        party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&party_one_third_input.ec_key_pair_party1);

    let party_one_private =
        party_one::Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

    let correct_key_proof =
        party_one::PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);
    
    return serde_json::to_string(KeyGenPartyOneThirdOutput {
        paillier_key_pair,
        party_one_private,
        correct_key_proof,
        result: true,
    });
}

#[wasm_bindgen]
pub fn keygen_party_two_third(input: String) -> String {
    let party_two_third_input: KeyGenPartyTwoThirdInput = serde_json::from_str(input).unwrap();
    let party_two_paillier = party_two::PaillierPublic {
        ek: party_two_third_input.paillier_key_pair.ek.clone(),
        encrypted_secret_share: party_two_third_input.paillier_key_pair.encrypted_share.clone(),
    };

    party_two_third_input.correct_key_proof
        .verify(&party_two_paillier.ek)
        .expect("bad paillier key");

    return serde_json::to_string(KeyGenPartyTwoThirdOutput {
        party_two_paillier,
        result: true
    });
}

#[wasm_bindgen]
pub fn keygen_party_one_fourth(input: String) -> String {
    let party_one_fourth_input: KeyGenPartyOneFourthInput = serde_json::from_str(input).unwrap();
    // zk proof of correct paillier key

    // zk range proof
    let range_proof = party_one::PaillierKeyPair::generate_range_proof(
        &party_one_fourth_input.paillier_key_pair,
        &party_one_fourth_input.party_one_private,
    );

    return serde_json::to_string(KeyGenPartyOneFourthOutput {
        range_proof,
        result: true
    });
}

#[wasm_bindgen]
pub fn keygen_party_two_fourth(input: String) -> String {
    let party_two_fourth_input: KeyGenPartyTwoFourthInput = serde_json::from_str(input).unwrap();
    party_two::PaillierPublic::verify_range_proof(&party_two_fourth_input.party_two_paillier, &party_two_fourth_input.range_proof)
        .expect("range proof error");
    return serde_json::to_string(KeyGenPartyTwoFourthOutput {
        result: true
    });    
}
