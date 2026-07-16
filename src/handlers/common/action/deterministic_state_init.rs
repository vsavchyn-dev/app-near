use crate::{
    AppSW,
    app_ui::aliases::CappedAccountId,
    handlers::common::action::ActionParams,
    parsing::{
        HashingStream, SingleTxStream,
        types::common::action::deterministic_state_init::{
            DeterministicAccountStateInit, DeterministicAccountStateInitV1,
        },
    },
};

use near_token::NearToken;

use borsh::BorshDeserialize;
use ledger_device_sdk::{
    hash::{HashInit, sha3::Keccak256},
    log,
};

pub fn handle(
    stream: &mut HashingStream<SingleTxStream<'_>>,
    params: ActionParams,
    derived_account_id: &CappedAccountId,
) -> Result<(), AppSW> {
    log::debug!("handling state init");
    let mut keccak256 = Keccak256::new();

    let version = DeterministicAccountStateInit::deserialize_reader(stream)
        .map_err(|_| AppSW::TxParsingFail)?;

    log::debug!("parsed version");

    keccak256
        .update(&[(version as u8).to_le()])
        .map_err(|_err| AppSW::TxHashFail)?;

    match version {
        DeterministicAccountStateInit::V1 => {
            log::debug!("state init v1");

            handle_v1(stream, params, derived_account_id, &mut keccak256)
        }
    }
}

const ACCOUNT_ID_PREFIX_LEN: usize = 2;
const STATE_INIT_ACCOUNT_ID_PREFIX: [u8; ACCOUNT_ID_PREFIX_LEN] = *b"0s";
/// 40 bytes ("hex::encode(keccak256.finalize(...)[12..32])")
const STATE_INIT_ACCOUNT_ID_V1_LEN_NO_PREFIX: usize = 40;
/// 2 prefix bytes ("0s") + 40 bytes ("hex::encode(keccak256.finalize(...)[12..32])")
const STATE_INIT_ACCOUNT_ID_V1_LEN: usize =
    STATE_INIT_ACCOUNT_ID_V1_LEN_NO_PREFIX + ACCOUNT_ID_PREFIX_LEN;

fn handle_v1(
    stream: &mut HashingStream<SingleTxStream<'_>>,
    _params: ActionParams,
    derived_account_id: &CappedAccountId,
    keccak256: &mut Keccak256,
) -> Result<(), AppSW> {
    let _state_init_v1 = DeterministicAccountStateInitV1::deserialize_and_hash(stream, keccak256)
        .map_err(|_err| AppSW::TxParsingFail)?;
    log::debug!("v1: parsed state init");

    // TODO: refactor and bring deposit parsing and possibly ui parsing into `handle`?
    let _deposit = NearToken::deserialize_reader(stream).map_err(|_err| AppSW::TxParsingFail)?;

    log::debug!("v1 parsed deposit");

    let mut buf = [0u8; 32];
    let mut hex_buf = [0u8; STATE_INIT_ACCOUNT_ID_V1_LEN_NO_PREFIX];

    keccak256
        .finalize(&mut buf)
        .map_err(|_err| AppSW::TxParsingFail)?;

    // .unwrap() is fine as 40 = 20 * 2, which fits hex_buf
    hex::encode_to_slice(&buf[12..32], &mut hex_buf).unwrap();

    let acc = derived_account_id.as_bytes();

    if acc.len() == STATE_INIT_ACCOUNT_ID_V1_LEN
        && acc[..ACCOUNT_ID_PREFIX_LEN] == STATE_INIT_ACCOUNT_ID_PREFIX
        && acc[ACCOUNT_ID_PREFIX_LEN..STATE_INIT_ACCOUNT_ID_V1_LEN] == hex_buf
    {
        log::debug!("v1: derived account is valid");
        // TODO: display action
        return Ok(());
    }

    log::debug!("v1: derived account is invalid");
    // TODO: display error validating derived account id
    Err(AppSW::TxParsingFail)
}

// fn display_verify_account_id_error.
