/*****************************************************************************
 *   Ledger App Near Rust.
 *   (c) 2023 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/
use crate::AppSW;
use crate::app_ui::aliases::CappedAccountId;
use crate::parsing;
use crate::parsing::{HashingStream, SingleTxStream};
use crate::sign_ui;
use crate::utils::crypto::public_key::DisallowedKeys;
use crate::utils::crypto::{self, PublicKeyBe};
use borsh::BorshDeserialize;

use crate::handlers::common::action::{ActionParams, handle_action};

use super::common::finalize_sign::{self, Signature};
use super::common::validate_public_key;

struct PrefixResult {
    number_of_actions: u32,
    receiver_id: CappedAccountId,
    tx_public_key_prevalidation: Result<PublicKeyBe, DisallowedKeys>,
}

fn handle_transaction_prefix(
    stream: &mut HashingStream<SingleTxStream<'_>>,
) -> Result<PrefixResult, AppSW> {
    let mut tx_prefix = parsing::types::transaction::prefix::Prefix::new();

    tx_prefix
        .deserialize_reader_in_place(stream)
        .map_err(|_err| AppSW::TxParsingFail)?;

    if !sign_ui::transaction::prefix::ui_display(&mut tx_prefix) {
        return Err(AppSW::Deny);
    }
    let tx_public_key = PublicKeyBe::try_from(tx_prefix.public_key);

    Ok(PrefixResult {
        number_of_actions: tx_prefix.number_of_actions,
        receiver_id: tx_prefix.receiver_id,
        tx_public_key_prevalidation: tx_public_key,
    })
}

pub fn handler(mut stream: SingleTxStream<'_>) -> Result<Signature, AppSW> {
    sign_ui::widgets::display_receiving();
    let path = <crypto::PathBip32 as BorshDeserialize>::deserialize_reader(&mut stream)
        .map_err(|_| AppSW::Bip32PathParsingFail)?;

    let mut stream = HashingStream::new(stream)?;

    let PrefixResult {
        number_of_actions,
        receiver_id,
        tx_public_key_prevalidation,
    } = handle_transaction_prefix(&mut stream)?;
    validate_public_key::validate(tx_public_key_prevalidation, &path)?;

    for i in 0..number_of_actions {
        sign_ui::widgets::display_receiving();
        let params = ActionParams {
            ordinal_action: i + 1,
            total_actions: number_of_actions,
            is_nested_delegate: false,
        };
        handle_action(&mut stream, params, &receiver_id)?;
    }

    finalize_sign::end(stream, &path)
}

use ledger_device_sdk::libcall::swap::CreateTxParams;

/// Sign handler for the swap transaction
/// This handler is called when the user wants to sign a swap transaction
/// The swap transaction is a transfer transaction with a specific amount and destination address
/// The handler checks the transaction parameters and signs the transaction
pub fn swap_handler(
    mut stream: SingleTxStream<'_>,
    tx_params: &CreateTxParams,
) -> Result<Signature, AppSW> {
    ledger_device_sdk::log::debug!("sign_tx.rs: swap_handler()\n");

    let path = <crypto::PathBip32 as BorshDeserialize>::deserialize_reader(&mut stream)
        .map_err(|_| AppSW::Bip32PathParsingFail)?;

    ledger_device_sdk::log::debug!("sign_tx.rs: path computed\n");

    // Get the public key from the transaction
    let mut stream = HashingStream::new(stream)?;
    let mut tx_prefix = parsing::types::transaction::prefix::Prefix::new();
    tx_prefix
        .deserialize_reader_in_place(&mut stream)
        .map_err(|_err| AppSW::TxParsingFail)?;
    let tx_public_key = match PublicKeyBe::try_from(tx_prefix.public_key) {
        Ok(tx_public_key) => tx_public_key,
        Err(_) => return Err(AppSW::PublicKeyMismatch),
    };

    // Derive the public key from the path and compare it with the transaction public key
    let dpath_public_key = {
        let pk = ledger_device_sdk::ecc::Ed25519::derive_from_path_slip10(&path.0)
            .public_key()
            .map_err(|_| AppSW::KeyDeriveFail)?;
        PublicKeyBe::from_little_endian(pk)
    };

    if tx_public_key != dpath_public_key {
        return Err(AppSW::PublicKeyMismatch);
    }

    // Check nb of actions (shall be == 1 == Transfer in swap context)
    if tx_prefix.number_of_actions != 1 {
        return Err(AppSW::TxSignFail);
    }
    let action = crate::parsing::types::Action::deserialize_reader(&mut stream)
        .map_err(|_err| AppSW::TxParsingFail)?;
    if action != crate::parsing::types::Action::Transfer {
        return Err(AppSW::TxSignFail);
    }

    // Check the tx parameters match with the ones previously validated in Exchange app (tx_params)
    let transfer = crate::parsing::types::Transfer::deserialize_reader(&mut stream)
        .map_err(|_err| AppSW::TxParsingFail)?;

    let amount_match = near_token::NearToken::from_yoctonear(u128::from_be_bytes(tx_params.amount))
        == transfer.deposit;
    if !amount_match {
        ledger_device_sdk::log::debug!("sign_tx.rs: amounts do not not match\n");
        return Err(AppSW::TxSignFail);
    }

    let dest_address_match = tx_prefix.receiver_id.as_str()
        == core::str::from_utf8(tx_params.dest_address[..tx_params.dest_address_len].as_ref())
            .unwrap();
    if !dest_address_match {
        ledger_device_sdk::log::debug!(
            "sign_tx.rs: receiver_id does not match with dest_address\n",
        );
        return Err(AppSW::TxSignFail);
    }

    finalize_sign::end(stream, &path)
}
