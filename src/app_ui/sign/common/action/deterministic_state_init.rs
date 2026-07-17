use crate::{
    app_ui::{
        aliases::{U32Buffer, U64Buffer},
        fields_writer::FieldsWriter,
    },
    parsing,
    utils::types::elipsis_fields::ElipsisFields,
};
#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
use ledger_device_sdk::nbgl::Field;
#[cfg(any(target_os = "nanox", target_os = "nanosplus"))]
use ledger_device_sdk::ui::gadgets::Field;

use numtoa::NumToA;

pub struct V1FieldsContext {
    pub data_size_buf: U64Buffer,
    pub data_entries_buf: U32Buffer,
}

impl V1FieldsContext {
    pub fn new() -> Self {
        Self {
            data_size_buf: U64Buffer::default(),
            data_entries_buf: U32Buffer::default(),
        }
    }
}

pub fn format_v1<'b, 'a: 'b, const N: usize>(
    state_init_v1: &'a mut parsing::types::DeterministicAccountStateInitV1,
    field_context: &'a mut V1FieldsContext,
    writer: &'_ mut FieldsWriter<'b, N>,
) {
    let (display_name, display_val) = match &mut state_init_v1.code {
        parsing::types::GlobalContractIdentifier::CodeHash(code_hash) => {
            ("Contract SHA256", code_hash.as_str())
        }
        parsing::types::GlobalContractIdentifier::AccountId(account_id) => {
            ("Contract AccountId", account_id.as_str())
        }
    };

    writer.push_fields(ElipsisFields::one(Field {
        name: display_name,
        value: display_val,
    }));

    writer.push_fields(ElipsisFields::one(Field {
        name: "State Size",
        // TODO: use buffer to write down appropriate size in bytes and kilobytes
        value: state_init_v1
            .data_size_bytes
            // numtoa_buf has to be at least 20 bytes for u64 (8 bytes) : ok
            .numtoa_str(10, &mut field_context.data_size_buf),
    }));

    writer.push_fields(ElipsisFields::one(Field {
        name: "State Total Entries",
        value: state_init_v1
            .data_entries
            // numtoa_buf has to be at least 10 bytes for u32 (4 bytes) : ok
            .numtoa_str(10, &mut field_context.data_entries_buf),
    }));
}
