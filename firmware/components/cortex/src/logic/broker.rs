use core::ffi::c_char;

use crate::platform;
use crate::platform::active_substance::{self, ActiveSubstanceCommandRaw};
use crate::platform::amino_acids;
use crate::platform::mqtt_broker;
use crate::platform::ribosome_table;
use crate::platform::Result;

use super::membrane::Membrane;
use super::stomach::DigestedActiveSubstance;

pub const DEVICE_COMMAND_QOS: u8 = 0;
pub const DEVICE_COMMAND_RETAIN: bool = false;

pub struct BrokerPipeline;

impl BrokerPipeline {
    pub fn publish_digested(membrane: &Membrane, digested: &DigestedActiveSubstance) -> Result {
        publish_digested_command(membrane, digested)
    }
}

pub fn publish_digested_command(membrane: &Membrane, digested: &DigestedActiveSubstance) -> Result {
    let command = &digested.command;

    active_substance::validate_command(command)?;

    if !cstr_equal(
        command.device_id.as_ptr(),
        active_substance::ACTIVE_SUBSTANCE_DEVICE_ID_LEN,
        digested.device.mqtt_client_id.as_ptr(),
        ribosome_table::RIBOSOME_MQTT_CLIENT_ID_LEN,
    ) {
        return Err(platform::ESP_ERR_INVALID_STATE);
    }

    let payload_value = command_payload_value(command)?;
    if !membrane.allows(&digested.device, command.amino_id, payload_value) {
        return Err(platform::ESP_ERR_INVALID_STATE);
    }

    publish_command_to_device(command, digested.device.mqtt_client_id.as_ptr())
}

fn publish_command_to_device(
    command: &ActiveSubstanceCommandRaw,
    mqtt_client_id: *const c_char,
) -> Result {
    active_substance::validate_command(command)?;

    let mut payload = [0u8; mqtt_broker::MQTT_BROKER_PAYLOAD_MAX_LEN];
    let payload_len = encode_command_payload(command, &mut payload)?;

    mqtt_broker::publish_to_client_cstr(
        mqtt_client_id,
        command.topic.as_ptr(),
        &payload[..payload_len],
        DEVICE_COMMAND_QOS,
        DEVICE_COMMAND_RETAIN,
    )
}

fn command_payload_value(command: &ActiveSubstanceCommandRaw) -> Result<Option<&i32>> {
    match command.payload_type as i32 {
        amino_acids::AMINO_VALUE_NONE => Ok(None),
        amino_acids::AMINO_VALUE_BOOL | amino_acids::AMINO_VALUE_INT => {
            Ok(Some(&command.payload_i32))
        }
        _ => Err(platform::ESP_ERR_INVALID_ARG),
    }
}

fn encode_command_payload(command: &ActiveSubstanceCommandRaw, out: &mut [u8]) -> Result<usize> {
    match command.payload_type as i32 {
        amino_acids::AMINO_VALUE_NONE => Ok(0),
        amino_acids::AMINO_VALUE_BOOL => {
            if out.is_empty() {
                return Err(platform::ESP_ERR_INVALID_SIZE);
            }
            match command.payload_i32 {
                0 => {
                    out[0] = b'0';
                    Ok(1)
                }
                1 => {
                    out[0] = b'1';
                    Ok(1)
                }
                _ => Err(platform::ESP_ERR_INVALID_ARG),
            }
        }
        amino_acids::AMINO_VALUE_INT => encode_i32_ascii(command.payload_i32, out),
        _ => Err(platform::ESP_ERR_INVALID_ARG),
    }
}

fn encode_i32_ascii(value: i32, out: &mut [u8]) -> Result<usize> {
    let mut cursor = 0usize;
    let mut magnitude = value as i64;

    if magnitude < 0 {
        if out.is_empty() {
            return Err(platform::ESP_ERR_INVALID_SIZE);
        }
        out[cursor] = b'-';
        cursor += 1;
        magnitude = -magnitude;
    }

    let mut digits = [0u8; 10];
    let mut digit_count = 0usize;
    let mut n = magnitude as u64;

    loop {
        digits[digit_count] = b'0' + (n % 10) as u8;
        digit_count += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }

    if cursor + digit_count > out.len() {
        return Err(platform::ESP_ERR_INVALID_SIZE);
    }

    while digit_count > 0 {
        digit_count -= 1;
        out[cursor] = digits[digit_count];
        cursor += 1;
    }

    Ok(cursor)
}

fn cstr_equal(a: *const c_char, a_max: usize, b: *const c_char, b_max: usize) -> bool {
    if a.is_null() || b.is_null() {
        return false;
    }

    let max = if a_max > b_max { a_max } else { b_max };
    for i in 0..max {
        let a_ch = if i < a_max { unsafe { *a.add(i) } } else { 0 };
        let b_ch = if i < b_max { unsafe { *b.add(i) } } else { 0 };

        if a_ch != b_ch {
            return false;
        }
        if a_ch == 0 {
            return true;
        }
    }

    false
}
