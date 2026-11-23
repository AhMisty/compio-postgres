//! 按 JSON 或 JSONB 的线格式读写 serde_json 值。

use std::io::{self, Write};

use serde_json::Value;

use super::{CodecError, Decode, EncodedValue, Format, JsonText, Oid, RawValue, json_payload};

impl<'a> Decode<'a> for Value {
    fn accepts(oid: Oid, format: Format) -> bool {
        JsonText::accepts(oid, format)
    }

    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        serde_json::from_slice(json_payload(value)?)
            .map_err(|error| CodecError::Conversion(Box::new(error)))
    }
}

struct JsonBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for JsonBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let used = self.bytes.len();
        if bytes.len() > self.limit - used {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let needed = used + bytes.len();
        if needed > self.bytes.capacity() {
            let capacity = needed
                .max(self.bytes.capacity().saturating_mul(2))
                .max(64)
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - used)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// 编码 JSON 或 JSONB 参数。写入期间限制字节数，返回值可反复借给同一条或不同的 SQL。
pub fn encode_json(oid: Oid, value: &Value, max_bytes: usize) -> Result<EncodedValue, CodecError> {
    if !Value::accepts(oid, Format::Binary) {
        return Err(CodecError::WrongType {
            oid,
            format: Format::Binary,
        });
    }
    let mut output = JsonBuffer {
        bytes: Vec::new(),
        limit: max_bytes.min(i32::MAX as usize),
    };
    let version: &[u8] = if oid == Oid::JSONB { &[1] } else { &[] };
    output
        .write_all(version)
        .map_err(serde_json::Error::io)
        .and_then(|()| serde_json::to_writer(&mut output, value))
        .map_err(|error| match error.io_error_kind() {
            Some(io::ErrorKind::FileTooLarge) => {
                CodecError::Limit("JSON value exceeds its storage limit")
            }
            Some(io::ErrorKind::OutOfMemory) => CodecError::Allocation,
            _ => CodecError::Conversion(Box::new(error)),
        })?;
    EncodedValue::from_raw(oid, Format::Binary, Some(output.bytes), max_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_and_jsonb_round_trip_at_the_exact_wire_limit() {
        let value = serde_json::json!({"active": true});
        for (oid, expected) in [
            (Oid::JSON, br#"{"active":true}"#.as_slice()),
            (Oid::JSONB, b"\x01{\"active\":true}".as_slice()),
        ] {
            let encoded = encode_json(oid, &value, expected.len()).unwrap();
            assert_eq!(encoded.raw_value().bytes, Some(expected));
            assert_eq!(encoded.raw_value().decode::<Value>().unwrap(), value);
            assert!(matches!(
                encode_json(oid, &value, expected.len() - 1),
                Err(CodecError::Limit(_))
            ));
        }
        assert!(
            RawValue {
                oid: Oid::JSONB,
                format: Format::Binary,
                bytes: Some(b"\x02{}")
            }
            .decode::<Value>()
            .is_err()
        );
    }
}
