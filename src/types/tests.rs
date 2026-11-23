use std::ops::Bound;

use postgres_protocol::types as pg;

use super::*;

fn binary(oid: Oid, bytes: &[u8]) -> RawValue<'_> {
    RawValue {
        oid,
        format: Format::Binary,
        bytes: Some(bytes),
    }
}

#[test]
fn scalar_parameters_are_inline_and_preserve_values_and_null_types() {
    for value in [i32::MIN, -1, 0, i32::MAX] {
        let parameter = Parameter::int4(value);
        assert_eq!(parameter.oid(), Oid::INT4);
        assert_eq!(
            parameter.raw_value().bytes,
            Some(value.to_be_bytes().as_slice())
        );
        assert_eq!(parameter.raw_value().decode::<i32>().unwrap(), value);
    }
    assert_eq!(
        Parameter::int2(i16::MIN)
            .raw_value()
            .decode::<i16>()
            .unwrap(),
        i16::MIN
    );
    assert_eq!(
        Parameter::int8(i64::MAX)
            .raw_value()
            .decode::<i64>()
            .unwrap(),
        i64::MAX
    );
    assert!(Parameter::bool(true).raw_value().decode::<bool>().unwrap());
    assert_eq!(Parameter::char(-1).raw_value().decode::<i8>().unwrap(), -1);
    let null = Parameter::null(Oid::INT4, Format::Binary);
    assert_eq!(null.raw_value().decode::<Option<i32>>().unwrap(), None);
    assert!(matches!(
        null.raw_value().decode::<i32>(),
        Err(CodecError::UnexpectedNull)
    ));
    assert!(matches!(
        null.raw_value().decode::<Option<i64>>(),
        Err(CodecError::WrongType { .. })
    ));
    assert!(matches!(
        Parameter::int4(1).raw_value().decode::<f32>(),
        Err(CodecError::WrongType { .. })
    ));
}

#[test]
fn oid8_is_unsigned_and_does_not_expand_metadata_oids() {
    assert_eq!(Oid::OID8.0, 6437);
    assert_eq!(Oid::OID8_ARRAY.0, 6442);
    assert_eq!(std::mem::size_of::<Oid>(), 4);
    for value in [0, 1, u64::MAX] {
        let parameter = Parameter::oid8(Oid8(value));
        assert_eq!(parameter.raw_value().decode::<Oid8>().unwrap(), Oid8(value));
        assert_eq!(parameter.raw_value().decode::<u64>().unwrap(), value);
    }
    assert!(binary(Oid::OID8, &[0; 4]).decode::<Oid8>().is_err());
    assert_eq!(
        Parameter::text(Oid::OID8, "18446744073709551615")
            .raw_value()
            .decode::<Oid8>()
            .unwrap(),
        Oid8(u64::MAX)
    );
}

#[test]
fn regdatabase_binary_scalar_and_array_use_four_byte_database_oids() {
    assert_eq!(Oid::REGDATABASE.0, 6490);
    assert_eq!(Oid::REGDATABASE_ARRAY.0, 6491);
    let database = RegDatabase(u32::MAX);
    let parameter = Parameter::regdatabase(database);
    assert_eq!(parameter.raw_value().bytes, Some([255; 4].as_slice()));
    assert_eq!(
        parameter.raw_value().decode::<RegDatabase>().unwrap(),
        database
    );
    assert!(
        binary(Oid::REGDATABASE, &[0; 8])
            .decode::<RegDatabase>()
            .is_err()
    );
    assert!(
        Parameter::text(Oid::REGDATABASE, "postgres")
            .raw_value()
            .decode::<RegDatabase>()
            .is_err()
    );

    let layout = ArrayLayout::REGDATABASE;
    let dimension = ArrayDimension {
        len: 2,
        lower_bound: 1,
    };
    let null = Parameter::null(Oid::REGDATABASE, Format::Binary);
    let array = encode_array(layout, &[dimension], &[parameter, null], 32).unwrap();
    assert_eq!(
        &array.raw_value().bytes.unwrap()[8..12],
        &6490_u32.to_be_bytes()
    );
    let view = ArrayView::parse(array.raw_value(), layout).unwrap();
    let mut values = view.values();
    assert_eq!(
        values
            .next()
            .unwrap()
            .unwrap()
            .decode::<Option<RegDatabase>>()
            .unwrap(),
        Some(database)
    );
    assert_eq!(
        values
            .next()
            .unwrap()
            .unwrap()
            .decode::<Option<RegDatabase>>()
            .unwrap(),
        None
    );
    assert!(values.next().is_none());
}

#[test]
fn text_and_bytea_distinguish_borrowed_binary_from_text_decoding() {
    let text = Parameter::string("你好");
    let decoded = text.raw_value().decode::<&str>().unwrap();
    assert_eq!(decoded, "你好");
    assert!(std::ptr::eq(
        decoded.as_ptr(),
        text.raw_value().bytes.unwrap().as_ptr()
    ));
    assert!(binary(Oid::TEXT, &[255]).decode::<&str>().is_err());
    let data = Parameter::bytea(b"\0\xff");
    assert_eq!(data.raw_value().decode::<&[u8]>().unwrap(), b"\0\xff");
    let hex = Parameter::text(Oid::BYTEA, "\\x00ff5c");
    assert!(hex.raw_value().decode::<&[u8]>().is_err());
}

#[test]
fn text_bytea_reserves_decoded_bytes_and_preserves_escape_boundaries() {
    for (text, expected) in [
        ("", b"".as_slice()),
        ("\\x", b"".as_slice()),
        ("plain", b"plain".as_slice()),
        ("\\x00ff5C", b"\0\xff\\".as_slice()),
        ("\\000\\377\\\\A", b"\0\xff\\A".as_slice()),
        ("\\0010\\\\7", b"\x010\\7".as_slice()),
    ] {
        let decoded = Parameter::text(Oid::BYTEA, text)
            .raw_value()
            .decode::<Vec<u8>>()
            .unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.capacity(), expected.len());
    }
    for text in ["\\x0", "\\xgg", "\\400", "\\08A", "\\", "\\0", "\\00"] {
        assert!(
            Parameter::text(Oid::BYTEA, text)
                .raw_value()
                .decode::<Vec<u8>>()
                .is_err(),
            "accepted invalid bytea text: {text:?}"
        );
    }
    let text = "\\377".repeat(4096);
    let decoded = Parameter::text(Oid::BYTEA, &text)
        .raw_value()
        .decode::<Vec<u8>>()
        .unwrap();
    assert_eq!(decoded, vec![255; 4096]);
    assert_eq!(decoded.capacity(), decoded.len());
}

#[test]
fn floating_point_and_uuid_wire_forms_are_checked() {
    assert!(
        Parameter::float8(f64::NAN)
            .raw_value()
            .decode::<f64>()
            .unwrap()
            .is_nan()
    );
    assert_eq!(
        Parameter::text(Oid::FLOAT8, "Infinity")
            .raw_value()
            .decode::<f64>()
            .unwrap(),
        f64::INFINITY
    );
    assert_eq!(
        Parameter::float4(-0.0)
            .raw_value()
            .decode::<f32>()
            .unwrap()
            .to_bits(),
        (-0.0_f32).to_bits()
    );
    let uuid = Uuid([
        1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239,
    ]);
    assert_eq!(
        Parameter::uuid(uuid).raw_value().decode::<Uuid>().unwrap(),
        uuid
    );
    assert_eq!(
        Parameter::text(Oid::UUID, "01234567-89ab-cdef-0123-456789abcdef")
            .raw_value()
            .decode::<Uuid>()
            .unwrap(),
        uuid
    );
    assert!(
        Parameter::text(Oid::UUID, "01234567_89ab-cdef-0123-456789abcdef")
            .raw_value()
            .decode::<Uuid>()
            .is_err()
    );
}

#[test]
fn temporal_boundaries_and_infinities_preserve_postgres_units() {
    for value in [
        PgDate::NegativeInfinity,
        PgDate::Finite(0),
        PgDate::PositiveInfinity,
    ] {
        assert_eq!(
            Parameter::date(value)
                .unwrap()
                .raw_value()
                .decode::<PgDate>()
                .unwrap(),
            value
        );
    }
    assert!(Parameter::date(PgDate::Finite(i32::MAX)).is_err());
    assert!(Parameter::date(PgDate::Finite(-2_451_546)).is_err());
    assert!(Parameter::date(PgDate::Finite(2_145_031_949)).is_err());
    for value in [
        PgTimestamp::NegativeInfinity,
        PgTimestamp::Finite(0),
        PgTimestamp::PositiveInfinity,
    ] {
        assert_eq!(
            Parameter::timestamp(value)
                .unwrap()
                .raw_value()
                .decode::<PgTimestamp>()
                .unwrap(),
            value
        );
        assert_eq!(
            Parameter::timestamptz(PgTimestampTz(value))
                .unwrap()
                .raw_value()
                .decode::<PgTimestampTz>()
                .unwrap(),
            PgTimestampTz(value)
        );
    }
    assert!(Parameter::timestamp(PgTimestamp::Finite(9_223_371_331_200_000_000)).is_err());
    assert_eq!(
        Parameter::time(PgTime(86_400_000_000))
            .unwrap()
            .raw_value()
            .decode::<PgTime>()
            .unwrap(),
        PgTime(86_400_000_000)
    );
    assert!(Parameter::time(PgTime(-1)).is_err());
    assert!(Parameter::time(PgTime(86_400_000_001)).is_err());
    let zone = PgTimeTz {
        microseconds: 0,
        seconds_west_of_utc: -57_599,
    };
    assert_eq!(
        Parameter::timetz(zone)
            .unwrap()
            .raw_value()
            .decode::<PgTimeTz>()
            .unwrap(),
        zone
    );
    assert!(
        Parameter::timetz(PgTimeTz {
            microseconds: 0,
            seconds_west_of_utc: -57_600
        })
        .is_err()
    );
    let interval = PgInterval {
        microseconds: -12,
        days: 2,
        months: -3,
    };
    assert_eq!(
        Parameter::interval(interval)
            .raw_value()
            .decode::<PgInterval>()
            .unwrap(),
        interval
    );
}

#[test]
fn bits_reject_invalid_values_and_limits_before_encoding() {
    for (oid, value, limit) in [(Oid::VARBIT, &[1][..], 4), (Oid::BIT, &[3][..], 5)] {
        let invalid = BitString {
            bit_len: 7,
            bytes: value,
        };
        let result = encode_bits(oid, invalid, limit);
        if limit == 4 {
            assert!(matches!(result, Err(CodecError::Limit(_))));
        } else {
            assert!(matches!(
                result,
                Err(CodecError::Invalid("nonzero unused bit string bits"))
            ));
        }
    }
}

#[cfg(feature = "diagnostics")]
#[test]
#[ignore = "分配诊断须单独运行，以隔离进程级计数"]
fn network_parameters_and_invalid_bit_padding_do_not_allocate() {
    let network = Network {
        address: std::net::Ipv4Addr::LOCALHOST.into(),
        prefix_len: 8,
        is_cidr: true,
    };
    let bits = BitString {
        bit_len: 7,
        bytes: &[1],
    };
    let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
    assert!(matches!(
        Parameter::network(network),
        Err(CodecError::Invalid(_))
    ));
    let valid = Parameter::network(Network {
        address: std::net::Ipv6Addr::LOCALHOST.into(),
        prefix_len: 128,
        is_cidr: false,
    })
    .unwrap();
    assert_eq!(valid.raw_value().bytes.map(<[u8]>::len), Some(20));
    assert!(matches!(
        encode_bits(Oid::BIT, bits, 5),
        Err(CodecError::Invalid(_))
    ));
    let change = region.change();
    assert_eq!(change.allocations, 0);
    assert_eq!(change.reallocations, 0);
}

#[test]
fn network_parameters_preserve_binary_ipv4_ipv6_and_typed_nulls() {
    // 扩充内联槽不可增加 64 位平台上每个参数的大小。
    #[cfg(target_pointer_width = "64")]
    const _: () = assert!(size_of::<Parameter<'_>>() == 32);

    for (address, prefix_len, is_cidr, expected) in [
        (
            "192.0.2.1",
            24,
            false,
            b"\x02\x18\0\x04\xc0\0\x02\x01".as_slice(),
        ),
        (
            "192.0.2.0",
            24,
            true,
            b"\x02\x18\x01\x04\xc0\0\x02\0".as_slice(),
        ),
        (
            "::1",
            128,
            false,
            b"\x03\x80\0\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01".as_slice(),
        ),
        (
            "2001:db8::",
            32,
            true,
            b"\x03\x20\x01\x10\x20\x01\x0d\xb8\0\0\0\0\0\0\0\0\0\0\0\0".as_slice(),
        ),
    ] {
        let value = Network {
            address: address.parse().unwrap(),
            prefix_len,
            is_cidr,
        };
        let parameter = Parameter::network(value).unwrap();
        let oid = if is_cidr { Oid::CIDR } else { Oid::INET };
        assert_eq!(parameter.oid(), oid);
        assert_eq!(parameter.raw_value().bytes, Some(expected));
        assert_eq!(parameter.raw_value().decode::<Network>().unwrap(), value);
        assert_eq!(
            Parameter::null(oid, Format::Binary)
                .raw_value()
                .decode::<Option<Network>>()
                .unwrap(),
            None
        );
    }
    for (address, prefix_len) in [
        ("192.0.2.1", 24),
        ("::1", 64),
        ("192.0.2.0", 33),
        ("::", 129),
    ] {
        let network = Network {
            address: address.parse().unwrap(),
            prefix_len,
            is_cidr: true,
        };
        assert!(matches!(
            Parameter::network(network),
            Err(CodecError::Invalid(_))
        ));
    }
}

#[test]
fn bit_and_lsn_representations_validate_boundaries() {
    let encoded = encode_bits(
        Oid::VARBIT,
        BitString {
            bit_len: 9,
            bytes: &[0xa5, 0x80],
        },
        6,
    )
    .unwrap();
    assert_eq!(
        encoded.raw_value().decode::<BitString>().unwrap(),
        BitString {
            bit_len: 9,
            bytes: &[0xa5, 0x80]
        }
    );
    assert!(
        encode_bits(
            Oid::BIT,
            BitString {
                bit_len: 9,
                bytes: &[0, 1]
            },
            6
        )
        .is_err()
    );
    assert_eq!(
        Parameter::text(Oid::PG_LSN, "FFFFFFFF/FFFFFFFF")
            .raw_value()
            .decode::<PgLsn>()
            .unwrap(),
        PgLsn(u64::MAX)
    );
    assert_eq!(
        Parameter::pg_lsn(PgLsn(42))
            .raw_value()
            .decode::<PgLsn>()
            .unwrap(),
        PgLsn(42)
    );
}

#[test]
fn numeric_preserves_base_10000_digits_and_special_values() {
    let encoded = encode_numeric(NumericSign::Negative, 1, 3, &[12, 3456, 7000], 14).unwrap();
    let value = encoded.raw_value().decode::<NumericView>().unwrap();
    assert_eq!(value.sign, NumericSign::Negative);
    assert_eq!(value.weight, 1);
    assert_eq!(value.scale, 3);
    assert_eq!(value.digits().collect::<Vec<_>>(), [12, 3456, 7000]);
    for sign in [
        NumericSign::NaN,
        NumericSign::NegativeInfinity,
        NumericSign::PositiveInfinity,
    ] {
        assert_eq!(
            encode_numeric(sign, 0, 0, &[], 8)
                .unwrap()
                .raw_value()
                .decode::<NumericView>()
                .unwrap()
                .sign,
            sign
        );
    }
    assert!(encode_numeric(NumericSign::Positive, 0, 0, &[10_000], 10).is_err());
    assert!(encode_numeric(NumericSign::NaN, 0, 0, &[1], 10).is_err());
    assert!(encode_numeric(NumericSign::Positive, 0, 0, &[1], 9).is_err());
    let mut truncated = encoded.into_bytes().unwrap();
    truncated.pop();
    assert!(
        binary(Oid::NUMERIC, &truncated)
            .decode::<NumericView>()
            .is_err()
    );
}

#[test]
fn numeric_encoding_rejects_digits_postgresql_would_truncate() {
    for (weight, scale, digits, fits) in [
        (0, 0, &[1, 0][..], true),
        (0, 0, &[1, 2][..], false),
        (-1, 3, &[1230][..], true),
        (-1, 3, &[1234][..], false),
        (-1, 3, &[1230, 1][..], false),
        (-1, 4, &[1234][..], true),
        (-2, 4, &[1][..], false),
        (-2, 5, &[1000][..], true),
        (-2, 5, &[1001][..], false),
        (-3, 5, &[1000][..], false),
    ] {
        assert_eq!(
            encode_numeric(NumericSign::Positive, weight, scale, digits, 32).is_ok(),
            fits,
        );
    }
    let invalid_fraction = [0, 1, 255, 255, 0, 0, 0, 3, 4, 210];
    assert!(matches!(
        binary(Oid::NUMERIC, &invalid_fraction).decode::<NumericView>(),
        Err(CodecError::Invalid(
            "numeric digits exceed the declared scale"
        ))
    ));
}

#[test]
fn scaled_numeric_preserves_exact_integers_and_rejects_rounding_or_overflow() {
    for (coefficient, scale) in [
        (0, 0),
        (0, 0x3fff),
        (10_000, 0),
        (-1_234_567, 2),
        (1, 0x3fff),
        (i128::MIN, 1),
        (i128::MAX, 38),
        (i128::MAX, 0x3fff),
    ] {
        let encoded = encode_scaled_numeric(coefficient, scale, 30).unwrap();
        let view = encoded.raw_value().decode::<NumericView>().unwrap();
        assert_eq!(view.scale, scale);
        assert_eq!(view.to_scaled_i128(scale).unwrap(), coefficient);
    }
    let amount = encode_scaled_numeric(-12_345, 3, 12).unwrap();
    assert_eq!(amount.as_bytes(), b"\0\x02\0\0\x40\0\0\x03\0\x0c\x0d\x7a");
    assert_eq!(
        amount.parameter().raw_value().bytes,
        Some(amount.as_bytes())
    );
    let value = amount.raw_value().decode::<NumericView>().unwrap();
    assert_eq!(value.digits().collect::<Vec<_>>(), [12, 3450]);
    assert_eq!(value.to_scaled_i128(5).unwrap(), -1_234_500);
    assert!(matches!(
        value.to_scaled_i128(2),
        Err(CodecError::Invalid(_))
    ));
    let largest = encode_scaled_numeric(i128::MAX, 0, 30).unwrap();
    assert!(matches!(
        largest
            .raw_value()
            .decode::<NumericView>()
            .unwrap()
            .to_scaled_i128(1),
        Err(CodecError::Limit(_))
    ));
    assert!(encode_scaled_numeric(1, 0x4000, 30).is_err());
    assert!(encode_scaled_numeric(1, 1, 9).is_err());
    assert_eq!(
        encode_scaled_numeric(10_000, 0, 10).unwrap().as_bytes(),
        b"\0\x01\0\x01\0\0\0\0\0\x01"
    );
    assert_eq!(
        encode_scaled_numeric(0, 0x3fff, 8).unwrap().as_bytes(),
        b"\0\0\0\0\0\0\x3f\xff"
    );
}

#[test]
fn money_xml_and_jsonpath_preserve_their_supported_formats() {
    let money = Parameter::money(PgMoney(i64::MIN));
    assert_eq!(
        money.raw_value().decode::<PgMoney>().unwrap(),
        PgMoney(i64::MIN)
    );
    assert!(money.raw_value().decode::<i64>().is_err());
    assert!(!PgMoney::accepts(Oid::MONEY, Format::Text));
    assert_eq!(
        binary(Oid::XML, "<名称/>".as_bytes())
            .decode::<&str>()
            .unwrap(),
        "<名称/>"
    );
    let path = JsonPath("$.enabled");
    let parameter = Parameter::from(path);
    assert_eq!(parameter.oid(), Oid::JSONPATH);
    assert_eq!(parameter.format(), Format::Text);
    assert_eq!(parameter.raw_value().decode::<JsonPath>().unwrap(), path);
    let encoded = path.encode_binary(10).unwrap();
    assert_eq!(encoded.raw_value().bytes, Some(b"\x01$.enabled".as_slice()));
    assert!(path.encode_binary(9).is_err());
    assert_eq!(
        binary(Oid::JSONPATH, b"\x01$.enabled")
            .decode::<JsonPath>()
            .unwrap(),
        path
    );
    assert!(
        binary(Oid::JSONPATH, b"\x02$.enabled")
            .decode::<JsonPath>()
            .is_err()
    );
    assert!(
        binary(Oid::JSONPATH, b"\x01$")
            .decode::<JsonText>()
            .is_err()
    );
}

#[test]
fn array_dimensions_nulls_and_embedded_oid_are_preserved() {
    let layout = ArrayLayout::INT4;
    let dimensions = [ArrayDimension {
        len: 3,
        lower_bound: -4,
    }];
    let values = [
        Parameter::int4(1),
        Parameter::null(Oid::INT4, Format::Binary),
        Parameter::int4(3),
    ];
    #[cfg(feature = "diagnostics")]
    let before = crate::diagnostics::snapshot();
    let encoded = encode_array(layout, &dimensions, &values, 64).unwrap();
    #[cfg(feature = "diagnostics")]
    assert_eq!(
        crate::diagnostics::snapshot()
            .delta(before)
            .unwrap()
            .frontend_parameter_bytes_copied,
        0,
    );
    let view = ArrayView::parse(encoded.raw_value(), layout).unwrap();
    assert_eq!(view.dimensions().collect::<Vec<_>>(), dimensions);
    assert_eq!(
        view.values()
            .map(|value| value.unwrap().decode::<Option<i32>>())
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        [Some(1), None, Some(3)]
    );
    let mut reference = bytes::BytesMut::new();
    pg::array_to_sql(
        dimensions.iter().map(|dimension| pg::ArrayDimension {
            len: dimension.len,
            lower_bound: dimension.lower_bound,
        }),
        layout.element_oid.0,
        [Some(1_i32), None, Some(3)],
        |value, output| match value {
            Some(value) => {
                pg::int4_to_sql(value, output);
                Ok(postgres_protocol::IsNull::No)
            }
            None => Ok(postgres_protocol::IsNull::Yes),
        },
        &mut reference,
    )
    .unwrap();
    assert_eq!(encoded.raw_value().bytes.unwrap(), reference.as_ref());
    let mature = pg::array_from_sql(encoded.raw_value().bytes.unwrap()).unwrap();
    assert_eq!(mature.element_type(), 23);
    assert!(mature.has_nulls());
    let mut observed = Vec::new();
    ArrayView::visit(encoded.raw_value(), layout, |value| {
        observed.push(value.decode::<Option<i32>>()?);
        Ok(())
    })
    .unwrap();
    assert_eq!(observed, [Some(1), None, Some(3)]);
    let mut invalid = encoded.into_bytes().unwrap();
    invalid[20..24].copy_from_slice(&(-2_i32).to_be_bytes());
    assert!(ArrayView::parse(binary(layout.oid, &invalid), layout).is_err());
    assert!(
        encode_array(
            layout,
            &[ArrayDimension {
                len: 2,
                lower_bound: i32::MAX
            }],
            &values[..2],
            64
        )
        .is_err()
    );
    assert!(encode_array(layout, &dimensions, &values[..2], 64).is_err());
    assert!(encode_array(layout, &dimensions, &values, 8).is_err());
}

#[test]
fn arrays_reject_false_null_flags_trailing_bytes_and_unresolved_layouts() {
    let layout = ArrayLayout::INT4;
    let value = [Parameter::null(Oid::INT4, Format::Binary)];
    let encoded = encode_array(
        layout,
        &[ArrayDimension {
            len: 1,
            lower_bound: 1,
        }],
        &value,
        24,
    )
    .unwrap();
    let mut invalid = encoded.into_bytes().unwrap();
    invalid[4..8].copy_from_slice(&0_i32.to_be_bytes());
    assert!(ArrayView::parse(binary(layout.oid, &invalid), layout).is_err());
    let encoded = encode_array(layout, &[], &[], 12).unwrap();
    assert!(
        ArrayView::parse(encoded.raw_value(), layout)
            .unwrap()
            .is_empty()
    );
    let mut invalid = encoded.into_bytes().unwrap();
    invalid.push(0);
    assert!(ArrayView::parse(binary(layout.oid, &invalid), layout).is_err());
    assert!(
        encode_array(
            ArrayLayout {
                oid: Oid(0),
                element_oid: Oid::INT4
            },
            &[],
            &[],
            12
        )
        .is_err()
    );
}

#[test]
fn array_subscripts_require_a_representable_exclusive_upper_bound() {
    let layout = ArrayLayout::OID8;
    let values = [Parameter::oid8(Oid8(1))];
    let mut dimension = ArrayDimension {
        len: 1,
        lower_bound: i32::MAX - 1,
    };
    let encoded = encode_array(layout, &[dimension], &values, 32).unwrap();
    assert_eq!(
        ArrayView::parse(encoded.raw_value(), layout)
            .unwrap()
            .dimensions()
            .next(),
        Some(dimension)
    );
    dimension.lower_bound = i32::MAX;
    assert!(encode_array(layout, &[dimension], &values, 32).is_err());
    let mut invalid = encoded.into_bytes().unwrap();
    invalid[16..20].copy_from_slice(&dimension.lower_bound.to_be_bytes());
    assert!(ArrayView::parse(binary(layout.oid, &invalid), layout).is_err());
}

#[test]
fn composite_layout_checks_each_nested_type_without_a_field_offset_vector() {
    let layout = CompositeLayout {
        oid: Oid(90_001),
        fields: vec![Oid::INT4, Oid::TEXT, Oid::BYTEA].into_boxed_slice(),
    };
    let values = [
        Parameter::int4(7),
        Parameter::string("a"),
        Parameter::null(Oid::BYTEA, Format::Binary),
    ];
    let encoded = encode_composite(&layout, &values, 64).unwrap();
    let view = CompositeView::parse(encoded.raw_value(), &layout).unwrap();
    let mut fields = view.fields();
    assert_eq!(fields.next().unwrap().unwrap().decode::<i32>().unwrap(), 7);
    assert_eq!(
        fields.next().unwrap().unwrap().decode::<&str>().unwrap(),
        "a"
    );
    assert_eq!(
        fields
            .next()
            .unwrap()
            .unwrap()
            .decode::<Option<&[u8]>>()
            .unwrap(),
        None
    );
    assert!(fields.next().is_none());
    let mut invalid = encoded.into_bytes().unwrap();
    invalid[16..20].copy_from_slice(&Oid::INT8.0.to_be_bytes());
    assert!(CompositeView::parse(binary(layout.oid, &invalid), &layout).is_err());
    let mut observed = Vec::new();
    assert!(
        CompositeView::visit(binary(layout.oid, &invalid), &layout, |value| {
            observed.push(value.decode::<i32>()?);
            Ok(())
        })
        .is_err()
    );
    assert_eq!(observed, [7]);
    assert!(encode_composite(&layout, &values[..2], 64).is_err());
}

#[test]
fn ranges_distinguish_empty_unbounded_and_nullable_values() {
    let layout = RangeLayout::INT4RANGE;
    let lower = Parameter::int4(1);
    let upper = Parameter::int4(10);
    let bounds = RangeValue::Bounds {
        lower: Bound::Included(lower.raw_value()),
        upper: Bound::Excluded(upper.raw_value()),
    };
    let encoded = encode_range(layout, bounds, 32).unwrap();
    let view = RangeView::parse(encoded.raw_value(), layout).unwrap();
    let RangeValue::Bounds {
        lower: Bound::Included(lower),
        upper: Bound::Excluded(upper),
    } = view.value()
    else {
        panic!("expected both finite bounds");
    };
    assert_eq!(lower.decode::<i32>().unwrap(), 1);
    assert_eq!(upper.decode::<i32>().unwrap(), 10);
    assert!(matches!(
        pg::range_from_sql(encoded.raw_value().bytes.unwrap()).unwrap(),
        pg::Range::Nonempty(
            pg::RangeBound::Inclusive(Some(_)),
            pg::RangeBound::Exclusive(Some(_))
        )
    ));
    let empty = encode_range(layout, RangeValue::Empty, 1).unwrap();
    assert!(
        RangeView::parse(empty.raw_value(), layout)
            .unwrap()
            .is_empty()
    );
    let unbounded = encode_range(
        layout,
        RangeValue::Bounds {
            lower: Bound::Unbounded,
            upper: Bound::Unbounded,
        },
        1,
    )
    .unwrap();
    assert!(
        !RangeView::parse(unbounded.raw_value(), layout)
            .unwrap()
            .is_empty()
    );
    let null = Parameter::null(Oid::INT4, Format::Binary);
    assert!(
        encode_range(
            layout,
            RangeValue::Bounds {
                lower: Bound::Included(null.raw_value()),
                upper: Bound::Unbounded,
            },
            32
        )
        .is_err()
    );
    for invalid in [
        b"\x80".as_slice(),
        b"\x01\x00",
        b"\x0a",
        b"\x00\xff\xff\xff\xfe",
    ] {
        assert!(RangeView::parse(binary(layout.oid, invalid), layout).is_err());
    }
}

#[test]
fn multirange_validates_every_member_and_final_boundary() {
    let layout = MultiRangeLayout::INT4MULTIRANGE;
    let lower = Parameter::int4(1);
    let upper = Parameter::int4(3);
    let ranges = [
        RangeValue::Bounds {
            lower: Bound::Included(lower.raw_value()),
            upper: Bound::Excluded(upper.raw_value()),
        },
        RangeValue::Empty,
    ];
    let encoded = encode_multirange(layout, &ranges, 30).unwrap();
    assert!(encode_multirange(layout, &ranges, 29).is_err());
    let view = MultiRangeView::parse(encoded.raw_value(), layout).unwrap();
    assert_eq!(view.len(), 2);
    assert_eq!(
        view.ranges()
            .map(|range| range.unwrap().is_empty())
            .collect::<Vec<_>>(),
        [false, true]
    );
    let mut bytes = encoded.into_bytes().unwrap();
    bytes.push(0);
    assert!(MultiRangeView::parse(binary(layout.oid, &bytes), layout).is_err());
    let mut observed = Vec::new();
    assert!(
        MultiRangeView::visit(binary(layout.oid, &bytes), layout, |range| {
            observed.push(range.is_empty());
            Ok(())
        })
        .is_err()
    );
    assert_eq!(observed, [false, true]);
}

#[test]
fn jsonb_wire_version_and_utf8_are_checked_without_claiming_a_json_dom() {
    assert_eq!(
        binary(Oid::JSONB, b"\x01{\"a\":1}")
            .decode::<JsonText>()
            .unwrap()
            .0,
        "{\"a\":1}"
    );
    assert!(binary(Oid::JSONB, b"\x02{}").decode::<JsonText>().is_err());
    assert!(binary(Oid::JSON, &[255]).decode::<JsonText>().is_err());
    assert!(binary(Oid(99_999), b"opaque").decode::<i32>().is_err());
}

#[cfg(feature = "postgres-types")]
#[test]
fn optional_adapters_validate_type_nulls_and_the_retained_output_limit() {
    let ty = postgres_types::Type::INT4;
    let encoded = encode_postgres(&42_i32, &ty, 4).unwrap();
    assert_eq!(
        decode_postgres::<i32>(encoded.raw_value(), &ty).unwrap(),
        42
    );
    assert!(encode_postgres(&42_i32, &ty, 3).is_err());
    let null = RawValue {
        oid: Oid::INT4,
        format: Format::Binary,
        bytes: None,
    };
    assert_eq!(decode_postgres::<Option<i32>>(null, &ty).unwrap(), None);
    assert!(decode_postgres::<Option<i64>>(null, &ty).is_err());
    let oid8_type = Oid::OID8.builtin_postgres_type().unwrap();
    let encoded = encode_postgres(&Oid8(u64::MAX), &oid8_type, 8).unwrap();
    assert_eq!(
        decode_postgres::<Oid8>(encoded.raw_value(), &oid8_type).unwrap(),
        Oid8(u64::MAX)
    );
}

#[cfg(feature = "postgres-types")]
#[test]
fn externally_resolved_composite_layout_preserves_wire_field_order() {
    use postgres_types::{Field, Kind, Type};

    let ty = Type::new(
        "pair".into(),
        90_001,
        Kind::Composite(vec![
            Field::new("label".into(), Type::TEXT),
            Field::new("count".into(), Type::INT4),
        ]),
        "public".into(),
    );
    let layout = CompositeLayout::from_postgres_type(&ty).unwrap();
    assert_eq!(layout.oid, Oid(ty.oid()));
    assert_eq!(layout.fields.as_ref(), &[Oid::TEXT, Oid::INT4]);
    assert!(CompositeLayout::from_postgres_type(&Type::RECORD).is_none());
    assert!(CompositeLayout::from_postgres_type(&Type::TEXT_ARRAY).is_none());

    #[cfg(feature = "diagnostics")]
    let before = crate::diagnostics::snapshot();
    let value =
        encode_composite(&layout, &[Parameter::string("a"), Parameter::int4(5)], 64).unwrap();
    #[cfg(feature = "diagnostics")]
    assert_eq!(
        crate::diagnostics::snapshot()
            .delta(before)
            .unwrap()
            .frontend_parameter_bytes_copied,
        0,
    );
    let decoded = CompositeView::parse(value.raw_value(), &layout).unwrap();
    let mut fields = decoded.fields();
    assert_eq!(
        fields.next().unwrap().unwrap().decode::<&str>().unwrap(),
        "a"
    );
    assert_eq!(fields.next().unwrap().unwrap().decode::<i32>().unwrap(), 5);
}

#[cfg(feature = "postgres-types")]
#[test]
fn builtin_lookup_includes_pg19_scalar_and_array_metadata() {
    assert_eq!(
        Oid::INT4.builtin_postgres_type(),
        Some(postgres_types::Type::INT4)
    );
    assert!(Oid(u32::MAX).builtin_postgres_type().is_none());
    for (layout, name, array_name) in [
        (ArrayLayout::OID8, "oid8", "_oid8"),
        (ArrayLayout::REGDATABASE, "regdatabase", "_regdatabase"),
    ] {
        let element = layout.element_oid.builtin_postgres_type().unwrap();
        assert_eq!(element.schema(), "pg_catalog");
        assert_eq!(element.name(), name);
        let array = layout.oid.builtin_postgres_type().unwrap();
        assert_eq!(array.name(), array_name);
        assert_eq!(array.kind(), &postgres_types::Kind::Array(element));
        assert_eq!(ArrayLayout::from_postgres_type(&array), Some(layout));
    }
    let database = RegDatabase(u32::MAX);
    let ty = Oid::REGDATABASE.builtin_postgres_type().unwrap();
    let encoded = encode_postgres(&database, &ty, 4).unwrap();
    assert_eq!(
        decode_postgres::<RegDatabase>(encoded.raw_value(), &ty).unwrap(),
        database
    );
}

#[cfg(feature = "postgres-types")]
#[test]
fn postgres_adapter_reuses_fitting_storage_and_compacts_oversized_backing() {
    use std::cell::Cell;

    use postgres_types::{IsNull, Type};

    std::thread_local! {
        static ACCEPTS_CALLS: Cell<u8> = const { Cell::new(0) };
    }

    #[derive(Debug)]
    struct BufferedInt4 {
        capacity: usize,
        offset: usize,
        pointer: Cell<*const u8>,
    }

    impl postgres_types::ToSql for BufferedInt4 {
        fn to_sql(
            &self,
            _: &Type,
            output: &mut bytes::BytesMut,
        ) -> Result<IsNull, Box<dyn StdError + Send + Sync>> {
            *output = bytes::BytesMut::with_capacity(self.capacity);
            output.resize(self.offset, 0);
            output.extend_from_slice(&42_i32.to_be_bytes());
            if self.offset != 0 {
                *output = output.split_off(self.offset);
            }
            self.pointer.set(output.as_ptr());
            Ok(IsNull::No)
        }

        fn accepts(ty: &Type) -> bool {
            ACCEPTS_CALLS.with(|calls| calls.set(calls.get() + 1));
            *ty == Type::INT4
        }

        postgres_types::to_sql_checked!();
    }

    for (capacity, offset) in [(4, 0), (64, 0), (64, 60)] {
        let input = BufferedInt4 {
            capacity,
            offset,
            pointer: Cell::new(std::ptr::null()),
        };
        let encoded = encode_postgres(&input, &Type::INT4, 4).unwrap();
        assert_eq!(ACCEPTS_CALLS.with(|calls| calls.replace(0)), 1);
        let bytes = encoded.raw_value().bytes.unwrap();
        assert_eq!(bytes, &42_i32.to_be_bytes());
        assert_eq!(encoded.retained_bytes(), 4);
        if capacity == 4 {
            assert_eq!(bytes.as_ptr(), input.pointer.get());
        }
    }
}
