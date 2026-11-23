//! 同步值编解码器和借用协议容器。
//!
//! 容器视图校验结构、数量、长度及嵌入的类型标识。
//! 数组元素和复合字段保留为 [`RawValue`]，由调用方显式解码。
//! 需要保留视图或重复读取时先 `parse`；只访问一次时可用 `visit`，在校验结构的同一遍扫描中处理成员。

use std::{error::Error as StdError, fmt, net::IpAddr};

pub use crate::protocol::Format;

mod container;
pub use container::{
    ArrayDimension, ArrayLayout, ArrayValues, ArrayView, CompositeFields, CompositeLayout,
    CompositeView, MultiRangeLayout, MultiRangeValues, MultiRangeView, RangeLayout, RangeValue,
    RangeView, encode_array, encode_composite, encode_multirange, encode_range,
};
mod numeric;
use crate::protocol::ProtocolError;
pub use numeric::{NumericSign, NumericView, ScaledNumeric, encode_numeric, encode_scaled_numeric};

#[cfg(feature = "serde_json")]
mod json;
#[cfg(feature = "serde_json")]
pub use json::encode_json;
#[cfg(feature = "time")]
mod time;

/// 数据库目录和协议消息中的四字节类型标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Oid(pub u32);

// PostgreSQL 19 的内置类型 OID 和数组 OID 由 pg_type.dat 定义。
// RowDescription 和数组头中的类型标识均为四字节，包括 oid8 值的类型标识。
macro_rules! builtin_arrays {
    ($(($name:ident, $oid:literal, $array:ident, $array_oid:literal)),+ $(,)?) => {
        impl Oid {
            $(
                pub const $name: Self = Self($oid);
                pub const $array: Self = Self($array_oid);
            )+
        }
        impl ArrayLayout {
            $(pub const $name: Self = Self { oid: Oid::$array, element_oid: Oid::$name };)+
        }
    };
}

builtin_arrays! {
    (BOOL, 16, BOOL_ARRAY, 1000),
    (BYTEA, 17, BYTEA_ARRAY, 1001),
    (CHAR, 18, CHAR_ARRAY, 1002),
    (NAME, 19, NAME_ARRAY, 1003),
    (INT8, 20, INT8_ARRAY, 1016),
    (INT2, 21, INT2_ARRAY, 1005),
    (INT4, 23, INT4_ARRAY, 1007),
    (TEXT, 25, TEXT_ARRAY, 1009),
    (OID, 26, OID_ARRAY, 1028),
    (PG_TYPE, 71, PG_TYPE_ARRAY, 210),
    (PG_ATTRIBUTE, 75, PG_ATTRIBUTE_ARRAY, 270),
    (PG_PROC, 81, PG_PROC_ARRAY, 272),
    (PG_CLASS, 83, PG_CLASS_ARRAY, 273),
    (JSON, 114, JSON_ARRAY, 199),
    (XML, 142, XML_ARRAY, 143),
    (CIDR, 650, CIDR_ARRAY, 651),
    (FLOAT4, 700, FLOAT4_ARRAY, 1021),
    (FLOAT8, 701, FLOAT8_ARRAY, 1022),
    (MACADDR8, 774, MACADDR8_ARRAY, 775),
    (MONEY, 790, MONEY_ARRAY, 791),
    (MACADDR, 829, MACADDR_ARRAY, 1040),
    (INET, 869, INET_ARRAY, 1041),
    (BPCHAR, 1042, BPCHAR_ARRAY, 1014),
    (VARCHAR, 1043, VARCHAR_ARRAY, 1015),
    (DATE, 1082, DATE_ARRAY, 1182),
    (TIME, 1083, TIME_ARRAY, 1183),
    (TIMESTAMP, 1114, TIMESTAMP_ARRAY, 1115),
    (TIMESTAMPTZ, 1184, TIMESTAMPTZ_ARRAY, 1185),
    (INTERVAL, 1186, INTERVAL_ARRAY, 1187),
    (TIMETZ, 1266, TIMETZ_ARRAY, 1270),
    (BIT, 1560, BIT_ARRAY, 1561),
    (VARBIT, 1562, VARBIT_ARRAY, 1563),
    (NUMERIC, 1700, NUMERIC_ARRAY, 1231),
    (RECORD, 2249, RECORD_ARRAY, 2287),
    (UUID, 2950, UUID_ARRAY, 2951),
    (PG_LSN, 3220, PG_LSN_ARRAY, 3221),
    (JSONB, 3802, JSONB_ARRAY, 3807),
    (JSONPATH, 4072, JSONPATH_ARRAY, 4073),
    (OID8, 6437, OID8_ARRAY, 6442),
    (REGDATABASE, 6490, REGDATABASE_ARRAY, 6491),
}

// 区间、子类型和多区间的对应关系由 PostgreSQL 19 的 pg_range.dat 定义。
macro_rules! builtin_ranges {
    ($(($subtype:ident, $range:ident, $range_oid:literal, $array:ident, $array_oid:literal,
        $multi:ident, $multi_oid:literal, $multi_array:ident, $multi_array_oid:literal)),+ $(,)?) => {
        builtin_arrays! {
            $(($range, $range_oid, $array, $array_oid),
              ($multi, $multi_oid, $multi_array, $multi_array_oid),)+
        }
        impl RangeLayout {
            $(pub const $range: Self = Self { oid: Oid::$range, subtype_oid: Oid::$subtype };)+
        }
        impl MultiRangeLayout {
            $(pub const $multi: Self = Self { oid: Oid::$multi, range: RangeLayout::$range };)+
        }
    };
}

builtin_ranges! {
    (INT4, INT4RANGE, 3904, INT4RANGE_ARRAY, 3905, INT4MULTIRANGE, 4451, INT4MULTIRANGE_ARRAY, 6150),
    (NUMERIC, NUMRANGE, 3906, NUMRANGE_ARRAY, 3907, NUMMULTIRANGE, 4532, NUMMULTIRANGE_ARRAY, 6151),
    (TIMESTAMP, TSRANGE, 3908, TSRANGE_ARRAY, 3909, TSMULTIRANGE, 4533, TSMULTIRANGE_ARRAY, 6152),
    (TIMESTAMPTZ, TSTZRANGE, 3910, TSTZRANGE_ARRAY, 3911, TSTZMULTIRANGE, 4534, TSTZMULTIRANGE_ARRAY, 6153),
    (DATE, DATERANGE, 3912, DATERANGE_ARRAY, 3913, DATEMULTIRANGE, 4535, DATEMULTIRANGE_ARRAY, 6155),
    (INT8, INT8RANGE, 3926, INT8RANGE_ARRAY, 3927, INT8MULTIRANGE, 4536, INT8MULTIRANGE_ARRAY, 6157),
}

impl Oid {
    /// 离线查找内置类型元数据。目录行类型或用户自定义类型可能需要查询具体数据库；
    /// 查找返回 `None` 时，向编解码器或布局构造器提供已解析的 `Type`。
    #[cfg(feature = "postgres-types")]
    pub fn builtin_postgres_type(self) -> Option<postgres_types::Type> {
        use std::sync::LazyLock;

        use postgres_types::{Kind, Type};

        fn catalog_type(name: &str, oid: Oid, kind: Kind) -> Type {
            Type::new(name.to_owned(), oid.0, kind, "pg_catalog".to_owned())
        }

        static OID8: LazyLock<Type> =
            LazyLock::new(|| catalog_type("oid8", Oid::OID8, Kind::Simple));
        static OID8_ARRAY: LazyLock<Type> =
            LazyLock::new(|| catalog_type("_oid8", Oid::OID8_ARRAY, Kind::Array(OID8.clone())));
        static REGDATABASE: LazyLock<Type> =
            LazyLock::new(|| catalog_type("regdatabase", Oid::REGDATABASE, Kind::Simple));
        static REGDATABASE_ARRAY: LazyLock<Type> = LazyLock::new(|| {
            catalog_type(
                "_regdatabase",
                Oid::REGDATABASE_ARRAY,
                Kind::Array(REGDATABASE.clone()),
            )
        });

        Some(match self {
            Self::OID8 => OID8.clone(),
            Self::OID8_ARRAY => OID8_ARRAY.clone(),
            Self::REGDATABASE => REGDATABASE.clone(),
            Self::REGDATABASE_ARRAY => REGDATABASE_ARRAY.clone(),
            _ => return Type::from_oid(self.0),
        })
    }
}

#[derive(Debug)]
pub enum CodecError {
    WrongType { oid: Oid, format: Format },
    UnexpectedNull,
    Invalid(&'static str),
    Limit(&'static str),
    Allocation,
    Protocol(ProtocolError),
    Conversion(Box<dyn StdError + Send + Sync>),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongType { oid, format } => {
                write!(f, "unsupported value type {} in {format:?} format", oid.0)
            }
            Self::UnexpectedNull => f.write_str("SQL NULL requires a nullable target type"),
            Self::Invalid(message) | Self::Limit(message) => f.write_str(message),
            Self::Allocation => f.write_str("value storage allocation failed"),
            Self::Protocol(error) => error.fmt(f),
            Self::Conversion(error) => error.fmt(f),
        }
    }
}

impl StdError for CodecError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Conversion(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<ProtocolError> for CodecError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// 带类型和格式的借用值。`None` 表示 SQL NULL，`Some(&[])` 表示空载荷。
#[derive(Clone, Copy)]
pub struct RawValue<'a> {
    pub oid: Oid,
    pub format: Format,
    pub bytes: Option<&'a [u8]>,
}

impl fmt::Debug for RawValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawValue")
            .field("oid", &self.oid)
            .field("format", &self.format)
            .field("length", &self.bytes.map(<[u8]>::len))
            .finish()
    }
}

impl<'a> RawValue<'a> {
    pub fn decode<T: Decode<'a>>(self) -> Result<T, CodecError> {
        T::decode(self)
    }

    fn non_null(self, accepted: &[Oid], binary_only: bool) -> Result<&'a [u8], CodecError> {
        if !accepted.contains(&self.oid) || (binary_only && self.format != Format::Binary) {
            return Err(CodecError::WrongType {
                oid: self.oid,
                format: self.format,
            });
        }
        self.bytes.ok_or(CodecError::UnexpectedNull)
    }
}

/// 同步解码器校验类型 OID、格式和值。网络状态机独立于具体解码器。
pub trait Decode<'a>: Sized {
    fn accepts(oid: Oid, format: Format) -> bool;
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError>;
}

impl<'a, T: Decode<'a>> Decode<'a> for Option<T> {
    fn accepts(oid: Oid, format: Format) -> bool {
        T::accepts(oid, format)
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        if value.bytes.is_some() {
            return T::decode(value).map(Some);
        }
        if !T::accepts(value.oid, value.format) {
            return Err(CodecError::WrongType {
                oid: value.oid,
                format: value.format,
            });
        }
        Ok(None)
    }
}

const PARAMETER_INLINE_BYTES: usize = 20;
const PARAMETER_LENGTH_BYTES: usize = size_of::<i32>();

#[derive(Clone)]
enum ParameterData<'a> {
    Null,
    Borrowed(&'a [u8]),
    FixedBinary {
        field: [u8; PARAMETER_INLINE_BYTES],
        length: u8,
    },
    InlinePayload([u8; PARAMETER_INLINE_BYTES]),
}

/// 已编码的参数。小型数值内联存储，其他预编码值借用调用方字节。
#[derive(Clone)]
pub struct Parameter<'a> {
    oid: Oid,
    format: Format,
    data: ParameterData<'a>,
}

impl fmt::Debug for Parameter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw_value().fmt(f)
    }
}

impl<'a> Parameter<'a> {
    pub fn null(oid: Oid, format: Format) -> Self {
        Self {
            oid,
            format,
            data: ParameterData::Null,
        }
    }
    pub fn binary(oid: Oid, bytes: &'a [u8]) -> Self {
        Self {
            oid,
            format: Format::Binary,
            data: ParameterData::Borrowed(bytes),
        }
    }
    pub fn text(oid: Oid, text: &'a str) -> Self {
        Self {
            oid,
            format: Format::Text,
            data: ParameterData::Borrowed(text.as_bytes()),
        }
    }
    pub fn raw(oid: Oid, format: Format, bytes: Option<&'a [u8]>) -> Self {
        Self {
            oid,
            format,
            data: bytes.map_or(ParameterData::Null, ParameterData::Borrowed),
        }
    }
    pub fn string(text: &'a str) -> Self {
        Self::binary(Oid::TEXT, text.as_bytes())
    }
    pub fn bytea(bytes: &'a [u8]) -> Self {
        Self::binary(Oid::BYTEA, bytes)
    }
    pub fn bool(value: bool) -> Self {
        Self::inline(Oid::BOOL, &[u8::from(value)])
    }
    pub fn char(value: i8) -> Self {
        Self::inline(Oid::CHAR, &value.to_be_bytes())
    }
    pub fn int2(value: i16) -> Self {
        Self::inline(Oid::INT2, &value.to_be_bytes())
    }
    pub fn int4(value: i32) -> Self {
        Self::inline(Oid::INT4, &value.to_be_bytes())
    }
    pub fn int8(value: i64) -> Self {
        Self::inline(Oid::INT8, &value.to_be_bytes())
    }
    pub fn float4(value: f32) -> Self {
        Self::inline(Oid::FLOAT4, &value.to_be_bytes())
    }
    pub fn float8(value: f64) -> Self {
        Self::inline(Oid::FLOAT8, &value.to_be_bytes())
    }
    pub fn money(value: PgMoney) -> Self {
        Self::inline(Oid::MONEY, &value.0.to_be_bytes())
    }
    pub fn oid_value(value: u32) -> Self {
        Self::inline(Oid::OID, &value.to_be_bytes())
    }
    pub fn oid8(value: Oid8) -> Self {
        Self::inline(Oid::OID8, &value.0.to_be_bytes())
    }
    pub fn regdatabase(value: RegDatabase) -> Self {
        Self::inline(Oid::REGDATABASE, &value.0.to_be_bytes())
    }
    pub fn uuid(value: Uuid) -> Self {
        Self::inline(Oid::UUID, &value.0)
    }
    pub fn macaddr(value: MacAddress) -> Self {
        Self::inline(Oid::MACADDR, &value.0)
    }
    pub fn macaddr8(value: MacAddress8) -> Self {
        Self::inline(Oid::MACADDR8, &value.0)
    }
    /// 内联编码 INET 或 CIDR。CIDR 必须清零前缀之外的宿主位。
    pub fn network(value: Network) -> Result<Self, CodecError> {
        value.validate()?;
        let cidr = u8::from(value.is_cidr);
        let oid = if value.is_cidr { Oid::CIDR } else { Oid::INET };
        match value.address {
            IpAddr::V4(address) => {
                let [a, b, c, d] = address.octets();
                Ok(Self::inline(
                    oid,
                    &[PG_IPV4_FAMILY, value.prefix_len, cidr, 4, a, b, c, d],
                ))
            }
            IpAddr::V6(address) => {
                let mut bytes = [0; PARAMETER_INLINE_BYTES];
                bytes[..4].copy_from_slice(&[PG_IPV6_FAMILY, value.prefix_len, cidr, 16]);
                bytes[4..].copy_from_slice(&address.octets());
                Ok(Self {
                    oid,
                    format: Format::Binary,
                    data: ParameterData::InlinePayload(bytes),
                })
            }
        }
    }
    pub fn pg_lsn(value: PgLsn) -> Self {
        Self::inline(Oid::PG_LSN, &value.0.to_be_bytes())
    }
    pub fn date(value: PgDate) -> Result<Self, CodecError> {
        let encoded = value.wire()?;
        Ok(Self::inline(Oid::DATE, &encoded.to_be_bytes()))
    }
    pub fn time(value: PgTime) -> Result<Self, CodecError> {
        check_time(value.0)?;
        Ok(Self::inline(Oid::TIME, &value.0.to_be_bytes()))
    }
    pub fn timestamp(value: PgTimestamp) -> Result<Self, CodecError> {
        Ok(Self::inline(Oid::TIMESTAMP, &value.wire()?.to_be_bytes()))
    }
    pub fn timestamptz(value: PgTimestampTz) -> Result<Self, CodecError> {
        Ok(Self::inline(
            Oid::TIMESTAMPTZ,
            &value.0.wire()?.to_be_bytes(),
        ))
    }
    pub fn timetz(value: PgTimeTz) -> Result<Self, CodecError> {
        value.validate()?;
        let mut bytes = [0; 12];
        bytes[..8].copy_from_slice(&value.microseconds.to_be_bytes());
        bytes[8..].copy_from_slice(&value.seconds_west_of_utc.to_be_bytes());
        Ok(Self::inline(Oid::TIMETZ, &bytes))
    }
    pub fn interval(value: PgInterval) -> Self {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&value.microseconds.to_be_bytes());
        bytes[8..12].copy_from_slice(&value.days.to_be_bytes());
        bytes[12..].copy_from_slice(&value.months.to_be_bytes());
        Self::inline(Oid::INTERVAL, &bytes)
    }
    pub fn oid(&self) -> Oid {
        self.oid
    }
    pub fn format(&self) -> Format {
        self.format
    }
    pub fn raw_value(&self) -> RawValue<'_> {
        RawValue {
            oid: self.oid,
            format: self.format,
            bytes: self.bytes(),
        }
    }
    #[expect(
        clippy::indexing_slicing,
        reason = "定宽字段的前缀与载荷合计长度由 inline 构造器在编译时检查"
    )]
    fn bytes(&self) -> Option<&[u8]> {
        match &self.data {
            ParameterData::Null => None,
            ParameterData::Borrowed(bytes) => Some(bytes),
            ParameterData::FixedBinary { field, length } => {
                let end = PARAMETER_LENGTH_BYTES + usize::from(*length);
                Some(&field[PARAMETER_LENGTH_BYTES..end])
            }
            ParameterData::InlinePayload(bytes) => Some(bytes),
        }
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.non_null_len().unwrap_or(0)
    }

    fn non_null_len(&self) -> Option<usize> {
        match &self.data {
            ParameterData::Null => None,
            ParameterData::Borrowed(bytes) => Some(bytes.len()),
            ParameterData::FixedBinary { length, .. } => Some(usize::from(*length)),
            ParameterData::InlinePayload(bytes) => Some(bytes.len()),
        }
    }

    /// 追加已通过长度预检的 Bind 参数字段。定宽标量包含编好的长度前缀。
    #[inline]
    pub(crate) fn append_bind_field(&self, output: &mut Vec<u8>) {
        self.append_field::<true>(output);
    }

    /// 追加已通过长度预检的字段，Bind 诊断只统计请求本身的复制。
    #[inline]
    #[expect(
        clippy::indexing_slicing,
        reason = "定宽字段的前缀与载荷合计长度由 inline 构造器在编译时检查"
    )]
    fn append_field<const BIND: bool>(&self, output: &mut Vec<u8>) {
        let bytes = match &self.data {
            ParameterData::Null => {
                output.extend_from_slice(&(-1_i32).to_be_bytes());
                return;
            }
            ParameterData::Borrowed(bytes) => *bytes,
            ParameterData::FixedBinary { field, length } => {
                let length = usize::from(*length);
                output.extend_from_slice(&field[..PARAMETER_LENGTH_BYTES + length]);
                #[cfg(feature = "diagnostics")]
                if BIND {
                    crate::diagnostics::parameter_copy(length);
                }
                return;
            }
            ParameterData::InlinePayload(bytes) => bytes.as_slice(),
        };
        append_payload(output, bytes);
        #[cfg(feature = "diagnostics")]
        if BIND {
            crate::diagnostics::parameter_copy(bytes.len());
        }
    }

    // 内联标量的最大长度在编译时检查。
    fn inline<const N: usize>(oid: Oid, value: &[u8; N]) -> Self {
        let (length, prefix) = const {
            assert!(N <= PARAMETER_INLINE_BYTES - PARAMETER_LENGTH_BYTES);
            (N as u8, (N as i32).to_be_bytes())
        };
        let mut field = [0; PARAMETER_INLINE_BYTES];
        let (header, payload) = field.split_at_mut(PARAMETER_LENGTH_BYTES);
        header.copy_from_slice(&prefix);
        for (target, source) in payload.iter_mut().zip(value) {
            *target = *source;
        }
        Self {
            oid,
            format: Format::Binary,
            data: ParameterData::FixedBinary { field, length },
        }
    }
}

fn fixed_binary<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CodecError> {
    bytes
        .try_into()
        .map_err(|_| CodecError::Invalid("invalid fixed-width PostgreSQL value length"))
}

fn utf8(bytes: &[u8]) -> Result<&str, CodecError> {
    std::str::from_utf8(bytes).map_err(|_| ProtocolError::InvalidUtf8.into())
}

macro_rules! numeric_scalar_codec {
    ($rust:ty, $oid:expr) => {
        impl<'a> Decode<'a> for $rust {
            fn accepts(oid: Oid, _format: Format) -> bool {
                oid == $oid
            }
            fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
                let bytes = value.non_null(&[$oid], false)?;
                match value.format {
                    Format::Binary => fixed_binary(bytes).map(Self::from_be_bytes),
                    Format::Text => utf8(bytes)?
                        .parse::<Self>()
                        .map_err(|error| CodecError::Conversion(Box::new(error))),
                }
            }
        }
    };
}

numeric_scalar_codec!(i16, Oid::INT2);
numeric_scalar_codec!(i32, Oid::INT4);
numeric_scalar_codec!(i64, Oid::INT8);
numeric_scalar_codec!(u32, Oid::OID);
numeric_scalar_codec!(u64, Oid::OID8);
numeric_scalar_codec!(f32, Oid::FLOAT4);
numeric_scalar_codec!(f64, Oid::FLOAT8);

impl<'a> Decode<'a> for bool {
    fn accepts(oid: Oid, _format: Format) -> bool {
        oid == Oid::BOOL
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let bytes = value.non_null(&[Oid::BOOL], false)?;
        match value.format {
            Format::Binary => fixed_binary(bytes).map(|[byte]| byte != 0),
            Format::Text => match bytes {
                b"t" | b"true" => Ok(true),
                b"f" | b"false" => Ok(false),
                _ => Err(CodecError::Invalid("invalid PostgreSQL boolean text")),
            },
        }
    }
}

impl<'a> Decode<'a> for i8 {
    fn accepts(oid: Oid, format: Format) -> bool {
        oid == Oid::CHAR && format == Format::Binary
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        fixed_binary(value.non_null(&[Oid::CHAR], true)?).map(Self::from_be_bytes)
    }
}

impl<'a> Decode<'a> for Oid {
    fn accepts(oid: Oid, format: Format) -> bool {
        u32::accepts(oid, format)
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        u32::decode(value).map(Self)
    }
}

/// PostgreSQL `regdatabase` 二进制值中保存的数据库 OID。
///
/// 文本格式可能返回数据库名称。读取 OID 时选择二进制格式，或由应用自行解释原始文本。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegDatabase(pub u32);

impl<'a> Decode<'a> for RegDatabase {
    fn accepts(oid: Oid, format: Format) -> bool {
        oid == Oid::REGDATABASE && format == Format::Binary
    }

    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        fixed_binary(value.non_null(&[Oid::REGDATABASE], true)?)
            .map(|bytes| Self(u32::from_be_bytes(bytes)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Oid8(pub u64);

impl<'a> Decode<'a> for Oid8 {
    fn accepts(oid: Oid, format: Format) -> bool {
        u64::accepts(oid, format)
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        u64::decode(value).map(Self)
    }
}

/// `money` 的二进制有符号整数。小数位数由目标会话的 `lc_monetary` 决定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgMoney(pub i64);

impl<'a> Decode<'a> for PgMoney {
    fn accepts(oid: Oid, format: Format) -> bool {
        oid == Oid::MONEY && format == Format::Binary
    }

    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        fixed_binary(value.non_null(&[Oid::MONEY], true)?)
            .map(|bytes| Self(i64::from_be_bytes(bytes)))
    }
}

const TEXT_TYPES: &[Oid] = &[Oid::TEXT, Oid::VARCHAR, Oid::BPCHAR, Oid::NAME, Oid::XML];

impl<'a> Decode<'a> for &'a str {
    fn accepts(oid: Oid, _format: Format) -> bool {
        TEXT_TYPES.contains(&oid)
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        utf8(value.non_null(TEXT_TYPES, false)?)
    }
}

impl<'a> Decode<'a> for String {
    fn accepts(oid: Oid, format: Format) -> bool {
        <&str>::accepts(oid, format)
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let text = <&str>::decode(value)?;
        let mut output = String::new();
        output
            .try_reserve_exact(text.len())
            .map_err(|_| CodecError::Allocation)?;
        output.push_str(text);
        Ok(output)
    }
}

impl<'a> Decode<'a> for &'a [u8] {
    fn accepts(oid: Oid, format: Format) -> bool {
        oid == Oid::BYTEA && format == Format::Binary
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        value.non_null(&[Oid::BYTEA], true)
    }
}

impl<'a> Decode<'a> for Vec<u8> {
    fn accepts(oid: Oid, _format: Format) -> bool {
        oid == Oid::BYTEA
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let bytes = value.non_null(&[Oid::BYTEA], false)?;
        let mut output = Vec::new();
        let hex = match value.format {
            Format::Binary => None,
            Format::Text => bytes.strip_prefix(b"\\x"),
        };
        if let Some(hex) = hex {
            let (pairs, remainder) = hex.as_chunks::<2>();
            if !remainder.is_empty() {
                return Err(CodecError::Invalid("odd bytea hex length"));
            }
            output
                .try_reserve_exact(pairs.len())
                .map_err(|_| CodecError::Allocation)?;
            for &[high, low] in pairs {
                output.push(hex_digit(high)? * 16 + hex_digit(low)?);
            }
        } else if value.format == Format::Binary || !bytes.contains(&b'\\') {
            output
                .try_reserve_exact(bytes.len())
                .map_err(|_| CodecError::Allocation)?;
            output.extend_from_slice(bytes);
        } else {
            let mut cursor = ValueCursor::new(bytes);
            let mut length = 0;
            while !cursor.is_empty() {
                read_bytea_byte(&mut cursor)?;
                length += 1;
            }
            output
                .try_reserve_exact(length)
                .map_err(|_| CodecError::Allocation)?;
            let mut cursor = ValueCursor::new(bytes);
            while !cursor.is_empty() {
                output.push(read_bytea_byte(&mut cursor)?);
            }
        }
        Ok(output)
    }
}

fn read_bytea_byte(cursor: &mut ValueCursor<'_>) -> Result<u8, CodecError> {
    let byte = cursor.byte()?;
    if byte != b'\\' {
        return Ok(byte);
    }
    let first = cursor.byte()?;
    if first == b'\\' {
        return Ok(b'\\');
    }
    let second = cursor.byte()?;
    let third = cursor.byte()?;
    if !(b'0'..=b'3').contains(&first)
        || !(b'0'..=b'7').contains(&second)
        || !(b'0'..=b'7').contains(&third)
    {
        return Err(CodecError::Invalid("invalid bytea escape"));
    }
    Ok((first - b'0') * 64 + (second - b'0') * 8 + (third - b'0'))
}

fn hex_digit(byte: u8) -> Result<u8, CodecError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(CodecError::Invalid("invalid hexadecimal digit")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uuid(pub [u8; 16]);

#[cfg(feature = "uuid")]
impl From<uuid::Uuid> for Parameter<'_> {
    fn from(value: uuid::Uuid) -> Self {
        Self::uuid(Uuid(value.into_bytes()))
    }
}

#[cfg(feature = "uuid")]
impl<'a> Decode<'a> for uuid::Uuid {
    fn accepts(oid: Oid, format: Format) -> bool {
        Uuid::accepts(oid, format)
    }

    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        Uuid::decode(value).map(|uuid| Self::from_bytes(uuid.0))
    }
}

impl<'a> Decode<'a> for Uuid {
    fn accepts(oid: Oid, _format: Format) -> bool {
        oid == Oid::UUID
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let bytes = value.non_null(&[Oid::UUID], false)?;
        if value.format == Format::Binary {
            return fixed_binary(bytes).map(Self);
        }
        if bytes.len() != 36 {
            return Err(CodecError::Invalid(
                "UUID text must use the canonical 36-byte form",
            ));
        }
        let mut output = [0; 16];
        let mut position = 0;
        let mut high = None;
        for (index, byte) in bytes.iter().copied().enumerate() {
            if [8, 13, 18, 23].contains(&index) {
                if byte != b'-' {
                    return Err(CodecError::Invalid("invalid UUID separator"));
                }
            } else {
                let digit = hex_digit(byte)?;
                if let Some(first) = high.take() {
                    *output
                        .get_mut(position)
                        .ok_or(CodecError::Invalid("invalid UUID length"))? = first * 16 + digit;
                    position += 1;
                } else {
                    high = Some(digit);
                }
            }
        }
        Ok(Self(output))
    }
}

/// 相对 2000-01-01 的天数，保留 PostgreSQL 的正负无穷值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgDate {
    NegativeInfinity,
    Finite(i32),
    PositiveInfinity,
}

impl PgDate {
    fn from_wire(value: i32) -> Result<Self, CodecError> {
        match value {
            i32::MIN => Ok(Self::NegativeInfinity),
            i32::MAX => Ok(Self::PositiveInfinity),
            -2_451_545..2_145_031_949 => Ok(Self::Finite(value)),
            _ => Err(CodecError::Invalid(
                "date is outside PostgreSQL's finite range",
            )),
        }
    }
    fn wire(self) -> Result<i32, CodecError> {
        match self {
            Self::NegativeInfinity => Ok(i32::MIN),
            Self::PositiveInfinity => Ok(i32::MAX),
            Self::Finite(value) => match Self::from_wire(value)? {
                Self::Finite(_) => Ok(value),
                _ => Err(CodecError::Invalid("finite date uses an infinity sentinel")),
            },
        }
    }
}

impl<'a> Decode<'a> for PgDate {
    fn accepts(oid: Oid, format: Format) -> bool {
        oid == Oid::DATE && format == Format::Binary
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let bytes = fixed_binary(value.non_null(&[Oid::DATE], true)?)?;
        Self::from_wire(i32::from_be_bytes(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgTime(pub i64);

fn check_time(value: i64) -> Result<(), CodecError> {
    if !(0..=86_400_000_000).contains(&value) {
        return Err(CodecError::Invalid("time is outside 00:00:00..=24:00:00"));
    }
    Ok(())
}

impl<'a> Decode<'a> for PgTime {
    fn accepts(oid: Oid, format: Format) -> bool {
        oid == Oid::TIME && format == Format::Binary
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let bytes = fixed_binary(value.non_null(&[Oid::TIME], true)?)?;
        let value = i64::from_be_bytes(bytes);
        check_time(value)?;
        Ok(Self(value))
    }
}

/// 相对 2000-01-01 的微秒数。日历和时区换算由应用显式处理。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgTimestamp {
    NegativeInfinity,
    Finite(i64),
    PositiveInfinity,
}

impl PgTimestamp {
    fn from_wire(value: i64) -> Result<Self, CodecError> {
        match value {
            i64::MIN => Ok(Self::NegativeInfinity),
            i64::MAX => Ok(Self::PositiveInfinity),
            -211_813_488_000_000_000..9_223_371_331_200_000_000 => Ok(Self::Finite(value)),
            _ => Err(CodecError::Invalid(
                "timestamp is outside PostgreSQL's finite range",
            )),
        }
    }
    fn wire(self) -> Result<i64, CodecError> {
        match self {
            Self::NegativeInfinity => Ok(i64::MIN),
            Self::PositiveInfinity => Ok(i64::MAX),
            Self::Finite(value) => match Self::from_wire(value)? {
                Self::Finite(_) => Ok(value),
                _ => Err(CodecError::Invalid(
                    "finite timestamp uses an infinity sentinel",
                )),
            },
        }
    }
}

impl<'a> Decode<'a> for PgTimestamp {
    fn accepts(oid: Oid, format: Format) -> bool {
        oid == Oid::TIMESTAMP && format == Format::Binary
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let bytes = fixed_binary(value.non_null(&[Oid::TIMESTAMP], true)?)?;
        Self::from_wire(i64::from_be_bytes(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgTimestampTz(pub PgTimestamp);

impl<'a> Decode<'a> for PgTimestampTz {
    fn accepts(oid: Oid, format: Format) -> bool {
        oid == Oid::TIMESTAMPTZ && format == Format::Binary
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let bytes = fixed_binary(value.non_null(&[Oid::TIMESTAMPTZ], true)?)?;
        PgTimestamp::from_wire(i64::from_be_bytes(bytes)).map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgTimeTz {
    pub microseconds: i64,
    pub seconds_west_of_utc: i32,
}

impl PgTimeTz {
    fn validate(self) -> Result<(), CodecError> {
        check_time(self.microseconds)?;
        if !(-57_599..=57_599).contains(&self.seconds_west_of_utc) {
            return Err(CodecError::Invalid(
                "time zone displacement is outside PostgreSQL's range",
            ));
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for PgTimeTz {
    fn accepts(oid: Oid, format: Format) -> bool {
        oid == Oid::TIMETZ && format == Format::Binary
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let mut cursor = ValueCursor::new(value.non_null(&[Oid::TIMETZ], true)?);
        let result = Self {
            microseconds: cursor.i64()?,
            seconds_west_of_utc: cursor.i32()?,
        };
        cursor.finish()?;
        result.validate()?;
        Ok(result)
    }
}

/// interval 的独立协议分量。三个分量同时为各自最小值或最大值时保留 PostgreSQL 正负无穷的表示。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgInterval {
    pub microseconds: i64,
    pub days: i32,
    pub months: i32,
}

impl<'a> Decode<'a> for PgInterval {
    fn accepts(oid: Oid, format: Format) -> bool {
        oid == Oid::INTERVAL && format == Format::Binary
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let mut cursor = ValueCursor::new(value.non_null(&[Oid::INTERVAL], true)?);
        let value = Self {
            microseconds: cursor.i64()?,
            days: cursor.i32()?,
            months: cursor.i32()?,
        };
        cursor.finish()?;
        Ok(value)
    }
}

const PG_IPV4_FAMILY: u8 = 2;
const PG_IPV6_FAMILY: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    pub address: IpAddr,
    pub prefix_len: u8,
    pub is_cidr: bool,
}

impl Network {
    fn validate(self) -> Result<(), CodecError> {
        let max_prefix = if self.address.is_ipv4() { 32 } else { 128 };
        if self.prefix_len > max_prefix {
            let error = if self.address.is_ipv4() {
                "invalid IPv4 netmask"
            } else {
                "invalid IPv6 netmask"
            };
            return Err(CodecError::Invalid(error));
        }

        if self.is_cidr {
            let host_bits_zero = match self.address {
                IpAddr::V4(address) => {
                    let bits = u32::from(address);
                    self.prefix_len == 32 || (bits & (u32::MAX >> u32::from(self.prefix_len))) == 0
                }
                IpAddr::V6(address) => {
                    let bits = u128::from(address);
                    self.prefix_len == 128
                        || (bits & (u128::MAX >> u32::from(self.prefix_len))) == 0
                }
            };
            if !host_bits_zero {
                return Err(CodecError::Invalid("CIDR address has nonzero host bits"));
            }
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for Network {
    fn accepts(oid: Oid, format: Format) -> bool {
        [Oid::INET, Oid::CIDR].contains(&oid) && format == Format::Binary
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let bytes = value.non_null(&[Oid::INET, Oid::CIDR], true)?;
        let (&[family, prefix_len, tag, size], payload) = bytes
            .split_first_chunk::<4>()
            .ok_or(CodecError::Invalid("truncated network header"))?;
        let is_cidr = value.oid == Oid::CIDR;
        if tag != u8::from(is_cidr) {
            return Err(CodecError::Invalid(
                "network type flag does not match its OID",
            ));
        }
        let address = match (family, size) {
            (PG_IPV4_FAMILY, 4) => IpAddr::from(fixed_binary::<4>(payload)?),
            (PG_IPV6_FAMILY, 16) => IpAddr::from(fixed_binary::<16>(payload)?),
            _ => return Err(CodecError::Invalid("invalid network family or length")),
        };
        let result = Self {
            address,
            prefix_len,
            is_cidr,
        };
        result.validate()?;
        Ok(result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl<'a> Decode<'a> for MacAddress {
    fn accepts(oid: Oid, format: Format) -> bool {
        oid == Oid::MACADDR && format == Format::Binary
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        fixed_binary(value.non_null(&[Oid::MACADDR], true)?).map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress8(pub [u8; 8]);

impl<'a> Decode<'a> for MacAddress8 {
    fn accepts(oid: Oid, format: Format) -> bool {
        oid == Oid::MACADDR8 && format == Format::Binary
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        fixed_binary(value.non_null(&[Oid::MACADDR8], true)?).map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgLsn(pub u64);

impl<'a> Decode<'a> for PgLsn {
    fn accepts(oid: Oid, _format: Format) -> bool {
        oid == Oid::PG_LSN
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let bytes = value.non_null(&[Oid::PG_LSN], false)?;
        if value.format == Format::Binary {
            return fixed_binary(bytes).map(|bytes| Self(u64::from_be_bytes(bytes)));
        }
        let text = utf8(bytes)?;
        let (high, low) = text
            .split_once('/')
            .ok_or(CodecError::Invalid("invalid pg_lsn text"))?;
        let high = u32::from_str_radix(high, 16)
            .map_err(|error| CodecError::Conversion(Box::new(error)))?;
        let low = u32::from_str_radix(low, 16)
            .map_err(|error| CodecError::Conversion(Box::new(error)))?;
        Ok(Self((u64::from(high) << 32) | u64::from(low)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitString<'a> {
    pub bit_len: usize,
    pub bytes: &'a [u8],
}

impl BitString<'_> {
    fn check_padding(self) -> Result<(), CodecError> {
        let tail = self.bit_len % 8;
        if tail != 0 {
            let last = self
                .bytes
                .last()
                .ok_or(CodecError::Invalid("missing bit string payload"))?;
            let unused = 8 - tail;
            if *last & ((1_u8 << unused) - 1) != 0 {
                return Err(CodecError::Invalid("nonzero unused bit string bits"));
            }
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for BitString<'a> {
    fn accepts(oid: Oid, format: Format) -> bool {
        [Oid::BIT, Oid::VARBIT].contains(&oid) && format == Format::Binary
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let (length, bytes) = value
            .non_null(&[Oid::BIT, Oid::VARBIT], true)?
            .split_first_chunk::<4>()
            .ok_or(CodecError::Invalid("missing bit string length"))?;
        let bit_len = usize::try_from(i32::from_be_bytes(*length))
            .map_err(|_| CodecError::Invalid("negative bit string length"))?;
        if bytes.len() != bit_len.div_ceil(8) {
            return Err(CodecError::Invalid("bit length and bytes differ"));
        }
        let bits = Self { bit_len, bytes };
        bits.check_padding()?;
        Ok(bits)
    }
}

/// UTF-8 JSON 文本视图。二进制 JSONB 会检查版本字节；完整 JSON 校验和对象构建由应用负责。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonText<'a>(pub &'a str);

impl<'a> Decode<'a> for JsonText<'a> {
    fn accepts(oid: Oid, _format: Format) -> bool {
        [Oid::JSON, Oid::JSONB].contains(&oid)
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        utf8(json_payload(value)?).map(Self)
    }
}

fn json_payload(value: RawValue<'_>) -> Result<&[u8], CodecError> {
    let bytes = value.non_null(&[Oid::JSON, Oid::JSONB], false)?;
    if value.oid == Oid::JSONB && value.format == Format::Binary {
        version_one_payload(bytes, "unsupported or missing JSONB wire version")
    } else {
        Ok(bytes)
    }
}

fn version_one_payload<'a>(bytes: &'a [u8], error: &'static str) -> Result<&'a [u8], CodecError> {
    bytes.strip_prefix(&[1]).ok_or(CodecError::Invalid(error))
}

/// PostgreSQL JSONPath 表达式的借用文本。服务端负责解析表达式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonPath<'a>(pub &'a str);

impl JsonPath<'_> {
    /// 按二进制格式编码，可用作数组元素或二进制绑定参数。
    /// 使用 `Parameter::from` 可直接借用文本作为绑定参数。
    pub fn encode_binary(self, max_bytes: usize) -> Result<EncodedValue, CodecError> {
        let mut bytes = value_storage(add_length(1, self.0.len())?, max_bytes)?;
        bytes.push(1);
        bytes.extend_from_slice(self.0.as_bytes());
        EncodedValue::from_raw(Oid::JSONPATH, Format::Binary, Some(bytes), max_bytes)
    }
}

impl<'a> From<JsonPath<'a>> for Parameter<'a> {
    fn from(value: JsonPath<'a>) -> Self {
        Self::text(Oid::JSONPATH, value.0)
    }
}

impl<'a> Decode<'a> for JsonPath<'a> {
    fn accepts(oid: Oid, _format: Format) -> bool {
        oid == Oid::JSONPATH
    }

    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let bytes = value.non_null(&[Oid::JSONPATH], false)?;
        let payload = match value.format {
            Format::Text => bytes,
            Format::Binary => {
                version_one_payload(bytes, "unsupported or missing JSONPath wire version")?
            }
        };
        utf8(payload).map(Self)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ValueCursor<'a> {
    bytes: &'a [u8],
}

impl<'a> ValueCursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
    pub(crate) fn remaining(self) -> &'a [u8] {
        self.bytes
    }
    pub(crate) fn is_empty(self) -> bool {
        self.bytes.is_empty()
    }
    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let (head, tail) = self
            .bytes
            .split_at_checked(length)
            .ok_or(CodecError::Invalid("truncated PostgreSQL value"))?;
        self.bytes = tail;
        Ok(head)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let (value, rest) = self
            .bytes
            .split_first_chunk::<N>()
            .ok_or(CodecError::Invalid("truncated PostgreSQL value"))?;
        self.bytes = rest;
        Ok(*value)
    }
    fn byte(&mut self) -> Result<u8, CodecError> {
        let [byte] = self.array()?;
        Ok(byte)
    }
    pub(crate) fn u16(&mut self) -> Result<u16, CodecError> {
        self.array().map(u16::from_be_bytes)
    }
    pub(crate) fn i32(&mut self) -> Result<i32, CodecError> {
        self.array().map(i32::from_be_bytes)
    }
    pub(crate) fn u32(&mut self) -> Result<u32, CodecError> {
        self.array().map(u32::from_be_bytes)
    }
    fn i64(&mut self) -> Result<i64, CodecError> {
        self.array().map(i64::from_be_bytes)
    }
    pub(crate) fn nullable(&mut self) -> Result<Option<&'a [u8]>, CodecError> {
        let length = self.i32()?;
        if length == -1 {
            return Ok(None);
        }
        let length = usize::try_from(length)
            .map_err(|_| CodecError::Invalid("negative value length other than NULL"))?;
        self.take(length).map(Some)
    }
    pub(crate) fn finish(self) -> Result<(), CodecError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(CodecError::Invalid("trailing PostgreSQL value bytes"))
        }
    }
}

/// 一个自有的编码值，实际保留容量受限。绑定参数可借用它的存储；请求编码器会按需要将内容复制到连续的 Bind 消息中。
pub struct EncodedValue {
    oid: Oid,
    format: Format,
    bytes: Option<Vec<u8>>,
}

impl fmt::Debug for EncodedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncodedValue")
            .field("oid", &self.oid)
            .field("format", &self.format)
            .field("length", &self.bytes.as_ref().map(Vec::len))
            .finish()
    }
}

impl EncodedValue {
    pub fn from_raw(
        oid: Oid,
        format: Format,
        bytes: Option<Vec<u8>>,
        max_bytes: usize,
    ) -> Result<Self, CodecError> {
        if let Some(bytes) = &bytes {
            i32::try_from(bytes.len())
                .map_err(|_| CodecError::Limit("value exceeds the signed wire length"))?;
            if bytes.capacity() > max_bytes {
                return Err(CodecError::Limit(
                    "encoded value exceeds its retained storage limit",
                ));
            }
        }
        Ok(Self { oid, format, bytes })
    }
    pub fn parameter(&self) -> Parameter<'_> {
        Parameter::raw(self.oid, self.format, self.bytes.as_deref())
    }
    pub fn raw_value(&self) -> RawValue<'_> {
        RawValue {
            oid: self.oid,
            format: self.format,
            bytes: self.bytes.as_deref(),
        }
    }
    pub fn retained_bytes(&self) -> usize {
        self.bytes.as_ref().map_or(0, Vec::capacity)
    }
    pub fn into_bytes(self) -> Option<Vec<u8>> {
        self.bytes
    }
}

fn check_storage_length(length: usize, max_bytes: usize) -> Result<(), CodecError> {
    i32::try_from(length).map_err(|_| CodecError::Limit("value exceeds the signed wire length"))?;
    if length > max_bytes {
        return Err(CodecError::Limit("encoded value exceeds its storage limit"));
    }
    Ok(())
}

fn value_storage(length: usize, max_bytes: usize) -> Result<Vec<u8>, CodecError> {
    validated_storage(length, max_bytes, || Ok(()))
}

fn validated_storage(
    length: usize,
    max_bytes: usize,
    validate: impl FnOnce() -> Result<(), CodecError>,
) -> Result<Vec<u8>, CodecError> {
    check_storage_length(length, max_bytes)?;
    validate()?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| CodecError::Allocation)?;
    if bytes.capacity() > max_bytes {
        return Err(CodecError::Limit(
            "actual encoded capacity exceeds its limit",
        ));
    }
    Ok(bytes)
}

fn add_length(total: usize, extra: usize) -> Result<usize, CodecError> {
    total
        .checked_add(extra)
        .ok_or(CodecError::Limit("encoded value length overflow"))
}

// 编码器先检查总长度能否写入 i32，因此每个成员的长度也可直接转换。
#[inline]
fn append_payload(output: &mut Vec<u8>, bytes: &[u8]) {
    let [.., a, b, c, d] = bytes.len().to_be_bytes();
    output.extend_from_slice(&[a, b, c, d]);
    output.extend_from_slice(bytes);
}

pub fn encode_bits(
    oid: Oid,
    bits: BitString<'_>,
    max_bytes: usize,
) -> Result<EncodedValue, CodecError> {
    if ![Oid::BIT, Oid::VARBIT].contains(&oid) {
        return Err(CodecError::WrongType {
            oid,
            format: Format::Binary,
        });
    }
    let count = i32::try_from(bits.bit_len)
        .map_err(|_| CodecError::Limit("bit length exceeds its wire range"))?;
    if bits.bytes.len() != bits.bit_len.div_ceil(8) {
        return Err(CodecError::Invalid("bit length and bytes differ"));
    }
    let length = add_length(4, bits.bytes.len())?;
    let mut output = validated_storage(length, max_bytes, || bits.check_padding())?;
    output.extend_from_slice(&count.to_be_bytes());
    output.extend_from_slice(bits.bytes);
    EncodedValue::from_raw(oid, Format::Binary, Some(output), max_bytes)
}

/// 与 postgres-types 互操作。调用方传入已解析的 Type，转换时不访问数据库目录。
#[cfg(feature = "postgres-types")]
pub fn decode_postgres<'a, T: postgres_types::FromSql<'a>>(
    value: RawValue<'a>,
    ty: &postgres_types::Type,
) -> Result<T, CodecError> {
    if value.oid.0 != ty.oid() || value.format != Format::Binary || !T::accepts(ty) {
        return Err(CodecError::WrongType {
            oid: value.oid,
            format: value.format,
        });
    }
    T::from_sql_nullable(ty, value.bytes).map_err(CodecError::Conversion)
}

/// 在请求接纳前编码。`max_bytes` 约束返回缓冲区的实际保留容量。自定义编解码器可临时分配；
/// 适配器复用合规存储，必要时复制以缩小容量。
#[cfg(feature = "postgres-types")]
pub fn encode_postgres<T: postgres_types::ToSql>(
    value: &T,
    ty: &postgres_types::Type,
    max_bytes: usize,
) -> Result<EncodedValue, CodecError> {
    if !T::accepts(ty) {
        return Err(CodecError::WrongType {
            oid: Oid(ty.oid()),
            format: Format::Binary,
        });
    }
    let format = match value.encode_format(ty) {
        postgres_types::Format::Text => Format::Text,
        postgres_types::Format::Binary => Format::Binary,
    };
    let mut buffer = bytes::BytesMut::new();
    // 上方已检查 ToSql::accepts，可直接调用已知适用类型的编解码入口。
    let null = value
        .to_sql(ty, &mut buffer)
        .map_err(CodecError::Conversion)?;
    match null {
        postgres_types::IsNull::Yes => {
            if !buffer.is_empty() {
                return Err(CodecError::Invalid("NULL codec wrote a value body"));
            }
            EncodedValue::from_raw(Oid(ty.oid()), format, None, max_bytes)
        }
        postgres_types::IsNull::No => {
            check_storage_length(buffer.len(), max_bytes)?;
            let compact = |bytes: &[u8]| {
                let mut output = value_storage(bytes.len(), max_bytes)?;
                output.extend_from_slice(bytes);
                Ok::<_, CodecError>(output)
            };
            let output = if buffer.capacity() <= max_bytes {
                let bytes = Vec::from(buffer);
                // 编解码器若切分或推进了 BytesMut，转换得到的 Vec 容量可能大于原视图显示的容量。
                if bytes.capacity() <= max_bytes {
                    bytes
                } else {
                    compact(&bytes)?
                }
            } else {
                compact(&buffer)?
            };
            EncodedValue::from_raw(Oid(ty.oid()), format, Some(output), max_bytes)
        }
    }
}

#[cfg(feature = "postgres-types")]
macro_rules! postgres_oid_codec {
    ($rust:ty, $oid:expr) => {
        impl<'a> postgres_types::FromSql<'a> for $rust {
            fn from_sql(
                ty: &postgres_types::Type,
                raw: &'a [u8],
            ) -> Result<Self, Box<dyn StdError + Send + Sync>> {
                <Self as Decode>::decode(RawValue {
                    oid: Oid(ty.oid()),
                    format: Format::Binary,
                    bytes: Some(raw),
                })
                .map_err(|error| -> Box<dyn StdError + Send + Sync> { Box::new(error) })
            }
            fn accepts(ty: &postgres_types::Type) -> bool {
                ty.oid() == ($oid).0
            }
        }

        impl postgres_types::ToSql for $rust {
            fn to_sql(
                &self,
                ty: &postgres_types::Type,
                output: &mut bytes::BytesMut,
            ) -> Result<postgres_types::IsNull, Box<dyn StdError + Send + Sync>> {
                if ty.oid() != ($oid).0 {
                    return Err(Box::new(CodecError::WrongType {
                        oid: Oid(ty.oid()),
                        format: Format::Binary,
                    }));
                }
                output.extend_from_slice(&self.0.to_be_bytes());
                Ok(postgres_types::IsNull::No)
            }
            fn accepts(ty: &postgres_types::Type) -> bool {
                ty.oid() == ($oid).0
            }
            postgres_types::to_sql_checked!();
        }
    };
}

#[cfg(feature = "postgres-types")]
postgres_oid_codec!(Oid8, Oid::OID8);
#[cfg(feature = "postgres-types")]
postgres_oid_codec!(RegDatabase, Oid::REGDATABASE);

#[cfg(test)]
mod tests;
