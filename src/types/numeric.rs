//! PostgreSQL NUMERIC 的借用数位与定点整数编码。

use std::fmt;

use super::{
    CodecError, Decode, EncodedValue, Format, Oid, Parameter, RawValue, add_length,
    check_storage_length, value_storage,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericSign {
    Positive,
    Negative,
    NaN,
    PositiveInfinity,
    NegativeInfinity,
}

#[derive(Debug, Clone, Copy)]
pub struct NumericView<'a> {
    pub sign: NumericSign,
    pub weight: i16,
    pub scale: u16,
    digits: &'a [u8],
}

impl NumericView<'_> {
    pub fn digits(&self) -> impl ExactSizeIterator<Item = u16> + DoubleEndedIterator + '_ {
        self.digits
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
    }

    /// 返回乘以 `10^scale` 后的精确整数。溢出、非有限值或舍入需求均返回错误。
    pub fn to_scaled_i128(&self, scale: u16) -> Result<i128, CodecError> {
        const OVERFLOW: CodecError =
            CodecError::Limit("numeric coefficient exceeds the i128 range");
        const ROUNDING: CodecError =
            CodecError::Invalid("numeric requires rounding at the requested scale");
        let sign = match self.sign {
            NumericSign::Positive => 1_i32,
            NumericSign::Negative => -1_i32,
            _ => {
                return Err(CodecError::Invalid(
                    "nonfinite numeric has no integer coefficient",
                ));
            }
        };
        let mut digits = self.digits();
        let mut coefficient = 0_i128;
        let mut exponent = i32::from(self.weight) * 4 + i32::from(scale);
        // 先合并全部整数位，每组用同一个基数。小数点最多切过一组。
        while exponent >= 0 {
            let Some(digit) = digits.next() else { break };
            coefficient = coefficient
                .checked_mul(10_000)
                .and_then(|value| value.checked_add(i128::from(sign * i32::from(digit))))
                .ok_or(OVERFLOW)?;
            exponent -= 4;
        }
        if coefficient != 0 && exponent != -4 {
            let last_exponent = exponent + 4;
            if last_exponent > 38 {
                return Err(OVERFLOW);
            }
            coefficient = coefficient
                .checked_mul(10_i128.pow(last_exponent.unsigned_abs()))
                .ok_or(OVERFLOW)?;
        }
        if let Some(digit) = digits.next()
            && digit != 0
        {
            let divisor = match exponent {
                -1 => 10,
                -2 => 100,
                -3 => 1000,
                _ => return Err(ROUNDING),
            };
            if !digit.is_multiple_of(divisor) {
                return Err(ROUNDING);
            }
            coefficient = coefficient
                .checked_add(i128::from(sign * i32::from(digit / divisor)))
                .ok_or(OVERFLOW)?;
        }
        if digits.any(|digit| digit != 0) {
            return Err(ROUNDING);
        }
        Ok(coefficient)
    }
}

impl<'a> Decode<'a> for NumericView<'a> {
    fn accepts(oid: Oid, format: Format) -> bool {
        oid == Oid::NUMERIC && format == Format::Binary
    }
    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let bytes = value.non_null(&[Oid::NUMERIC], true)?;
        let (&[a, b, c, d, e, f, g, h], digits) = bytes
            .split_first_chunk::<NUMERIC_HEADER_BYTES>()
            .ok_or(CodecError::Invalid("truncated numeric header"))?;
        let count = usize::from(u16::from_be_bytes([a, b]));
        let weight = i16::from_be_bytes([c, d]);
        let sign = match u16::from_be_bytes([e, f]) {
            0x0000 => NumericSign::Positive,
            0x4000 => NumericSign::Negative,
            0xc000 => NumericSign::NaN,
            0xd000 => NumericSign::PositiveInfinity,
            0xf000 => NumericSign::NegativeInfinity,
            _ => return Err(CodecError::Invalid("invalid numeric sign")),
        };
        let scale = u16::from_be_bytes([g, h]);
        if scale > 0x3fff {
            return Err(CodecError::Invalid("invalid numeric scale"));
        }
        if digits.len() != count * 2 {
            return Err(CodecError::Invalid(
                "numeric digit count differs from its payload",
            ));
        }
        if !matches!(sign, NumericSign::Positive | NumericSign::Negative) && count != 0 {
            return Err(CodecError::Invalid(
                "special numeric value has ordinary digits",
            ));
        }
        let result = Self {
            sign,
            weight,
            scale,
            digits,
        };
        validate_numeric_digits(weight, scale, result.digits())?;
        Ok(result)
    }
}

/// 编码一个 NUMERIC 值。首个基数为 10000 的数位对应 `10000^weight`，
/// `scale` 指定十进制小数位数。超出小数位数的非零数位会返回错误。
pub fn encode_numeric(
    sign: NumericSign,
    weight: i16,
    scale: u16,
    digits: &[u16],
    max_bytes: usize,
) -> Result<EncodedValue, CodecError> {
    let count = u16::try_from(digits.len())
        .map_err(|_| CodecError::Limit("numeric digit count exceeds its wire range"))?;
    if scale > 0x3fff {
        return Err(CodecError::Invalid("invalid numeric scale"));
    }
    if !matches!(sign, NumericSign::Positive | NumericSign::Negative) && !digits.is_empty() {
        return Err(CodecError::Invalid(
            "special numeric value has ordinary digits",
        ));
    }
    validate_numeric_digits(weight, scale, digits.iter().copied())?;
    let mut output = value_storage(
        add_length(
            NUMERIC_HEADER_BYTES,
            digits
                .len()
                .checked_mul(2)
                .ok_or(CodecError::Limit("numeric length overflow"))?,
        )?,
        max_bytes,
    )?;
    output.extend_from_slice(&numeric_header(count, weight, sign, scale));
    for digit in digits {
        output.extend_from_slice(&digit.to_be_bytes());
    }
    EncodedValue::from_raw(Oid::NUMERIC, Format::Binary, Some(output), max_bytes)
}

const NUMERIC_HEADER_BYTES: usize = 8;
const MAX_SCALED_NUMERIC_BYTES: usize = NUMERIC_HEADER_BYTES + 11 * 2;

fn numeric_header(
    count: u16,
    weight: i16,
    sign: NumericSign,
    scale: u16,
) -> [u8; NUMERIC_HEADER_BYTES] {
    let sign: u16 = match sign {
        NumericSign::Positive => 0x0000,
        NumericSign::Negative => 0x4000,
        NumericSign::NaN => 0xc000,
        NumericSign::PositiveInfinity => 0xd000,
        NumericSign::NegativeInfinity => 0xf000,
    };
    let [a, b] = count.to_be_bytes();
    let [c, d] = weight.to_be_bytes();
    let [e, f] = sign.to_be_bytes();
    let [g, h] = scale.to_be_bytes();
    [a, b, c, d, e, f, g, h]
}

/// 固定小数位数的二进制 NUMERIC。编码和保存均无需堆分配。
#[derive(Clone, Copy)]
pub struct ScaledNumeric {
    bytes: [u8; MAX_SCALED_NUMERIC_BYTES],
    start: u8,
    end: u8,
}

impl fmt::Debug for ScaledNumeric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.raw_value().fmt(f)
    }
}

impl ScaledNumeric {
    #[expect(
        clippy::indexing_slicing,
        reason = "编码器用定长数组中实际写入的组数计算并核对两个偏移"
    )]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[usize::from(self.start)..usize::from(self.end)]
    }

    pub fn parameter(&self) -> Parameter<'_> {
        Parameter::binary(Oid::NUMERIC, self.as_bytes())
    }

    pub fn raw_value(&self) -> RawValue<'_> {
        RawValue {
            oid: Oid::NUMERIC,
            format: Format::Binary,
            bytes: Some(self.as_bytes()),
        }
    }
}

/// 把 `coefficient × 10^-scale` 精确编码为保留小数位数的 NUMERIC。
/// `max_bytes` 限制实际线上值的字节数。
pub fn encode_scaled_numeric(
    coefficient: i128,
    scale: u16,
    max_bytes: usize,
) -> Result<ScaledNumeric, CodecError> {
    if scale > 0x3fff {
        return Err(CodecError::Invalid("invalid numeric scale"));
    }
    let sign = if coefficient < 0 {
        NumericSign::Negative
    } else {
        NumericSign::Positive
    };
    let mut magnitude = coefficient.unsigned_abs();
    // i128 最多 39 个十进制数位，右移小数点到下一个基数边界最多补三个零。
    let padding = 10_u32.pow(u32::from((4 - scale % 4) % 4));
    let mut bytes = [0; MAX_SCALED_NUMERIC_BYTES];
    let mut groups = 0;
    let mut trailing_zero_groups = 0;
    let mut carry = 0;
    let (pairs, _) = bytes[NUMERIC_HEADER_BYTES..].as_chunks_mut::<2>();
    for pair in pairs.iter_mut().rev() {
        if magnitude == 0 && carry == 0 {
            break;
        }
        // 两个余数均小于基数 10000，可直接写入协议数位。
        let group = (magnitude % 10_000) as u32 * padding + carry;
        let digit = (group % 10_000) as u16;
        if digit == 0 && trailing_zero_groups == groups {
            trailing_zero_groups += 1;
        }
        *pair = digit.to_be_bytes();
        carry = group / 10_000;
        magnitude /= 10_000;
        groups += 1;
    }
    // 先从末尾写入数位，再在首个数位前写入头部。末尾的零只调整边界。
    let start = MAX_SCALED_NUMERIC_BYTES - groups * 2 - NUMERIC_HEADER_BYTES;
    let end = MAX_SCALED_NUMERIC_BYTES - trailing_zero_groups * 2;
    check_storage_length(end - start, max_bytes)?;
    // 有效数位最多占 11 组，小数部分最多占 4096 组。
    let weight = if groups == 0 {
        0
    } else {
        groups as i16 - 1 - scale.div_ceil(4) as i16
    };
    let count = (groups - trailing_zero_groups) as u16;
    bytes
        .get_mut(start..start + NUMERIC_HEADER_BYTES)
        .ok_or(CodecError::Invalid("missing numeric header"))?
        .copy_from_slice(&numeric_header(count, weight, sign, scale));
    Ok(ScaledNumeric {
        bytes,
        start: start as u8,
        end: end as u8,
    })
}

fn validate_numeric_digits(
    weight: i16,
    scale: u16,
    mut digits: impl Iterator<Item = u16>,
) -> Result<(), CodecError> {
    // 每个基数为 10000 的数位对应四个十进制数位。第一个受约束的位置可以在输入起点以前。
    let full_digits = i32::from(weight) + i32::from(scale / 4) + 1;
    let unconstrained = usize::try_from(full_digits).unwrap_or_default();
    if digits
        .by_ref()
        .take(unconstrained)
        .any(|digit| digit >= 10_000)
    {
        return Err(CodecError::Invalid("numeric digit exceeds base 10000"));
    }
    let Some(digit) = digits.next() else {
        return Ok(());
    };
    if digit >= 10_000 {
        return Err(CodecError::Invalid("numeric digit exceeds base 10000"));
    }
    let partial_width = scale % 4;
    if digit != 0
        && (full_digits < 0
            || partial_width == 0
            || !digit.is_multiple_of(10_u16.pow(u32::from(4 - partial_width))))
        || digits.any(|digit| digit != 0)
    {
        return Err(CodecError::Invalid(
            "numeric digits exceed the declared scale",
        ));
    }
    Ok(())
}
