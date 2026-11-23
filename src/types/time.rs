//! time 的日历类型与 PostgreSQL 二进制日期时间之间的无分配转换。

use ::time::{Date, OffsetDateTime, PlainDateTime, SignedDuration, Time};

use super::{
    CodecError, Decode, Format, Oid, Parameter, PgDate, PgTime, PgTimestamp, PgTimestampTz,
    RawValue,
};

const PG_EPOCH_JULIAN_DAY: i32 = 2_451_545;
const PG_EPOCH_UNIX_SECONDS: i64 = 946_684_800;
const PG_EPOCH_UNIX_NANOS: i128 = PG_EPOCH_UNIX_SECONDS as i128 * 1_000_000_000;
const MICROS_PER_SECOND: i64 = 1_000_000;

impl TryFrom<Date> for Parameter<'_> {
    type Error = CodecError;

    fn try_from(value: Date) -> Result<Self, Self::Error> {
        Self::date(PgDate::Finite(value.to_julian_day() - PG_EPOCH_JULIAN_DAY))
    }
}

impl<'a> Decode<'a> for Date {
    fn accepts(oid: Oid, format: Format) -> bool {
        PgDate::accepts(oid, format)
    }

    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let PgDate::Finite(days) = PgDate::decode(value)? else {
            return Err(CodecError::Invalid("time::Date cannot represent infinity"));
        };
        Self::from_julian_day(days + PG_EPOCH_JULIAN_DAY)
            .map_err(|error| CodecError::Conversion(Box::new(error)))
    }
}

fn microsecond_fraction(nanos: u32) -> Result<i64, CodecError> {
    if !nanos.is_multiple_of(1_000) {
        return Err(CodecError::Invalid(
            "PostgreSQL requires microsecond precision",
        ));
    }
    Ok(i64::from(nanos / 1_000))
}

impl TryFrom<Time> for Parameter<'_> {
    type Error = CodecError;

    fn try_from(value: Time) -> Result<Self, Self::Error> {
        let (hour, minute, second, nanos) = value.as_hms_nano();
        let seconds = i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);
        Self::time(PgTime(
            seconds * MICROS_PER_SECOND + microsecond_fraction(nanos)?,
        ))
    }
}

impl<'a> Decode<'a> for Time {
    fn accepts(oid: Oid, format: Format) -> bool {
        PgTime::accepts(oid, format)
    }

    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let PgTime(micros) = PgTime::decode(value)?;
        if micros == 86_400_000_000 {
            return Err(CodecError::Invalid("time::Time cannot represent 24:00:00"));
        }
        Ok(Time::MIDNIGHT + SignedDuration::microseconds(micros))
    }
}

fn encode_timestamp(value: OffsetDateTime) -> Result<PgTimestamp, CodecError> {
    let fraction = microsecond_fraction(value.nanosecond())?;
    let seconds = value.unix_timestamp() - PG_EPOCH_UNIX_SECONDS;
    seconds
        .checked_mul(MICROS_PER_SECOND)
        .and_then(|micros| micros.checked_add(fraction))
        .map(PgTimestamp::Finite)
        .ok_or(CodecError::Invalid("timestamp exceeds wire range"))
}

fn decode_timestamp(value: PgTimestamp) -> Result<OffsetDateTime, CodecError> {
    let PgTimestamp::Finite(micros) = value else {
        return Err(CodecError::Invalid(
            "time cannot represent an infinite timestamp",
        ));
    };
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1_000 + PG_EPOCH_UNIX_NANOS)
        .map_err(|error| CodecError::Conversion(Box::new(error)))
}

impl TryFrom<PlainDateTime> for Parameter<'_> {
    type Error = CodecError;

    fn try_from(value: PlainDateTime) -> Result<Self, Self::Error> {
        Self::timestamp(encode_timestamp(value.assume_utc())?)
    }
}

impl<'a> Decode<'a> for PlainDateTime {
    fn accepts(oid: Oid, format: Format) -> bool {
        PgTimestamp::accepts(oid, format)
    }

    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        let utc = decode_timestamp(PgTimestamp::decode(value)?)?;
        Ok(Self::new(utc.date(), utc.time()))
    }
}

impl TryFrom<OffsetDateTime> for Parameter<'_> {
    type Error = CodecError;

    fn try_from(value: OffsetDateTime) -> Result<Self, Self::Error> {
        Self::timestamptz(PgTimestampTz(encode_timestamp(value)?))
    }
}

impl<'a> Decode<'a> for OffsetDateTime {
    fn accepts(oid: Oid, format: Format) -> bool {
        PgTimestampTz::accepts(oid, format)
    }

    fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
        decode_timestamp(PgTimestampTz::decode(value)?.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_instants_preserve_the_epoch_and_reject_unrepresentable_values() {
        let utc = OffsetDateTime::from_unix_timestamp_nanos(PG_EPOCH_UNIX_NANOS - 1_000).unwrap();
        let local = PlainDateTime::new(utc.date(), utc.time());
        let parameter = Parameter::try_from(utc).unwrap();
        assert_eq!(
            parameter.raw_value().decode::<OffsetDateTime>().unwrap(),
            utc
        );
        assert_eq!(
            parameter.raw_value().bytes,
            Some((-1_i64).to_be_bytes().as_slice())
        );
        assert_eq!(
            Parameter::try_from(local)
                .unwrap()
                .raw_value()
                .decode::<PlainDateTime>()
                .unwrap(),
            local
        );
        assert_eq!(
            Parameter::try_from(utc.date())
                .unwrap()
                .raw_value()
                .decode::<Date>()
                .unwrap(),
            utc.date()
        );
        assert_eq!(
            Parameter::try_from(utc.time())
                .unwrap()
                .raw_value()
                .decode::<Time>()
                .unwrap(),
            utc.time()
        );
        assert!(Parameter::try_from(utc + SignedDuration::NANOSECOND).is_err());
        assert!(
            Parameter::date(PgDate::PositiveInfinity)
                .unwrap()
                .raw_value()
                .decode::<Date>()
                .is_err()
        );
        assert!(
            Parameter::time(PgTime(86_400_000_000))
                .unwrap()
                .raw_value()
                .decode::<Time>()
                .is_err()
        );
    }
}
