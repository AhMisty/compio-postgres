//! 数组、复合类型、区间及多区间的借用视图和有界编码。

use std::ops::Bound;

use super::{
    CodecError, EncodedValue, Format, Oid, Parameter, RawValue, ValueCursor, add_length,
    append_payload, value_storage,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArrayLayout {
    pub oid: Oid,
    pub element_oid: Oid,
}

impl ArrayLayout {
    /// 将已解析的数组元数据转换为二进制数组布局。
    #[cfg(feature = "postgres-types")]
    pub fn from_postgres_type(ty: &postgres_types::Type) -> Option<Self> {
        match ty.kind() {
            postgres_types::Kind::Array(element) => Some(Self {
                oid: Oid(ty.oid()),
                element_oid: Oid(element.oid()),
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArrayDimension {
    pub len: i32,
    pub lower_bound: i32,
}

#[derive(Debug, Clone, Copy)]
pub struct ArrayView<'a> {
    layout: ArrayLayout,
    raw: &'a [u8],
    dimensions: &'a [u8],
    values: &'a [u8],
    count: usize,
}

impl<'a> ArrayView<'a> {
    pub fn parse(value: RawValue<'a>, layout: ArrayLayout) -> Result<Self, CodecError> {
        Self::parse_with(value, layout, |_| Ok(()))
    }

    /// 按协议顺序一次校验并访问所有元素。回调先接收合法前缀，随后才可能发现损坏的尾部。
    pub fn visit(
        value: RawValue<'a>,
        layout: ArrayLayout,
        on_value: impl FnMut(RawValue<'a>) -> Result<(), CodecError>,
    ) -> Result<(), CodecError> {
        Self::parse_with(value, layout, on_value).map(|_| ())
    }

    fn parse_with(
        value: RawValue<'a>,
        layout: ArrayLayout,
        mut on_value: impl FnMut(RawValue<'a>) -> Result<(), CodecError>,
    ) -> Result<Self, CodecError> {
        if layout.oid.0 == 0 || layout.element_oid.0 == 0 {
            return Err(CodecError::Invalid("array layout requires resolved OIDs"));
        }
        let raw = value.non_null(&[layout.oid], true)?;
        let mut cursor = ValueCursor::new(raw);
        let dimensions_count = usize::try_from(cursor.i32()?)
            .map_err(|_| CodecError::Invalid("negative array dimension count"))?;
        // 维度上限取自 PostgreSQL 19 的 src/include/utils/array.h 中的 MAXDIM。
        if dimensions_count > 6 {
            return Err(CodecError::Invalid(
                "array exceeds PostgreSQL's six dimensions",
            ));
        }
        let has_nulls = match cursor.i32()? {
            0 => false,
            1 => true,
            _ => return Err(CodecError::Invalid("invalid array NULL flag")),
        };
        if Oid(cursor.u32()?) != layout.element_oid {
            return Err(CodecError::Invalid(
                "array element OID differs from its resolved layout",
            ));
        }
        let dimensions = cursor.take(dimensions_count * 8)?;
        let mut dimension_cursor = ValueCursor::new(dimensions);
        let mut count = usize::from(dimensions_count != 0);
        for _ in 0..dimensions_count {
            let len = dimension_cursor.i32()?;
            let lower_bound = dimension_cursor.i32()?;
            let len_usize = validate_dimension(ArrayDimension { len, lower_bound })?;
            count = count
                .checked_mul(len_usize)
                .ok_or(CodecError::Limit("array element count overflow"))?;
        }
        let values = cursor.remaining();
        if count > values.len() / 4 {
            return Err(CodecError::Invalid(
                "array count cannot fit in its value bytes",
            ));
        }
        for _ in 0..count {
            let bytes = cursor.nullable()?;
            if bytes.is_none() && !has_nulls {
                return Err(CodecError::Invalid(
                    "array NULL element contradicts its header",
                ));
            }
            on_value(RawValue {
                oid: layout.element_oid,
                format: Format::Binary,
                bytes,
            })?;
        }
        cursor.finish()?;
        Ok(Self {
            layout,
            raw,
            dimensions,
            values,
            count,
        })
    }
    pub fn layout(self) -> ArrayLayout {
        self.layout
    }
    pub fn len(self) -> usize {
        self.count
    }
    pub fn is_empty(self) -> bool {
        self.count == 0
    }
    pub fn dimensions(
        self,
    ) -> impl ExactSizeIterator<Item = ArrayDimension> + DoubleEndedIterator + 'a {
        self.dimensions
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| ArrayDimension {
                len: i32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                lower_bound: i32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
            })
    }
    pub fn values(self) -> ArrayValues<'a> {
        ArrayValues {
            cursor: ValueCursor::new(self.values),
            remaining: self.count,
            oid: self.layout.element_oid,
        }
    }
    pub fn raw_value(self) -> RawValue<'a> {
        RawValue {
            oid: self.layout.oid,
            format: Format::Binary,
            bytes: Some(self.raw),
        }
    }
}

pub struct ArrayValues<'a> {
    cursor: ValueCursor<'a>,
    remaining: usize,
    oid: Oid,
}

impl<'a> Iterator for ArrayValues<'a> {
    type Item = Result<RawValue<'a>, CodecError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let result = self.cursor.nullable().map(|bytes| RawValue {
            oid: self.oid,
            format: Format::Binary,
            bytes,
        });
        if result.is_err() {
            self.remaining = 0;
        }
        Some(result)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for ArrayValues<'_> {}

fn validate_dimension(dimension: ArrayDimension) -> Result<usize, CodecError> {
    let length = usize::try_from(dimension.len)
        .map_err(|_| CodecError::Invalid("negative array dimension length"))?;
    // PostgreSQL 的 ArrayCheckBounds 校验开区间的上界。
    if dimension.lower_bound.checked_add(dimension.len).is_none() {
        return Err(CodecError::Invalid("array subscript range overflow"));
    }
    Ok(length)
}

/// 按协议顺序保存复合类型及其字段的 OID。应用可在开发期声明字段布局，
/// 启动时验证目标数据库的目录并取得顶层 OID，然后在该数据库内复用布局。
/// 部署更改类型定义的迁移后须重新预热。
///
/// 以下示例针对迁移创建的 `app.score(label text, points int4)`。一次查询同时确认字段名、
/// 顺序和类型。类型不存在或布局不匹配时，预热返回错误，服务可以在接纳流量前发现问题。
///
/// ```no_run
/// use compio_postgres::{
///     Client, Error, OnError, ResultFormats, WireTransport,
///     types::{CompositeLayout, Format, Oid},
/// };
///
/// async fn load_score<T: WireTransport>(client: &mut Client<T>) -> Result<CompositeLayout, Error> {
///     let sql = r#"
///         SELECT t.oid
///         FROM pg_catalog.pg_type AS t
///         JOIN pg_catalog.pg_attribute AS a ON a.attrelid = t.typrelid
///         WHERE t.oid = pg_catalog.to_regtype('app.score') AND t.typtype = 'c'
///           AND a.attnum > 0 AND NOT a.attisdropped
///         GROUP BY t.oid
///         HAVING array_agg(a.attname::text ORDER BY a.attnum) = ARRAY['label', 'points']
///            AND array_agg(a.atttypid ORDER BY a.attnum)
///                = ARRAY['pg_catalog.text'::regtype::oid, 'pg_catalog.int4'::regtype::oid]
///     "#;
///     let oid = client.one_shot(sql, &[], ResultFormats::All(Format::Binary))
///         .one::<u32>(OnError::RecoverExplicitly).await?;
///     Ok(CompositeLayout { oid: Oid(oid), fields: Box::new([Oid::TEXT, Oid::INT4]) })
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeLayout {
    pub oid: Oid,
    pub fields: Box<[Oid]>,
}

impl CompositeLayout {
    /// 以已解析的复合类型元数据构造可复用的协议布局。
    #[cfg(feature = "postgres-types")]
    pub fn from_postgres_type(ty: &postgres_types::Type) -> Option<Self> {
        let postgres_types::Kind::Composite(fields) = ty.kind() else {
            return None;
        };
        Some(Self {
            oid: Oid(ty.oid()),
            fields: fields
                .iter()
                .map(|field| Oid(field.type_().oid()))
                .collect(),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CompositeView<'a, 'm> {
    layout: &'m CompositeLayout,
    raw: &'a [u8],
    fields: &'a [u8],
}

impl<'a, 'm> CompositeView<'a, 'm> {
    pub fn parse(value: RawValue<'a>, layout: &'m CompositeLayout) -> Result<Self, CodecError> {
        Self::parse_with(value, layout, |_| Ok(()))
    }

    /// 按协议顺序一次校验并访问所有字段。回调先接收合法前缀，随后才可能发现损坏的尾部。
    pub fn visit(
        value: RawValue<'a>,
        layout: &'m CompositeLayout,
        on_field: impl FnMut(RawValue<'a>) -> Result<(), CodecError>,
    ) -> Result<(), CodecError> {
        Self::parse_with(value, layout, on_field).map(|_| ())
    }

    fn parse_with(
        value: RawValue<'a>,
        layout: &'m CompositeLayout,
        mut on_field: impl FnMut(RawValue<'a>) -> Result<(), CodecError>,
    ) -> Result<Self, CodecError> {
        if layout.oid.0 == 0 {
            return Err(CodecError::Invalid(
                "composite layout requires a resolved OID",
            ));
        }
        let raw = value.non_null(&[layout.oid], true)?;
        let mut cursor = ValueCursor::new(raw);
        let count = usize::try_from(cursor.i32()?)
            .map_err(|_| CodecError::Invalid("negative composite field count"))?;
        if count != layout.fields.len() {
            return Err(CodecError::Invalid(
                "composite field count differs from its resolved layout",
            ));
        }
        let fields = cursor.remaining();
        if count > fields.len() / 8 {
            return Err(CodecError::Invalid(
                "composite field count cannot fit in its body",
            ));
        }
        for &oid in &layout.fields {
            if Oid(cursor.u32()?) != oid || oid.0 == 0 {
                return Err(CodecError::Invalid(
                    "composite field OID differs from its resolved layout",
                ));
            }
            on_field(RawValue {
                oid,
                format: Format::Binary,
                bytes: cursor.nullable()?,
            })?;
        }
        cursor.finish()?;
        Ok(Self {
            layout,
            raw,
            fields,
        })
    }
    pub fn len(self) -> usize {
        self.layout.fields.len()
    }
    pub fn is_empty(self) -> bool {
        self.layout.fields.is_empty()
    }
    pub fn fields(self) -> CompositeFields<'a> {
        CompositeFields {
            cursor: ValueCursor::new(self.fields),
            remaining: self.len(),
        }
    }
    pub fn raw_value(self) -> RawValue<'a> {
        RawValue {
            oid: self.layout.oid,
            format: Format::Binary,
            bytes: Some(self.raw),
        }
    }
}

pub struct CompositeFields<'a> {
    cursor: ValueCursor<'a>,
    remaining: usize,
}

impl<'a> Iterator for CompositeFields<'a> {
    type Item = Result<RawValue<'a>, CodecError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let result = (|| {
            Ok(RawValue {
                oid: Oid(self.cursor.u32()?),
                format: Format::Binary,
                bytes: self.cursor.nullable()?,
            })
        })();
        if result.is_err() {
            self.remaining = 0;
        }
        Some(result)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for CompositeFields<'_> {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeLayout {
    pub oid: Oid,
    pub subtype_oid: Oid,
}

impl RangeLayout {
    /// 由已解析的区间类型取得区间与子类型的 OID。
    #[cfg(feature = "postgres-types")]
    pub fn from_postgres_type(ty: &postgres_types::Type) -> Option<Self> {
        let postgres_types::Kind::Range(subtype) = ty.kind() else {
            return None;
        };
        Some(Self {
            oid: Oid(ty.oid()),
            subtype_oid: Oid(subtype.oid()),
        })
    }
}

const RANGE_EMPTY: u8 = 0x01;
const RANGE_LOWER_INCLUDED: u8 = 0x02;
const RANGE_UPPER_INCLUDED: u8 = 0x04;
const RANGE_LOWER_UNBOUNDED: u8 = 0x08;
const RANGE_UPPER_UNBOUNDED: u8 = 0x10;
const RANGE_FLAGS: u8 = RANGE_EMPTY
    | RANGE_LOWER_INCLUDED
    | RANGE_UPPER_INCLUDED
    | RANGE_LOWER_UNBOUNDED
    | RANGE_UPPER_UNBOUNDED;

/// 区间的借用值。有限边界须提供子类型的非空二进制值。
#[derive(Debug, Clone, Copy)]
pub enum RangeValue<'a> {
    Empty,
    Bounds {
        lower: Bound<RawValue<'a>>,
        upper: Bound<RawValue<'a>>,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct RangeView<'a> {
    layout: RangeLayout,
    raw: &'a [u8],
    empty: bool,
    lower: Bound<&'a [u8]>,
    upper: Bound<&'a [u8]>,
}

impl<'a> RangeView<'a> {
    pub fn parse(value: RawValue<'a>, layout: RangeLayout) -> Result<Self, CodecError> {
        if layout.oid.0 == 0 || layout.subtype_oid.0 == 0 {
            return Err(CodecError::Invalid("range layout requires resolved OIDs"));
        }
        Self::parse_body(value.non_null(&[layout.oid], true)?, layout)
    }

    fn parse_body(raw: &'a [u8], layout: RangeLayout) -> Result<Self, CodecError> {
        let mut cursor = ValueCursor::new(raw);
        let flags = cursor.byte()?;
        if flags & !RANGE_FLAGS != 0 {
            return Err(CodecError::Invalid("range has unsupported wire flags"));
        }
        if flags & RANGE_EMPTY != 0 {
            if flags != RANGE_EMPTY {
                return Err(CodecError::Invalid("empty range has bound flags"));
            }
            cursor.finish()?;
            return Ok(Self {
                layout,
                raw,
                empty: true,
                lower: Bound::Unbounded,
                upper: Bound::Unbounded,
            });
        }
        let lower = parse_bound(
            &mut cursor,
            flags & RANGE_LOWER_UNBOUNDED != 0,
            flags & RANGE_LOWER_INCLUDED != 0,
        )?;
        let upper = parse_bound(
            &mut cursor,
            flags & RANGE_UPPER_UNBOUNDED != 0,
            flags & RANGE_UPPER_INCLUDED != 0,
        )?;
        cursor.finish()?;
        Ok(Self {
            layout,
            raw,
            empty: false,
            lower,
            upper,
        })
    }
    pub fn is_empty(self) -> bool {
        self.empty
    }
    pub fn layout(self) -> RangeLayout {
        self.layout
    }
    pub fn value(self) -> RangeValue<'a> {
        if self.empty {
            RangeValue::Empty
        } else {
            RangeValue::Bounds {
                lower: self.value_bound(self.lower),
                upper: self.value_bound(self.upper),
            }
        }
    }
    fn value_bound(self, bound: Bound<&'a [u8]>) -> Bound<RawValue<'a>> {
        bound.map(|bytes| RawValue {
            oid: self.layout.subtype_oid,
            format: Format::Binary,
            bytes: Some(bytes),
        })
    }
    pub fn raw_value(self) -> RawValue<'a> {
        RawValue {
            oid: self.layout.oid,
            format: Format::Binary,
            bytes: Some(self.raw),
        }
    }
}

fn parse_bound<'a>(
    cursor: &mut ValueCursor<'a>,
    unbounded: bool,
    inclusive: bool,
) -> Result<Bound<&'a [u8]>, CodecError> {
    if unbounded {
        if inclusive {
            return Err(CodecError::Invalid(
                "unbounded range bound cannot be inclusive",
            ));
        }
        return Ok(Bound::Unbounded);
    }
    let length = usize::try_from(cursor.i32()?)
        .map_err(|_| CodecError::Invalid("finite range bound cannot be SQL NULL"))?;
    let value = cursor.take(length)?;
    Ok(if inclusive {
        Bound::Included(value)
    } else {
        Bound::Excluded(value)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiRangeLayout {
    pub oid: Oid,
    pub range: RangeLayout,
}

#[derive(Debug, Clone, Copy)]
pub struct MultiRangeView<'a> {
    layout: MultiRangeLayout,
    raw: &'a [u8],
    ranges: &'a [u8],
    count: usize,
}

impl<'a> MultiRangeView<'a> {
    pub fn parse(value: RawValue<'a>, layout: MultiRangeLayout) -> Result<Self, CodecError> {
        Self::parse_with(value, layout, |_| Ok(()))
    }

    /// 按协议顺序一次校验并访问所有区间。回调先接收合法前缀，随后才可能发现损坏的尾部。
    pub fn visit(
        value: RawValue<'a>,
        layout: MultiRangeLayout,
        on_range: impl FnMut(RangeView<'a>) -> Result<(), CodecError>,
    ) -> Result<(), CodecError> {
        Self::parse_with(value, layout, on_range).map(|_| ())
    }

    fn parse_with(
        value: RawValue<'a>,
        layout: MultiRangeLayout,
        mut on_range: impl FnMut(RangeView<'a>) -> Result<(), CodecError>,
    ) -> Result<Self, CodecError> {
        if layout.oid.0 == 0 || layout.range.oid.0 == 0 || layout.range.subtype_oid.0 == 0 {
            return Err(CodecError::Invalid(
                "multirange layout requires resolved OIDs",
            ));
        }
        let raw = value.non_null(&[layout.oid], true)?;
        let mut cursor = ValueCursor::new(raw);
        let count = usize::try_from(cursor.i32()?)
            .map_err(|_| CodecError::Invalid("negative multirange count"))?;
        let ranges = cursor.remaining();
        if count > ranges.len() / 5 {
            return Err(CodecError::Invalid(
                "multirange count cannot fit in its body",
            ));
        }
        for _ in 0..count {
            on_range(read_range(&mut cursor, layout.range)?)?;
        }
        cursor.finish()?;
        Ok(Self {
            layout,
            raw,
            ranges,
            count,
        })
    }
    pub fn len(self) -> usize {
        self.count
    }
    pub fn is_empty(self) -> bool {
        self.count == 0
    }
    pub fn ranges(self) -> MultiRangeValues<'a> {
        MultiRangeValues {
            cursor: ValueCursor::new(self.ranges),
            layout: self.layout.range,
            remaining: self.count,
        }
    }
    pub fn raw_value(self) -> RawValue<'a> {
        RawValue {
            oid: self.layout.oid,
            format: Format::Binary,
            bytes: Some(self.raw),
        }
    }
}

fn read_range<'a>(
    cursor: &mut ValueCursor<'a>,
    layout: RangeLayout,
) -> Result<RangeView<'a>, CodecError> {
    let length = usize::try_from(cursor.i32()?)
        .map_err(|_| CodecError::Invalid("negative multirange member length"))?;
    RangeView::parse_body(cursor.take(length)?, layout)
}

pub struct MultiRangeValues<'a> {
    cursor: ValueCursor<'a>,
    layout: RangeLayout,
    remaining: usize,
}

impl<'a> Iterator for MultiRangeValues<'a> {
    type Item = Result<RangeView<'a>, CodecError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let result = read_range(&mut self.cursor, self.layout);
        if result.is_err() {
            self.remaining = 0;
        }
        Some(result)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for MultiRangeValues<'_> {}

fn member_length(parameter: &Parameter<'_>, expected: Oid) -> Result<Option<usize>, CodecError> {
    if parameter.oid() != expected || parameter.format() != Format::Binary {
        return Err(CodecError::WrongType {
            oid: parameter.oid(),
            format: parameter.format(),
        });
    }
    Ok(parameter.non_null_len())
}

fn append_nullable(output: &mut Vec<u8>, bytes: Option<&[u8]>) {
    match bytes {
        None => output.extend_from_slice(&(-1_i32).to_be_bytes()),
        Some(bytes) => append_payload(output, bytes),
    }
}

pub fn encode_array(
    layout: ArrayLayout,
    dimensions: &[ArrayDimension],
    values: &[Parameter<'_>],
    max_bytes: usize,
) -> Result<EncodedValue, CodecError> {
    if dimensions.len() > 6 || layout.oid.0 == 0 || layout.element_oid.0 == 0 {
        return Err(CodecError::Invalid("invalid array layout"));
    }
    let mut count = usize::from(!dimensions.is_empty());
    for dimension in dimensions {
        count = count
            .checked_mul(validate_dimension(*dimension)?)
            .ok_or(CodecError::Limit("array element count overflow"))?;
    }
    if count != values.len() {
        return Err(CodecError::Invalid(
            "array dimensions and element count differ",
        ));
    }
    let mut length = 12 + dimensions.len() * 8;
    let mut has_nulls = false;
    for value in values {
        let payload = member_length(value, layout.element_oid)?;
        has_nulls |= payload.is_none();
        length = add_length(add_length(length, 4)?, payload.unwrap_or(0))?;
    }
    let mut output = value_storage(length, max_bytes)?;
    output.extend_from_slice(
        &i32::try_from(dimensions.len())
            .map_err(|_| CodecError::Limit("dimension count overflow"))?
            .to_be_bytes(),
    );
    output.extend_from_slice(&i32::from(has_nulls).to_be_bytes());
    output.extend_from_slice(&layout.element_oid.0.to_be_bytes());
    for dimension in dimensions {
        output.extend_from_slice(&dimension.len.to_be_bytes());
        output.extend_from_slice(&dimension.lower_bound.to_be_bytes());
    }
    for value in values {
        value.append_field::<false>(&mut output);
    }
    EncodedValue::from_raw(layout.oid, Format::Binary, Some(output), max_bytes)
}

pub fn encode_composite(
    layout: &CompositeLayout,
    values: &[Parameter<'_>],
    max_bytes: usize,
) -> Result<EncodedValue, CodecError> {
    if layout.oid.0 == 0 {
        return Err(CodecError::Invalid(
            "composite layout requires resolved OIDs",
        ));
    }
    if values.len() != layout.fields.len() {
        return Err(CodecError::Invalid(
            "composite field count differs from its layout",
        ));
    }
    let count = i32::try_from(values.len())
        .map_err(|_| CodecError::Limit("composite field count overflow"))?;
    let mut length = 4;
    for (value, oid) in values.iter().zip(layout.fields.iter()) {
        if oid.0 == 0 {
            return Err(CodecError::Invalid(
                "composite layout requires resolved OIDs",
            ));
        }
        let payload = member_length(value, *oid)?.unwrap_or(0);
        length = add_length(add_length(length, 8)?, payload)?;
    }
    let mut output = value_storage(length, max_bytes)?;
    output.extend_from_slice(&count.to_be_bytes());
    for value in values {
        output.extend_from_slice(&value.oid().0.to_be_bytes());
        value.append_field::<false>(&mut output);
    }
    EncodedValue::from_raw(layout.oid, Format::Binary, Some(output), max_bytes)
}

pub fn encode_range(
    layout: RangeLayout,
    value: RangeValue<'_>,
    max_bytes: usize,
) -> Result<EncodedValue, CodecError> {
    if layout.oid.0 == 0 || layout.subtype_oid.0 == 0 {
        return Err(CodecError::Invalid("range layout requires resolved OIDs"));
    }
    let mut output = value_storage(range_size(value, layout.subtype_oid)?, max_bytes)?;
    append_range(&mut output, value);
    EncodedValue::from_raw(layout.oid, Format::Binary, Some(output), max_bytes)
}

fn range_size(value: RangeValue<'_>, subtype_oid: Oid) -> Result<usize, CodecError> {
    let RangeValue::Bounds { lower, upper } = value else {
        return Ok(1);
    };
    let mut length = 1;
    for bound in [lower, upper] {
        if let Bound::Included(value) | Bound::Excluded(value) = bound {
            let bytes = value.non_null(&[subtype_oid], true)?;
            length = add_length(add_length(length, 4)?, bytes.len())?;
        }
    }
    Ok(length)
}

fn bound_flags(bound: Bound<RawValue<'_>>, included: u8, unbounded: u8) -> u8 {
    match bound {
        Bound::Included(_) => included,
        Bound::Excluded(_) => 0,
        Bound::Unbounded => unbounded,
    }
}

fn append_range(output: &mut Vec<u8>, value: RangeValue<'_>) {
    match value {
        RangeValue::Empty => output.push(RANGE_EMPTY),
        RangeValue::Bounds { lower, upper } => {
            output.push(
                bound_flags(lower, RANGE_LOWER_INCLUDED, RANGE_LOWER_UNBOUNDED)
                    | bound_flags(upper, RANGE_UPPER_INCLUDED, RANGE_UPPER_UNBOUNDED),
            );
            for bound in [lower, upper] {
                if let Bound::Included(value) | Bound::Excluded(value) = bound {
                    append_nullable(output, value.bytes);
                }
            }
        }
    }
}

/// 在同一输出缓冲区编码所有成员。区间归并和排序由 PostgreSQL 完成。
pub fn encode_multirange(
    layout: MultiRangeLayout,
    ranges: &[RangeValue<'_>],
    max_bytes: usize,
) -> Result<EncodedValue, CodecError> {
    if layout.oid.0 == 0 || layout.range.oid.0 == 0 || layout.range.subtype_oid.0 == 0 {
        return Err(CodecError::Invalid(
            "multirange layout requires resolved OIDs",
        ));
    }
    let count =
        i32::try_from(ranges.len()).map_err(|_| CodecError::Limit("multirange count overflow"))?;
    let mut length = 4;
    for &range in ranges {
        length = add_length(
            add_length(length, 4)?,
            range_size(range, layout.range.subtype_oid)?,
        )?;
    }
    let mut output = value_storage(length, max_bytes)?;
    output.extend_from_slice(&count.to_be_bytes());
    for &range in ranges {
        let length_start = output.len();
        output.extend_from_slice(&[0; 4]);
        let range_start = output.len();
        append_range(&mut output, range);
        // 整体长度已通过 i32 上限检查，成员长度可直接写入预留字段。
        let length = (output.len() - range_start) as i32;
        output
            .get_mut(length_start..range_start)
            .ok_or(CodecError::Invalid("missing multirange member length"))?
            .copy_from_slice(&length.to_be_bytes());
    }
    EncodedValue::from_raw(layout.oid, Format::Binary, Some(output), max_bytes)
}
