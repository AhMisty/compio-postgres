//! 不可变结果布局、顺序借用的数据行和有界的自有行存储。
//!
//! 会话驱动控制帧消费和存储复用。行视图只读取已借用的数据。

use std::{fmt, rc::Rc};

use crate::{
    protocol::{DataRow, FieldDescription, RowDescription},
    types::{CodecError, Decode, Format, Oid, RawValue, ValueCursor},
};

/// 用于构造 [`RowLayout`] 的自有列信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub table_oid: Oid,
    pub column_id: i16,
    pub type_oid: Oid,
    pub type_size: i16,
    pub type_modifier: i32,
}

impl Column {
    pub fn new(name: String, type_oid: Oid) -> Self {
        Self {
            name,
            table_oid: Oid(0),
            column_id: 0,
            type_oid,
            type_size: -1,
            type_modifier: -1,
        }
    }

    fn as_ref(&self) -> ColumnRef<'_> {
        ColumnRef {
            name: &self.name,
            table_oid: self.table_oid,
            column_id: self.column_id,
            type_oid: self.type_oid,
            type_size: self.type_size,
            type_modifier: self.type_modifier,
        }
    }
}

/// 从共享行布局借用一列的名称、来源和类型信息。结果格式由 [`RowLayout::formats`] 提供。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColumnRef<'a> {
    pub name: &'a str,
    pub table_oid: Oid,
    pub column_id: i16,
    pub type_oid: Oid,
    pub type_size: i16,
    pub type_modifier: i32,
}

impl<'a> ColumnRef<'a> {
    fn from_field(field: FieldDescription<'a>) -> Self {
        Self {
            name: field.name,
            table_oid: Oid(field.table_oid),
            column_id: field.column_id,
            type_oid: Oid(field.type_oid),
            type_size: field.type_size,
            type_modifier: field.type_modifier,
        }
    }
}

struct ColumnSlot {
    name_end: u32,
    table_oid: Oid,
    column_id: i16,
    type_oid: Oid,
    type_size: i16,
    type_modifier: i32,
    format: Format,
}

/// 实际发送到 Bind 的结果格式。Describe 预备语句时报告的文本标记不决定执行结果格式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultFormats {
    All(Format),
    PerColumn(Box<[Format]>),
}

impl ResultFormats {
    pub fn as_slice(&self) -> &[Format] {
        match self {
            Self::All(format) => std::slice::from_ref(format),
            Self::PerColumn(formats) => formats,
        }
    }

    pub fn format(&self, index: usize) -> Option<Format> {
        match self {
            Self::All(format) => Some(*format),
            Self::PerColumn(formats) => formats.get(index).copied(),
        }
    }

    pub(crate) fn matches_reported(
        &self,
        description: RowDescription<'_>,
    ) -> Result<bool, crate::protocol::ProtocolError> {
        match self {
            Self::All(format) => {
                Ok(description.is_empty() || description.uniform_format() == Some(*format))
            }
            Self::PerColumn(formats) => {
                let Some(reported_columns) = formats.get(..description.len()) else {
                    return Ok(false);
                };
                if let Some(uniform) = description.uniform_format() {
                    return Ok(reported_columns.iter().all(|format| *format == uniform));
                }
                for (field, expected) in description.iter().zip(reported_columns) {
                    if field?.format != *expected {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }

    pub(crate) fn validate(&self, count: usize) -> Result<(), CodecError> {
        if let Self::PerColumn(formats) = self
            && formats.len() != count
        {
            return Err(CodecError::Invalid(
                "result format count differs from the column count",
            ));
        }
        Ok(())
    }

    fn retained_bytes(&self) -> usize {
        match self {
            Self::All(_) => 0,
            Self::PerColumn(formats) => std::mem::size_of_val(formats.as_ref()),
        }
    }
}

/// 查询结果布局。各行共享列信息，读取时无需再次查找类型或克隆列名。
pub struct RowLayout {
    columns: Box<[ColumnSlot]>,
    names: Box<str>,
    formats: ResultFormats,
    retained_bytes: usize,
    scalar: Option<ScalarColumn>,
}

impl fmt::Debug for RowLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RowLayout")
            .field(
                "columns",
                &fmt::from_fn(|f| f.debug_list().entries(self.columns()).finish()),
            )
            .field("formats", &self.formats)
            .field("retained_bytes", &self.retained_bytes)
            .field("scalar", &self.scalar)
            .finish()
    }
}

/// 标量和命令终结方法所需的结果形状。只有向应用交付完整行才需构造列名和来源信息。
#[derive(Clone, Copy, Default)]
pub(crate) struct ResultShape {
    pub(crate) columns: u16,
    pub(crate) scalar: Option<ScalarColumn>,
}

impl ResultShape {
    pub(crate) fn from_description(description: RowDescription<'_>) -> Self {
        Self {
            columns: description.column_count(),
            scalar: description.scalar().map(|(oid, format)| ScalarColumn {
                oid: Oid(oid),
                format,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ScalarColumn {
    oid: Oid,
    format: Format,
}

impl ScalarColumn {
    pub(crate) fn validate<V>(self) -> Result<(), CodecError>
    where
        for<'row> V: Decode<'row>,
    {
        if V::accepts(self.oid, self.format) {
            Ok(())
        } else {
            Err(CodecError::WrongType {
                oid: self.oid,
                format: self.format,
            })
        }
    }

    pub(crate) fn decode<'a, V: Decode<'a>>(
        self,
        field: Option<Option<&'a [u8]>>,
    ) -> Result<V, CodecError> {
        let bytes = field.ok_or(CodecError::Invalid(
            "row field count differs from its result layout",
        ))?;
        RawValue {
            oid: self.oid,
            format: self.format,
            bytes,
        }
        .decode()
    }

    fn from_layout(columns: &[ColumnSlot]) -> Option<Self> {
        let [column] = columns else {
            return None;
        };
        Some(Self {
            oid: column.type_oid,
            format: column.format,
        })
    }
}

impl RowLayout {
    pub fn new(columns: Vec<Column>, formats: ResultFormats) -> Result<Self, CodecError> {
        u16::try_from(columns.len())
            .map_err(|_| CodecError::Limit("column count exceeds its wire width"))?;
        formats.validate(columns.len())?;
        let name_bytes = columns
            .iter()
            .try_fold(0_usize, |bytes, column| {
                bytes.checked_add(column.name.len())
            })
            .ok_or(CodecError::Limit("metadata capacity overflow"))?;
        let retained_bytes =
            Self::storage_bytes(columns.len(), name_bytes, formats.retained_bytes())?;
        let (columns, names) = Self::pack_columns::<CodecError>(
            columns.len(),
            name_bytes,
            columns.iter().enumerate().map(|(index, column)| {
                let format = formats
                    .format(index)
                    .ok_or(CodecError::Invalid("missing column format"))?;
                Ok((column.as_ref(), format))
            }),
        )?;
        Ok(Self {
            scalar: ScalarColumn::from_layout(&columns),
            columns,
            names,
            formats,
            retained_bytes,
        })
    }

    /// 限额覆盖列槽、列名和显式格式存储。
    /// Rc 控制块及分配器元数据另计。
    pub fn from_description(
        description: RowDescription<'_>,
        formats: ResultFormats,
        max_metadata_bytes: usize,
    ) -> Result<Self, CodecError> {
        Self::from_description_checked(description, formats, Ok(max_metadata_bytes), |_, _| Ok(()))
    }

    /// 先完成调用方参数校验，再分配元数据。
    pub(crate) fn from_description_checked<E>(
        description: RowDescription<'_>,
        formats: ResultFormats,
        max_metadata_bytes: Result<usize, E>,
        validate: impl FnOnce(RowDescription<'_>, &ResultFormats) -> Result<(), E>,
    ) -> Result<Self, E>
    where
        E: From<CodecError> + From<crate::protocol::ProtocolError>,
    {
        Self::from_pending_description(
            description,
            &mut Some(formats),
            max_metadata_bytes,
            validate,
        )
    }

    /// 完成所有校验和分配后才接管调用方的格式数组，成功路径无需逐列克隆。
    pub(crate) fn from_pending_description<E>(
        description: RowDescription<'_>,
        pending_formats: &mut Option<ResultFormats>,
        max_metadata_bytes: Result<usize, E>,
        validate: impl FnOnce(RowDescription<'_>, &ResultFormats) -> Result<(), E>,
    ) -> Result<Self, E>
    where
        E: From<CodecError> + From<crate::protocol::ProtocolError>,
    {
        Self::build_description(
            description,
            Some(pending_formats),
            max_metadata_bytes,
            validate,
        )
    }

    /// 简单查询没有 Bind 格式请求，以 RowDescription 为准，包括二进制游标返回的格式。
    pub(crate) fn from_reported_description(
        description: RowDescription<'_>,
        max_metadata_bytes: usize,
    ) -> Result<Self, crate::Error> {
        Self::build_description(description, None, Ok(max_metadata_bytes), |_, _| Ok(()))
    }

    fn build_description<E>(
        description: RowDescription<'_>,
        pending_formats: Option<&mut Option<ResultFormats>>,
        max_metadata_bytes: Result<usize, E>,
        validate: impl FnOnce(RowDescription<'_>, &ResultFormats) -> Result<(), E>,
    ) -> Result<Self, E>
    where
        E: From<CodecError> + From<crate::protocol::ProtocolError>,
    {
        let expected = pending_formats
            .as_deref()
            .map(|formats| {
                formats
                    .as_ref()
                    .ok_or(CodecError::Invalid("result formats are missing"))
            })
            .transpose()?;
        if let Some(expected) = expected {
            validate(description, expected)?;
        }
        let max_metadata_bytes = max_metadata_bytes?;
        let mixed = expected.is_none() && description.uniform_format().is_none();
        let retained_bytes =
            Self::check_description_budget(description, expected, max_metadata_bytes)?;
        let mut reported = Vec::new();
        if mixed {
            reported
                .try_reserve_exact(description.len())
                .map_err(|_| CodecError::Allocation)?;
        }
        let (columns, names) = Self::pack_columns::<E>(
            description.len(),
            description.name_bytes(),
            description.iter().enumerate().map(|(index, field)| {
                let field = field?;
                if mixed {
                    reported.push(field.format);
                }
                let format = match expected {
                    Some(formats) => formats
                        .format(index)
                        .ok_or(CodecError::Invalid("missing column format"))?,
                    None => field.format,
                };
                Ok((ColumnRef::from_field(field), format))
            }),
        )?;
        let formats = match pending_formats {
            Some(formats) => formats
                .take()
                .ok_or(CodecError::Invalid("result formats are missing"))?,
            None => match description.uniform_format() {
                Some(format) => ResultFormats::All(format),
                None => ResultFormats::PerColumn(reported.into_boxed_slice()),
            },
        };
        Ok(Self {
            scalar: ScalarColumn::from_layout(&columns),
            columns,
            names,
            formats,
            retained_bytes,
        })
    }

    /// 标量终结方法也按完整列信息核算元数据额度，包括服务端报告的每个列名。
    pub(crate) fn check_description_budget(
        description: RowDescription<'_>,
        expected: Option<&ResultFormats>,
        max_metadata_bytes: usize,
    ) -> Result<usize, CodecError> {
        let format_bytes = if let Some(expected) = expected {
            expected.validate(description.len())?;
            expected.retained_bytes()
        } else if description.uniform_format().is_none() {
            description
                .len()
                .checked_mul(std::mem::size_of::<Format>())
                .ok_or(CodecError::Limit("format storage size overflow"))?
        } else {
            0
        };
        let retained_bytes =
            Self::storage_bytes(description.len(), description.name_bytes(), format_bytes)?;
        if retained_bytes > max_metadata_bytes {
            return Err(CodecError::Limit(
                "column metadata exceeds its storage limit",
            ));
        }
        Ok(retained_bytes)
    }

    pub(crate) fn empty_from_pending(
        pending_formats: &mut Option<ResultFormats>,
        max_metadata_bytes: usize,
    ) -> Result<Self, CodecError> {
        let formats = pending_formats
            .as_ref()
            .ok_or(CodecError::Invalid("result formats are missing"))?;
        formats.validate(0)?;
        let retained_bytes = Self::storage_bytes(0, 0, formats.retained_bytes())?;
        if retained_bytes > max_metadata_bytes {
            return Err(CodecError::Limit("query metadata exceeds its limit"));
        }
        Ok(Self {
            columns: Box::default(),
            names: Box::default(),
            formats: pending_formats
                .take()
                .ok_or(CodecError::Invalid("result formats are missing"))?,
            retained_bytes,
            scalar: None,
        })
    }

    pub fn len(&self) -> usize {
        self.columns.len()
    }
    pub fn is_empty(&self) -> bool {
        self.columns.is_empty()
    }
    pub(crate) fn scalar_column(&self) -> Option<ScalarColumn> {
        self.scalar
    }

    /// 按结果顺序逐列借用元数据。
    pub fn columns(&self) -> impl ExactSizeIterator<Item = ColumnRef<'_>> + DoubleEndedIterator {
        self.columns
            .iter()
            .enumerate()
            .map(|(index, column)| self.borrow_column(index, column))
    }

    /// 按从零开始的列序号借用元数据。
    pub fn column(&self, index: usize) -> Option<ColumnRef<'_>> {
        self.columns
            .get(index)
            .map(|column| self.borrow_column(index, column))
    }

    fn borrow_column(&self, index: usize, column: &ColumnSlot) -> ColumnRef<'_> {
        // 两个偏移均来自成功写入的列名长度，落在 UTF-8 字符边界且可恢复为 usize。
        let start = index
            .checked_sub(1)
            .and_then(|previous| self.columns.get(previous))
            .map_or(0, |previous| previous.name_end as usize);
        ColumnRef {
            name: self
                .names
                .get(start..column.name_end as usize)
                .unwrap_or_default(),
            table_oid: column.table_oid,
            column_id: column.column_id,
            type_oid: column.type_oid,
            type_size: column.type_size,
            type_modifier: column.type_modifier,
        }
    }

    pub fn formats(&self) -> &ResultFormats {
        &self.formats
    }

    /// 编译列投影时按名称查找。遇到重名列返回歧义错误。
    pub fn column_index(&self, name: &str) -> Result<usize, CodecError> {
        let name = name.as_bytes();
        let mut start = 0;
        let mut found = None;
        for (index, column) in self.columns.iter().enumerate() {
            let end = column.name_end as usize;
            if self.names.as_bytes().get(start..end) == Some(name) {
                if found.is_some() {
                    return Err(CodecError::Invalid("column name is ambiguous"));
                }
                found = Some(index);
            }
            start = end;
        }
        found.ok_or(CodecError::Invalid("column name was not found"))
    }

    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    fn pack_columns<'a, E>(
        count: usize,
        name_bytes: usize,
        fields: impl Iterator<Item = Result<(ColumnRef<'a>, Format), E>>,
    ) -> Result<(Box<[ColumnSlot]>, Box<str>), E>
    where
        E: From<CodecError>,
    {
        u32::try_from(name_bytes)
            .map_err(|_| CodecError::Limit("metadata names exceed the storage width"))?;
        let mut columns = Vec::new();
        columns
            .try_reserve_exact(count)
            .map_err(|_| CodecError::Allocation)?;
        let mut names = String::new();
        names
            .try_reserve_exact(name_bytes)
            .map_err(|_| CodecError::Allocation)?;
        for column in fields {
            let (column, format) = column?;
            names.push_str(column.name);
            columns.push(ColumnSlot {
                name_end: u32::try_from(names.len())
                    .map_err(|_| CodecError::Limit("metadata names exceed the storage width"))?,
                table_oid: column.table_oid,
                column_id: column.column_id,
                type_oid: column.type_oid,
                type_size: column.type_size,
                type_modifier: column.type_modifier,
                format,
            });
        }
        // 列槽、名称和逐列格式使用定长自有存储，按长度计费与实际保留容量一致。
        Ok((columns.into_boxed_slice(), names.into_boxed_str()))
    }

    fn storage_bytes(
        columns: usize,
        name_bytes: usize,
        format_bytes: usize,
    ) -> Result<usize, CodecError> {
        columns
            .checked_mul(size_of::<ColumnSlot>())
            .and_then(|bytes| bytes.checked_add(size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(name_bytes))
            .and_then(|bytes| bytes.checked_add(format_bytes))
            .ok_or(CodecError::Limit("metadata capacity overflow"))
    }
}

#[derive(Clone, Copy)]
pub struct RowView<'data, 'meta> {
    fields: &'data [u8],
    layout: &'meta RowLayout,
}

impl fmt::Debug for RowView<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RowView")
            .field("columns", &self.layout.len())
            .field("encoded_bytes", &self.fields.len())
            .finish()
    }
}

impl<'data, 'meta> RowView<'data, 'meta> {
    pub fn new(data: DataRow<'data>, layout: &'meta RowLayout) -> Result<Self, CodecError> {
        if data.len() != layout.len() {
            return Err(CodecError::Invalid(
                "row field count differs from its result layout",
            ));
        }
        Ok(Self::from_matching_layout(data, layout))
    }

    /// 行字段数与布局一致后构造视图。
    pub(crate) fn from_matching_layout(data: DataRow<'data>, layout: &'meta RowLayout) -> Self {
        Self {
            fields: data.encoded_fields(),
            layout,
        }
    }
    pub fn len(self) -> usize {
        self.layout.len()
    }
    pub fn is_empty(self) -> bool {
        self.layout.is_empty()
    }
    pub fn layout(self) -> &'meta RowLayout {
        self.layout
    }
    pub fn fields(self) -> RowFields<'data, 'meta> {
        RowFields {
            cursor: ValueCursor::new(self.fields),
            columns: self.layout.columns.iter(),
        }
    }
    pub fn decoder(self) -> RowDecoder<'data, 'meta> {
        RowDecoder {
            fields: self.fields(),
        }
    }
    pub fn encoded_len(self) -> usize {
        self.fields.len()
    }
}

pub struct RowFields<'data, 'meta> {
    cursor: ValueCursor<'data>,
    columns: std::slice::Iter<'meta, ColumnSlot>,
}

impl<'data> RowFields<'data, '_> {
    fn next_value(&mut self) -> Result<RawValue<'data>, CodecError> {
        self.next()
            .ok_or(CodecError::Invalid("row has no remaining column"))?
    }

    fn skip_field(&mut self) -> Result<(), CodecError> {
        self.columns
            .next()
            .ok_or(CodecError::Invalid("row has no remaining column"))?;
        self.cursor
            .nullable()
            .map(|_| ())
            .inspect_err(|_| self.clear())
    }

    fn clear(&mut self) {
        self.columns = [].iter();
    }
}

impl<'data> Iterator for RowFields<'data, '_> {
    type Item = Result<RawValue<'data>, CodecError>;
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let column = self.columns.next()?;
        let result = self.cursor.nullable().map(|bytes| RawValue {
            oid: column.type_oid,
            format: column.format,
            bytes,
        });
        if result.is_err() {
            self.clear();
        }
        Some(result)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.columns.size_hint()
    }
}

pub struct RowDecoder<'data, 'meta> {
    fields: RowFields<'data, 'meta>,
}

impl<'data> RowDecoder<'data, '_> {
    /// 顺序解码下一列，直接沿字段前缀前进。
    pub fn decode_next<T: Decode<'data>>(&mut self) -> Result<T, CodecError> {
        self.fields.next_value()?.decode()
    }
    pub fn next_raw(&mut self) -> Result<RawValue<'data>, CodecError> {
        self.fields.next_value()
    }
    /// 跳过一个已验证结构的字段，不解码其中的值。
    pub fn skip(&mut self) -> Result<(), CodecError> {
        self.fields.skip_field()
    }
    pub fn finish(self) -> Result<(), CodecError> {
        if self.fields.columns.len() != 0 {
            return Err(CodecError::Invalid("row decoder has unconsumed columns"));
        }
        // RowView 只借用已经完整校验的字段，行尾无需再检查。
        Ok(())
    }
}

/// 只能向前读取的 DataRow 消费器，字段结构随读取逐一校验。
///
/// 回调可能先读取合法前缀，随后才发现损坏的后续字段或行尾。
/// 回调返回后，驱动会校验剩余字段。
/// 读取、解码或跳过失败后，`remaining()` 变为零，后续读取与 `finish()` 均返回错误。
pub struct RowConsumer<'data, 'meta> {
    fields: RowFields<'data, 'meta>,
    layout: &'meta RowLayout,
    failed: bool,
}

impl fmt::Debug for RowConsumer<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RowConsumer")
            .field("columns", &self.layout.len())
            .field("remaining", &self.remaining())
            .field("failed", &self.failed)
            .finish()
    }
}

impl<'data, 'meta> RowConsumer<'data, 'meta> {
    pub(crate) fn from_body(
        body: &'data [u8],
        layout: &'meta RowLayout,
    ) -> Result<Self, CodecError> {
        let mut cursor = ValueCursor::new(body);
        if usize::from(cursor.u16()?) != layout.len() {
            return Err(CodecError::Invalid(
                "row field count differs from its result layout",
            ));
        }
        Ok(Self {
            fields: RowFields {
                cursor,
                columns: layout.columns.iter(),
            },
            layout,
            failed: false,
        })
    }

    pub fn len(&self) -> usize {
        self.layout.len()
    }

    pub fn is_empty(&self) -> bool {
        self.layout.is_empty()
    }

    pub fn remaining(&self) -> usize {
        self.fields.columns.len()
    }

    pub fn layout(&self) -> &'meta RowLayout {
        self.layout
    }

    /// 校验并读取一个字段的原始内容。调用方再对 RawValue 解码时，解码失败不改变此消费器的状态。
    pub fn next_raw(&mut self) -> Result<RawValue<'data>, CodecError> {
        self.fields.next_value().inspect_err(|_| self.mark_failed())
    }

    /// 按保留的列元数据读取并解码下一个字段。
    pub fn decode_next<T: Decode<'data>>(&mut self) -> Result<T, CodecError> {
        self.fields
            .next_value()
            .and_then(RawValue::decode)
            .inspect_err(|_| self.mark_failed())
    }

    pub fn skip(&mut self) -> Result<(), CodecError> {
        self.fields.skip_field().inspect_err(|_| self.mark_failed())
    }

    /// 消费并校验所有剩余字段及行尾。成功后重复调用不会重新扫描。
    pub fn finish(&mut self) -> Result<(), CodecError> {
        if self.failed {
            return Err(CodecError::Invalid("row consumer has already failed"));
        }
        let remaining = self.remaining();
        if remaining != 0 {
            self.fields.clear();
            for _ in 0..remaining {
                let _ = self
                    .fields
                    .cursor
                    .nullable()
                    .inspect_err(|_| self.failed = true)?;
            }
        }
        self.fields
            .cursor
            .finish()
            .inspect_err(|_| self.failed = true)
    }

    fn mark_failed(&mut self) {
        self.failed = true;
        self.fields.clear();
    }
}

/// 复制一行已校验数据到紧凑自有存储。限额约束字节缓冲区的容量，不含共享的不可变布局。
pub struct OwnedRow {
    layout: Rc<RowLayout>,
    fields: Vec<u8>,
}

impl fmt::Debug for OwnedRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedRow")
            .field("columns", &self.layout.len())
            .field("retained_bytes", &self.fields.capacity())
            .finish()
    }
}

impl OwnedRow {
    pub fn copy_from(
        row: RowView<'_, '_>,
        layout: Rc<RowLayout>,
        max_bytes: usize,
    ) -> Result<Self, CodecError> {
        if !std::ptr::eq(row.layout, layout.as_ref()) {
            return Err(CodecError::Invalid(
                "owned row layout is not the source layout",
            ));
        }
        let mut fields = reserve_storage(row.fields.len(), max_bytes)?;
        fields.extend_from_slice(row.fields);
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::owned_copy(row.fields.len());
        Ok(Self { layout, fields })
    }
    pub fn view(&self) -> RowView<'_, '_> {
        RowView {
            fields: &self.fields,
            layout: &self.layout,
        }
    }
    pub fn layout(&self) -> &RowLayout {
        &self.layout
    }
    /// 保留对行布局的引用，供其他自有行复用。
    pub fn share_layout(&self) -> Rc<RowLayout> {
        Rc::clone(&self.layout)
    }
    pub fn retained_bytes(&self) -> usize {
        self.fields.capacity()
    }
    pub fn into_parts(self) -> (Rc<RowLayout>, Vec<u8>) {
        (self.layout, self.fields)
    }
}

/// 自有行集和 COPY 输出的分配策略。
///
/// 实际保留容量受指定字节上限约束。能否复用由收集器生命周期决定，额度不覆盖峰值 RSS 和内核内存。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationPolicy {
    /// 按输出字节上限预留。行收集器在首行到达时分配，COPY 收集器在读取前分配。借用结束后可复用已有容量合适的缓冲区。
    ReserveLimit,
    /// 随输出增长。访问回调返回后可清空并复用容量合适的存储；如果下一成员的额度较小，则释放过大的存储。有限流水线分别保留各结果的存储。
    ///
    /// 扩容可能复制旧行并暂时同时持有新旧存储。字节额度约束最终保留容量，不含临时峰值、共享布局或回调复制的数据。
    /// 返回批次的 push 不会扩容。
    Grow,
}

/// 共享同一布局的固定容量行存储。`new` 一次预留 max_bytes，push 不分配。查询收集器可在交付前扩容。
/// 每行占用四字节长度及字段内容，数据从接收缓冲区复制而来。
pub struct OwnedBatch {
    layout: Rc<RowLayout>,
    storage: Vec<u8>,
    row_count: usize,
    max_rows: usize,
}

impl fmt::Debug for OwnedBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedBatch")
            .field("rows", &self.row_count)
            .field("retained_bytes", &self.storage.capacity())
            .finish()
    }
}

impl OwnedBatch {
    pub(crate) fn reuse_for<const GROW: bool>(
        mut self,
        layout: &Rc<RowLayout>,
        max_rows: usize,
        max_bytes: usize,
    ) -> Option<Self> {
        let capacity = self.storage.capacity();
        if capacity > max_bytes || (!GROW && capacity != max_bytes) {
            return None;
        }
        // 上次同步借用已结束，先清空旧行再更换布局。
        self.clear();
        if !Rc::ptr_eq(&self.layout, layout) {
            self.layout = Rc::clone(layout);
        }
        self.max_rows = max_rows;
        Some(self)
    }
    pub fn new(
        layout: Rc<RowLayout>,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            layout,
            storage: reserve_storage(max_bytes, max_bytes)?,
            row_count: 0,
            max_rows,
        })
    }
    pub fn push(&mut self, row: RowView<'_, '_>) -> Result<(), CodecError> {
        self.discard_unpublished();
        let (length, required) = self.row_record(row, self.row_count)?;
        if required > self.storage.capacity() {
            return Err(CodecError::Limit("owned batch byte limit reached"));
        }
        self.append_row(row, length);
        self.row_count += 1;
        Ok(())
    }

    pub(crate) fn push_growing(
        &mut self,
        row: RowView<'_, '_>,
        max_bytes: usize,
    ) -> Result<(), CodecError> {
        self.discard_unpublished();
        let (length, required) = self.row_record(row, self.row_count)?;
        let current_capacity = self.storage.capacity();
        if required > max_bytes || current_capacity > max_bytes {
            return Err(CodecError::Limit("owned batch byte limit reached"));
        }
        if required > current_capacity {
            let capacity = required
                .max(current_capacity.saturating_mul(2))
                .min(max_bytes);
            self.storage
                .try_reserve_exact(capacity - self.storage.len())
                .map_err(|_| CodecError::Allocation)?;
            if self.storage.capacity() > max_bytes {
                // 增长只发生在尚未交付的查询结果中。调用方会丢弃失败的成员，超限存储须在返回前释放。
                self.storage = Vec::new();
                self.row_count = 0;
                return Err(CodecError::Limit(
                    "actual row storage capacity exceeds its limit",
                ));
            }
        }
        self.append_row(row, length);
        self.row_count += 1;
        Ok(())
    }

    fn row_record(
        &self,
        row: RowView<'_, '_>,
        row_count: usize,
    ) -> Result<(u32, usize), CodecError> {
        if !std::ptr::eq(row.layout, self.layout.as_ref()) {
            return Err(CodecError::Invalid("batch row has a different layout"));
        }
        if row_count >= self.max_rows {
            return Err(CodecError::Limit("owned batch row limit reached"));
        }
        let length = u32::try_from(row.fields.len())
            .map_err(|_| CodecError::Limit("row storage length overflow"))?;
        let required = self
            .storage
            .len()
            .checked_add(4)
            .and_then(|size| size.checked_add(row.fields.len()))
            .ok_or(CodecError::Limit("owned batch size overflow"))?;
        Ok((length, required))
    }

    fn append_row(&mut self, row: RowView<'_, '_>, length: u32) {
        // 行记录仅驻留本地内存。长度使用本机序，行字段保留协议字节。
        self.storage.extend_from_slice(&length.to_ne_bytes());
        self.storage.extend_from_slice(row.fields);
        #[cfg(feature = "diagnostics")]
        crate::diagnostics::owned_copy(row.fields.len());
    }
    pub fn len(&self) -> usize {
        self.row_count
    }
    pub fn is_empty(&self) -> bool {
        self.row_count == 0
    }
    pub fn used_bytes(&self) -> usize {
        if self.row_count == 0 {
            0
        } else {
            self.storage.len()
        }
    }
    pub fn retained_bytes(&self) -> usize {
        self.storage.capacity()
    }
    pub fn layout(&self) -> &RowLayout {
        &self.layout
    }
    pub fn rows(&self) -> OwnedRows<'_> {
        OwnedRows {
            cursor: ValueCursor::new(&self.storage),
            layout: &self.layout,
            remaining: self.row_count,
        }
    }
    pub fn clear(&mut self) {
        self.storage.clear();
        self.row_count = 0;
    }

    fn discard_unpublished(&mut self) {
        if self.row_count == 0 {
            self.storage.clear();
        }
    }

    pub(crate) fn stage(&mut self) -> StagedBatch<'_> {
        self.clear();
        StagedBatch {
            batch: self,
            row_count: 0,
            published: false,
        }
    }
}

/// 写入调用方的既有存储，交付前对外显示零行。遗忘守卫只会留下尚未公布的字节。
pub(crate) struct StagedBatch<'a> {
    batch: &'a mut OwnedBatch,
    row_count: usize,
    published: bool,
}

impl StagedBatch<'_> {
    pub(crate) fn push(&mut self, row: RowView<'_, '_>) -> Result<(), CodecError> {
        let (length, required) = self.batch.row_record(row, self.row_count)?;
        if required > self.batch.storage.capacity() {
            return Err(CodecError::Limit("owned batch byte limit reached"));
        }
        self.batch.append_row(row, length);
        self.row_count += 1;
        Ok(())
    }

    pub(crate) fn layout(&self) -> &RowLayout {
        &self.batch.layout
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.batch.retained_bytes()
    }

    pub(crate) fn publish(mut self) {
        self.batch.row_count = self.row_count;
        self.published = true;
    }
}

impl Drop for StagedBatch<'_> {
    fn drop(&mut self) {
        if !self.published {
            self.batch.clear();
        }
    }
}

pub struct OwnedRows<'a> {
    cursor: ValueCursor<'a>,
    layout: &'a RowLayout,
    remaining: usize,
}

impl<'a> Iterator for OwnedRows<'a> {
    type Item = Result<RowView<'a, 'a>, CodecError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let result = (|| {
            let length = usize::try_from(u32::from_ne_bytes(self.cursor.array()?))
                .map_err(|_| CodecError::Limit("row storage length does not fit this platform"))?;
            Ok(RowView {
                fields: self.cursor.take(length)?,
                layout: self.layout,
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

impl ExactSizeIterator for OwnedRows<'_> {}

fn reserve_storage(length: usize, max_bytes: usize) -> Result<Vec<u8>, CodecError> {
    if length > max_bytes {
        return Err(CodecError::Limit("owned row exceeds its byte limit"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| CodecError::Allocation)?;
    if bytes.capacity() > max_bytes {
        return Err(CodecError::Limit(
            "actual row storage capacity exceeds its limit",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{BackendMessage, Frame, parse_backend};

    fn data(body: &[u8]) -> DataRow<'_> {
        match parse_backend(Frame { tag: b'D', body }).expect("valid row fixture") {
            BackendMessage::DataRow(row) => row,
            _ => panic!("expected DataRow"),
        }
    }

    fn int4_body(value: i32) -> Vec<u8> {
        let mut bytes = Vec::from(1_u16.to_be_bytes());
        bytes.extend_from_slice(&4_i32.to_be_bytes());
        bytes.extend_from_slice(&value.to_be_bytes());
        bytes
    }

    #[test]
    fn validated_scalar_reborrow_preserves_null_empty_and_custom_decode() {
        struct Passthrough<'a>(RawValue<'a>);

        impl<'a> Decode<'a> for Passthrough<'a> {
            fn accepts(_: Oid, _: Format) -> bool {
                panic!("scalar decoding must not call accepts before decode");
            }

            fn decode(value: RawValue<'a>) -> Result<Self, CodecError> {
                Ok(Self(value))
            }
        }

        let layout = RowLayout::new(
            vec![Column::new("value".to_owned(), Oid::TEXT)],
            ResultFormats::All(Format::Text),
        )
        .unwrap();
        for (body, expected) in [
            (&[0, 1, 255, 255, 255, 255][..], None),
            (&[0, 1, 0, 0, 0, 0][..], Some(&[][..])),
            (&[0, 1, 0, 0, 0, 1, b'x'][..], Some(&b"x"[..])),
        ] {
            let descriptor = data(body).descriptor();
            let row = descriptor.reborrow(Frame { tag: b'D', body }).unwrap();
            let Passthrough(decoded) = layout
                .scalar_column()
                .unwrap()
                .decode(row.scalar_field())
                .unwrap();
            assert_eq!(decoded.oid, Oid::TEXT);
            assert_eq!(decoded.format, Format::Text);
            assert_eq!(decoded.bytes, expected);
            if let Some(bytes) = decoded.bytes {
                assert_eq!(bytes.as_ptr(), body[6..].as_ptr());
            }
        }
    }

    fn consumer_layout() -> RowLayout {
        RowLayout::new(
            vec![
                Column::new("n".to_owned(), Oid::INT4),
                Column::new("value".to_owned(), Oid::BYTEA),
            ],
            ResultFormats::All(Format::Binary),
        )
        .unwrap()
    }

    fn consumer_prefix() -> Vec<u8> {
        let mut body = Vec::from(2_u16.to_be_bytes());
        body.extend_from_slice(&4_i32.to_be_bytes());
        body.extend_from_slice(&42_i32.to_be_bytes());
        body
    }

    #[test]
    fn row_consumer_decodes_prefix_and_automatically_validates_unread_null_or_bytes() {
        let layout = consumer_layout();
        for suffix in [
            Vec::from((-1_i32).to_be_bytes()),
            vec![0, 0, 0, 3, 0, 255, 7],
        ] {
            let mut body = consumer_prefix();
            body.extend(suffix);
            let mut row = RowConsumer::from_body(&body, &layout).unwrap();
            assert_eq!(row.len(), 2);
            assert!(!row.is_empty());
            assert_eq!(row.decode_next::<i32>().unwrap(), 42);
            assert_eq!(row.remaining(), 1);
            row.finish().unwrap();
            assert_eq!(row.remaining(), 0);
            row.finish().unwrap();
        }
        let mut body = consumer_prefix();
        body.extend_from_slice(&(-1_i32).to_be_bytes());
        let mut row = RowConsumer::from_body(&body, &layout).unwrap();
        assert_eq!(row.decode_next::<i32>().unwrap(), 42);
        assert_eq!(row.decode_next::<Option<&[u8]>>().unwrap(), None);
        row.finish().unwrap();
    }

    #[test]
    fn row_consumer_rejects_unread_negative_truncated_or_trailing_fields_after_valid_prefix() {
        let layout = consumer_layout();
        for suffix in [
            Vec::from((-2_i32).to_be_bytes()),
            vec![0, 0],
            vec![0, 0, 0, 4, 1, 2],
            vec![255, 255, 255, 255, 9],
        ] {
            let mut body = consumer_prefix();
            body.extend(suffix);
            let mut row = RowConsumer::from_body(&body, &layout).unwrap();
            assert_eq!(row.decode_next::<i32>().unwrap(), 42);
            assert!(row.finish().is_err());
            assert!(row.finish().is_err());
            assert!(row.next_raw().is_err());
        }
    }

    #[test]
    fn row_consumer_ignored_read_or_decode_failure_cannot_be_accepted() {
        let layout = consumer_layout();
        let mut body = consumer_prefix();
        body.extend_from_slice(&(-1_i32).to_be_bytes());
        let mut row = RowConsumer::from_body(&body, &layout).unwrap();
        assert!(row.decode_next::<i64>().is_err());
        assert_eq!(row.remaining(), 0);
        assert!(row.next_raw().is_err());
        assert!(row.skip().is_err());
        assert!(row.finish().is_err());

        let mut row = RowConsumer::from_body(&body, &layout).unwrap();
        row.finish().unwrap();
        assert!(row.next_raw().is_err());
        assert_eq!(row.remaining(), 0);
        assert!(row.skip().is_err());
        assert!(row.finish().is_err());

        let mut bad = consumer_prefix();
        bad.extend_from_slice(&(-2_i32).to_be_bytes());
        let mut row = RowConsumer::from_body(&bad, &layout).unwrap();
        row.skip().unwrap();
        assert!(row.next_raw().is_err());
        assert_eq!(row.remaining(), 0);
        assert!(row.skip().is_err());
        assert!(row.finish().is_err());

        let mut row = RowConsumer::from_body(&bad, &layout).unwrap();
        row.skip().unwrap();
        assert!(row.skip().is_err());
        assert_eq!(row.remaining(), 0);
        assert!(row.next_raw().is_err());
        assert!(row.finish().is_err());
    }

    #[test]
    fn row_consumer_checks_column_count_and_empty_row_envelope() {
        let layout = consumer_layout();
        for body in [&[][..], &[0][..], &[0, 1][..]] {
            assert!(RowConsumer::from_body(body, &layout).is_err());
        }
        let empty = RowLayout::new(Vec::new(), ResultFormats::All(Format::Binary)).unwrap();
        RowConsumer::from_body(&[0, 0], &empty)
            .unwrap()
            .finish()
            .unwrap();
        assert!(
            RowConsumer::from_body(&[0, 0, 1], &empty)
                .unwrap()
                .finish()
                .is_err()
        );
    }

    fn int4_layout() -> Rc<RowLayout> {
        Rc::new(
            RowLayout::new(
                vec![Column::new("value".to_owned(), Oid::INT4)],
                ResultFormats::All(Format::Binary),
            )
            .unwrap(),
        )
    }

    #[test]
    fn sequential_decoder_uses_the_actual_per_column_formats_and_nulls() {
        let layout = RowLayout::new(
            vec![
                Column::new("n".into(), Oid::INT4),
                Column::new("s".into(), Oid::TEXT),
                Column::new("b".into(), Oid::BYTEA),
            ],
            ResultFormats::PerColumn(
                vec![Format::Binary, Format::Text, Format::Binary].into_boxed_slice(),
            ),
        )
        .unwrap();
        let mut body = Vec::from(3_u16.to_be_bytes());
        body.extend_from_slice(&4_i32.to_be_bytes());
        body.extend_from_slice(&123_i32.to_be_bytes());
        body.extend_from_slice(&(-1_i32).to_be_bytes());
        body.extend_from_slice(&0_i32.to_be_bytes());
        let row = RowView::new(data(&body), &layout).unwrap();
        let mut decoder = row.decoder();
        assert_eq!(decoder.decode_next::<i32>().unwrap(), 123);
        assert_eq!(decoder.decode_next::<Option<&str>>().unwrap(), None);
        assert_eq!(decoder.decode_next::<&[u8]>().unwrap(), b"");
        decoder.finish().unwrap();
        assert_eq!(layout.column_index("s").unwrap(), 1);
        assert!(layout.column_index("missing").is_err());
    }

    #[test]
    fn owned_rows_and_fields_report_the_exact_remaining_count() {
        let layout = int4_layout();
        let body = int4_body(7);
        let row = RowView::new(data(&body), &layout).unwrap();
        let mut batch = OwnedBatch::new(layout.clone(), 2, 24).unwrap();
        batch.push(row).unwrap();
        batch.push(row).unwrap();

        let mut rows = batch.rows();
        assert_eq!(rows.len(), 2);
        let mut fields = rows.next().unwrap().unwrap().fields();
        assert_eq!(fields.size_hint(), (1, Some(1)));
        assert_eq!(fields.next().unwrap().unwrap().decode::<i32>().unwrap(), 7);
        assert_eq!(fields.size_hint(), (0, Some(0)));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows.nth(1).map(|_| ()), None);
        assert_eq!(rows.size_hint(), (0, Some(0)));
    }

    #[test]
    fn projection_skips_raw_content_without_claiming_scalar_validation() {
        let layout = RowLayout::new(
            vec![
                Column::new("value".into(), Oid::INT4),
                Column::new("unused".into(), Oid::TEXT),
            ],
            ResultFormats::All(Format::Binary),
        )
        .unwrap();
        let mut body = Vec::from(2_u16.to_be_bytes());
        body.extend_from_slice(&4_i32.to_be_bytes());
        body.extend_from_slice(&7_i32.to_be_bytes());
        body.extend_from_slice(&1_i32.to_be_bytes());
        body.push(255);
        let row = RowView::new(data(&body), &layout).unwrap();
        let mut decoder = row.decoder();
        assert_eq!(decoder.decode_next::<i32>().unwrap(), 7);
        assert!(decoder.finish().is_err());
        let mut decoder = row.decoder();
        decoder.skip().unwrap();
        assert!(decoder.decode_next::<&str>().is_err());
        let mut decoder = row.decoder();
        assert_eq!(decoder.decode_next::<i32>().unwrap(), 7);
        decoder.skip().unwrap();
        decoder.finish().unwrap();
    }

    #[test]
    fn incompatible_layouts_and_ambiguous_names_are_rejected() {
        assert!(
            RowLayout::new(
                vec![Column::new("a".into(), Oid::INT4)],
                ResultFormats::PerColumn(Vec::new().into_boxed_slice()),
            )
            .is_err()
        );
        let layout = RowLayout::new(
            vec![
                Column::new("same".into(), Oid::INT4),
                Column::new("same".into(), Oid::TEXT),
            ],
            ResultFormats::All(Format::Binary),
        )
        .unwrap();
        assert!(layout.column_index("same").is_err());
        assert!(RowView::new(data(&int4_body(1)), &layout).is_err());
        let float_layout = RowLayout::new(
            vec![Column::new("same_width".into(), Oid::FLOAT4)],
            ResultFormats::All(Format::Binary),
        )
        .unwrap();
        let body = int4_body(1);
        let row = RowView::new(data(&body), &float_layout).unwrap();
        assert!(matches!(
            row.decoder().decode_next::<i32>(),
            Err(CodecError::WrongType { .. })
        ));
    }

    #[test]
    fn owned_row_survives_source_storage_and_metadata_owner_release() {
        let layout = int4_layout();
        let owned = {
            let body = int4_body(99);
            let view = RowView::new(data(&body), &layout).unwrap();
            assert!(OwnedRow::copy_from(view, layout.clone(), 7).is_err());
            OwnedRow::copy_from(view, layout.clone(), 8).unwrap()
        };
        drop(layout);
        let mut decoder = owned.view().decoder();
        assert_eq!(decoder.decode_next::<i32>().unwrap(), 99);
        decoder.finish().unwrap();
        assert_eq!(owned.retained_bytes(), 8);
    }

    #[test]
    fn owned_batch_is_one_fixed_arena_and_limit_failure_keeps_existing_rows() {
        const _: () = assert!(
            size_of::<OwnedBatch>()
                == size_of::<Rc<RowLayout>>() + size_of::<Vec<u8>>() + 2 * size_of::<usize>()
        );
        let layout = int4_layout();
        let first = int4_body(1);
        let second = int4_body(2);
        let mut batch = OwnedBatch::new(layout.clone(), 2, 24).unwrap();
        let capacity = batch.retained_bytes();
        batch
            .push(RowView::new(data(&first), &layout).unwrap())
            .unwrap();
        batch
            .push(RowView::new(data(&second), &layout).unwrap())
            .unwrap();
        assert_eq!(batch.retained_bytes(), capacity);
        assert_eq!(batch.used_bytes(), 24);
        assert!(batch.storage.starts_with(&8_u32.to_ne_bytes()));
        assert_eq!(batch.len(), 2);
        assert!(matches!(
            batch.push(RowView::new(data(&first), &layout).unwrap()),
            Err(CodecError::Limit(_))
        ));
        assert_eq!(batch.len(), 2);
        let decoded = batch
            .rows()
            .map(|row| row.unwrap().decoder().decode_next::<i32>())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(decoded, [1, 2]);
        let different_layout = int4_layout();
        let mut empty = OwnedBatch::new(layout.clone(), 1, 12).unwrap();
        assert!(
            empty
                .push(RowView::new(data(&first), &different_layout).unwrap())
                .is_err()
        );
        assert!(empty.is_empty());
        let mut short = OwnedBatch::new(layout.clone(), 2, 23).unwrap();
        short
            .push(RowView::new(data(&first), &layout).unwrap())
            .unwrap();
        assert!(
            short
                .push(RowView::new(data(&second), &layout).unwrap())
                .is_err()
        );
        assert_eq!(short.len(), 1);
        assert_eq!(short.used_bytes(), 12);
        batch.clear();
        assert!(batch.is_empty());
        assert_eq!(batch.retained_bytes(), capacity);
    }

    #[test]
    fn reserved_visitor_arena_can_rebind_after_the_previous_borrow_ends() {
        let previous_layout = int4_layout();
        let next_layout = Rc::new(
            RowLayout::new(
                vec![Column::new("next".into(), Oid::INT4)],
                ResultFormats::All(Format::Binary),
            )
            .unwrap(),
        );
        let mut batch = OwnedBatch::new(previous_layout.clone(), 1, 24).unwrap();
        let previous = int4_body(1);
        batch
            .push(RowView::new(data(&previous), &previous_layout).unwrap())
            .unwrap();
        let allocation = batch.storage.as_ptr();

        let mut batch = batch.reuse_for::<false>(&next_layout, 2, 24).unwrap();
        assert!(batch.is_empty());
        assert_eq!(batch.storage.as_ptr(), allocation);
        let next = int4_body(42);
        let view = RowView::new(data(&next), &next_layout).unwrap();
        batch.push(view).unwrap();
        batch.push(view).unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(
            batch
                .rows()
                .next()
                .unwrap()
                .unwrap()
                .layout()
                .column(0)
                .unwrap()
                .name,
            "next"
        );
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    #[ignore = "分配诊断须单独运行，以隔离进程级计数"]
    fn rebinding_and_filling_an_existing_arena_do_not_allocate() {
        let exchange_layout = int4_layout();
        let next_layout = int4_layout();
        let body = int4_body(7);
        let previous = RowView::new(data(&body), &exchange_layout).unwrap();
        let next = RowView::new(data(&body), &next_layout).unwrap();
        for grow in [false, true] {
            let mut batch = OwnedBatch::new(Rc::clone(&exchange_layout), 1, 24).unwrap();
            batch.push(previous).unwrap();
            let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
            let mut batch = if grow {
                batch.reuse_for::<true>(&next_layout, 2, 32).unwrap()
            } else {
                batch.reuse_for::<false>(&next_layout, 2, 24).unwrap()
            };
            batch.push(next).unwrap();
            batch.push(next).unwrap();
            let change = region.change();
            assert_eq!(change.allocations, 0);
            assert_eq!(change.reallocations, 0);
            assert_eq!(batch.len(), 2);
            assert_eq!(batch.used_bytes(), 24);
        }
    }

    #[test]
    fn private_batch_growth_keeps_public_push_fixed_and_errors_preserve_rows() {
        let layout = int4_layout();
        let body = int4_body(7);
        let row = RowView::new(data(&body), &layout).unwrap();
        let mut batch = OwnedBatch::new(layout.clone(), 8, 0).unwrap();
        batch.push_growing(row, 64 * 1024 * 1024).unwrap();
        assert_eq!(batch.retained_bytes(), 12);
        assert_eq!(batch.used_bytes(), 12);
        let pointer = batch.storage.as_ptr();
        assert!(matches!(batch.push(row), Err(CodecError::Limit(_))));
        assert_eq!(batch.storage.as_ptr(), pointer);
        assert_eq!(batch.retained_bytes(), 12);
        assert_eq!(batch.len(), 1);

        for expected_capacity in [24, 48, 48, 60] {
            batch.push_growing(row, 60).unwrap();
            assert_eq!(batch.retained_bytes(), expected_capacity);
        }
        let pointer = batch.storage.as_ptr();
        for maximum in [60, 59, 0] {
            assert!(matches!(
                batch.push_growing(row, maximum),
                Err(CodecError::Limit(_))
            ));
            assert_eq!(batch.storage.as_ptr(), pointer);
            assert_eq!(batch.retained_bytes(), 60);
            assert_eq!(batch.used_bytes(), 60);
            assert_eq!(batch.len(), 5);
        }
        let different_layout = int4_layout();
        let different_row = RowView::new(data(&body), &different_layout).unwrap();
        assert!(matches!(
            batch.push_growing(different_row, 120),
            Err(CodecError::Invalid(_))
        ));
        assert_eq!(batch.storage.as_ptr(), pointer);
        assert_eq!(batch.retained_bytes(), 60);
        assert_eq!(batch.used_bytes(), 60);
        let values = batch
            .rows()
            .map(|row| row.unwrap().decoder().decode_next::<i32>())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(values, [7; 5]);

        batch.clear();
        for _ in 0..5 {
            batch.push(row).unwrap();
        }
        assert!(matches!(batch.push(row), Err(CodecError::Limit(_))));
        assert_eq!(batch.storage.as_ptr(), pointer);
        assert_eq!(batch.retained_bytes(), 60);

        let mut one_row = OwnedBatch::new(layout.clone(), 1, 0).unwrap();
        one_row.push_growing(row, 60).unwrap();
        let pointer = one_row.storage.as_ptr();
        assert!(matches!(
            one_row.push_growing(row, 60),
            Err(CodecError::Limit(_))
        ));
        assert_eq!(one_row.storage.as_ptr(), pointer);
        assert_eq!(one_row.len(), 1);
        assert_eq!(one_row.retained_bytes(), 12);
    }

    #[test]
    fn reported_formats_and_name_storage_match_the_validated_wire_fields() {
        const _: () = assert!(size_of::<ColumnSlot>() == 24);
        for formats in [
            &[][..],
            &[Format::Text, Format::Text],
            &[Format::Binary, Format::Binary],
            &[Format::Binary, Format::Text, Format::Binary],
        ] {
            let mut body = Vec::from(u16::try_from(formats.len()).unwrap().to_be_bytes());
            let names = ["id", "", "状态"];
            for (name, format) in names.iter().zip(formats) {
                body.extend_from_slice(name.as_bytes());
                body.push(0);
                body.extend_from_slice(&[0; 16]);
                body.extend_from_slice(&format.code().to_be_bytes());
            }
            let BackendMessage::RowDescription(description) = parse_backend(Frame {
                tag: b'T',
                body: &body,
            })
            .unwrap() else {
                unreachable!();
            };
            assert_eq!(
                description.name_bytes(),
                names[..formats.len()]
                    .iter()
                    .map(|name| name.len())
                    .sum::<usize>()
            );
            let layout = RowLayout::from_reported_description(description, 4096).unwrap();
            assert_eq!(layout.len(), formats.len());
            for (index, format) in formats.iter().enumerate() {
                assert_eq!(layout.formats().format(index), Some(*format));
            }
            let mut row = Vec::from(u16::try_from(formats.len()).unwrap().to_be_bytes());
            for _ in formats {
                row.extend_from_slice(&(-1_i32).to_be_bytes());
            }
            assert!(
                RowView::new(data(&row), &layout)
                    .unwrap()
                    .fields()
                    .map(|field| field.unwrap().format)
                    .eq(formats.iter().copied())
            );
            for candidate in [Format::Text, Format::Binary] {
                assert_eq!(
                    ResultFormats::All(candidate)
                        .matches_reported(description)
                        .unwrap(),
                    formats.iter().all(|format| *format == candidate)
                );
            }
            assert!(
                ResultFormats::PerColumn(formats.into())
                    .matches_reported(description)
                    .unwrap()
            );
        }
    }

    fn description_body(columns: &[(&str, Format)]) -> Vec<u8> {
        let mut body = Vec::from(u16::try_from(columns.len()).unwrap().to_be_bytes());
        for &(name, format) in columns {
            body.extend_from_slice(name.as_bytes());
            body.push(0);
            body.extend_from_slice(&17_u32.to_be_bytes());
            body.extend_from_slice(&(-3_i16).to_be_bytes());
            body.extend_from_slice(&Oid::INT4.0.to_be_bytes());
            body.extend_from_slice(&4_i16.to_be_bytes());
            body.extend_from_slice(&(-1_i32).to_be_bytes());
            body.extend_from_slice(&format.code().to_be_bytes());
        }
        body
    }

    #[test]
    fn compact_layout_retains_mixed_names_and_metadata_after_the_frame_is_dropped() {
        let columns = [
            ("id", Format::Binary),
            ("", Format::Text),
            ("状态", Format::Binary),
            ("id", Format::Text),
        ];
        let exact = size_of::<RowLayout>()
            + columns.len() * (size_of::<ColumnSlot>() + size_of::<Format>())
            + columns.iter().map(|(name, _)| name.len()).sum::<usize>();
        let layout = {
            let body = description_body(&columns);
            let BackendMessage::RowDescription(description) = parse_backend(Frame {
                tag: b'T',
                body: &body,
            })
            .unwrap() else {
                panic!("expected row description");
            };
            assert!(matches!(
                RowLayout::from_reported_description(description, exact - 1),
                Err(crate::Error::Codec(error)) if matches!(*error, CodecError::Limit(_))
            ));
            RowLayout::from_reported_description(description, exact).unwrap()
        };
        assert_eq!(layout.retained_bytes(), exact);
        let mut descriptions = layout.columns();
        assert_eq!(descriptions.len(), 4);
        assert_eq!(descriptions.next_back().unwrap().name, "id");
        assert_eq!(descriptions.next().unwrap().name, "id");
        assert_eq!(descriptions.next().unwrap().name, "");
        assert_eq!(descriptions.next_back().unwrap().name, "状态");
        assert!(descriptions.next().is_none());
        assert_eq!(layout.column_index("状态").unwrap(), 2);
        assert!(matches!(
            layout.column_index("id"),
            Err(CodecError::Invalid("column name is ambiguous"))
        ));
        assert!(layout.column(4).is_none());
        assert_eq!(
            layout.column(2).unwrap(),
            ColumnRef {
                name: "状态",
                table_oid: Oid(17),
                column_id: -3,
                type_oid: Oid::INT4,
                type_size: 4,
                type_modifier: -1,
            }
        );
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    #[ignore = "分配诊断须单独运行，以隔离进程级计数"]
    fn described_columns_share_two_backings_plus_mixed_formats() {
        let names: Vec<_> = (0..32).map(|index| format!("结果_{index}")).collect();
        for mixed in [false, true] {
            let fields: Vec<_> = names
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    let format = if mixed && index == 0 {
                        Format::Text
                    } else {
                        Format::Binary
                    };
                    (name.as_str(), format)
                })
                .collect();
            let body = description_body(&fields);
            let BackendMessage::RowDescription(description) = parse_backend(Frame {
                tag: b'T',
                body: &body,
            })
            .unwrap() else {
                panic!("expected row description");
            };
            let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
            let layout = RowLayout::from_reported_description(description, 4096).unwrap();
            let delta = region.change();
            assert_eq!(delta.allocations, 2 + usize::from(mixed));
            assert_eq!(delta.reallocations, 0);
            assert_eq!(
                delta.bytes_allocated,
                layout.retained_bytes() - size_of::<RowLayout>()
            );
            assert!(
                layout
                    .columns()
                    .map(|column| column.name)
                    .eq(names.iter().map(String::as_str))
            );
        }
    }

    #[test]
    fn cold_description_uses_bind_format_and_has_a_metadata_limit() {
        let mut bytes = Vec::from(1_u16.to_be_bytes());
        bytes.extend_from_slice(b"value\0");
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.extend_from_slice(&0_i16.to_be_bytes());
        bytes.extend_from_slice(&23_u32.to_be_bytes());
        bytes.extend_from_slice(&4_i16.to_be_bytes());
        bytes.extend_from_slice(&(-1_i32).to_be_bytes());
        bytes.extend_from_slice(&0_i16.to_be_bytes());
        let description = match parse_backend(Frame {
            tag: b'T',
            body: &bytes,
        })
        .unwrap()
        {
            BackendMessage::RowDescription(value) => value,
            _ => panic!("expected description"),
        };
        let layout =
            RowLayout::from_description(description, ResultFormats::All(Format::Binary), 4096)
                .unwrap();
        assert_eq!(layout.formats().format(0), Some(Format::Binary));
        assert_eq!(
            RowView::new(data(&int4_body(42)), &layout)
                .unwrap()
                .decoder()
                .decode_next::<i32>()
                .unwrap(),
            42
        );
        assert_eq!(layout.column(0).unwrap().name, "value");
        let exact = layout.retained_bytes();
        assert!(
            RowLayout::from_description(description, ResultFormats::All(Format::Binary), exact)
                .is_ok()
        );
        assert!(
            RowLayout::from_description(description, ResultFormats::All(Format::Binary), exact - 1)
                .is_err()
        );
        let mut checked = 0;
        let failure = RowLayout::from_description_checked::<crate::Error>(
            description,
            ResultFormats::PerColumn(Vec::new().into_boxed_slice()),
            Err(crate::Error::Limit("deferred registry budget")),
            |description, formats| {
                checked += 1;
                if !formats.matches_reported(description)? {
                    return Err(crate::Error::Protocol(
                        crate::protocol::ProtocolError::InvalidMessage("wire format mismatch"),
                    ));
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(checked, 1);
        assert!(matches!(failure, crate::Error::Protocol(_)));
        let combined = RowLayout::from_description_checked::<crate::Error>(
            description,
            ResultFormats::All(Format::Binary),
            Ok(exact),
            |description, _| {
                if description.uniform_format() != Some(Format::Text) {
                    return Err(crate::Error::Protocol(
                        crate::protocol::ProtocolError::InvalidMessage("statement format mismatch"),
                    ));
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(combined.retained_bytes(), exact);
        assert!(combined.columns().eq(layout.columns()));

        let mut pending = Some(ResultFormats::PerColumn(
            vec![Format::Binary].into_boxed_slice(),
        ));
        let format_pointer = pending.as_ref().unwrap().as_slice().as_ptr();
        assert!(matches!(
            RowLayout::from_pending_description::<crate::Error>(
                description, &mut pending, Ok(0), |_, _| Ok(()),
            ),
            Err(crate::Error::Codec(error)) if matches!(*error, CodecError::Limit(_))
        ));
        assert_eq!(
            pending.as_ref().unwrap().as_slice().as_ptr(),
            format_pointer
        );
        assert!(matches!(
            RowLayout::from_pending_description::<crate::Error>(
                description,
                &mut pending,
                Ok(4096),
                |_, _| Err(crate::Error::InvalidInput("caller validation")),
            ),
            Err(crate::Error::InvalidInput("caller validation"))
        ));
        assert_eq!(
            pending.as_ref().unwrap().as_slice().as_ptr(),
            format_pointer
        );
        let owned = RowLayout::from_pending_description::<crate::Error>(
            description,
            &mut pending,
            Ok(4096),
            |_, _| Ok(()),
        )
        .unwrap();
        assert!(pending.is_none());
        assert_eq!(owned.formats().as_slice().as_ptr(), format_pointer);

        let mut empty_formats = Some(ResultFormats::All(Format::Binary));
        assert!(matches!(
            RowLayout::empty_from_pending(&mut empty_formats, 0),
            Err(CodecError::Limit(_))
        ));
        assert_eq!(empty_formats, Some(ResultFormats::All(Format::Binary)));
        let empty = RowLayout::empty_from_pending(&mut empty_formats, 4096).unwrap();
        assert!(empty_formats.is_none());
        assert_eq!(
            empty.retained_bytes(),
            RowLayout::new(Vec::new(), ResultFormats::All(Format::Binary))
                .unwrap()
                .retained_bytes()
        );
    }
}
