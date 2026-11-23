//! 预备语句的同步校验与发送包编码。
//! 校验顺序和提交时机由调用方控制，此处的借用仅在当前同步操作内有效。

use super::PreparedAdmission;
use crate::{
    Error,
    frontend::{PreparedExecution, StatementParameters, WindowExecutionLayout},
    protocol::QueryTail,
    types::Parameter,
};

impl PreparedAdmission<'_> {
    pub(in crate::client) fn parameters<'a>(
        &'a self,
        values: &'a [Parameter<'a>],
        count_error: &'static str,
    ) -> Result<StatementParameters<'a>, Error> {
        StatementParameters::new(
            values,
            self.parameter_oids,
            self.name,
            self.bind_formats,
            self.bind_size,
            count_error,
        )
    }

    pub(in crate::client) fn validate_metadata(
        &self,
        max_metadata_bytes: usize,
        message: &'static str,
    ) -> Result<(), Error> {
        if self.layout.retained_bytes() > max_metadata_bytes {
            return Err(Error::Limit(message));
        }
        Ok(())
    }

    /// 核对参数类型后检查本地结果布局，再检查报文大小。
    pub(in crate::client) fn packet<'a>(
        &'a self,
        parameters: &StatementParameters<'a>,
        tail: QueryTail,
        max_bytes: usize,
        type_error: &'static str,
        check_layout: impl FnOnce() -> Result<(), Error>,
    ) -> Result<PreparedExecution<'a>, Error> {
        PreparedExecution::checked(parameters, tail, max_bytes, type_error, check_layout)
    }

    pub(in crate::client) fn window_packet<'a>(
        &'a self,
        parameters: &'a [Parameter<'a>],
        layout: Option<WindowExecutionLayout>,
        max_bytes: usize,
        count_error: &'static str,
        type_error: &'static str,
    ) -> Result<PreparedExecution<'a>, Error> {
        if let Some(layout) = layout {
            return Ok(PreparedExecution::reuse_window(
                self.name,
                parameters,
                self.bind_formats,
                layout,
            ));
        }
        let parameters = self.parameters(parameters, count_error)?;
        self.packet(&parameters, QueryTail::Sync, max_bytes, type_error, || {
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    use crate::{
        client::{
            PreparedStatement, PreparedStatementStorage, Session,
            general::{Extended, Record, RemoteStatement, Slot, StatementData},
        },
        protocol::Format,
        row::{Column, ResultFormats, RowLayout},
        types::Oid,
    };

    fn snapshot() -> (Extended, PreparedStatement) {
        let layout = Rc::new(
            RowLayout::new(
                vec![Column::new("n".to_owned(), Oid::INT4)],
                ResultFormats::All(Format::Binary),
            )
            .unwrap(),
        );
        let name = crate::frontend::StatementName::numbered(0).unwrap();
        let data = Rc::new(
            StatementData::new(
                name.wire(),
                vec![Oid::INT4].into_boxed_slice(),
                layout,
                PreparedStatementStorage::Named,
            )
            .unwrap(),
        );
        let statement = PreparedStatement {
            connection_id: 7,
            slot: 0,
            generation: 1,
            schema_epoch: 0,
            data: Rc::clone(&data),
        };
        let mut extended = Extended::new();
        extended.slots.push(Slot {
            generation: 1,
            record: Some(Record {
                name,
                data: Some(data),
                remote: RemoteStatement::Created,
            }),
        });
        (extended, statement)
    }

    type UnusedTransport = crate::transport::Transport;

    #[test]
    fn validated_null_parameters_preserve_each_sync_and_group_open_tail() {
        let (extended, statement) = snapshot();
        let admission =
            Session::<UnusedTransport>::resolve_prepared(7, Some(&extended), &statement, true)
                .unwrap();
        let parameters = [Parameter::null(Oid::INT4, Format::Binary)];
        let checked = admission.parameters(&parameters, "count").unwrap();
        admission.validate_metadata(4096, "metadata").unwrap();
        let sync = admission
            .packet(&checked, QueryTail::Sync, 4096, "type", || Ok(()))
            .unwrap();
        let group = admission
            .packet(&checked, QueryTail::Open, 4096, "type", || Ok(()))
            .unwrap();
        let mut synchronized = Vec::new();
        let mut open = Vec::new();
        sync.append_to(&mut synchronized, 4096).unwrap();
        group.append_to(&mut open, 4096).unwrap();
        assert_eq!(synchronized.len(), sync.encoded_len());
        assert_eq!(open.len(), group.encoded_len());
        assert_eq!(&synchronized[..open.len()], open);
        assert_eq!(&synchronized[open.len()..], b"S\0\0\0\x04");
        let exact = sync.encode_into(Vec::new(), 4096).unwrap();
        assert_eq!(exact, synchronized);
        let nonnull = [Parameter::int4(0)];
        assert_eq!(
            admission
                .window_packet(&nonnull, None, 4096, "count", "type")
                .unwrap()
                .encoded_len(),
            sync.encoded_len() + 4
        );
    }

    #[test]
    fn type_count_metadata_and_private_append_failures_keep_their_boundaries() {
        let (extended, statement) = snapshot();
        let admission =
            Session::<UnusedTransport>::resolve_prepared(7, Some(&extended), &statement, true)
                .unwrap();
        assert!(matches!(
            admission.parameters(&[], "count"),
            Err(Error::InvalidInput("count"))
        ));
        let wrong = [Parameter::null(Oid::TEXT, Format::Binary)];
        assert!(matches!(
            admission.window_packet(&wrong, None, 4096, "count", "type"),
            Err(Error::InvalidInput("type"))
        ));
        assert!(matches!(
            admission.validate_metadata(0, "metadata"),
            Err(Error::Limit("metadata"))
        ));
        let parameters = [Parameter::int4(42)];
        let execution = admission
            .window_packet(&parameters, None, 4096, "count", "type")
            .unwrap();
        let mut packet = b"private-prefix".to_vec();
        let before = packet.clone();
        let bound = packet.len() + execution.encoded_len() - 1;
        assert!(matches!(
            execution.append_to(&mut packet, bound),
            Err(Error::Limit(_))
        ));
        assert_eq!(packet, before);
    }

    #[test]
    fn closed_foreign_and_invalidated_snapshots_are_not_new_encoding_authority() {
        let (mut extended, statement) = snapshot();
        assert!(matches!(
            Session::<UnusedTransport>::resolve_prepared(8, Some(&extended), &statement, true),
            Err(Error::InvalidInput(_))
        ));
        extended.bump_epoch().unwrap();
        assert!(matches!(
            Session::<UnusedTransport>::resolve_prepared(7, Some(&extended), &statement, true),
            Err(Error::InvalidInput(_))
        ));
        // 布局失效的语句仍可被显式关闭。
        assert!(
            Session::<UnusedTransport>::resolve_prepared(7, Some(&extended), &statement, false)
                .is_ok()
        );
        extended.slots[0].record.as_mut().unwrap().remote = RemoteStatement::Closed { next: None };
        assert!(matches!(
            Session::<UnusedTransport>::resolve_prepared(7, Some(&extended), &statement, false),
            Err(Error::InvalidInput(_))
        ));
    }
}
