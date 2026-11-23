use std::future::{Future, Ready};

use crate::{Client, WireTransport};

use super::{
    BatchDispatch, BatchDispatchOperation, DispatchBatch, DispatchOperation, SessionHygiene,
    SingleDispatch,
};

pub trait ExecuteBatch<T: WireTransport, S, O: DispatchOperation<T, S>> {
    fn max_requests(&self) -> usize;

    fn execute(
        &self,
        operation: &O,
        client: &mut Client<T>,
        state: &mut S,
        batch: &mut DispatchBatch<'_, O::Request, O::Response>,
    ) -> Option<impl Future<Output = SessionHygiene>>;
}

impl<T: WireTransport, S, O: DispatchOperation<T, S>> ExecuteBatch<T, S, O> for SingleDispatch {
    fn max_requests(&self) -> usize {
        1
    }

    fn execute(
        &self,
        _: &O,
        _: &mut Client<T>,
        _: &mut S,
        _: &mut DispatchBatch<'_, O::Request, O::Response>,
    ) -> Option<impl Future<Output = SessionHygiene>> {
        None::<Ready<SessionHygiene>>
    }
}

impl<T: WireTransport, S, O: BatchDispatchOperation<T, S>> ExecuteBatch<T, S, O> for BatchDispatch {
    fn max_requests(&self) -> usize {
        self.0.get()
    }

    fn execute(
        &self,
        operation: &O,
        client: &mut Client<T>,
        state: &mut S,
        batch: &mut DispatchBatch<'_, O::Request, O::Response>,
    ) -> Option<impl Future<Output = SessionHygiene>> {
        Some(operation.execute_batch(client, state, batch))
    }
}
