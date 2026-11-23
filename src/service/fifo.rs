use std::{
    collections::{TryReserveError, VecDeque},
    fmt,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueLimits {
    pub max_items: usize,
    pub max_charged_bytes: usize,
}

impl QueueLimits {
    pub(super) fn rejection(
        self,
        items: usize,
        bytes: usize,
        additional_bytes: usize,
    ) -> Option<RejectReason> {
        if additional_bytes > self.max_charged_bytes {
            Some(RejectReason::Oversize)
        } else if items == self.max_items {
            Some(RejectReason::ItemLimit)
        } else if additional_bytes > self.max_charged_bytes - bytes {
            Some(RejectReason::ByteLimit)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    Oversize,
    ItemLimit,
    ByteLimit,
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Oversize => "the request exceeds the queue byte limit",
            Self::ItemLimit => "the queue has reached its request limit",
            Self::ByteLimit => "the request would exceed the remaining queue byte budget",
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Rejected<T> {
    pub item: T,
    pub reason: RejectReason,
}

/// 预分配的本地 FIFO。字节额度由调用方按请求存储计量，队列元数据另外预留。
pub struct BoundedFifo<T> {
    items: VecDeque<(T, usize)>,
    limits: QueueLimits,
    charged_bytes: usize,
}

impl<T> BoundedFifo<T> {
    pub fn try_new(limits: QueueLimits) -> Result<Self, TryReserveError> {
        let mut items = VecDeque::new();
        items.try_reserve_exact(limits.max_items)?;
        Ok(Self {
            items,
            limits,
            charged_bytes: 0,
        })
    }

    /// 请求数限额为零时拒绝所有排队请求。
    pub fn try_push_back(&mut self, item: T, charged_bytes: usize) -> Result<(), Rejected<T>> {
        if let Some(reason) =
            self.limits
                .rejection(self.items.len(), self.charged_bytes, charged_bytes)
        {
            return Err(Rejected { item, reason });
        }
        self.items.push_back((item, charged_bytes));
        self.charged_bytes += charged_bytes;
        Ok(())
    }

    pub fn front(&self) -> Option<&T> {
        self.items.front().map(|(item, _)| item)
    }

    pub fn pop_front(&mut self) -> Option<T> {
        let (item, charged_bytes) = self.items.pop_front()?;
        self.charged_bytes -= charged_bytes;
        Some(item)
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn charged_bytes(&self) -> usize {
        self.charged_bytes
    }
}
