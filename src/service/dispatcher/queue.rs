use std::num::NonZeroUsize;

use super::DriverError;

// 槽位从一开始编号，可空链接只占一个机器字。支持撤回任意槽位的队列还需保存前驱链接。
type Link = Option<NonZeroUsize>;
type PoppedEntry<'a, T, P> = (NonZeroUsize, &'a mut Entry<T, P>);

pub(super) trait Previous: Default {
    const TRACKED: bool;
    fn set(&mut self, link: Link);
}

impl Previous for Link {
    const TRACKED: bool = true;
    fn set(&mut self, link: Link) {
        *self = link;
    }
}

impl Previous for () {
    const TRACKED: bool = false;
    fn set(&mut self, _: Link) {}
}

impl<T, P> Entry<T, P> {
    #[inline]
    pub(super) fn get(slots: &[Self], id: NonZeroUsize) -> Result<&Self, DriverError> {
        slots.get(id.get() - 1).ok_or(DriverError::InvalidState)
    }

    #[inline]
    pub(super) fn get_mut(slots: &mut [Self], id: NonZeroUsize) -> Result<&mut Self, DriverError> {
        slots.get_mut(id.get() - 1).ok_or(DriverError::InvalidState)
    }
}

pub(super) struct Entry<T, P = Link> {
    previous: P,
    next: Link,
    pub(super) value: T,
}

impl<T, P: Previous> Entry<T, P> {
    pub(super) fn new(value: T) -> Self {
        Self {
            previous: P::default(),
            next: None,
            value,
        }
    }

    pub(super) fn link_free_slot(&mut self, next: Link) {
        self.next = next;
    }

    pub(super) fn take_free_link(&mut self) -> Link {
        self.next.take()
    }
}

/// 队列使用槽内链接，已入队槽可直接撤除，入队和拼接无需移动载荷。
/// 队列及每个入队槽的编号与同一张槽表关联，编号存续期间其槽位必须保留。
#[derive(Default)]
pub(super) struct IndexQueue {
    first: Link,
    last: Link,
    len: usize,
}

impl IndexQueue {
    pub(super) fn front(&self) -> Link {
        self.first
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn is_empty(&self) -> bool {
        self.first.is_none()
    }

    pub(super) fn push<'a, T, P: Previous>(
        &mut self,
        id: NonZeroUsize,
        slots: &'a mut [Entry<T, P>],
    ) -> Result<&'a mut T, DriverError> {
        let len = self.len.checked_add(1).ok_or(DriverError::InvalidState)?;
        let slot = self.link_tail(id, slots)?;
        self.last = Some(id);
        self.len = len;
        Ok(&mut slot.value)
    }

    pub(super) fn pop_front<'a, T, P: Previous>(
        &mut self,
        slots: &'a mut [Entry<T, P>],
    ) -> Result<Option<PoppedEntry<'a, T, P>>, DriverError> {
        self.pop_front_when(slots, |_| Ok(true))
    }

    /// 检查队首的接纳或轮询条件。检查失败时保留原队首及链接。
    pub(super) fn pop_front_when<'a, T, P: Previous>(
        &mut self,
        slots: &'a mut [Entry<T, P>],
        eligible: impl FnOnce(&T) -> Result<bool, DriverError>,
    ) -> Result<Option<PoppedEntry<'a, T, P>>, DriverError> {
        let Some(id) = self.first else {
            return Ok(None);
        };
        let len = self.len.checked_sub(1).ok_or(DriverError::InvalidState)?;
        let slot = if P::TRACKED {
            let first = Entry::get(slots, id)?;
            if !eligible(&first.value)? {
                return Ok(None);
            }
            if let Some(next) = first.next {
                let [slot, successor] = slots
                    .get_disjoint_mut([id.get() - 1, next.get() - 1])
                    .map_err(|_| DriverError::InvalidState)?;
                successor.previous.set(None);
                slot
            } else {
                Entry::get_mut(slots, id)?
            }
        } else {
            let slot = Entry::get_mut(slots, id)?;
            if !eligible(&slot.value)? {
                return Ok(None);
            }
            slot
        };
        self.first = slot.next.take();
        if self.first.is_none() {
            self.last = None;
        }
        self.len = len;
        Ok(Some((id, slot)))
    }

    pub(super) fn remove<T>(
        &mut self,
        id: NonZeroUsize,
        slots: &mut [Entry<T>],
    ) -> Result<(), DriverError> {
        let len = self.len.checked_sub(1).ok_or(DriverError::InvalidState)?;
        let slot = Entry::get_mut(slots, id)?;
        let (previous, next) = (slot.previous, slot.next);
        let slot = match (previous, next) {
            (Some(previous), Some(next)) => {
                let [slot, before, after] = slots
                    .get_disjoint_mut([id.get() - 1, previous.get() - 1, next.get() - 1])
                    .map_err(|_| DriverError::InvalidState)?;
                before.next = Some(next);
                after.previous = Some(previous);
                slot
            }
            (Some(previous), None) => {
                let [slot, before] = slots
                    .get_disjoint_mut([id.get() - 1, previous.get() - 1])
                    .map_err(|_| DriverError::InvalidState)?;
                before.next = None;
                slot
            }
            (None, Some(next)) => {
                let [slot, after] = slots
                    .get_disjoint_mut([id.get() - 1, next.get() - 1])
                    .map_err(|_| DriverError::InvalidState)?;
                after.previous = None;
                slot
            }
            (None, None) => slot,
        };
        slot.previous = None;
        slot.next = None;
        if previous.is_none() {
            self.first = next;
        }
        if next.is_none() {
            self.last = previous;
        }
        self.len = len;
        Ok(())
    }

    /// 槽位刚从同一张槽表的队列取出，仍然有效且没有后继。
    pub(super) fn push_detached<T>(
        &mut self,
        id: NonZeroUsize,
        slots: &mut [Entry<T, ()>],
    ) -> Result<(), DriverError> {
        let len = self.len.checked_add(1).ok_or(DriverError::InvalidState)?;
        self.link_forward_tail(id, slots)?;
        self.last = Some(id);
        self.len = len;
        Ok(())
    }

    pub(super) fn append<T>(
        &mut self,
        pending: &mut Self,
        slots: &mut [Entry<T, ()>],
    ) -> Result<(), DriverError> {
        let Some(first) = pending.first else {
            return Ok(());
        };
        let len = self
            .len
            .checked_add(pending.len)
            .ok_or(DriverError::InvalidState)?;
        self.link_forward_tail(first, slots)?;
        self.last = pending.last;
        self.len = len;
        *pending = Self::default();
        Ok(())
    }

    fn link_forward_tail<T>(
        &mut self,
        next: NonZeroUsize,
        slots: &mut [Entry<T, ()>],
    ) -> Result<(), DriverError> {
        if let Some(last) = self.last {
            if last == next {
                return Err(DriverError::InvalidState);
            }
            Entry::get_mut(slots, last)?.next = Some(next);
        } else {
            self.first = Some(next);
        }
        Ok(())
    }

    fn link_tail<'a, T, P: Previous>(
        &mut self,
        next: NonZeroUsize,
        slots: &'a mut [Entry<T, P>],
    ) -> Result<&'a mut Entry<T, P>, DriverError> {
        if let Some(last) = self.last {
            let [tail, following] = slots
                .get_disjoint_mut([last.get() - 1, next.get() - 1])
                .map_err(|_| DriverError::InvalidState)?;
            tail.next = Some(next);
            following.previous.set(Some(last));
            Ok(following)
        } else {
            let first = Entry::get_mut(slots, next)?;
            first.previous.set(None);
            self.first = Some(next);
            Ok(first)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invalid_neighbor_does_not_remove_a_queued_slot() {
        let [first, middle, last, missing] =
            std::array::from_fn(|index| NonZeroUsize::MIN.checked_add(index).unwrap());
        let mut slots = [Entry::new(1), Entry::new(2), Entry::new(3)];
        let mut queue = IndexQueue::default();
        for id in [first, middle, last] {
            queue.push(id, &mut slots).unwrap();
        }
        Entry::get_mut(&mut slots, middle).unwrap().next = Some(missing);
        assert_eq!(
            queue.remove(middle, &mut slots),
            Err(DriverError::InvalidState)
        );
        assert_eq!(queue.len(), 3);
        assert_eq!(Entry::get(&slots, first).unwrap().next, Some(middle));
        assert_eq!(Entry::get(&slots, last).unwrap().previous, Some(middle));

        Entry::get_mut(&mut slots, middle).unwrap().next = Some(last);
        queue.remove(middle, &mut slots).unwrap();
        let (id, slot) = queue.pop_front(&mut slots).unwrap().unwrap();
        assert_eq!(id, first);
        assert_eq!(queue.len(), 1);
        slot.value = 4;
        assert_eq!(Entry::get(&slots, first).unwrap().value, 4);
        let (id, slot) = queue.pop_front(&mut slots).unwrap().unwrap();
        assert_eq!((id, slot.value), (last, 3));
        assert!(queue.is_empty());
    }
}
