use std::sync::mpsc::Receiver;

/// An iterator over events.
pub struct EventIter<T> {
    /// The event receiver channel.
    event_receiver: Receiver<T>,
}

impl<T> EventIter<T> {
    /// Create a new event iterator. This function is kept internal so that it can be used to create event iterators from within the crate but not from outside.
    ///
    /// `event_receiver`: the event receiver.
    ///
    /// Returns the new event iterator.
    pub(crate) fn new(event_receiver: Receiver<T>) -> Self {
        Self { event_receiver }
    }
}

impl<T> Iterator for EventIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.event_receiver.try_recv().ok()
    }
}
