use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc::Receiver;
use tokio_stream::Stream;

/// An asynchronous stream of events.
pub struct EventStream<T> {
    /// The event receiver channel.
    event_receiver: Receiver<T>,
}

impl<T> EventStream<T> {
    /// Create a new event stream. This function is kept internal so that it can be used to create event streams from within the crate but not from outside.
    ///
    /// `event_receiver`: the event receiver.
    ///
    /// Returns the new event stream.
    pub(crate) fn new(event_receiver: Receiver<T>) -> Self {
        Self { event_receiver }
    }
}

impl<T> Stream for EventStream<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.event_receiver.poll_recv(cx)
    }
}
