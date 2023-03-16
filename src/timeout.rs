/// Attempt to await an async value within a given timeframe.
macro_rules! timeout {
    ($value:expr, $ms:expr, $msg:expr) => {
        ::tokio::select! {
            x = $value => {
                Ok(x)
            },
            _ = ::tokio::time::sleep(::std::time::Duration::from_millis($ms)) => {
                ::core::result::Result::Err(::std::io::Error::new(::std::io::ErrorKind::TimedOut, $msg))
            }
        }
    };
}

/// Attempt to await reading from a socket with the default data read timeout.
macro_rules! data_read_timeout {
    ($value:expr) => {
        $crate::timeout::timeout!(
            $value,
            $crate::util::DATA_READ_TIMEOUT,
            "timed out waiting for data from socket"
        )
    };
}

/// Attempt to await performing a handshake with the default handshake timeout.
macro_rules! handshake_timeout {
    ($value:expr) => {
        $crate::timeout::timeout!(
            $value,
            $crate::util::HANDSHAKE_TIMEOUT,
            "timed out waiting for handshake"
        )
    };
}

pub(crate) use data_read_timeout;
pub(crate) use handshake_timeout;
pub(crate) use timeout;

// use crate::util::DATA_READ_TIMEOUT;
// use std::future::Future;
// use std::io;
// use std::time::Duration;

// async fn wait() {
//     tokio::time::sleep(Duration::from_millis(DATA_READ_TIMEOUT)).await;
// }

// pub async fn timeout<F, V, T>(callback: F) -> io::Result<T>
// where
//     F: FnOnce() -> V,
//     V: Future<Output = T>,
// {
//     tokio::select! {
//         value = callback() => {
//             Ok(value)
//         },
//         _ = wait() => {
//             Err(io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for value"))
//         },
//     }
// }
