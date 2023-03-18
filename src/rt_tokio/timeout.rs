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
        super::timeout::timeout!(
            $value,
            $crate::util::DATA_READ_TIMEOUT,
            "timed out waiting for data from socket"
        )
    };
}

/// Attempt to await performing a handshake with the default handshake timeout.
macro_rules! handshake_timeout {
    ($value:expr) => {
        super::timeout::timeout!(
            $value,
            $crate::util::HANDSHAKE_TIMEOUT,
            "timed out waiting for handshake"
        )
    };
}

pub(super) use data_read_timeout;
pub(super) use handshake_timeout;
pub(super) use timeout;
