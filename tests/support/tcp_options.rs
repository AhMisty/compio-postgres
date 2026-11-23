use compio_postgres::{TcpNoDelay, TcpOptions};

pub(crate) const TCP_OPTIONS: TcpOptions = TcpOptions::new(TcpNoDelay::Enabled);
