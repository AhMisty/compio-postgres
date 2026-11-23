use std::num::NonZeroUsize;

use compio_postgres::{TlsNegotiation, TlsOptions, TlsResumption, TlsVersions};

pub(super) fn fixture_tls_options(
    negotiation: TlsNegotiation,
    versions: TlsVersions,
) -> TlsOptions {
    TlsOptions {
        negotiation,
        versions,
        resumption: TlsResumption::InMemory,
        send_buffer_limit: NonZeroUsize::new(64 * 1024),
    }
}
