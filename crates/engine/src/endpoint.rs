//! Owned transport input, with the host's explicit peer authority.
use crate::Error;
use std::net::SocketAddr;
use tokio::net::{TcpStream, UnixStream};

/// One owned endpoint transport, not permission to dial or reconnect.
///
/// TCP inputs derive their peer from the socket. A relay input requires a trusted
/// host to attest its fixed upstream peer; its Unix channel conveys no IP socket
/// capability. The engine still checks the approved endpoint against the profile.
/// Dropping this value closes its transport. Debug never exposes peer addresses.
pub struct EndpointStream {
    pub(crate) inner: Box<dyn meow_transport::Stream>,
    pub(crate) peer: SocketAddr,
}

impl std::fmt::Debug for EndpointStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EndpointStream([redacted])")
    }
}

impl EndpointStream {
    /// Accept an owned Unix payload channel from a trusted, endpoint-confined
    /// supervisor. The caller must authenticate that supervisor/control channel;
    /// this constructor cannot discover or authenticate the remote IP of a relay.
    /// No DNS, socket creation, handshake or fallback. Invalid peer metadata closes
    /// the supplied channel and returns `Error::Endpoint` without external changes.
    pub fn relayed(stream: UnixStream, peer: SocketAddr) -> Result<Self, Error> {
        if peer.port() == 0 || peer.ip().is_unspecified() {
            return Err(Error::Endpoint);
        }
        Ok(Self {
            inner: Box::new(stream),
            peer,
        })
    }
}

impl TryFrom<TcpStream> for EndpointStream {
    type Error = Error;
    fn try_from(stream: TcpStream) -> Result<Self, Error> {
        let peer = stream.peer_addr().map_err(|_| Error::Endpoint)?;
        Ok(Self {
            inner: Box::new(stream),
            peer,
        })
    }
}
