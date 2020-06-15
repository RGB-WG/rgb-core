// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use crate::internet::InetSocketAddr;
use ::std::path::PathBuf;

/// Represents a connection to a generic node operating with LNP protocol
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum RemoteAddr {
    /// Direct access to LNP API methods without any serialization/deserialization
    /// of data structures
    Embedded,

    /// Local node operating as a separate **thread**, connected with unencrypted
    /// ZMQ `inproc` socket, utilizing POSIX memory sharing (and not POSIX
    /// sockets), i.e. mutexes, semaphores etc.
    Inproc(String),

    /// Local node operating as a separate **process**, connected with  
    /// unencrypted ZMQ `ipc` POSIX/UNIX socket (using standard POSIX I/O).
    Ipc(PathBuf),

    /// Local node operating as a separate **process**, connected with
    /// unencrypted POSIX file I/O (like in c-lightning)
    File(PathBuf),

    /// Standard TCP socket connection **required** to use end-to-end encryption,
    /// that may be served  either over plain IP, IPSec or Tor v2 and v3
    Tcp(InetSocketAddr),

    /// Standard UDP socket connection **required** to use end-to-end encryption,
    /// that may be served  either over plain IP, IPSec or utilize UDP hole
    /// punching
    Udp(InetSocketAddr),

    /// SMTP connection: asynchronous end-to-end-over SMTP information transfer
    /// which is usefull for ultra-low bandwidth non-real-time connections like
    /// satellite networks
    Smtp(InetSocketAddr),

    /// End-to-end ecnruption over web connection: think of this as LN protocol
    /// streamed over Websocket
    Websocket(InetSocketAddr),
}
