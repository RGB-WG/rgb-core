// LNP/BP Rust Library
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

mod error;
mod encode;

pub use error::*;
pub use encode::*;


pub type Multipart = Vec<zmq::Message>;
pub type CommandId = u16;

pub fn split_cmd_args(multipart: &Multipart) -> Result<(CommandId, &[zmq::Message]), Error> {
    Ok(multipart.split_first()
        .ok_or(Error::MalformedRequest)
        .and_then(|(cmd_data, args)| {
            if cmd_data.len() != 2 {
                Err(Error::MalformedCommand)?
            }
            let mut buf = [0u8; 2];
            buf.clone_from_slice(&cmd_data[0..2]);
            Ok((u16::from_be_bytes(buf), args))
        })?)
}
