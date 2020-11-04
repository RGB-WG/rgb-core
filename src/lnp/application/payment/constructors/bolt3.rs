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

use bitcoin::blockdata::{opcodes::all::*, script};
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::{OutPoint, Transaction, TxIn, TxOut};

use crate::bp::{IntoPk, LexOrder, LockScript, PubkeyScript, WitnessScript};
use crate::lnp::application::payment::ExtensionId;
use crate::lnp::application::{channel, ChannelExtension, Extension, Messages};

pub struct Bolt3 {}

impl Bolt3 {}

impl Extension for Bolt3 {
    type Identity = ExtensionId;

    fn identity(&self) -> Self::Identity {
        ExtensionId::Bolt3
    }

    fn update_from_peer(
        &mut self,
        data: &Messages,
    ) -> Result<(), channel::Error> {
        unimplemented!()
    }

    fn extension_state(&self) -> Box<dyn channel::State> {
        unimplemented!()
    }
}

impl ChannelExtension for Bolt3 {
    fn channel_state(&self) -> Box<dyn channel::State> {
        unimplemented!()
    }

    fn apply(
        &mut self,
        tx_graph: &mut channel::TxGraph,
    ) -> Result<(), channel::Error> {
        unimplemented!()
    }
}

pub trait ScriptGenerators {
    fn ln_funding(amount: u64, pubkey1: PublicKey, pubkey2: PublicKey) -> Self;

    fn ln_to_local(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self;

    fn ln_to_remote_v1(amount: u64, remote_pubkey: PublicKey) -> Self;

    fn ln_to_remote_v2(amount: u64, remote_pubkey: PublicKey) -> Self;
}

impl ScriptGenerators for LockScript {
    fn ln_funding(_: u64, pubkey1: PublicKey, pubkey2: PublicKey) -> Self {
        let pk = vec![pubkey1.into_pk(), pubkey2.into_pk()].lex_ordered();

        script::Builder::new()
            .push_int(2)
            .push_key(&pk[0])
            .push_key(&pk[1])
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
            .into()
    }

    fn ln_to_local(
        _: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        script::Builder::new()
            .push_opcode(OP_IF)
            .push_key(&revocationpubkey.into_pk())
            .push_opcode(OP_ELSE)
            .push_int(to_self_delay as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_key(&local_delayedpubkey.into_pk())
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_CHECKSIG)
            .into_script()
            .into()
    }

    fn ln_to_remote_v1(_: u64, _: PublicKey) -> Self {
        unimplemented!("LockScript can't be generated for to_remote v1 output")
    }

    fn ln_to_remote_v2(_: u64, remote_pubkey: PublicKey) -> Self {
        script::Builder::new()
            .push_key(&remote_pubkey.into_pk())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_int(1)
            .push_opcode(OP_CSV)
            .into_script()
            .into()
    }
}

impl ScriptGenerators for WitnessScript {
    #[inline]
    fn ln_funding(amount: u64, pubkey1: PublicKey, pubkey2: PublicKey) -> Self {
        LockScript::ln_funding(amount, pubkey1, pubkey2).into()
    }

    #[inline]
    fn ln_to_local(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        LockScript::ln_to_local(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .into()
    }

    #[inline]
    fn ln_to_remote_v1(_: u64, _: PublicKey) -> Self {
        unimplemented!(
            "WitnessScript can't be generated for to_remote v1 output"
        )
    }

    fn ln_to_remote_v2(amount: u64, remote_pubkey: PublicKey) -> Self {
        LockScript::ln_to_remote_v2(amount, remote_pubkey).into()
    }
}

impl ScriptGenerators for PubkeyScript {
    #[inline]
    fn ln_funding(amount: u64, pubkey1: PublicKey, pubkey2: PublicKey) -> Self {
        WitnessScript::ln_funding(amount, pubkey1, pubkey2).to_p2wsh()
    }

    #[inline]
    fn ln_to_local(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        WitnessScript::ln_to_local(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .to_p2wsh()
    }

    #[inline]
    fn ln_to_remote_v1(_: u64, remote_pubkey: PublicKey) -> Self {
        remote_pubkey
            .into_pk()
            .wpubkey_hash()
            .expect("We just generated non-compressed key")
            .into()
    }

    #[inline]
    fn ln_to_remote_v2(amount: u64, remote_pubkey: PublicKey) -> Self {
        WitnessScript::ln_to_remote_v2(amount, remote_pubkey).to_p2wsh()
    }
}

impl ScriptGenerators for TxOut {
    #[inline]
    fn ln_funding(amount: u64, pubkey1: PublicKey, pubkey2: PublicKey) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_funding(amount, pubkey1, pubkey2)
                .into(),
        }
    }

    #[inline]
    fn ln_to_local(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_to_local(
                amount,
                revocationpubkey,
                local_delayedpubkey,
                to_self_delay,
            )
            .into(),
        }
    }

    #[inline]
    fn ln_to_remote_v1(amount: u64, remote_pubkey: PublicKey) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_to_remote_v1(amount, remote_pubkey)
                .into(),
        }
    }

    #[inline]
    fn ln_to_remote_v2(amount: u64, remote_pubkey: PublicKey) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_to_remote_v2(amount, remote_pubkey)
                .into(),
        }
    }
}

pub trait TxGenerators {
    fn ln_cmt_base(
        local_amount: u64,
        remote_amount: u64,
        commitment_number: u64,
        obscuring_factor: u64,
        funding_outpoint: OutPoint,
        remote_pubkey: PublicKey,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self;

    fn ln_closing(outpoint: OutPoint, txout: Vec<TxOut>) -> Self;
}

impl TxGenerators for Transaction {
    fn ln_cmt_base(
        local_amount: u64,
        remote_amount: u64,
        commitment_number: u64,
        obscuring_factor: u64,
        funding_outpoint: OutPoint,
        remote_pubkey: PublicKey,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        // The 48-bit commitment number is obscured by XOR with the lower
        // 48 bits of `obscuring_factor`
        let obscured_commitment =
            (commitment_number & 0xFFFFFF) ^ (obscuring_factor & 0xFFFFFF);
        let obscured_commitment = obscured_commitment as u32;
        let lock_time = (0x20u32 << 24) | obscured_commitment;
        let sequence = (0x80u32 << 24) | obscured_commitment;
        let tx = Transaction {
            version: 2,
            lock_time,
            input: vec![TxIn {
                previous_output: funding_outpoint,
                script_sig: none!(),
                sequence,
                witness: empty!(),
            }],
            output: vec![
                TxOut::ln_to_local(
                    local_amount,
                    revocationpubkey,
                    local_delayedpubkey,
                    to_self_delay,
                ),
                TxOut::ln_to_remote_v1(remote_amount, remote_pubkey),
            ],
        };
        tx.lex_ordered()
    }

    fn ln_closing(outpoint: OutPoint, txout: Vec<TxOut>) -> Self {
        Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: none!(),
                sequence: core::u32::MAX,
                witness: empty!(),
            }],
            output: txout,
        }
    }
}

impl TxGenerators for Psbt {
    fn ln_cmt_base(
        local_amount: u64,
        remote_amount: u64,
        commitment_number: u64,
        obscuring_factor: u64,
        funding_outpoint: OutPoint,
        remote_pubkey: PublicKey,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        Psbt::from_unsigned_tx(Transaction::ln_cmt_base(
            local_amount,
            remote_amount,
            commitment_number,
            obscuring_factor,
            funding_outpoint,
            remote_pubkey,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        ))
        .expect("Tx has empty sigs so PSBT creation does not faile")
    }

    fn ln_closing(outpoint: OutPoint, txout: Vec<TxOut>) -> Self {
        Psbt::from_unsigned_tx(Transaction::ln_closing(outpoint, txout))
            .expect("Tx has empty sigs so PSBT creation does not faile")
    }
}
