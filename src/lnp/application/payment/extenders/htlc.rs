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
use bitcoin::secp256k1;
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::{OutPoint, Transaction, TxIn, TxOut};

use crate::bp::{
    chain::AssetId, HashLock, HashPreimage, IntoPk, LockScript, PubkeyScript,
    WitnessScript,
};
use crate::lnp::application::payment::ExtensionId;
use crate::lnp::application::{channel, ChannelExtension, Extension, Messages};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HtlcKnown {
    pub preimage: HashPreimage,
    pub id: u64,
    pub cltv_expiry: u32,
    pub asset_id: Option<AssetId>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HtlcSecret {
    pub hashlock: HashLock,
    pub id: u64,
    pub cltv_expiry: u32,
    pub asset_id: Option<AssetId>,
}

pub struct HtlcState {
    offered_htlc: Vec<HtlcKnown>,
    received_htlc: Vec<HtlcSecret>,
    resolved_htlc: Vec<HtlcKnown>,
}
impl channel::State for HtlcState {}

pub struct Htlc {}

impl Extension for Htlc {
    type Identity = ExtensionId;

    fn identity(&self) -> Self::Identity {
        ExtensionId::Htlc
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

impl ChannelExtension for Htlc {
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
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        payment_hash: HashLock,
    ) -> Self;

    fn ln_received_htlc(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self;

    fn ln_htlc_output(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self;
}

impl ScriptGenerators for LockScript {
    fn ln_offered_htlc(
        _: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        payment_hash: HashLock,
    ) -> Self {
        script::Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(&revocationpubkey.into_pk().pubkey_hash())
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_key(&remote_htlcpubkey.into_pk())
            .push_opcode(OP_SWAP)
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_NOTIF)
            .push_opcode(OP_DROP)
            .push_int(2)
            .push_opcode(OP_SWAP)
            .push_key(&local_htlcpubkey.into_pk())
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .push_opcode(OP_ELSE)
            .push_opcode(OP_HASH160)
            .push_slice(payment_hash.as_ref())
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_ENDIF)
            .into_script()
            .into()
    }

    fn ln_received_htlc(
        _: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self {
        script::Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(&revocationpubkey.into_pk().pubkey_hash())
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_key(&remote_htlcpubkey.into_pk())
            .push_opcode(OP_SWAP)
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_HASH160)
            .push_slice(payment_hash.as_ref())
            .push_opcode(OP_EQUALVERIFY)
            .push_int(2)
            .push_opcode(OP_SWAP)
            .push_key(&local_htlcpubkey.into_pk())
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .push_opcode(OP_ELSE)
            .push_opcode(OP_DROP)
            .push_int(cltv_expiry as i64)
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_ENDIF)
            .into_script()
            .into()
    }

    fn ln_htlc_output(
        _: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
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
}

impl ScriptGenerators for WitnessScript {
    #[inline]
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        payment_hash: HashLock,
    ) -> Self {
        LockScript::ln_offered_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            payment_hash,
        )
        .into()
    }

    #[inline]
    fn ln_received_htlc(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self {
        LockScript::ln_received_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            cltv_expiry,
            payment_hash,
        )
        .into()
    }

    #[inline]
    fn ln_htlc_output(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self {
        LockScript::ln_htlc_output(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .into()
    }
}

impl ScriptGenerators for PubkeyScript {
    #[inline]
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        payment_hash: HashLock,
    ) -> Self {
        WitnessScript::ln_offered_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            payment_hash,
        )
        .to_p2wsh()
    }

    #[inline]
    fn ln_received_htlc(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self {
        WitnessScript::ln_received_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            cltv_expiry,
            payment_hash,
        )
        .to_p2wsh()
    }

    #[inline]
    fn ln_htlc_output(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self {
        WitnessScript::ln_htlc_output(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .to_p2wsh()
    }
}

impl ScriptGenerators for TxOut {
    #[inline]
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        payment_hash: HashLock,
    ) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_offered_htlc(
                amount,
                revocationpubkey,
                local_htlcpubkey,
                remote_htlcpubkey,
                payment_hash,
            )
            .into(),
        }
    }

    #[inline]
    fn ln_received_htlc(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_received_htlc(
                amount,
                revocationpubkey,
                local_htlcpubkey,
                remote_htlcpubkey,
                cltv_expiry,
                payment_hash,
            )
            .into(),
        }
    }

    #[inline]
    fn ln_htlc_output(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_htlc_output(
                amount,
                revocationpubkey,
                local_delayedpubkey,
                to_self_delay,
            )
            .into(),
        }
    }
}

pub trait TxGenerators {
    fn ln_htlc(
        amount: u64,
        outpoint: OutPoint,
        cltv_expiry: u32,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self;
}

impl TxGenerators for Transaction {
    /// NB: For HTLC Success transaction always set `cltv_expiry` parameter
    ///     to zero!
    fn ln_htlc(
        amount: u64,
        outpoint: OutPoint,
        cltv_expiry: u32,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self {
        Transaction {
            version: 2,
            lock_time: cltv_expiry,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: none!(),
                sequence: 0,
                witness: empty!(),
            }],
            output: vec![TxOut::ln_htlc_output(
                amount,
                revocationpubkey,
                local_delayedpubkey,
                to_self_delay,
            )],
        }
    }
}

impl TxGenerators for Psbt {
    fn ln_htlc(
        amount: u64,
        outpoint: OutPoint,
        cltv_expiry: u32,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self {
        Psbt::from_unsigned_tx(Transaction::ln_htlc(
            amount,
            outpoint,
            cltv_expiry,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        ))
        .expect("Tx has empty sigs so PSBT creation does not faile")
    }
}
