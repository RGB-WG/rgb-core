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

use crate::bp::{LockScript, PubkeyScript, WitnessScript};
use crate::lnp::PaymentHash;

macro_rules! to_bitcoin_pk {
    ($pk:ident) => {
        ::bitcoin::PublicKey {
            compressed: true,
            key: $pk,
        }
    };
}

pub trait ScriptGenerators {
    fn ln_funding(
        pubkey1: secp256k1::PublicKey,
        pubkey2: secp256k1::PublicKey,
    ) -> Self;

    fn ln_to_local(
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self;

    fn ln_offered_htlc(
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        payment_hash: PaymentHash,
    ) -> Self;

    fn ln_received_htlc(
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        cltv_expiry: u32,
        payment_hash: PaymentHash,
    ) -> Self;

    fn ln_htlc_output(
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self;
}

impl ScriptGenerators for LockScript {
    fn ln_funding(
        pubkey1: secp256k1::PublicKey,
        pubkey2: secp256k1::PublicKey,
    ) -> Self {
        let (smaller, greater) = if pubkey1 < pubkey2 {
            (to_bitcoin_pk!(pubkey1), to_bitcoin_pk!(pubkey2))
        } else {
            (to_bitcoin_pk!(pubkey1), to_bitcoin_pk!(pubkey2))
        };

        script::Builder::new()
            .push_int(2)
            .push_key(&smaller)
            .push_key(&greater)
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
            .into()
    }

    fn ln_to_local(
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self {
        let revocationpubkey = to_bitcoin_pk!(revocationpubkey);
        let local_delayedpubkey = to_bitcoin_pk!(local_delayedpubkey);
        script::Builder::new()
            .push_opcode(OP_IF)
            .push_key(&revocationpubkey)
            .push_opcode(OP_ELSE)
            .push_int(to_self_delay as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_key(&local_delayedpubkey)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_CHECKSIG)
            .into_script()
            .into()
    }

    fn ln_offered_htlc(
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        payment_hash: PaymentHash,
    ) -> Self {
        let revocationpubkey = to_bitcoin_pk!(revocationpubkey);
        let remote_htlcpubkey = to_bitcoin_pk!(remote_htlcpubkey);
        let local_htlcpubkey = to_bitcoin_pk!(local_htlcpubkey);
        script::Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(&revocationpubkey.pubkey_hash())
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_key(&remote_htlcpubkey)
            .push_opcode(OP_SWAP)
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_NOTIF)
            .push_opcode(OP_DROP)
            .push_int(2)
            .push_opcode(OP_SWAP)
            .push_key(&local_htlcpubkey)
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
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        cltv_expiry: u32,
        payment_hash: PaymentHash,
    ) -> Self {
        let revocationpubkey = to_bitcoin_pk!(revocationpubkey);
        let remote_htlcpubkey = to_bitcoin_pk!(remote_htlcpubkey);
        let local_htlcpubkey = to_bitcoin_pk!(local_htlcpubkey);
        script::Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(&revocationpubkey.pubkey_hash())
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_key(&remote_htlcpubkey)
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
            .push_key(&local_htlcpubkey)
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
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self {
        let revocationpubkey = to_bitcoin_pk!(revocationpubkey);
        let local_delayedpubkey = to_bitcoin_pk!(local_delayedpubkey);
        script::Builder::new()
            .push_opcode(OP_IF)
            .push_key(&revocationpubkey)
            .push_opcode(OP_ELSE)
            .push_int(to_self_delay as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_key(&local_delayedpubkey)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_CHECKSIG)
            .into_script()
            .into()
    }
}

impl ScriptGenerators for WitnessScript {
    #[inline]
    fn ln_funding(
        pubkey1: secp256k1::PublicKey,
        pubkey2: secp256k1::PublicKey,
    ) -> Self {
        LockScript::ln_funding(pubkey1, pubkey2).into()
    }

    #[inline]
    fn ln_to_local(
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self {
        LockScript::ln_to_local(
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .into()
    }

    #[inline]
    fn ln_offered_htlc(
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        payment_hash: PaymentHash,
    ) -> Self {
        LockScript::ln_offered_htlc(
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            payment_hash,
        )
        .into()
    }

    #[inline]
    fn ln_received_htlc(
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        cltv_expiry: u32,
        payment_hash: PaymentHash,
    ) -> Self {
        LockScript::ln_received_htlc(
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
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self {
        LockScript::ln_htlc_output(
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .into()
    }
}

impl ScriptGenerators for PubkeyScript {
    #[inline]
    fn ln_funding(
        pubkey1: secp256k1::PublicKey,
        pubkey2: secp256k1::PublicKey,
    ) -> Self {
        WitnessScript::ln_funding(pubkey1, pubkey2).to_p2wsh()
    }

    #[inline]
    fn ln_to_local(
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self {
        WitnessScript::ln_to_local(
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .to_p2wsh()
    }

    #[inline]
    fn ln_offered_htlc(
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        payment_hash: PaymentHash,
    ) -> Self {
        WitnessScript::ln_offered_htlc(
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            payment_hash,
        )
        .to_p2wsh()
    }

    #[inline]
    fn ln_received_htlc(
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        cltv_expiry: u32,
        payment_hash: PaymentHash,
    ) -> Self {
        WitnessScript::ln_received_htlc(
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
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self {
        WitnessScript::ln_htlc_output(
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .to_p2wsh()
    }
}
