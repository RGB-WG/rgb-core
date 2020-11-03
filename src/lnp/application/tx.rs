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

use crate::bp::{LexOrder, LockScript, PubkeyScript, WitnessScript};
use crate::lnp::PaymentHash;

macro_rules! to_bitcoin_pk {
    ($pk:ident) => {
        ::bitcoin::PublicKey {
            compressed: true,
            key: $pk,
        }
    };
}

// TODO: (v0.3) Add support for generating LN feature-specific outputs
//      - add `to_local_anchor`
//      - add `to_remote_anchor`
//      - add `offered/received_htlc` anchored version
pub trait ScriptGenerators {
    fn ln_funding(
        amount: u64,
        pubkey1: secp256k1::PublicKey,
        pubkey2: secp256k1::PublicKey,
    ) -> Self;

    fn ln_to_local(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self;

    fn ln_to_remote_v1(
        amount: u64,
        remote_pubkey: secp256k1::PublicKey,
    ) -> Self;

    fn ln_to_remote_v2(
        amount: u64,
        remote_pubkey: secp256k1::PublicKey,
    ) -> Self;

    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        payment_hash: PaymentHash,
    ) -> Self;

    fn ln_received_htlc(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        cltv_expiry: u32,
        payment_hash: PaymentHash,
    ) -> Self;

    fn ln_htlc_output(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self;
}

impl ScriptGenerators for LockScript {
    fn ln_funding(
        _: u64,
        pubkey1: secp256k1::PublicKey,
        pubkey2: secp256k1::PublicKey,
    ) -> Self {
        let pk = vec![to_bitcoin_pk!(pubkey1), to_bitcoin_pk!(pubkey2)]
            .lex_ordered();

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

    fn ln_to_remote_v1(_: u64, _: secp256k1::PublicKey) -> Self {
        unimplemented!("LockScript can't be generated for to_remote v1 output")
    }

    fn ln_to_remote_v2(_: u64, remote_pubkey: secp256k1::PublicKey) -> Self {
        let remote_pubkey = to_bitcoin_pk!(remote_pubkey);
        script::Builder::new()
            .push_key(&remote_pubkey)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_int(1)
            .push_opcode(OP_CSV)
            .into_script()
            .into()
    }

    fn ln_offered_htlc(
        _: u64,
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
        _: u64,
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
        _: u64,
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
        amount: u64,
        pubkey1: secp256k1::PublicKey,
        pubkey2: secp256k1::PublicKey,
    ) -> Self {
        LockScript::ln_funding(amount, pubkey1, pubkey2).into()
    }

    #[inline]
    fn ln_to_local(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
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
    fn ln_to_remote_v1(_: u64, _: secp256k1::PublicKey) -> Self {
        unimplemented!(
            "WitnessScript can't be generated for to_remote v1 output"
        )
    }

    fn ln_to_remote_v2(
        amount: u64,
        remote_pubkey: secp256k1::PublicKey,
    ) -> Self {
        LockScript::ln_to_remote_v2(amount, remote_pubkey).into()
    }

    #[inline]
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        payment_hash: PaymentHash,
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
        payment_hash: PaymentHash,
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
    fn ln_funding(
        amount: u64,
        pubkey1: secp256k1::PublicKey,
        pubkey2: secp256k1::PublicKey,
    ) -> Self {
        WitnessScript::ln_funding(amount, pubkey1, pubkey2).to_p2wsh()
    }

    #[inline]
    fn ln_to_local(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
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
    fn ln_to_remote_v1(_: u64, remote_pubkey: secp256k1::PublicKey) -> Self {
        let remote_pubkey = to_bitcoin_pk!(remote_pubkey);
        remote_pubkey
            .wpubkey_hash()
            .expect("We just generated non-compressed key")
            .into()
    }

    #[inline]
    fn ln_to_remote_v2(
        amount: u64,
        remote_pubkey: secp256k1::PublicKey,
    ) -> Self {
        WitnessScript::ln_to_remote_v2(amount, remote_pubkey).to_p2wsh()
    }

    #[inline]
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        payment_hash: PaymentHash,
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
        payment_hash: PaymentHash,
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
    fn ln_funding(
        amount: u64,
        pubkey1: secp256k1::PublicKey,
        pubkey2: secp256k1::PublicKey,
    ) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_funding(amount, pubkey1, pubkey2)
                .into(),
        }
    }

    #[inline]
    fn ln_to_local(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
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
    fn ln_to_remote_v1(
        amount: u64,
        remote_pubkey: secp256k1::PublicKey,
    ) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_to_remote_v1(amount, remote_pubkey)
                .into(),
        }
    }

    #[inline]
    fn ln_to_remote_v2(
        amount: u64,
        remote_pubkey: secp256k1::PublicKey,
    ) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_to_remote_v2(amount, remote_pubkey)
                .into(),
        }
    }

    #[inline]
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: secp256k1::PublicKey,
        local_htlcpubkey: secp256k1::PublicKey,
        remote_htlcpubkey: secp256k1::PublicKey,
        payment_hash: PaymentHash,
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
        payment_hash: PaymentHash,
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
    fn ln_cmt_base(
        local_amount: u64,
        remote_amount: u64,
        commitment_number: u64,
        obscuring_factor: u64,
        funding_outpoint: OutPoint,
        remote_pubkey: secp256k1::PublicKey,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
        to_self_delay: u16,
    ) -> Self;

    fn ln_htlc(
        amount: u64,
        outpoint: OutPoint,
        cltv_expiry: u32,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
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
        remote_pubkey: secp256k1::PublicKey,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
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
        remote_pubkey: secp256k1::PublicKey,
        revocationpubkey: secp256k1::PublicKey,
        local_delayedpubkey: secp256k1::PublicKey,
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

    fn ln_closing(outpoint: OutPoint, txout: Vec<TxOut>) -> Self {
        Psbt::from_unsigned_tx(Transaction::ln_closing(outpoint, txout))
            .expect("Tx has empty sigs so PSBT creation does not faile")
    }
}
