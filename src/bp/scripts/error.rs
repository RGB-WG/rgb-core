pub enum Error {
    /// Opcode appeared which is not part of the script subset
    InvalidOpcode(bitcoin::blockdata::opcodes::All),
    /// Some opcode occurred followed by `OP_VERIFY` when it had
    /// a `VERIFY` version that should have been used instead
    NonMinimalVerify(miniscript::lex::Token),
    /// Push was illegal in some context
    InvalidPush(Vec<u8>),

    /// Something did a non-minimal push; for more information see
    /// `https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Push_operators`
    NonMinimalPush,
    /// Some opcode expected a parameter, but it was missing or truncated
    EarlyEndOfScript,
    /// Tried to read an array off the stack as a number when it was more than 4 bytes
    NumericOverflow,

    /// A `CHECKMULTISIG` opcode was preceded by a number > 20
    CmsTooManyKeys(u32),
    /// Failed to parse a push as a public key
    BadPubkey(bitcoin::util::key::Error),
    /// Bad Script Sig. As per standardness rules, only pushes are allowed in
    /// scriptSig. This error is invoked when op_codes are pushed onto the stack
    /// As per the current implementation, pushing an integer apart from 0 or 1
    /// will also trigger this. This is because, Miniscript only expects push
    /// bytes for pk, sig, preimage etc or 1 or 0 for `StackElement::Satisfied`
    /// or `StackElement::Dissatisfied`
    BadScriptSig,
    ///Witness must be empty for pre-segwit transactions
    NonEmptyWitness,
    ///ScriptSig must be empty for pure segwit transactions
    NonEmptyScriptSig,
    ///Incorrect Script pubkey Hash for the descriptor. This is used for both
    /// `PkH` and `Wpkh` descriptors
    IncorrectPubkeyHash,
    ///Incorrect Script pubkey Hash for the descriptor. This is used for both
    /// `Sh` and `Wsh` descriptors
    IncorrectScriptHash,
    /// Returned by `Miniscript::replace_pubkeys_and_hashes` in case when the processor has
    /// provided a public key hash instead of public key for a `ThreshM` terminal
    UnexpectedPubkeyHash,
    /// Pubkey processor failure
    PubkeyProcessorFailure,
}
