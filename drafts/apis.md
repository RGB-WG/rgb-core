
The file is subjected for different planned API drafts

RGB Layers:
- Singular zero-knowledge parallel commitments to bitcoin blockchain
- Single-use seal graph
- State structure
- Confidential amounts for state

## LNPBP-1: CRECC (collision-resistant elliptic-curve commitments)

Commit
Inputs: original public key, message
Outputs: tweaked public key, hmac

Verify
Inputs: tweaked public key, hmac, message
Output: true/false

```shell script
$ lbx crecc-commit 02d1d80235fa5bba42e9612a7fe7cd74c6b2bf400c92d866f28d429846c679cceb "This is the message"

deadbeaf35fa5bba42e9612a7fe7cd74c6b2bf400c92d866f28d429846c679cceb
35fa5bba42e9612a7fe7cd74c6b2bf400c92d866f28d429846c679ccebdeadbeaf

$ lbx crecc-verify deadbeaf35fa5bba42e9612a7fe7cd74c6b2bf400c92d866f28d429846c679cceb \
> 35fa5bba42e9612a7fe7cd74c6b2bf400c92d866f28d429846c679ccebdeadbeaf "This is the message"

process exited with the code 0
```

## LNPBP-2: CRECC TxOut embedding

Just use normal tools for txout and transaction construction with tweaked keys

```shell script
$ lbx address-commit -t <p2pk|p2(w)pkh|p2(w)sh|p2sh-p2wpk|p2sh-p2wsh|p2tr|p2s-opreturn> <redeemScript | pubkey> <msg>
<address>

$ lbx address-reveal [-r <redeemScript>] <addr> <msg> <orig_pubkey>+
process exited with the code 0|1
```

## LNPBP-3: CRECC Tx embedding

```shell script
$ lbx tx-commit -o <output-no> -e <entropy> -c <change-output> [-r <redeemScript>] -m <msg> <tx>
<tx>

$ lbx tx-commit -o <output-no> -e <entropy> -c <change-output> -a <addr> <tx>
<tx>

$ lbx tx-verify -e <entropy> <tx> <msg> <orig_pubkey>+
process exited with the code 0|1
```

## LNPBP-4: zk-MC (zero-knowledge multi-commit)

```shell script
$ lbx zkmc-commit <msg1> <proto1> <msg2> <proto2> ...
<serialized commitments>
<proofs>

$ lbx zkmc-reveal <serialized-commitment> <proofs> <msgN> <protoN>
process exited with the code 0|1
```


## Usecase

```shell script
$(TX) = # todo: construct tx
$(MSG) = `lbx zkmc-commit <msg1> <proto1> <msg2> <proto2> ...`
lbx tx-commit -o <output-no> -e <entropy> -c <change-output> [-r <redeemScript>] -m "$(MSG)" $(TX) |
bx tx-send
```

## Code


```rust
pub trait CommittableMessage {}
pub trait CommitmentContainer {}
pub trait CommitmentProofs {}
pub trait CommitmentEngine<MSG: CommittableMessage, CT: CommitmentContainer, PRF: CommitmentProofs=!> {
    fn commit(&self, message: &MSG, container: &CT) -> PRF;
    fn verify(&self, message: &MSG, container: &CT, proofs: &PRF) -> bool;
}

// Tweak pk
pub struct TweakSource(Sha256);
impl CommittableMessage for TweakSource {}
impl CommitmentContainer for PublicKey {}

pub struct TweakEngine {}

impl TweakEngine {
    const TAG: &'static str = "LNPBP-1";
    const EC: Secp256k1<All> = Secp256k1::new();
}

impl CommitmentEngine<TweakSource, PublicKey, PublicKey> for TweakEngine {
    fn commit(&self, message: &TweakSource, container: &PublicKey) -> PublicKey { unimplemented!() }
    fn verify(&self, message: &TweakSource, container: &PublicKey, original_pubkey: &PublicKey) -> bool { unimplemented!() }
}

// Tweak txout
pub struct TxoutContainer {
    pub txout: TxOut,
    pub redeem_script: Option<Script>,
}

pub struct TxoutProofs {
    pub redeem_script: Option<Script>,
    pub original_pubkeys: Vec<PublicKey>,
}

impl CommitmentContainer for TxoutContainer {}
impl CommitmentProofs for TxoutProofs {}

impl CommitmentEngine<TweakSource, TxoutContainer, TxoutProofs> for TweakEngine {
    fn commit(&self, message: &TweakSource, container: &mut TxoutContainer) -> TxoutProofs { unimplemented!() }
    fn verify(&self, message: &TweakSource, container: &TxoutContainer, proofs: &TxoutProofs) -> bool { unimplemented!() }
}

// Tweak tx
pub struct TxContainer {
    pub tx: Transaction,
    pub redeem_script: Option<Script>,
    pub vout: Option<u64>,
    pub entropy: u32,
}

pub struct TxProofs {
    pub redeem_script: Option<Script>,
    pub original_pubkeys: Vec<PublicKey>,
    pub entropy: u32,
}

impl CommitmentContainer for TxContainer {}
impl CommitmentProofs for TxProofs {}

impl CommitmentEngine<TweakSource, TxContainer, TxProofs> for TweakEngine {
    fn commit(&self, message: &TweakSource, container: &mut TxContainer) -> TxProofs { unimplemented!() }
    fn verify(&self, message: &TweakSource, container: &TxContainer, proofs: &TxProofs) -> bool { unimplemented!() }
}

// Multi-message
pub struct MessageSource {
    pub msg: Sha256,
    pub protocol: Sha256,
}
type MultimsgSource = Vec<MessageSource>;

impl CommittableMessage for MultimsgSource {}

pub struct MultimsgContainer(Box<[u8]>);
pub struct PedersenProof {
    pub blinding_factor: u256,
    pub pedersen_commitment: PublicKey,
}
type MultimsgProofs = Vec<PedersenProof>;

impl CommitmentContainer for MultimsgContainer {}
impl CommitmentProofs for MultimsgProofs {}

pub struct MultimsgEngine {}

impl CommitmentEngine<MultimsgSource, MultimsgContainer, MultimsgProofs> for MultimsgEngine {
    fn commit(&self, message: &MultimsgSource, container: &mut MultimsgContainer) -> TxProofs { unimplemented!() }
    fn verify(&self, message: &MultimsgSource, container: &MultimsgContainer, proofs: &MultimsgProofs) -> bool { unimplemented!() }
}
```


```c
struct crecc {
    struct public_key pubkey;
    struct hmac_sha256 hmac;
}

void crecc_commit(&struct crecc, ubyte* message, usize len);
bool crecc_reveal(struct crecc, ubyte* message, usize len);
```
