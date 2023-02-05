# Single-use-seal API specific for RGB implementation

Based on LNP/BP client-side-validation single-use-seals API (see
[`lnpbp::seals`]). RGB single-use-seal implementation differs in the fact
that seals are organized into a graph; thus a seal may be defined as
pointing witness transaction closing some other seal, which is meaningless
with LNP/BP seals.

Single-use-seals in RGB are used for holding assigned state, i.e. *state* +
*seal definition* = *assignment*. Closing of the single-use-seal invalidates
the assigned state.

Single-use-seals in RGB can have multiple forms because of the
confidentiality options and ability to be linked to the witness transaction
closing previous seal in RGB state evolution graph.

| **Type name**     | **Lib**  | **Txid**  | **Blinding** | **Confidential** | **String serialization**                | **Use case**  |
| ----------------- | -------- | --------- | ------------ | ---------------- | --------------------------------------- | ------------- |
| [`Outpoint`]      | BP Core  | Required  | No           | No               | `<txid>:<vout>`                         | Genesis       |
| [`RevealedSeal`]  | BP Core  | Required  | Yes          | No               | `<method>:<<txid>|~>:<vout>#<blinding>` | Stash         |
| [`ConcealedSeal`] | BP Core  | Unknown   | Implicit     | Yes              | `txob:<baid58>#<checksum>`              | Ext. payments |
| [`ExplicitSeal`]  | BP Core  | Optional  | Yes          | No               | `<method>:<<txid>|~>:<vout>`            | Internal      |
| [`VoutSeal`]      | RGB Core | Absent    | Yes          | No               | `<method>:~:<vout>#<blinding>`          | SealEndpoint  |
| [`SealEndpoint`]  | RGB Core | Optional  | Varies       | Could be         | `<concealed>|<explicit>`                | Consignments  |
