# Change Log

## v0.1.0-beta.2

### Breaking changes:
- Change of TransitionId hash tag value (previously-generated transition ids will be invalid)
- Change of GenesisId  hash tag value (previously-generated contract/assets ids will be invalid)
- TransitionId tyoe is replaced with NodeId
- NodeId and ContractId are now equal by value; ContractId now is NodeId wrapper
- `ancestors()` method moved from `Transition` to `Node` trait; genesis returns an empty array
- Consignment now has a version field
- Anchor contains txid field
- Consignment endpoints contains NodeId
