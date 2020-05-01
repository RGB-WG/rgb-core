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

use super::commit_verify::{self, CommitVerify};
use super::strict_encoding;

pub trait CommitEncode {
    fn commit_encode(self) -> Vec<u8>;
}

pub trait CommitEncodeStrategy {
    type Strategy;
}

/// Implemented after concept by Martin Habovštiak <martin.habovstiak@gmail.com>
pub mod commit_strategy {
    use super::*;
    use crate::strategy;

    // Defining strategies:
    pub struct UsingStrict;
    pub struct Merklization;

    impl<T> CommitEncode for strategy::Holder<T, UsingStrict>
    where
        T: strict_encoding::StrictEncode,
    {
        fn commit_encode(self) -> Vec<u8> {
            strict_encoding::strict_encode(&self.into_inner()).expect(
                "Strict encoding must not fail for types implementing \
                      ConsensusCommit via marker trait ConsensusCommitFromStrictEncoding",
            )
        }
    }

    impl<T> CommitEncode for T
    where
        T: CommitEncodeStrategy,
        strategy::Holder<T, <T as CommitEncodeStrategy>::Strategy>: CommitEncode,
    {
        fn commit_encode(self) -> Vec<u8> {
            strategy::Holder::new(self).commit_encode()
        }
    }
}

pub trait Conceal {
    fn conceal(&self) -> Self;
}

pub trait ConsensusCommit: Sized + CommitEncode {
    type Commitment: commit_verify::CommitVerify<Vec<u8>> + bitcoin::hashes::Hash;

    #[inline]
    fn consensus_commit(self) -> Self::Commitment {
        Self::Commitment::commit(&self.commit_encode())
    }

    #[inline]
    fn consensus_verify(self, commitment: &Self::Commitment) -> bool {
        commitment.verify(&self.commit_encode())
    }
}

/*
/// This simple trait MUST be used by all parties implementing client-side
/// validation paradigm. The core concept of this paradigm is that a client
/// must have a complete and uniform set of data, which can be represented
/// or accessed through a single structure; and MUST be able to deterministically
/// validate this set giving an external validation function, that is able to
/// provide validator with
pub trait ClientSideValidate<TR> where TR: TrustResolver {
    type ClientData: ClientData;
    type ValidationError: FromTrustProblem<TR> + FromInternalInconsistency<TR>;

    fn new() -> Self;

    fn client_side_validate(client_data: Self::ClientData, trust_resolver: TR) -> Result<(), Self::ValidationError> {
        let validator = Self::new();
        client_data.validate_internal_consistency()?;
        client_data.validation_iter().try_for_each(|item| {
            trust_resolver.resolve_trust(item, validator.get_context_for_atom(item))?;
            item.client_side_validate()
        })
    }

    fn get_context_for_item<C: TrustContext>(&self, data_item: Self::ClientData::ValidationItem) -> C;
}


pub trait ClientData {
    type ValidationItem: ClientData;
}

pub trait TrustContext {

}

/// Trust resolver for a given client data type MUST work with a single type
/// of `TrustContext`, defined by an associated type. Trust resolution MUST
/// always produce a singular success type (defined by `()`) or fail with a
/// well-defined type of `TrustProblem`.
///
/// Trust resolved may have an internal state (represented by `self` reference)
/// and it does not require to produce a deterministic result for the same
/// given data piece and context: the trust resolver may depend on previous
/// operation history and depend on type and other external parameters.
pub trait TrustResolver<T: ClientData> {
    type TrustProblem: std::error::Error;
    type Context: TrustContext;
    fn resolve_trust(&self, data_piece: &T, context: &Self::Context) -> Result<(), Self::TrustProblem>;
}



mod test {
    struct BlockchainValidator;
    impl ClientSideValidate for BlockchainValidator {
        type ClientData = Blockchain;
        fn new() -> Self { Self }
        fn get_context_for_item(&self, data_item: Block) -> Difficulty { }
    }



    fn test() {

    }
}
*/
