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


use std::sync::Once;

use super::{
    Schemata,
    super::schema::{
        *,
        Bits::*,
        Occurences::*,
        StateFormat::*,
        script::{
            Scripting,
            StandardProcedure::*,
            Procedure::*,
            Extensions::*
        }
    }
};


/// Schema for fungible assets with possible secondary issuance and history pruning (standard RGB-1)
pub struct Rgb1();

impl Schemata for Rgb1 {
    fn get_schema() -> &'static Schema {
        const ISSUE: usize = 0;
        const BALANCE: usize = 1;
        const PRUNE: usize = 2;

        static ONCE: Once = Once::new();
        let mut schema: &'static Option<Schema> = &None;

        ONCE.call_once(|| {
            schema = Box::leak(Box::new(Some(Schema {
                seals: map!{
                    ISSUE => Amount,
                    BALANCE => NoState,
                    PRUNE => NoState
                },
                transitions: vec![
                    // Genesis state: primary issue
                    Transition {
                        closes: None,
                        fields: vec![
                            // Ticker
                            Field(FieldFormat::String(16), Once),
                            // Title
                            Field(FieldFormat::String(256), Once),
                            // Description
                            Field(FieldFormat::String(1024), NoneOrOnce),
                            // Total supply
                            Field(FieldFormat::Unsigned { bits: Bit256, min: None, max: None }, NoneOrOnce),
                            // Fractional bits
                            Field(FieldFormat::Unsigned { bits: Bit8, min: None, max: None }, Once),
                            // Dust limit
                            Field(FieldFormat::Unsigned { bits: Bit256, min: None, max: None }, NoneOrOnce),
                            // Network
                            Field(FieldFormat::Enum { values: vec![0, 1, 2, 3, 4] }, Once),
                        ],
                        binds: map!{
                            BALANCE => OnceOrUpTo(None),
                            ISSUE => NoneOrOnce,
                            PRUNE => NoneOrOnce
                        },
                        scripting: Scripting {
                            validation: Standard(Rgb1Genesis),
                            extensions: ScriptsDenied
                        }
                    },
                    // Issuance transition: secondary issue
                    Transition {
                        closes: Some(map! {
                            ISSUE => Once
                        }),
                        fields: vec![],
                        binds: map!{
                            BALANCE => OnceOrUpTo(None),
                            ISSUE => NoneOrUpTo(None)
                        },
                        scripting: Scripting {
                            validation: Standard(Rgb1Issue),
                            extensions: ScriptsDenied
                        }
                    },
                    // Amount transition: asset transfers
                    Transition {
                        closes: Some(map!{
                            BALANCE => OnceOrUpTo(None)
                        }),
                        fields: vec![],
                        binds: map!{
                            BALANCE => NoneOrUpTo(None)
                        },
                        scripting: Scripting {
                            validation: Standard(Rgb1Transfer),
                            extensions: ScriptsDenied
                        }
                    },
                    // Pruning transition: asset re-issue
                    Transition {
                        closes: Some(map!{
                            PRUNE => NoneOrOnce
                        }),
                        fields: vec![],
                        binds: map!{
                            BALANCE => OnceOrUpTo(None),
                            PRUNE => Once
                        },
                        scripting: Scripting {
                            validation: Standard(Rgb1Prune),
                            extensions: ScriptsDenied
                        }
                    }
                ]
            })));
        });

        schema.as_ref().expect("This must be always initialized")
    }
}
