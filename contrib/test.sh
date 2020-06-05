#!/bin/sh -ex

FEATURES="rgb lnp daemons keygen tor tokio log url bulletproofs serde lnp,websockets,url,tokio,async"

if [ "$DO_COV" = true ]
then
    export RUSTFLAGS="-C link-dead-code"
fi


# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
fi

# Test without any features first
# TODO: This is not working b/c of bitcoin_hashes macro problem.
#       Uncomment once the problem will be fixed
# cargo test --verbose --all-features

# Test using all features
cargo test --verbose --all-features --all-targets

# Test each feature
for feature in ${FEATURES}
do
    cargo check --verbose --features="$feature" --all-targets
done

# Fuzz if told to
if [ "$DO_FUZZ" = true ]
then
    (
        cd fuzz
        cargo test --verbose --all-targets
        ./travis-fuzz.sh
    )
fi

# Bench if told to
if [ "$DO_BENCH" = true ]
then
    cargo bench --features unstable --all-targets
fi

# Use as dependency if told to
if [ -n "$AS_DEPENDENCY" ]
then
    cargo new dep_test
    cd dep_test
    printf 'lnpbp = { path = "..", features = ["all"] }\n\n[workspace]' >> Cargo.toml
    cargo build --verbose
    cd ..
    rm -rf dep_test
fi
