#!/bin/sh -ex

FEATURES=""

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
cargo test --verbose --all-features

# Test each feature
for feature in ${FEATURES}
do
    cargo test --verbose --features="$feature"
done

# Fuzz if told to
if [ "$DO_FUZZ" = true ]
then
    (
        cd fuzz
        cargo test --verbose
        ./travis-fuzz.sh
    )
fi

# Bench if told to
if [ "$DO_BENCH" = true ]
then
    cargo bench --features unstable
fi

# Use as dependency if told to
if [ -n "$AS_DEPENDENCY" ]
then
    cargo new dep_test
    cd dep_test
    echo 'lnpbp = { path = "..", features = ["all"] }' >> Cargo.toml
    cargo test --verbose
fi
