#!/bin/sh -ex

AS_DEPENDENCY=true
DO_LINT=true

# Library components
FEATURES="lnp"
# Cryptographic optionals
FEATURES="${FEATURES} keygen bulletproofs elgamal"
# Core rust optionals
FEATURES="${FEATURES} serde tokio async"
# Networking
FEATURES="${FEATURES} tor url websockets"
FEATURES="${FEATURES} tor,url"
# Full LNP strength, but without Serde
FEATURES="${FEATURES} lnp,websockets,url,tokio,async,keygen,bulletproofs"

if [ "$DO_COV" = true ]
then
    export RUSTFLAGS="-C link-dead-code"
fi


# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
fi

# Check that we can build w/o features
cargo check --verbose --all-targets --workspace
cargo check --verbose --no-default-features --all-targets --workspace

# Check that we can build with each feature
for feature in ${FEATURES}
do
    cargo check --verbose --features="$feature" --all-targets
done

# Check that we can build services with different features
for feature in "server client embedded cli server,serde client,serde"
do
    cargo check --manifest-path services/Cargo.toml --verbose --features="$feature"
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
    rm -rf dep_test
    cargo new dep_test
    cd dep_test
    cat ../contrib/depCargo.toml >> Cargo.toml
    cargo build --verbose
    cd ..
    rm -rf dep_test
fi

# Test all features
cargo test --verbose --all-features --all-targets --workspace

# Lint if told to
if [ "$DO_LINT" = true ]
then
    (
        rustup component add rustfmt
        cargo fmt --all -- --check
    )
fi
