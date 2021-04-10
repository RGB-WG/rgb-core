#!/bin/sh -ex

AS_DEPENDENCY=true
DO_LINT=true

# Library components
FEATURES="cli serde"


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

# Check that we can build rgb* crates
for crate in rgb20 rgb21 rgb22 rgb23
do
    cargo check --manifest-path $crate/Cargo.toml --verbose --features all
done

# Check that we can build rgb binary
# rgb binary is not building by following command and I am not sure why
cargo check --bins --features all --verbose

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
