# Git Workflow Guidelines

## Library development

The main library development happens in the `master` branch. This branch must always compile without errors (using Travis CI). All external contributions are made within PRs into this branch.

Each commitment within a PR to the `master` must 
* compile without errors;
* contain all necessary tests for the introduced functional;
* contain all docs.

Additionally to the `master` branch the repository has `develop` branch for any experimental developments. This branch may not compile and should not be used by any projects depending on `lnpbp` library.

## External dependencies

This library depends on a number of external Rust libraries managed by different organizations and people within bitcoin community, including Blockstream, Chaincode Labs, Pandora Core companies. Some of the functionality required for LNP/BP development related to the base Bitcoin protocol and Lightning Network is contributed by LNP/BP Association directly into the underlying libraries; however sometimes the present library requires changes in them that can't or not yet accepted by the community. This brings necessity to maintain our own forks of the dependencies. This section presents guidelines for organizing Git workflow managing all dependencies, branching, forks etc.

LNP/BP Standards Association maintains a fork of the following external libraries:
* bitcoin_hashes
* rust-bitcoin
* rust-miniscript
* rust-lightning
* rust-lightning-invoice
* rust-secp256k1-zkp

Functionality, specific to LNP/BP and not merged into the upstream `master` branches is kept in `staging` branch of each of these forks, which is defined as a default branch in GitHub. Parties wanting to contribute to it must fork the repo, create a branch per each feature (starting with `feat-` prefix) or bugfix (starting with `fix-` prefix) and do a PR to the `staging` branch.

Each commitment within a PR to the `staging` must 
* compile without errors;
* contain all necessary tests for the introduced functional;
* contain all docs.

