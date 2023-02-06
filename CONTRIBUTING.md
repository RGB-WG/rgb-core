Contributing guidelines
=======================

Contributions are very welcome. When contributing code, please follow these
simple guidelines.

#### Table Of Contents
- [Contribution workflow](#contribution-workflow)
    * [Proposing changes](#proposing-changes)
    * [Preparing PRs](#preparing-prs)
    * [Peer review](#peer-review)
- [Coding conventions](#coding-conventions)
- [Security](#security)
- [Testing](#testing)
- [Going further](#going-further)

Overview
--------

* Before adding any code dependencies, check with the maintainers if this is okay.
* Write properly formatted comments: they should be English sentences, eg:

        // Return the current UNIX time.

* Read the DCO and make sure all commits are signed off, using `git commit -s`.
* Follow the guidelines when proposing code changes (see below).
* Write properly formatted git commits (see below).
* Run the tests with `cargo test --workspace --all-features`.
* Make sure you run `rustfmt` on your code (see below details).
* Please don't file an issue to ask a question. Each repository - or  
  GitHub organization has a "Discussions" with Q&A section; please post your
  questions there. You'll get faster results by using this channel.

Contribution Workflow
---------------------
The codebase is maintained using the "contributor workflow" where everyone
without exception contributes patch proposals using "pull requests". This
facilitates social contribution, easy testing and peer review.

To contribute a patch, the workflow is a as follows:

1. Fork Repository
2. Create topic branch
3. Commit patches

In general commits should be atomic and diffs should be easy to read. For this
reason do not mix any formatting fixes or code moves with actual code changes.
Further, each commit, individually, should compile and pass tests, in order to
ensure git bisect and other automated tools function properly.

When adding a new feature thought must be given to the long term technical debt.
Every new features should be covered by unit tests.

When refactoring, structure your PR to make it easy to review and don't hesitate
to split it into multiple small, focused PRs.

Commits should cover both the issue fixed and the solution's rationale.
These [guidelines](https://chris.beams.io/posts/git-commit/) should be kept in
mind.

To facilitate communication with other contributors, the project is making use
of GitHub's "assignee" field. First check that no one is assigned and then
comment suggesting that you're working on it. If someone is already assigned,
don't hesitate to ask if the assigned party or previous commenters are still
working on it if it has been awhile.

### Proposing changes

When proposing changes via a pull-request or patch:

* Isolate changes in separate commits to make the review process easier.
* Don't make unrelated changes, unless it happens to be an obvious improvement to
  code you are touching anyway ("boyscout rule").
* Rebase on `master` when needed.
* Keep your changesets small, specific and uncontroversial, so that they can be
  merged more quickly.
* If the change is substantial or requires re-architecting certain parts of the
  codebase, write a proposal in English first, and get consensus on that before
  proposing the code changes.

### Preparing PRs

The main library development happens in the `master` branch. This branch must
always compile without errors (using Travis CI). All external contributions are
made within PRs into this branch.

Prerequisites that a PR must satisfy for merging into the `master` branch:
* the tip of any PR branch must compile and pass unit tests with no errors, with
  every feature combination (including compiling the fuzztests) on MSRV, stable
  and nightly compilers (this is partially automated with CI, so the rule
  is that we will not accept commits which do not pass GitHub CI);
* contain all necessary tests for the introduced functional (either as a part of
  commits, or, more preferably, as separate commits, so that it's easy to
  reorder them during review and check that the new tests fail without the new
  code);
* contain all inline docs for newly introduced API and pass doc tests;
* be based on the recent `master` tip from the original repository at.

NB: reviewers may run more complex test/CI scripts, thus, satisfying all the
requirements above is just a preliminary, but not necessary sufficient step for
getting the PR accepted as a valid candidate PR for the `master` branch.

Additionally, to the `master` branch some repositories may have `develop` branch
for any experimental developments. This branch may not compile and should not be
used by any projects depending on the library.

### Writing Git commit messages

A properly formed git commit subject line should always be able to complete the
following sentence:

     If applied, this commit will _____

In addition, it should be capitalized and *must not* include a period.

For example, the following message is well formed:

     Add support for .gif files

While these ones are **not**: `Adding support for .gif files`,
`Added support for .gif files`.

When it comes to formatting, here's a model git commit message[1]:

     Capitalized, short (50 chars or less) summary

     More detailed explanatory text, if necessary.  Wrap it to about 72
     characters or so.  In some contexts, the first line is treated as the
     subject of an email and the rest of the text as the body.  The blank
     line separating the summary from the body is critical (unless you omit
     the body entirely); tools like rebase can get confused if you run the
     two together.

     Write your commit message in the imperative: "Fix bug" and not "Fixed bug"
     or "Fixes bug."  This convention matches up with commit messages generated
     by commands like git merge and git revert.

     Further paragraphs come after blank lines.

     - Bullet points are okay, too.

     - Typically a hyphen or asterisk is used for the bullet, followed by a
       single space, with blank lines in between, but conventions vary here.

     - Use a hanging indent.

### Peer review

Anyone may participate in peer review which is expressed by comments in the pull
request. Typically reviewers will review the code for obvious errors, as well as
test out the patch set and opine on the technical merits of the patch. PR should
be reviewed first on the conceptual level before focusing on code style or
grammar fixes.

Coding Conventions
------------------
Our CI enforces [clippy's](https://github.com/rust-lang/rust-clippy)
[default linting](https://rust-lang.github.io/rust-clippy/rust-1.52.0/index.html)
and [rustfmt](https://github.com/rust-lang/rustfmt) formatting defined by rules
in [.rustfmt.toml](./.rustfmt.toml). The linter should be run with current
stable rust compiler, while formatter requires nightly version due to the use of
unstable formatting parameters.

If you use rustup, to lint locally you may run the following instructions:

```console
rustup component add clippy
rustup component add fmt
cargo +stable clippy --workspace --all-features
cargo +nightly fmt --all
```

Security
--------
Responsible disclosure of security vulnerabilities helps prevent user loss of
privacy. If you believe a vulnerability may affect other implementations, please
inform them. Guidelines for a responsible disclosure can be found in 
[SECURITY.md](./SECURITY.md) file in the project root.

Note that some of our projects are currently considered "pre-production".
Such projects can be distinguished by the absence of `SECURITY.md`. In such
cases there are no special handling of security issues; please simply open
an issue on GitHub.

Going further
-------------
You may be interested in Jon Atack guide on
[How to review Bitcoin Core PRs][Review] and [How to make Bitcoin Core PRs][PR].
While there are differences between the projects in terms of context and
maturity, many of the suggestions offered apply to this project.

Overall, have fun :)

[1]: http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html
[Review]: https://github.com/jonatack/bitcoin-development/blob/master/how-to-review-bitcoin-core-prs.md
[PR]: https://github.com/jonatack/bitcoin-development/blob/master/how-to-make-bitcoin-core-prs.md
