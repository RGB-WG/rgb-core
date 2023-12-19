# Security

We take the security of our software products and services seriously, which 
includes all source code repositories managed through our GitHub organizations.

If you believe you have found a security vulnerability in any of our repository 
that meets [definition of a security vulnerability][definition], please report 
it to us as described below.

## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them to the repository maintainers by sending a **GPG
encrypted e-mail** to _all maintainers of a specific repo_ using their GPG keys.

A list of repository maintainers and their keys and e-mail addresses are 
provided inside MAINTAINERS.md file and MANIFEST.yml, with the latter also 
included in the README.md as a manifest block, which looks in the following way:

```yaml
Name: <name>
...
Maintained: <organization name>
Maintainers:
  <name and surname of maintainer 1>:
    GPG: <encryption key fingerprint>
    EMail: <e-mail address>
  <name and surname of other maintainers>:
    ...
```

You should receive a response within 72 hours. If for some reason you do not, 
please follow up via email to ensure we received your original message. 

Please include the requested information listed below (as much as you can 
provide) to help us better understand the nature and scope of the possible 
issue:

* Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
* Full paths of source file(s) related to the manifestation of the issue
* The location of the affected source code (tag/branch/commit or direct URL)
* Any special configuration required to reproduce the issue
* Step-by-step instructions to reproduce the issue
* Proof-of-concept or exploit code (if possible)
* Impact of the issue, including how an attacker might exploit the issue

This information will help us triage your report more quickly.

## Preferred Languages

We prefer all communications to be in English.

## Policy

We follow the principle of [Coordinated Vulnerability Disclosure][disclosure].

[definition]: https://aka.ms/opensource/security/definition
[disclosure]: https://aka.ms/opensource/security/cvd
