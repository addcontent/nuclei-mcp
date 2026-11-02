# Security policy

nuclei-mcp gives an AI model the ability to send scanner traffic and touch
files on the host, so security reports are taken seriously.

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/addcontent/nuclei-mcp/security/advisories/new)
for this repository. Include the version (`nuclei-mcp --version`), your
configuration, and steps or a tool call that reproduces the problem.

## What counts

Anything that lets a client (or text that steers the model) go beyond the
documented [security model](README.md#security-model), for example:

- reading or writing files outside the templates directory
- scanning a target the scope settings should refuse
- running code on the host through a template
- leaking data from the host into tool results or out-of-band traffic

## Supported versions

Fixes go into the latest release.
