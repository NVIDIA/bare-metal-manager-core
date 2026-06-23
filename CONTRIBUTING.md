# Contributing to NCX Infra Controller

Thank you for your interest in contributing to NCX Infra Controller! 

We welcome contributions of all sizes — from fixing a typo in the docs to adding a new API endpoint. Whether you're a first-time contributor or a seasoned open source developer, there's a place for you here.

> **Project Status:** NCX Infra Controller is currently in **experimental**. This means:
>
> - APIs, configurations, and features may change without notice between releases.
> - Review timelines may vary as the team focuses on stabilizing the core platform.
> - Not all contributions will be accepted — we prioritize changes that align with the current roadmap.
>
> We appreciate your patience and contributions as we work toward a stable release.

## Table of Contents

- [Developer Certificate of Origin (DCO)](#developer-certificate-of-origin-dco)
- [Fork and Setup](#fork-and-setup)
- [Contribution Process](#contribution-process)
- [Engineering Guidelines](#engineering-guidelines)
- [Pull Request Guidelines](#pull-request-guidelines)

## Developer Certificate of Origin (DCO)

NCX Infra Controller requires the Developer Certificate of Origin (DCO) process to be followed for all contributions.

The DCO is a lightweight way for contributors to certify that they wrote or otherwise have the right to submit the code they are contributing. The full text of the DCO can be found at [developercertificate.org](https://developercertificate.org/):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### Signing Your Commits

To sign off on a commit, you must add a `Signed-off-by` line to your commit message. This is done by using the `-s` or `--signoff` flag when committing:

```bash
git commit -s -m "Your commit message"
```

**Tip:** You can create a Git alias to always sign off:

```bash
git config --global alias.ci 'commit -s'
# Now use: git ci -m "Your commit message"
```

This will automatically add a line like this to your commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

Make sure your `user.name` and `user.email` are set correctly in your Git configuration:

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### Signing Off Multiple Commits

If you have multiple commits that need to be signed off, you can use interactive rebase:

```bash
git rebase HEAD~<number_of_commits> --signoff
```

Or to sign off all commits in a branch:

```bash
git rebase --signoff origin/main
```

### DCO Enforcement

All pull requests are automatically checked for DCO compliance via DCO bot. Pull requests with unsigned commits cannot be merged until all commits are properly signed off.

## Fork and Setup

Developers must first fork the upstream [Infra Controller repository](https://github.com/NVIDIA/infra-controller).

### 1. Fork the Repository

1. Navigate to the [Infra Controller repository](https://github.com/NVIDIA/infra-controller) on GitHub.
2. Click the **Fork** button in the upper right corner.
3. Select your GitHub account as the destination.

### 2. Clone Your Fork

```bash
git clone https://github.com/<your-username>/metal-manager.git
cd metal-manager
```

### 3. Add Upstream Remote

Add the original repository as an upstream remote to keep your fork in sync:

```bash
git remote add upstream https://github.com/NVIDIA/metal-manager.git
git remote -v  # Verify remotes
```

### 4. Keep Your Fork Updated

Before starting new work, sync your fork with upstream:

```bash
# Fetch upstream changes
git fetch upstream

# Switch to main branch
git checkout main

# Merge upstream changes
git merge upstream/main

# Push to your fork
git push origin main
```

### 5. Create a Feature Branch

Always create a new branch for your changes:

```bash
git checkout -b feature/your-feature-name
```

Use descriptive branch names like:
- `feature/add-new-api`
- `fix/resolve-dhcp-issue`
- `docs/update-readme`

## Contribution Process

1. **Fork the repository** and create your branch from `main`.
2. **Make your changes** following our coding guidelines.
3. **Sign off all your commits** using `git commit -s`.
4. **Submit a pull request** with a clear description of your changes.

## Engineering Guidelines

Apply these guidelines to every code change, whether it is handwritten,
generated, or produced with automation. They are intended to keep changes
reviewable, low risk, and consistent with the existing codebase.

### Scope and ownership

- Make the smallest correct change that solves the problem. Avoid unrelated
  refactors, formatting churn, new configuration paths, compatibility layers,
  or feature flags unless the change requires them.
- If requirements are unclear, ask before changing scope. Do not silently
  simplify, rename, collapse, or replace the requested behavior with an adjacent
  improvement or quick win.
- Do not redefine success around an easier path. If the real workflow is
  blocked, report the concrete missing input, artifact, tool, permission, or
  configuration.
- Work with the current tree. Do not discard, rewrite, or revert someone else's
  changes unless the owner explicitly asks for that.
- Keep pull requests focused on one behavioral or documentation outcome. Remove
  unused code, temporary logging, skipped assertions, placeholders, and hidden
  TODOs before asking for review.
- Do not commit secrets, credentials, local environment files, generated
  private keys, or machine-specific artifacts.

### Reuse before adding code

Before introducing code or dependencies, check in this order:

1. Does this code need to exist, or can the caller use an existing behavior?
2. Does the standard library already solve it?
3. Does Rust, Go, Kubernetes, SQL, the OS, or another platform feature solve it
   natively?
4. Does an existing workspace dependency or local helper already solve it?
5. Can the change be expressed clearly inline instead of adding an abstraction?

Only add a helper, abstraction, dependency, compatibility path, or migration
when it removes real complexity, matches an established pattern, or is required
for the requested behavior.

### Evidence and assumptions

- Treat implementation claims as assumptions until they are backed by code,
  generated types, route registration, service definitions, schema, tests,
  documentation, or runtime output.
- Do not infer contracts from similar names or nearby code alone. Prove data
  flow, ownership, authorization, persistence, API shape, and deployment
  behavior before relying on them.
- Back claims with concrete evidence: diffs, generated output, logs, test
  results, API responses, screenshots, or direct observations from the relevant
  system.
- If an assumption cannot be checked cheaply, state it in the pull request or
  review notes instead of presenting it as fact. If new evidence contradicts an
  assumption, update the design before continuing.

### Verification

- Verification should exercise the behavior that changed. Do not claim a fix is
  covered by an unrelated build, a nearby test, generated examples, or a mocked
  path that avoids the real integration being changed.
- Use the real service, repository, dataset, device, workflow, command, and
  integration path that the change affects whenever practical. Call out any
  lower-fidelity substitute instead of treating it as equivalent coverage.
- Add or update focused tests for bug fixes, shared behavior, API contracts,
  migrations, and cross-module changes. For narrow documentation-only changes,
  a diff review is usually sufficient.
- Keep OpenAPI specs, protobufs, database migrations, Helm manifests, generated
  code, and documentation in sync with the behavior they describe.

## Pull Request Guidelines

- Provide a clear description of the problem and solution.
- Reference any related issues.
- Keep pull requests focused on a single change.
- Be responsive to feedback and code review comments.
- Ensure all CI checks pass before requesting review.

## Build Guide

For pinned dependency updates, image testing, and build optimization trade-offs, see the
[Build Guide](docs/development/build-guide.md).

## Questions?

If you have questions about contributing, please open an issue for discussion.
