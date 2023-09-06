# Contributing

## Codebase location

You can find the gitlab repository that contains the codebase at
https://gitlab-master.nvidia.com/nvmetal/carbide

In order to approve merge requests, you need to be added as a project member at
https://gitlab-master.nvidia.com/nvmetal/carbide/-/project_members

### Cloning the codebase

In order to clone the codebase onto a development computer, a gitlab access token
needs to be created via https://gitlab-master.nvidia.com/-/profile/personal_access_tokens.
The `read_repository` and `write_repository` scopes/permissions have to be added.

After an access token had been created, the codebase can be cloned using
```
git clone https://gitlab-master.nvidia.com/nvmetal/carbide.git
```
The username is your NVIDIA alias (without `@nvidia.com`).
The password is the value of the created access token.

## Conventional Commits

Forge follows conventional commits starting for the v2023.09 release.  Any
commit message prior, unfortunately cannot be used to generate a changelog.

We use `cocogitto` as a tool to manage and generate commits and changelogs for
our history.  Install it according to your platform using their instructions.

Please start reading the
(cocogitto)[https://docs.cocogitto.io/guide/#conventional-commits] document on
conventional commit.

Install the hooks and tab completion according to the user guide.

You may use `coq` to automatically format git commit logs.

```
coq commit feat "add feature"
```

It is a WIP and we're iterating on it.
