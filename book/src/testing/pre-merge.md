# Pre-Merge Testing

## Carbide pre-merge

Carbide pre-merge testing is currently an optional job in carbide Merge Request pipelines.

It is designed to bring up carbide from the MR branch in a dev env using the
`forged` repo's `main` branch.
Carbide `trunk` is merged into the MR branch before the test starts and the job
will fail if this step has merge conflicts.

The test process is similar to the procedure
[here](https://gitlab-master.nvidia.com/nvmetal/ci-tools/internal-services-images).
PXE artifacts are built (if they have changed compared to trunk), build containers are built,
forged is brought up, `skaffold run` used to bring in carbide, then the cluster is
checked for health.
Finally, `just clean` is called to clean the setup for the next job.

## Forged pre-merge

The forged pre-merge test job is added to Merge Request pipelines in the `forged`
repository when changes to certain directories are made. The test does not apply to
changes to kustomization.yaml files in the `envs` directory for example,
but it will run for more core changes.

The test is a subset of what is done for carbide; `just start`,
health checks and then `just clean`.


## Runner machine setup

This documents the steps needed to configure the dev environment machines used for
running pre-merge tests by CI.

This section applies to [Forged](https://gitlab-master.nvidia.com/nvmetal/forged)
as well as [Carbide](https://gitlab-master.nvidia.com/nvmetal/carbide).

### Create a dev env instance

Create an instance using the carbide-dev-environment image built
[here](https://gitlab-master.nvidia.com/nvmetal/ci-tools/internal-services-images).
Currently, the pre-merge test runner machines live in pdx01 in a VPC named
"[forge-internal-services](https://forge.ngc.nvidia.com/org/i1k1exmxlqr1/vpcs/0fdf4188-5834-445a-81f4-39982038fcf6)"
with the other GitLab runners used for builds.

### Install gitlab-runner

On the machine, as root (`doas -s`):

```
# Download the binary for your system
curl -L --output /usr/local/bin/gitlab-runner https://gitlab-runner-downloads.s3.amazonaws.com/latest/binaries/gitlab-runner-linux-amd64

# Give it permission to execute
chmod +x /usr/local/bin/gitlab-runner

# Create a GitLab Runner user
useradd --comment 'GitLab Runner' --create-home gitlab-runner --shell /bin/bash

# Install and run as a service
gitlab-runner install --user=gitlab-runner --working-directory=/home/gitlab-runner
gitlab-runner start
```

### Comment out clear_console in .bash_logout

This is necessary or CI jobs will fail.

```
(base) dblanc@forged-pre-merge-ci-runner-01:~$ cat /home/gitlab-runner/.bash_logout
# ~/.bash_logout: executed by bash(1) when login shell exits.

# when leaving the console clear the screen to increase privacy

#if [ "$SHLVL" = 1 ]; then
#    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
#fi
```

### Add gitlab-runner user to the docker group

On the machine, as root (`doas -s`):

```
(base) root@10-217-19-213:~# usermod -aG docker gitlab-runner
```


### Give the gitlab-runner user doas permission

Give the `gitlab-runner` user root access via doas, so that the new `just clean` can work.
Add this line to the bottom of `/etc/doas.conf`:
```
permit nopass gitlab-runner
```

## Re-registering a runner

It may become necessary to re-install a runner instance due to significant changes
in the dev env OS image.
We believe there is a procedure where we can re-install the instance and re-register
the runner if we keep the `/etc/gitlab-runner/config.toml` file which contains
the secret for talking to GitLab.
If not, then it isn't hard to register a new runner with the same tag
and delete the old one.
