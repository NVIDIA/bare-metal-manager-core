# Helm

Install Helm via your system package manager or by following the
directions [here](https://helm.sh/docs/intro/install/)

## Dependencies

All of the Helm charts in `Chart.yaml` should use [Nvidia Production Helm Repo](https://helm.ngc.nvidia.com/nvidian/forge)
or [Nvidia non-prod Helm Repo](https://helm.stg.ngc.nvidia.com).
You must authenticate with a user/pass to pull in dependencies outside Fleet Command.

```sh
helm repo add nvidia-stg https://stg.helm.ngc.nvidia.com/nvidia/nvforge --username \$oauthtoken --password $NGC_TOKEN
helm repo add nvidia https://helm.ngc.nvidia.com/nvidian/forge --username \$oauthtoken --password $NGC_TOKEN
```

Your NGC Token can be found in your settings / API key page at [ProdNGC](http://ngc.nvidia.com) or [Staging NGC](https://stg.ngc.nvidia.com).
You must get invited to the nvidian/forge and the nvidia/nvforge teams in NGC Production and NGC Staging, respectively.
The NGC SRE team can provide the necessary NGC invite to these teams.

**NOTE**

> The username is the literal text `$oauthtoken`.
>
> If passing the name on CLI you will need to escape the `$`
>
> e.g. `\$oauthtoken`

Once you add the `repos`, update the local helm cache by running:

```
helm repo update
```
