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

## Useful links to Helm chart documentation

- [Getting started](https://helm.sh/docs/chart_template_guide/getting_started/)
- [Functions and pipelines](https://helm.sh/docs/chart_template_guide/functions_and_pipelines/)
- [Template function list](https://helm.sh/docs/chart_template_guide/function_list/)


## Editing and testing helm charts for an application

Helm chart changes can be verified using the following steps:

1. Enter the path which contains the helm chart - e.g. `charts/carbideApi`
2. Fetch the dependencies for this chart:
   ```
   helm dependency build
   ```
   This step requires dependent repositories being added via `helm repo add`
   and `helm repo update` as described in the Dependencies section.
3. Render the helm chart from the edited templates by calling:
   ```
   helm template
   ```
   You can also redirect the output to a file, in order to use an editor to
   inspect the output:
   ```
   helm template . > myChartContent
   ```
4. You can verify the generated helm chart by inspecting the output
5. In case template rendering fails with a linting error like
   > [ERROR] templates/deployment.yaml: unable to parse YAML: error converting YAML to JSON: yaml: line 116: did not find expected node content
   
   You are able to inspect the generated yaml and why it fails by commenting
   the lines that have been added and are potential source of errors via
   prefixing them with `#`. After a line is commented, the `helm template .`
   command should succeed and templates should still be expected. Thereby
   you can inspect the output and spot malformed content, like
   > `#              value: [::0]:%!d(float64=1080)`
   
   After the template is fixed and rendering the content shows the expected
   values, you can uncomment the line again.