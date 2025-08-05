# Forge Site Tracing

Carbide (and potentially other services in the future) can be configured to emit OpenTelemetry traces and spans as it
runs.

Tracing information is collected similarly to logs, by the [OpenTelemetry collector
instance](https://gitlab-master.nvidia.com/nvmetal/forged/-/blob/main/bases/opentelemetry-collector/kustomization.yaml)
inside the site, which is deployed into the `otel` namespace.

The collector forwards the traces into a site-local [Grafana Tempo](https://grafana.com/docs/tempo/latest/) installation.
Currently it maintains the last 10GB of tracing data.

The UI for Tempo is accessed within Grafana, the URL for which is is `https://grafana-siteid.frg.nvidia.com`, e.g.
[grafana-dev3.frg.nvidia.com](https://grafana-dev3.frg.nvidia.com)

## Enabling tracing

Tracing is not enabled by default, as a lot of trace events are emitted and it has the potential to slow carbide down.
(How much this affects things has not yet been determined, this is a defensive measure.) Tracing is enabled via a
dynamic configuration option in `forge-admin-cli`. Use this command to enable tracing:

```
forge-admin-cli set tracing-enabled true
```

And when you're done, disable it again with:

```
forge-admin-cli set tracing-enabled false
```

## Accessing Tempo UI

See [Site metric access](site_metrics.md#site_metric_access) for general information on how to access Grafana on the
site.

In Grafana, navigate to the [Explore](https://grafana-dev3.frg.nvidia.com/explore) screen and select `Tempo` as as
datasource. You can configure query attributes using the UI.

## Accessing Tempo from local-dev environments

Assuming your local-dev environment is configured per the instructions on the [internal-services-images
README](https://gitlab-master.nvidia.com/nvmetal/ci-tools/internal-services-images), you can access grafana in via a
forwarded port via kubectl. First, run this command in a terminal window:

```
kubectl -n forge-monitoring port-forward svc/forge-monitoring-local-dev-grafana 8081:80
```

Then, browse to [http://localhost:8081](http://localhost:8081). Log in with username: `admin` and password `prom-operator` (the azure auth is
not enabled in local-dev environments.)
