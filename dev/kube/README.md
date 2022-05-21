## Generating Kubernetes configs

```
kubectl kustomize <environment>

e.g.
kubectl kustomize overlays/local
```

To build and apply configuration to a cluster


```
kubectl kustomize <environment> | kubectl apply -f -

e.g.
kubectl kustomize overlays/dev1 |  kubectl apply -f -
```
