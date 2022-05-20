## Generating Kubernetes configs

```
kubectl kustomize . A
```

To build and apply configuration to a cluster


```
kubectl kustomize . | kubectl apply -f -
```
