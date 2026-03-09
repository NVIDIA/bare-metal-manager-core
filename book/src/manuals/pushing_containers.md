# Tagging and Pushing Containers to a Private Registry

After building all NICo container images (see [Building NICo Containers](building_nico_containers.md)),
tag them for your private registry and push. Set your registry URL and version tag as
environment variables:

```sh
REGISTRY=<your-registry.example.com/carbide>
TAG=<your-version-tag>
```

## Authenticate with your registry

```sh
docker login <your-registry.example.com>
```

## Tag and Push NICo Core Images

```sh
docker tag nico $REGISTRY/nvmetal-carbide:$TAG
docker tag boot-artifacts-x86_64 $REGISTRY/boot-artifacts-x86_64:$TAG
docker tag boot-artifacts-aarch64 $REGISTRY/boot-artifacts-aarch64:$TAG
docker tag machine-validation-config $REGISTRY/machine-validation-config:$TAG

docker push $REGISTRY/nvmetal-carbide:$TAG
docker push $REGISTRY/boot-artifacts-x86_64:$TAG
docker push $REGISTRY/boot-artifacts-aarch64:$TAG
docker push $REGISTRY/machine-validation-config:$TAG
```

## Tag and Push BMM REST Images

```sh
for image in carbide-rest-api carbide-rest-workflow carbide-rest-site-manager \
             carbide-rest-site-agent carbide-rest-db carbide-rest-cert-manager; do
    docker push "$REGISTRY/$image:$TAG"
done
```
