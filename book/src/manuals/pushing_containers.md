# Tagging and Pushing Containers to a Private Registry

After building all NICo container images (refer to the [Building NICo Containers](building_nico_containers.md) section),
you will need to tag them and push them to your private registry.

## Setting Environment Variables

Set your registry URL and version tag as environment variables:

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

## Tag and Push REST Images

REST images are built from the
[ncx-infra-controller-rest](https://github.com/NVIDIA/ncx-infra-controller-rest)
repository. The `make docker-build` command tags images at build time when you pass the
`IMAGE_REGISTRY` and `IMAGE_TAG` environment variables:

```sh
cd /path/to/ncx-infra-controller-rest
make docker-build IMAGE_REGISTRY=$REGISTRY IMAGE_TAG=$TAG
```

Then, push all REST images to your private registry:

```sh
for image in carbide-rest-api carbide-rest-workflow carbide-rest-site-manager \
             carbide-rest-site-agent carbide-rest-db carbide-rest-cert-manager \
             carbide-rla carbide-psm carbide-nsm; do
    docker push "$REGISTRY/$image:$TAG"
done
```
