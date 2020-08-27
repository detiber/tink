# Deploying Tinkerbell Locally on Kubernetes with kind

Registry configuration roughly cribbed from https://www.civo.com/learn/set-up-a-private-docker-registry-with-tls-on-kubernetes

## Prerequisites

- [kind](https://kind.sigs.k8s.io/) (v0.8.0+, Tested with v0.8.1)
- kubectl
- [helm](https://helm.sh/docs/intro/quickstart/) (v3+, tested with v3.3.0)

## Setup

- Setup a new docker network to share between libvirt and kind

```sh
docker network create -d=bridge --subnet 172.30.0.0/16 --ip-range 172.30.100.0/24 \
  -o com.docker.network.bridge.enable_ip_masquerade=true \
  -o com.docker.network.bridge.name=tink-dev \
  -o com.docker.network.bridge.enable_icc=1 \
  -o com.docker.network.bridge.host_binding_ipv4=0.0.0.0 \
  tink-dev
```

- Bring up a new kind cluster

```sh
KIND_EXPERIMENTAL_DOCKER_NETWORK=tink-dev kind create cluster --name tink-dev

```

- Install a PostgreSQL DB using the bitnami helm chart (NOTE: this is not an ha db, bitnami does have a postgresql-ha that could be used for that)

```sh
kubectl create configmap db-init --from-file=../db/tinkerbell-init.sql
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install db --set postgresqlUsername=tinkerbell,postgresqlPassword=tinkerbell,postgresqlDatabase=tinkerbell,initdbScriptsConfigMap=db-init bitnami/postgresql
```

TODO: rather than hardcoding the password here, let it be generated and fetch it where needed (see helm output)

- Install cert-manager with a self-signed issuer

```sh
helm repo add jetstack https://charts.jetstack.io
kubectl create namespace cert-manager
helm install \
  cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --version v0.16.1 \
  --set installCRDs=true

# TODD: wait for deployment

kubectl create -f self-signed-issuer.yaml
```

- Install the registry

```sh
export TINKERBELL_REGISTRY_USERNAME=admin
export TINKERBELL_REGISTRY_PASSWORD=$(head -c 12 /dev/urandom | sha256sum | cut -d' ' -f1)

helm repo add stable https://kubernetes-charts.storage.googleapis.com/
helm install registry stable/docker-registry \
  --set persistence.enabled=false \
  --set secrets.htpasswd=$(docker run --entrypoint htpasswd registry:2.6 -Bbn ${TINKERBELL_REGISTRY_USERNAME} ${TINKERBELL_REGISTRY_PASSWORD})
```

- Deploy tink-server

```sh
cat <<EOF > tink-server/tink-credentials.env
TINKERBELL_TINK_USERNAME=admin
TINKERBELL_TINK_PASSWORD=$(head -c 12 /dev/urandom | sha256sum | cut -d' ' -f1)
EOF

kubectl create -f tink-server.yaml
```

- Deploy hegel

```sh
kubectl create -f hegel.yaml
```

- Bring up the vagrant host

```sh
vagrant up provisioner
```

TODO: move nginx to kind, pre-load mirror content as needed, set appropriate env vars below

- Gather env vars for the docker compose setup
```sh
TINK_IP=$(kubectl get nodes tink-dev-control-plane -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
TINK_GRPC_PORT=$(kubectl get services tink-server-node -o jsonpath='{.spec.ports[?(@.targetPort=="grpc-authority")].nodePort}')
TINK_HTTP_PORT=$(kubectl get services tink-server-node -o jsonpath='{.spec.ports[?(@.targetPort=="http-authority")].nodePort}')
TINKERBELL_REGISTRY_USERNAME ^^above
TINKERBELL_REGISTRY_PASSWORD ^^above

get them into the vagrant host and docker-compose -f <file> up --build -d
```


## Running the CLI

TODO: better way to run this outside of the kind cluster

kubectl run -it --command --rm --attach --image quay.io/tinkerbell/tink-cli:latest --env="TINKERBELL_GRPC_AUTHORITY=tink-server:42113" --env="TINKERBELL_CERT_URL=http://tink-server:42114/cert" cli /bin/ash

## Teardown

```sh
kind delete cluster --name tink-dev
```

## TODO
- Deploy components to cluster
  - basic manifests
  - add templating
    - kustomize???
    - helm???
- Solve networking between virtual hosts and kind
  - Linux and MacOS
  - Possible ideas:
    - ingress (wouldn't work for broadcast)
    - hacking kind to use same network bridge for host networking
    - ???
- Add some type of templating mechanism
- Add tilt configuration for automating updating/deployment of components for rapid development iteration
