# Deploying Tinkerbell Locally on Kubernetes with kind

Registry configuration roughly cribbed from https://www.civo.com/learn/set-up-a-private-docker-registry-with-tls-on-kubernetes

## Prerequisites

- [kind](https://kind.sigs.k8s.io/) (Tested with v0.8.1)
- kubectl
- [helm](https://helm.sh/docs/intro/quickstart/) (v3+, tested with v3.3.0)

## Setup

- Bring up a new kind cluster

```sh

COPY
cat <<EOF | kind create cluster --name tink-dev --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
  - containerPort: 443
    hostPort: 443
    protocol: TCP
EOF
```

- Install a PostgreSQL DB using the bitnami helm chart (NOTE: this is not an ha db, bitnami does have a postgresql-ha that could be used for that)

```sh
kubectl create configmap db-init --from-file=../db/tinkerbell-init.sql
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install db --set postgresqlUsername=tinkerbell,postgresqlPassword=tinkerbell,postgresqlDatabase=tinkerbell,initdbScriptsConfigMap=db-init bitnami/postgresql
```

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

- Deploy NGINX ingress

```sh
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
# taken from the deploy script that is used to generate the static manifest referenced by the kind docs
cat << EOF | helm install ingress ingress-nginx/ingress-nginx --values -
controller:
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  hostPort:
    enabled: true
  terminationGracePeriodSeconds: 0
  service:
    type: NodePort
  nodeSelector:
    ingress-ready: "true"
  tolerations:
    - key: "node-role.kubernetes.io/master"
      operator: "Equal"
      effect: "NoSchedule"
  publishService:
    enabled: false
  extraArgs:
    publish-status-address: localhost
EOF
```

- Create the ingress for the registry

```sh
kubectl create -f registry-ingress.yaml
```

- Deploy tink-server

```sh
export TINKERBELL_TINK_USERNAME=admin
export TINKERBELL_TINK_PASSWORD=$(head -c 12 /dev/urandom | sha256sum | cut -d' ' -f1)


```

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
