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
helm install db --set postgresqlUsername=tinkerbell,postgresqlDatabase=tinkerbell,initdbScriptsConfigMap=db-init bitnami/postgresql
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
export REGISTRY_PASSWORD=$(head -c 12 /dev/urandom | sha256sum | cut -d' ' -f1)
export TINK_IP=$(kubectl get nodes tink-dev-control-plane -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')

cat << EOF | kubectl create -f -
apiVersion: cert-manager.io/v1beta1
kind: Certificate
metadata:
  name: registry-server-certificate
spec:
  secretName: registry-server-certificate
  dnsNames:
  - tink-docker-registry
  - tink-docker-registry.default
  - tink-docker-registry.default.svc
  - tink-docker-registry.default.svc.cluster.local
  ipAddresses:
  - ${TINK_IP}
  issuerRef:
    name: selfsigned-issuer
    kind: Issuer
    group: cert-manager.io
EOF

helm repo add stable https://kubernetes-charts.storage.googleapis.com/
helm install tink stable/docker-registry \
  --set persistence.enabled=true,service.type=NodePort,tlsSecretName=registry-server-certificate \
  --set secrets.htpasswd=$(docker run --entrypoint htpasswd registry:2.6 -Bbn admin ${REGISTRY_PASSWORD})

PORT=$(kubectl get services tink-docker-registry -o jsonpath='{.spec.ports[?(@.targetPort==5000)].nodePort}') \
  kubectl create secret generic tink-registry --from-literal=USERNAME=admin \
  --from-literal=PASSWORD=${REGISTRY_PASSWORD} --from-literal=URL=${TINK_IP}:${PORT}
```

- Deploy tink-server

```sh
kubectl create secret generic tink-credentials \
  --from-literal USERNAME=admin \
  --from-literal PASSWORD=$(head -c 12 /dev/urandom | sha256sum | cut -d' ' -f1)

cat << EOF | kubectl create -f -
apiVersion: cert-manager.io/v1beta1
kind: Certificate
metadata:
  name: tink-server-certificate
spec:
  secretName: tink-server-certificate
  dnsNames:
  - tink-server
  - tink-server.default
  - tink-server.default.svc
  - tink-server.default.svc.cluster.local
  ipAddresses:
  - ${TINK_IP}
  issuerRef:
    name: selfsigned-issuer
    kind: Issuer
    group: cert-manager.io
EOF

kubectl create -f tink-server.yaml

kubectl create secret generic tink-server \
  --from-literal USERNAME=$(kubectl get secret -l app=tink-server -o jsonpath='{.items[0].data.USERNAME}' | base64 -d) \
  --from-literal PASSWORD=$(kubectl get secret -l app=tink-server -o jsonpath='{.items[0].data.PASSWORD}' | base64 -d) \
  --from-literal GRPC_AUTHORITY=${TINK_IP}:$(kubectl get services tink-server -o jsonpath='{.spec.ports[?(@.targetPort=="grpc-authority")].nodePort}')
  --from-literal CERT_URL=http://${TINK_IP}:$(kubectl get services tink-server -o jsonpath='{.spec.ports[?(@.targetPort=="http-authority")].nodePort}')/cert \
```

- Deploy hegel

```sh
kubectl create -f hegel.yaml
```

- bring up the mirror host

```sh
kubectl create -f nginx.yaml
kubectl create secret generic tink-mirror \
  --from-literal URL=http://${TINK_IP}/$(kubectl get services tink-mirror -o jsonpath='{.spec.ports[?(@.targetPort=="http")].nodePort}')
```

- Bring up boots

```sh
kubectl create -f boots.yaml
```

## Running the CLI

TODO: better way to run this outside of the kind cluster

```sh
kubectl run -it --command --rm --attach --image quay.io/tinkerbell/tink-cli:latest --env="TINKERBELL_GRPC_AUTHORITY=tink-server:42113" --env="TINKERBELL_CERT_URL=http://tink-server:42114/cert" cli /bin/ash
```

## Create the hardware

```sh
cat > hardware-data.json <<EOF
{
  "id": "ce2e62ed-826f-4485-a39f-a82bb74338e2",
  "metadata": {
    "facility": {
      "facility_code": "onprem"
    },
    "instance": {},
    "state": ""
  },
  "network": {
    "interfaces": [
      {
        "dhcp": {
          "arch": "x86_64",
          "ip": {
            "address": "172.30.0.5",
            "gateway": "172.30.0.1",
            "netmask": "255.255.0.0"
          },
          "mac": "08:00:27:00:00:01",
          "uefi": false
        },
        "netboot": {
          "allow_pxe": true,
          "allow_workflow": true
        }
      }
    ]
  }
}
EOF
```

Continue with rest of the steps from the local quickstart

## Teardown

```sh
kind delete cluster --name tink-dev
```

## TODO
- Add some type of templating mechanism helm/kustomize????
- Better networking solution for non-kind/libvirt environments
- Add tilt configuration for automating updating/deployment of components for rapid development iteration
