# Deploying Tinkerbell Locally on Kubernetes with kind

Registry configuration roughly cribbed from https://www.civo.com/learn/set-up-a-private-docker-registry-with-tls-on-kubernetes

## Prerequisites

- [kind](https://kind.sigs.k8s.io/) (v0.8.0+, Tested with v0.8.1)
- kubectl
- [helm](https://helm.sh/docs/intro/quickstart/) (v3+, tested with v3.3.0)
- If running Fedora 32, make sure that firewalld (if not disabled), is configured to use the iptables backend (since moby-engine/docker does not support nftables at the time this document was written) and you have not enabled masquerading on the active firewalld zone (likely FedoraWorkstation).

## Setup

- Setup a new docker network to share between libvirt and kind

```sh
docker network create -d=bridge --subnet 172.30.0.0/16 --ip-range 172.30.100.0/24 \
  -o com.docker.network.bridge.name=tink-dev \
  -o com.docker.network.bridge.enable_icc=1 \
  -o com.docker.network.bridge.host_binding_ipv4=0.0.0.0 \
  -o com.docker.network.bridge.enable_ip_masquerade=true \
  tink-dev
```

- Bring up a new kind cluster

```sh
KIND_EXPERIMENTAL_DOCKER_NETWORK=tink-dev kind create cluster --name tink-dev 
```

- Install MetalLB (from metallb.universe.tf/installation/)

```sh
# create the metal-lb config
cat << EOF | kubectl create -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: metallb-config
data:
  config: |
    address-pools:
    - name: default
      protocol: layer2
      addresses:
      - 172.30.10.0-172.30.10.255
EOF

helm repo add bitnami https://charts.bitnami.com/bitnami
helm install lb --set existingConfigMap=metallb-config bitnami/metallb
```

- Install a PostgreSQL DB using the bitnami helm chart (NOTE: this is not an ha db, bitnami does have a postgresql-ha that could be used for that)

```sh
kubectl create configmap db-init --from-file=../db/tinkerbell-init.sql
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

# create the self-signed issuer
cat << EOF | kubectl create -f -
apiVersion: cert-manager.io/v1beta1
kind: Issuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
EOF

# create the CA keypair
cat << EOF | kubectl create -f -
apiVersion: cert-manager.io/v1beta1
kind: Certificate
metadata:
  name: tink-certificate-authority
spec:
  secretName: tink-certificate-authority
  commonName: tink-certificate-authority
  isCA: true
  issuerRef:
    name: selfsigned-issuer
    kind: Issuer
    group: cert-manager.io
EOF

# create the CA issuer
cat << EOF | kubectl create -f -
apiVersion: cert-manager.io/v1beta1
kind: Issuer
metadata:
  name: tink-ca-issuer
spec:
  ca:
    secretName: tink-certificate-authority
EOF
```

- Install the registry

```sh
export REGISTRY_IP=172.30.10.0
export REGISTRY_PASSWORD=$(head -c 12 /dev/urandom | sha256sum | cut -d' ' -f1)

cat << EOF | kubectl create -f -
apiVersion: cert-manager.io/v1beta1
kind: Certificate
metadata:
  name: registry-server-certificate
spec:
  secretName: registry-server-certificate
  dnsNames:
  - registry-docker-registry
  - registry-docker-registry.default
  - registry-docker-registry.default.svc
  - registry-docker-registry.default.svc.cluster.local
  ipAddresses:
  - ${REGISTRY_IP}
  issuerRef:
    name: tink-ca-issuer
    kind: Issuer
    group: cert-manager.io
EOF

helm repo add stable https://kubernetes-charts.storage.googleapis.com/
helm install registry stable/docker-registry \
  --set persistence.enabled=true,service.type=LoadBalancer,service.LoadBalancerIP=${REGISTRY_IP} \
  --set service.port=443,tlsSecretName=registry-server-certificate \
  --set secrets.htpasswd=$(docker run --entrypoint htpasswd registry:2.6 -Bbn admin ${REGISTRY_PASSWORD})

kubectl create secret generic tink-registry --from-literal=USERNAME=admin \
  --from-literal=PASSWORD=${REGISTRY_PASSWORD} \
  --from-literal=URL=${REGISTRY_IP}


# TODO: pull, tag, and push the hello-world image
```

- Deploy tink-server

```sh
export TINK_IP=172.30.10.1

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
    name: tink-ca-issuer
    kind: Issuer
    group: cert-manager.io
EOF

kubectl create -f tink-server.yaml

kubectl create secret generic tink-server \
  --from-literal USERNAME=$(kubectl get secret tink-credentials -o jsonpath='{.data.USERNAME}' | base64 -d) \
  --from-literal PASSWORD=$(kubectl get secret tink-credentials -o jsonpath='{.data.PASSWORD}' | base64 -d) \
  --from-literal GRPC_AUTHORITY=${TINK_IP}:$(kubectl get services tink-server -o jsonpath='{.spec.ports[?(@.targetPort=="grpc-authority")].port}') \
  --from-literal CERT_URL=http://${TINK_IP}:$(kubectl get services tink-server -o jsonpath='{.spec.ports[?(@.targetPort=="http-authority")].port}')/cert
```

- Deploy hegel

```sh
kubectl create -f hegel.yaml
```

- bring up the mirror host

```sh
kubectl create -f nginx.yaml

kubectl create secret generic tink-mirror \
  --from-literal URL=http://$(kubectl get services tink-mirror -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
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

## Create the hardware, template, and workflow

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

tink hardware push --file hardware-data.json

cat > hello-world.yml  <<EOF
version: "0.1"
name: hello_world_workflow
global_timeout: 600
tasks:
  - name: "hello world"
    worker: "{{.device_1}}"
    actions:
      - name: "hello_world"
        image: hello-world
        timeout: 60
EOF

tink template create -n hello-world -p hello-world.yml

tink workflow create -t <template id> -r '{"device_1":"08:00:27:00:00:01"}'
```

## Bring up the worker VM

```sh
vagrant up
```

## Teardown

```sh
kind delete cluster --name tink-dev
```

## TODO
- Add some type of templating mechanism helm/kustomize????
- Better networking solution for non-kind/libvirt environments
- Add tilt configuration for automating updating/deployment of components for rapid development iteration
