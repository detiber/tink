# TODO: find actual minimum tilt version
load('ext://min_tilt_version', 'min_tilt_version')
min_tilt_version('0.17')

# We require at minimum CRD support, so need at least Kubernetes v1.16
load('ext://min_k8s_version', 'min_k8s_version')
min_k8s_version('1.16')

# Load the extension for live updating
load('ext://restart_process', 'docker_build_with_restart')

# Load the remote helm dependencies
load('ext://helm_remote', 'helm_remote')

# MetalLB
k8s_yaml(encode_yaml(decode_yaml("""
apiVersion: v1
kind: ConfigMap
metadata:
  name: metallb-config
  namespace: metallb
data:
  config: |
    address-pools:
    - name: default
      protocol: layer2
      addresses:
      - 172.30.10.0-172.30.10.255
""")))
helm_remote(
    'metallb',
    namespace='metallb',
    create_namespace=True,
    repo_url='https://charts.bitnami.com/bitnami',
    repo_name='metallb',
    set=['existingConfigMap=metallb-config']
)
k8s_resource(
    workload='metallb-speaker',
    objects=[
        'metallb-speaker:serviceaccount',
        'metallb-speaker:podsecuritypolicy'
    ]
)
k8s_resource(
    workload='metallb-controller',
    objects=[
        'metallb:namespace',
        'metallb-config:configmap',
        'metallb-controller:serviceaccount',
        'metallb-controller:podsecuritypolicy',
        'metallb-config-watcher:role',
        'metallb-pod-lister:role',
        'metallb-config-watcher:rolebinding',
        'metallb-pod-lister:rolebinding',
        'metallb-memberlist:secret'
    ]
)

# PostgreSQL
db_init_script = str(read_file('deploy/db/tinkerbell-init.sql')).rstrip('\n').replace(',', '\\,')
helm_remote(
    'postgresql',
    release_name='db',
    repo_url='https://charts.bitnami.com/bitnami',
    repo_name='postgresql',
    set=[
        'postgresqlUsername=tinkerbell',
        'postgresqlDatabase=tinkerbell',
        'initdbScripts.tinkerbell_init\\.sql='+db_init_script
    ]
)
k8s_resource(
    workload='db-postgresql',
    new_name='db',
    objects=[
        'db-postgresql-init-scripts:configmap',
        'db-postgresql:secret'
    ]
)

# cert-manager
helm_remote(
    'cert-manager',
    namespace='cert-manager',
    create_namespace=True,
    repo_url='https://charts.jetstack.io',
    repo_name='cert-manager',
    set=['installCRDs=true']
)
k8s_resource(
    workload='cert-manager',
    objects=[
        # Try to work arouund unmanaged role/clusterrole resources that cannot be included due to ':' in name
        #'cert-manager:namespace',
        'certificaterequests.cert-manager.io:customresourcedefinition',
        'certificates.cert-manager.io:customresourcedefinition',
        'challenges.acme.cert-manager.io:customresourcedefinition',
        'clusterissuers.cert-manager.io:customresourcedefinition',
        'issuers.cert-manager.io:customresourcedefinition',
        'orders.acme.cert-manager.io:customresourcedefinition',
        'cert-manager:serviceaccount',
        'cert-manager-controller-challenges:clusterrolebinding:cert-manager',
        'cert-manager-controller-orders:clusterrolebinding:cert-manager',
        'cert-manager-controller-certificates:clusterrolebinding:cert-manager',
        'cert-manager-controller-issuers:clusterrolebinding:cert-manager',
        'cert-manager-controller-clusterissuers:clusterrolebinding:cert-manager',
        'cert-manager-controller-ingress-shim:clusterrolebinding:cert-manager',
        'cert-manager-view:clusterrole:cert-manager',
        'cert-manager-edit:clusterrole:cert-manager',
        'cert-manager-controller-issuers:clusterrole:cert-manager',
        'cert-manager-controller-clusterissuers:clusterrole:cert-manager',
        'cert-manager-controller-certificates:clusterrole:cert-manager',
        'cert-manager-controller-orders:clusterrole:cert-manager',
        'cert-manager-controller-challenges:clusterrole:cert-manager',
        'cert-manager-controller-ingress-shim:clusterrole:cert-manager'
    ]
)
k8s_resource(
    workload='cert-manager-webhook',
    objects=[
        'cert-manager-webhook:mutatingwebhookconfiguration',
        'cert-manager-webhook:serviceaccount',
        'cert-manager-webhook:validatingwebhookconfiguration'
    ],
    resource_deps=['cert-manager-cainjector']
)
k8s_resource(
    workload='cert-manager-cainjector',
    objects=[
        'cert-manager-cainjector:serviceaccount',
        'cert-manager-cainjector:clusterrolebinding:cert-manager',
        'cert-manager-cainjector:clusterrole:cert-manager'
    ],
    resource_deps=['cert-manager']
)

# Deploy the CA and dependencies
k8s_yaml('deploy/kind/tink-selfsigned-issuer.yaml')
k8s_resource(
    new_name='tink-selfsigned-issuer',
    objects=['selfsigned-issuer:issuer'],
    resource_deps=['cert-manager-webhook']
)

k8s_yaml('deploy/kind/tink-ca-certificate.yaml')
k8s_resource(
    new_name='tink-ca-certificate',
    objects=['tink-certificate-authority:certificate'],
    resource_deps=['tink-selfsigned-issuer']    
)

k8s_yaml('deploy/kind/tink-ca-issuer.yaml')
k8s_resource(
    new_name='tink-ca-issuer',
    objects=['tink-ca-issuer:issuer'],
    resource_deps=['tink-ca-certificate']    
)

registry_ip = '172.30.10.0'
registry_password = str(local("head -c 12 /dev/urandom | sha256sum | cut -d' ' -f1")).rstrip('\n')
registry_cert = read_yaml('deploy/kind/tink-registry-certificate.yaml')
registry_cert['spec']['ipAddresses'] = [registry_ip]
registry_htpasswd = str(local('docker run --entrypoint htpasswd registry:2.6 -Bbn admin '+registry_password))

k8s_yaml(encode_yaml(registry_cert))
helm_remote(
    'docker-registry',
    repo_url='https://kubernetes-charts.storage.googleapis.com/',
    repo_name='docker-registry',
    set=[
        'persistence.enabled=true',
        'service.type=LoadBalancer',
        'service.LoadBalancerIP='+registry_ip,
        'service.port=443',
        'tlsSecretName=registry-server-certificate',
        'secrets.htpasswd='+registry_htpasswd
    ]
)

registry_secret = {
    'apiVersion': 'v1',
    'kind': 'Secret',
    'metadata': {
        'name': 'tink-registry'
    },
    'type': 'Opaque',
    'stringData': {
        'USERNAME': 'admin',
        'PASSWORD': registry_password,
        'URL': registry_ip
    }
}  
k8s_yaml(encode_yaml(registry_secret))

k8s_resource(
    workload='docker-registry',
    objects=[
        'docker-registry:persistentvolumeclaim',
        'docker-registry-config:configmap',
        'docker-registry-secret:secret',
        'registry-server-certificate:certificate',
        'tink-registry:secret'
    ],
    resource_deps=[
        'tink-ca-issuer',
        'metallb-controller'
    ]
)

def generate_certificate(name, namespace="default", dnsNames=[], ipAddresses=[]):
    cert = {
        'apiVersion': 'cert-manager.io/v1',
        'kind': 'Certificate',
        'metadata': {
            'name': name,
            'namespace': namespace,
        },
        'spec': {
            'secretName': name,
            'dnsNames': dnsNames,
            'ipAddresses': ipAddresses,
            'issuerRef': {
                'name': 'tink-ca-issuer',
                'kind': 'Issuer',
                'group': 'cert-manager.io'
            }
        }
    }
    k8s_yaml(encode_yaml(cert))


local_resource(
    'tink-server-build',
    'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/tink-server ./cmd/tink-server',
    deps=[
        'go.mod',
        'go.sum',
        'cmd/tink-server',
        'db',
        'grpc-server',
        'http-server',
        'metrics',
        'pkg',
        'protos'
    ]
)
docker_build_with_restart(
    'quay.io/tinkerbell/tink',
    '.',
    dockerfile_contents="""
FROM gcr.io/distroless/base:debug as debug
WORKDIR /
COPY build/tink-server /tink-server
ENTRYPOINT ["/tink-server"]
""",
    only=[
        './build/tink-server',
    ],
    target='debug',
    live_update=[
        sync('./build/tink-server', '/tink-server')
    ],
    entrypoint=[
        # Kubernetes deployment argments are ignored by
        # the restart process helper, so need to include
        # them here.
        '/tink-server',
        '--facility=onprem',
        '--ca-cert=/certs/ca.crt',
        '--tls-cert=/certs/tls.crt',
        '--tls-key=/certs/tls.key'
    ]
)

tink_ip = '172.30.10.1'
tink_password = str(local("head -c 12 /dev/urandom | sha256sum | cut -d' ' -f1")).rstrip('\n')

generate_certificate(
    name='tink-server-certificate',
    dnsNames=[
        'tink-server',
        'tink-server.default',
        'tink-server.default.svc',
        'tink-server.default.svc.cluster.local',
    ],
    ipAddresses=[tink_ip],
)

tink_secret = {
    'apiVersion': 'v1',
    'kind': 'Secret',
    'metadata': {
        'name': 'tink-credentials',
    },
    'type': 'Opaque',
    'stringData': {
        'USERNAME': 'admin',
        'PASSWORD': tink_password,
    }
}  
k8s_yaml(encode_yaml(tink_secret))

k8s_yaml('deploy/kind/tink-server.yaml')
k8s_resource(
    workload='tink-server',
    objects=[
        'tink-credentials:secret',
        'tink-server-certificate:certificate',
    ],
    resource_deps=[
        'tink-ca-issuer',
        'metallb-controller'
    ]
)

# TODO: Create tink-server secret for use in other components

# TODO: hegel, should be able to use local repo if configured or use upstream image otherwise

k8s_yaml('deploy/kind/nginx.yaml')
k8s_resource(
    workload='tink-mirror',
    objects=[
        'webroot:persistentvolumeclaim',
    ],
    resource_deps=['tink-server']
)

# TODO: boots, should be able to use local repo if configured or use upstream image otherwise
