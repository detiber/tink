# TODO: find actual minimum tilt version
load('ext://min_tilt_version', 'min_tilt_version')
min_tilt_version('0.17')

# We require at minimum CRD support, so need at least Kubernetes v1.16
load('ext://min_k8s_version', 'min_k8s_version')
min_k8s_version('1.16')

# Load the extension for live updating
load('ext://restart_process', 'docker_build_with_restart')

# Load the extension for helm_remote
load('ext://helm_remote', 'helm_remote')

# Load the extension for local_output
load('ext://local_output', 'local_output')

config.define_string('hegel_repo_path', args=True, usage='path to hegel repository')
cfg = config.parse()
hegel_repo_path = cfg.get('hegel_repo_path', '../hegel')

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

# Multus
k8s_yaml('deploy/kind/multus.yaml')
cni_config = {
    'cniVersion': '0.3.1',
    'name': 'tink-dev',
    'plugins': [
        {
            'type': 'bridge',
            'capabilities': {
                'ips': True,
            },
            'bridge': 'tink-dev',
            'ipam': {
                'type': 'static',
                'routes': [
                    {
                        'dst': '172.30.0.0/16',
                    }
                ]
            }
        },
        {
            'type': 'kind-no-snat-interface'
        }
    ]
}
multus_config = {
    'apiVersion': 'k8s.cni.cncf.io/v1',
    'kind': 'NetworkAttachmentDefinition',
    'metadata': {
        'name': 'tink-dev',
    },
    'spec': {
        'config': encode_json(cni_config)
    }
}  
k8s_yaml(encode_yaml(multus_config))
cni_config = {
    'cniVersion': '0.3.1',
    'name': 'tink-dev-no-ip',
    'plugins': [
        {
            'type': 'bridge',
            'bridge': 'tink-dev',
        },
        {
            'type': 'route-override',
            'addroutes': [
                {
                    'dst': '172.30.0.0/16'
                }
            ]
        },
        {
            'type': 'kind-no-snat-interface'
        }
    ]
}
multus_config = {
    'apiVersion': 'k8s.cni.cncf.io/v1',
    'kind': 'NetworkAttachmentDefinition',
    'metadata': {
        'name': 'tink-dev-no-ip',
    },
    'spec': {
        'config': encode_json(cni_config)
    }
}  
k8s_yaml(encode_yaml(multus_config))
k8s_resource(
    workload='kube-multus-ds',
    new_name='multus',
    objects=[
        'multus:serviceaccount',
        'network-attachment-definitions.k8s.cni.cncf.io:customresourcedefinition',
        'multus:clusterrole',
        'multus:clusterrolebinding',
        'tink-dev:networkattachmentdefinition',
        'tink-dev-no-ip:networkattachmentdefinition'
    ],
)

# KubeVirt
k8s_yaml('deploy/kind/kubevirt-operator.yaml')
k8s_resource(
     workload='virt-operator',
     objects=[
         'kubevirt:namespace',
         'kubevirts.kubevirt.io:customresourcedefinition',
         'kubevirt-operator:serviceaccount',
         'kubevirt-operator:role',
         'kubevirt-operator:clusterrole',
         'kubevirt-operator-rolebinding:rolebinding',
         'kubevirt-operator:clusterrolebinding',
         'kubevirt-cluster-critical:priorityclass'
     ],
     resource_deps=['multus']
)

k8s_yaml('deploy/kind/kubevirt-cr.yaml')
k8s_resource(
    new_name='kubevirt',
    objects=['kubevirt:kubevirt'],
    resource_deps=['virt-operator']    
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
    ],
    resource_deps=['multus']
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
    ],
    resource_deps=['multus']
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

registry_ip = '172.30.0.3'
registry_password = local_output("head -c 12 /dev/urandom | sha256sum | cut -d' ' -f1")
registry_htpasswd = local_output('docker run --entrypoint htpasswd registry:2.6 -Bbn admin '+registry_password)

generate_certificate(
    name='registry-server-certificate',
    dnsNames=[
        'docker-registry',
        'docker-registry.default',
        'docker-registry.default.svc',
        'docker-registry.default.svc.cluster.local',
    ],
    ipAddresses=[registry_ip]
)


helm_remote(
    'docker-registry',
    repo_url='https://kubernetes-charts.storage.googleapis.com/',
    repo_name='docker-registry',
    set=[
        'persistence.enabled=true',
        'service.port=443',
        'tlsSecretName=registry-server-certificate',
        'secrets.htpasswd='+registry_htpasswd,
        'podAnnotations.k8s\\.v1\\.cni\\.cncf\\.io/networks=[{"interface":"net1"\\,"mac":"08:00:29:00:00:00"\\,"ips":["'+registry_ip+'/16"]\\,"name":"tink-dev"\\,"namespace":"default"}]'
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
        'tink-ca-issuer'
    ]
)

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

tink_password = local_output("head -c 12 /dev/urandom | sha256sum | cut -d' ' -f1")

generate_certificate(
    name='tink-server-certificate',
    dnsNames=[
        'tink-server',
        'tink-server.default',
        'tink-server.default.svc',
        'tink-server.default.svc.cluster.local',
    ],
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
        'db'
    ]
)

# TODO: Create tink-server secret for use in other components

def load_from_repo_with_fallback(path, fallback_yaml):
    if os.path.exists(path):
        include(os.path.join(path, 'Tiltfile'))
    else:
        k8s_yaml(fallback_yaml)

# deploy hegel from locally checked out repo, falling back to static deployment
load_from_repo_with_fallback(hegel_repo_path, 'deploy/kind/hegel.yaml')

k8s_yaml('deploy/kind/nginx.yaml')
k8s_resource(
    workload='tink-mirror',
    objects=[
        'webroot:persistentvolumeclaim',
    ],
    resource_deps=[
        'tink-server',
    ]
)

# TODO: boots, should be able to use local repo if configured or use upstream image otherwise
k8s_yaml('deploy/kind/boots.yaml')
k8s_resource(
    workload='boots',
    resource_deps=[
        'tink-server',
    ]
)

# TODO: preload appropriate images into registry (depends on templates)
# TODO: preload hardware data (depends on worker definitions)
# TODO: preload templates and workflows
# TODO: where does pb&j fit into this?
# TODO: should portal fit into this?

# TODO: ensure secret, password, and other generated items are only generated once
# TODO: factor out some of the dependencies into library files
# TODO: improve cleanup of resources, some things are being left behind making tilt up/tilt down/tilt up not work correctly
# TODO: see if calico/cilium as a cni would avoid having to use a custom cni plugin