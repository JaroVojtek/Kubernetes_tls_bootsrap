import os
import commands
import re
import glob
from GeneratorSSL import GeneratorSSL

__author__ = """ZOOM International"""
__email__ = 'jaroslav.vojtek@zoomint.com'
# TODO: __version__ = VERSION

K8S_PKI_DIR = "/etc/kubernetes/pki"
K8S_ADMIN_PKI_DIR = "/etc/kubernetes/pki/admin"
K8S_CONTROLLER_PKI_DIR = "/etc/kubernetes/pki/controller-manager"
K8S_KUBELET_PKI_DIR = "/etc/kubernetes/pki/kubelet"
K8S_SCHEDULER_PKI_DIR = "/etc/kubernetes/pki/scheduler"
K8S_ETCD_PKI_DIR = "/etc/kubernetes/pki/etcd"
VAR_KUBELET_PKI_DIR = "/var/lib/kubelet/pki"
HOST_IP = commands.getoutput("hostname -I | awk '{print $1}'")
HOST_NAME = commands.getoutput("hostname")


def make_k8s_pki_dir_structure():
    list_of_dirs = [K8S_PKI_DIR, K8S_ADMIN_PKI_DIR, K8S_CONTROLLER_PKI_DIR,
                    K8S_KUBELET_PKI_DIR, K8S_SCHEDULER_PKI_DIR, K8S_ETCD_PKI_DIR,
                    VAR_KUBELET_PKI_DIR]

    for path in list_of_dirs:
        try:
            os.makedirs(path)
        except OSError:
            print("Ommiting dir creation : Directory {0} already exists".format(path))


def configure_kubelet_service_file():

    ca_client_cert = "--client-ca-file=/etc/kubernetes/pki/ca.crt"
    rotate = "--feature-gates=RotateKubeletClientCertificate=true,RotateKubeletServerCertificate=true"
    tls_cert_file = "--tls-cert-file=/var/lib/kubelet/pki/kubelet.crt"
    tls_private_key = "--tls-private-key-file=/var/lib/kubelet/pki/kubelet.key"

    with open("/etc/sysconfig/kubelet", 'r+') as kubelet_file:
        kubelet_args = kubelet_file.readline()
        kubelet_args = kubelet_args.rstrip()
        if kubelet_args[-1] == "=":
            kubelet_args = ["{0}{1} {2} {3} {4}".format(kubelet_args, ca_client_cert, rotate,
                                                        tls_cert_file, tls_private_key)]
        elif "CA_CLIENT_CERT" in kubelet_args:
            pass
        else:
            kubelet_args = ["{0} {1} {2} {3} {4}".format(kubelet_args, ca_client_cert, rotate,
                                                        tls_cert_file, tls_private_key)]
        kubelet_file.seek(0)
        kubelet_file.writelines(kubelet_args)


def create_ca_ext_file():
    with open("ca-ext.conf", 'w') as f:
        f.write("[ req ]\n"
                "default_bits = 2048\n"
                "prompt = no\nd"
                "efault_md = sha256\n"
                "distinguished_name = dn\n"
                "\n"
                "[ dn ]\n"
                "CN = kubernetes\n"
                "\n"
                "[ v3_ext ]\n"
                "keyUsage=critical,keyEncipherment,digitalSignature,keyCertSign\n"
                "basicConstraints=critical,CA:TRUE")


def create_apiserver_ext_file():
    with open("apiserver-ext.conf", 'w') as f:
        f.write("[ v3_ca ]\n"
                "keyUsage = critical, digitalSignature, keyEncipherment\n"
                "extendedKeyUsage = serverAuth\n"
                "subjectAltName = @alternate_names\n"
                "[ alternate_names ]\n"
                "DNS.1           = {0}\n"
                "DNS.2           = kubernetes\n"
                "DNS.3           = kubernetes.default\n"
                "DNS.4           = kubernetes.default.svc\n"
                "DNS.5           = kubernetes.default.svc.cluster.local\n"
                "IP.1            = 10.96.0.1\n"
                "IP.2            = {1}".format(HOST_NAME, HOST_IP))


def create_client_ext_file():
    with open('default-client-ext.conf', 'w') as f:
        f.write("[ v3_ca ]\n"
                "keyUsage = critical, digitalSignature, keyEncipherment\n"
                "extendedKeyUsage = clientAuth")


def create_peer_ext_file():
    with open('peer-ext.conf', 'w') as f:
        f.write("[ v3_ca ]\n"
                "keyUsage = critical, digitalSignature, keyEncipherment\n"
                "extendedKeyUsage = serverAuth,clientAuth\n"
                "subjectAltName = @alternate_names\n"
                "[ alternate_names ]\n"
                "DNS.1           = {0}\n"
                "DNS.2           = localhost\n"
                "IP.1            = {1}\n"
                "IP.2            = 127.0.0.1\n"
                "IP.3            = 0:0:0:0:0:0:0:1".format(HOST_NAME, HOST_IP))


def create_server_ext_file():
    with open('server-ext.conf', 'w') as f:
        f.write("[ v3_ca ]\n"
                "keyUsage = critical, digitalSignature, keyEncipherment\n"
                "extendedKeyUsage = serverAuth,clientAuth\n"
                "subjectAltName = @alternate_names\n"
                "[ alternate_names ]\n"
                "DNS.1           = {0}\n"
                "DNS.2           = localhost\n"
                "IP.1            = 127.0.0.1\n"
                "IP.2            = 0:0:0:0:0:0:0:1".format(HOST_NAME))


def create_kubelet_server_ext_file():
    with open('kubelet-server-ext.conf', 'w') as f:
        f.write("[ v3_ca ]\n"
                "keyUsage = critical, digitalSignature, keyEncipherment\n"
                "extendedKeyUsage = serverAuth\n"
                "basicConstraints = critical,CA:FALSE\n"
                "subjectAltName = @alternate_names\n"
                "[ alternate_names ]\n"
                "DNS.1           = {0}\n"
                "IP.1            = {1}".format(HOST_NAME, HOST_IP))


def set_k8s_service_accounts(svc_account, user):
    os.system("KUBECONFIG=/etc/kubernetes/{0}.conf kubectl config set-cluster kubernetes --server=https://{1}:6443 "
              "--certificate-authority /etc/kubernetes/pki/ca.crt --embed-certs".format(svc_account, HOST_IP.rstrip()))
    os.system("KUBECONFIG=/etc/kubernetes/{0}.conf kubectl config set-credentials {1} "
              "--client-key /etc/kubernetes/pki/{0}/{0}.key --client-certificate /etc/kubernetes/pki/{0}/{0}.crt "
              "--embed-certs".format(svc_account, user))
    os.system("KUBECONFIG=/etc/kubernetes/{0}.conf kubectl config set-context {1}@kubernetes --cluster kubernetes "
              "--user {1}".format(svc_account, user))
    os.system("KUBECONFIG=/etc/kubernetes/{0}.conf kubectl config use-context {1}@kubernetes".format(svc_account, user))


def purge_files(directory, pattern):
    for f in os.listdir(directory):
        if re.search(pattern, f):
            os.remove(os.path.join(directory, f))


# Adding KUBELET_EXTRA_ARGS into '/etc/sysconfig/kubelet' file,
# which is read by kubelet systemd file
configure_kubelet_service_file()

# Generate appropriate folder structure for PKIs used by Kubernetes
make_k8s_pki_dir_structure()

# Switch to '/etc/kubernetes/pki' folder
os.chdir(K8S_PKI_DIR)

# Generate extensions files for CA, SERVER and CLIENT certificates
create_ca_ext_file()
create_apiserver_ext_file()
create_client_ext_file()
create_peer_ext_file()
create_server_ext_file()
create_kubelet_server_ext_file()

# KEYs, CSRs, CRTs generation for each Kubernetes component
k8s_ca = GeneratorSSL('ca')
k8s_ca.ssl_ca_generate()

k8s_apiserver = GeneratorSSL('apiserver', 'ca', '/CN=kube-apiserver', 'apiserver-ext.conf')
k8s_apiserver.ssl_generate()

k8s_apiserver_kubelet_client = GeneratorSSL('apiserver-kubelet-client', 'ca', '/O=system:masters/CN=kube-apiserver-kubelet-client')
k8s_apiserver_kubelet_client.ssl_generate()

k8s_front_proxy_ca = GeneratorSSL('front-proxy-ca')
k8s_front_proxy_ca.ssl_ca_generate()

k8s_front_proxy_client = GeneratorSSL('front-proxy-client', 'front-proxy-ca', '/CN=front-proxy-client')
k8s_front_proxy_client.ssl_generate()

k8s_sa = GeneratorSSL('sa')
k8s_sa.generate_pub_priv_keys()

# KEYs, CSRs, CRTs generation for each Kubernetes service accounts
k8s_admin = GeneratorSSL('admin/admin', 'ca', '/O=system:masters/CN=kubernetes-admin')
k8s_admin.ssl_generate()

k8s_kubelet = GeneratorSSL('kubelet/kubelet', 'ca', '/O=system:nodes/CN=system:node:{0}'.format(HOST_NAME))
k8s_kubelet.ssl_generate()

k8s_controller_manager = GeneratorSSL('controller-manager/controller-manager', 'ca', '/CN=system:kube-controller-manager')
k8s_controller_manager.ssl_generate()

k8s_scheduler = GeneratorSSL('scheduler/scheduler', 'ca', '/CN=system:kube-scheduler')
k8s_scheduler.ssl_generate()

# KEY, CSR, CRT for Kubelet service deamon
k8s_var_kubelet = GeneratorSSL(VAR_KUBELET_PKI_DIR + '/kubelet', 'ca',
                               '/O=system:nodes/CN=system:node:{0}'.format(HOST_NAME), 'kubelet-server-ext.conf')
k8s_var_kubelet.ssl_generate()

# KEYs, CSRs, CRTs generation for each Kubernetes ETCD
k8s_etcd_ca = GeneratorSSL('etcd/ca')
k8s_etcd_ca.ssl_ca_generate()

k8s_healthcheck_client = GeneratorSSL('etcd/healthcheck-client', 'etcd/ca', '/O=system:masters/CN=kube-etcd-healthcheck-client')
k8s_healthcheck_client.ssl_generate()

k8s_etcd_peer = GeneratorSSL('etcd/peer', 'etcd/ca', '/CN={0}'.format(HOST_NAME), 'peer-ext.conf')
k8s_etcd_peer.ssl_generate()

k8s_etcd_server = GeneratorSSL('etcd/server', 'etcd/ca', '/CN={0}'.format(HOST_NAME), 'server-ext.conf')
k8s_etcd_server.ssl_generate()

k8s_apiserver_etcd_client = GeneratorSSL('apiserver-etcd-client', 'etcd/ca', '/O=system:masters/CN=kube-apiserver-etcd-client')
k8s_apiserver_etcd_client.ssl_generate()

set_k8s_service_accounts('admin', 'kubernetes-admin')
set_k8s_service_accounts('kubelet', 'system:node:{0}'.format(HOST_NAME))
set_k8s_service_accounts('controller-manager', 'system:kube-controller-manager')
set_k8s_service_accounts('scheduler', 'system:kube-scheduler')

# Cleaning and setting permissions
purge_files(K8S_PKI_DIR, ".*\.conf")

for root, dirnames, filenames in os.walk(K8S_PKI_DIR):
    for name in glob.glob(root + '/*.key'):
        os.chmod(name, 0600)

os.chmod(VAR_KUBELET_PKI_DIR + "/kubelet.key", 0600)

