import subprocess

OPENSSL = '/usr/bin/openssl'


def openssl(*args):
    cmdline = [OPENSSL] + list(args)
    subprocess.check_call(cmdline)


class GeneratorSSL:

    def __init__(self, component_name, ca=None, csr_subject=None, ext_conf_file='default-client-ext.conf'):
        self.component_name = component_name
        self.ca = ca
        self.csr_subject = csr_subject
        self.ext_conf_file = ext_conf_file

    def __generate_ssl_key(self):
        openssl('genrsa', '-out', self.component_name + '.key', '2048')

    def __generate_ssl_cert_ca(self):
        openssl('req', '-x509', '-new', '-nodes', '-key', self.component_name + '.key', '-subj', '"/CN=kubernetes"',
                '-extensions', 'v3_ext', '-config', 'ca-ext.conf',
                '-days', '3650', '-out', self.component_name + '.crt')

    def __generate_csr_file(self):
        openssl('req', '-new', '-key', self.component_name + '.key', '-out',
                self.component_name + '.csr', '-subj', self.csr_subject)

    def __generate_ssl_cert(self):
        openssl('x509', '-req', '-in', self.component_name + '.csr', '-CA',
                self.ca + '.crt', '-CAkey', self.ca + '.key', '-CAcreateserial',
                '-sha256', '-out', self.component_name + '.crt', '-extensions',
                'v3_ca', '-extfile', self.ext_conf_file, '-days', '3650')

    def __generate_pub_ssl_key(self):
        openssl('rsa', '-in', self.component_name + '.key', '-pubout', '-out', self.component_name + '.pub')

    def ssl_generate(self):
        self.__generate_ssl_key()
        self.__generate_csr_file()
        self.__generate_ssl_cert()

    def ssl_ca_generate(self):
        self.__generate_ssl_key()
        self.__generate_ssl_cert_ca()

    def generate_pub_priv_keys(self):
        self.__generate_ssl_key()
        self.__generate_pub_ssl_key()

