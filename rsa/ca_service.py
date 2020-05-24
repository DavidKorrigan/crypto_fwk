from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509 import DistributionPoint
from cryptography.x509.oid import NameOID

def genarate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def define_name(conf):
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, conf[u'country']),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, conf[u'state']),
        x509.NameAttribute(NameOID.LOCALITY_NAME, conf[u'locality']),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, conf[u'org_name']),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, conf[u'org_unit_name']),
        x509.NameAttribute(NameOID.COMMON_NAME, conf[u'common_name'])
    ])
    return name

def export_to_file(private_bytes, public_bytes, configuration):
    with open(configuration['folder'] + "/" + configuration['key_filename'], "wb") as fout:
        fout.write(private_bytes)
    with open(configuration['folder'] + "/" + configuration['cert_filename'], "wb") as fout:
        fout.write(public_bytes)

def create_root_ca(ca_private_key, ca_name, start_date, expiry_date, configuration):
    ca_public_key = ca_private_key.public_key()

    builder = x509.CertificateBuilder()

    builder = builder.subject_name(ca_name)
    builder = builder.issuer_name(ca_name)
    builder = builder.not_valid_before(start_date)
    builder = builder.not_valid_after(expiry_date)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(ca_public_key)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True)

    certificate = builder.sign(
        private_key=ca_private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    private_bytes = ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = certificate.public_bytes(
        encoding=serialization.Encoding.PEM)

    export_to_file(private_bytes, public_bytes, configuration)

def create_subject(ca_name, subject, ca_private_key, start_date, expiry_date, configuration):
    service_private_key = genarate_private_key()

    service_public_key = service_private_key.public_key()

    builder = x509.CertificateBuilder()

    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_name)
    builder = builder.not_valid_before(start_date)
    builder = builder.not_valid_after(expiry_date)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(service_public_key)

    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
    builder = builder.add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                content_commitment=False, data_encipherment=True, key_agreement=True, encipher_only=False,
                decipher_only=False, key_cert_sign=False, crl_sign=False), critical=False)
    builder = builder.add_extension(x509.ExtendedKeyUsage([
        x509.ExtendedKeyUsageOID.CLIENT_AUTH,
        x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    uri = x509.UniformResourceIdentifier(u'http://crl.korrigan.fr/crls/ca.crl')
    dist_point = DistributionPoint(full_name=[uri], relative_name=None, reasons=None, crl_issuer=None)
    builder = builder.add_extension(x509.CRLDistributionPoints([dist_point]), critical=False)

    certificate = builder.sign(
        private_key=ca_private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    private_bytes = service_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    public_bytes = certificate.public_bytes(
        encoding=serialization.Encoding.PEM)

    export_to_file(private_bytes, public_bytes, configuration)