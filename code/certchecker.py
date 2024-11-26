import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPCertStatus
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives import hashes
import requests


def load_certificate(cert_path):
    """
    Load certificate from certificate path as cryptography format
    :param cert_path: X.509 certificate (mostly SSL) file path
    :return: X.509 certificate content loaded as cryptography format
    """
    with open(cert_path, 'rb') as cert_file:
        cert_data = cert_file.read()
    return x509.load_pem_x509_certificate(cert_data, default_backend())


def is_ssl_certificate(cert):
    """
    Judge whether provided X.509 certificate is an SSL certificate (with serverAuth extension) or not
    :param cert: X.509 certificate loaded as cryptography format
    :return: whether provided X.509 certificate is an SSL certificate or not
    """
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        return x509.ExtendedKeyUsageOID.SERVER_AUTH in ext.value
    except x509.ExtensionNotFound:
        return False


def is_ssl_certificate_from_file(cert_path):
    """
    Judge whether provided X.509 certificate (auto-loading from file) is an SSL certificate (with serverAuth extension) or not
    :param cert_path: X.509 certificate file path
    :return: whether provided X.509 certificate is an SSL certificate or not
    """
    cert = load_certificate(cert_path)
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        return x509.ExtendedKeyUsageOID.SERVER_AUTH in ext.value
    except x509.ExtensionNotFound:
        return False


def get_ocsp_url(cert):
    """
    Get OCSP server URL from provided SSL certificate loaded as cryptography format
    :param cert: X.509 certificate loaded as cryptography format
    :return: OCSP server URL of provided SSL certificate
    """
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    for access in aia:
        if access.access_method == AuthorityInformationAccessOID.OCSP:
            return access.access_location.value


def get_issuer(cert) -> str:
    """
    Get Issuer(intermediate CA certificate mostly) CA cert file URL from provided SSL certificate loaded as cryptography format
    :param cert: X.509 certificate loaded as cryptography format
    :return: Issuer CA cert file URL of provided SSL certificate
    """
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    issuers = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
    if not issuers:
        raise Exception(f'no issuers entry in AIA')
    return issuers[0].access_location.value


def get_issuer_cert(ca_issuer, cert_format = "builtin"):
    """
    Download Issuer(intermediate CA certificate mostly) cert file from provided CA cert URL
    :param ca_issuer: Issuer CA cert file URL of provided SSL certificate
    :param cert_format: save format of Issuer CA cert file (available: builtin [for cryptography] and x.509)
    :return: Issuer CA cert file content of provided SSL certificate
    """
    issuer_response = requests.get(ca_issuer)
    if issuer_response.ok:
        issuerDER = issuer_response.content
        issuerPEM = ssl.DER_cert_to_PEM_cert(issuerDER)
        if cert_format == "builtin":
            return x509.load_pem_x509_certificate(issuerPEM.encode('utf-8'), default_backend())
        elif cert_format == "x.509":
            return issuerPEM
        else:
            raise Exception(f'unknown cert export format: {cert_format}')
    raise Exception(f'fetching issuer cert failed with response status: {issuer_response.status_code}')


def check_ocsp_revocation(ocsp_server, cert, issuer_crt):
    """
    Check whether provided SSL certificate is revoked by querying OCSP server
    :param ocsp_server: OCSP server URL of provided SSL certificate
    :param cert: SSL certificate loaded as cryptography format
    :param issuer_crt: Issuer CA certificate loaded as cryptography format
    :return: whether provided SSL certificate is revoked by querying OCSP server
    """
    builder = x509.ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_crt, SHA256())
    req = builder.build()
    req_data = req.public_bytes(serialization.Encoding.DER)
    response = requests.post(ocsp_server, data=req_data, headers={'Content-Type': 'application/ocsp-request'})
    if response.status_code == 200:
        ocsp_resp = x509.ocsp.load_der_ocsp_response(response.content)
        if ocsp_resp.certificate_status != OCSPCertStatus.GOOD:
            return True
        else:
            return False
    else:
        raise Exception(f'ocsp request failed with response status: {response.status_code}')


def check_ocsp_revocation_from_file(cert_path):
    """
    Check whether provided SSL certificate (auto-loading from file) is revoked by querying OCSP server
    :param cert_path: SSL certificate file path
    :return: whether provided SSL certificate is revoked by querying OCSP server
    """
    cert_load = load_certificate(cert_path)
    if not is_ssl_certificate(cert_load):
        return False
    return check_ocsp_revocation(get_ocsp_url(cert_load), cert_load, get_issuer_cert(get_issuer(cert_load)))


def get_crl_distribution_urls(cert):
    """
    Get CRL file URL from provided SSL certificate loaded as cryptography format
    :param cert: SSL certificate loaded as cryptography format
    :return: CRL file URL from provided SSL certificate
    """
    try:
        crl_distribution_points = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        distribution_points = crl_distribution_points.value
        urls = []
        for dp in distribution_points:
            for name in dp.full_name:
                if isinstance(name, x509.UniformResourceIdentifier) and name.value.startswith("http://"):
                    urls.append(name.value)
        return urls
    except x509.ExtensionNotFound:
        return []


def check_crl_revocation(cert, crl_lists):
    """
    Check whether provided SSL certificate is revoked by downloading CRL list file and checking cert S.N
    :param cert: SSL certificate loaded as cryptography format
    :param crl_lists: CRL file content of provided SSL certificate
    :return: whether provided SSL certificate is revoked by checking cert S.N from downloaded CRL list
    """
    first_crl_url = crl_lists[0]
    crl_response = requests.get(first_crl_url)
    if crl_response.status_code == 200:
        crl_data = crl_response.content
        crl = x509.load_der_x509_crl(crl_data, default_backend())
        return cert.serial_number in [x.serial_number for x in crl]
    else:
        raise Exception(f'fetching crl failed with response status: {crl_response.status_code}')


def check_crl_revocation_from_file(cert_path):
    """
    Check whether provided SSL certificate (auto-loading from file) is revoked by downloading CRL list file and checking cert S.N
    :param cert_path: SSL certificate file path
    :return: whether provided SSL certificate is revoked by checking cert S.N from downloaded CRL list
    """
    cert_load = load_certificate(cert_path)
    return check_crl_revocation(cert_load, get_crl_distribution_urls(cert_load))


def get_signature_algorithm(cert):
    """
    Get signature algorithm from provided SSL certificate loaded as cryptography format
    :param cert: SSL certificate loaded as cryptography format
    :return: signature algorithm of provided SSL certificate
    """
    sig_hash_oid = cert.signature_algorithm_oid
    return sig_hash_oid._name


def check_secure_signature_algorithm(cert):
    """
    Check whether signature algorithm of provided SSL certificate is in allowed secure signature algorithms
    :param cert: SSL certificate loaded as cryptography format
    :return: whether signature algorithm of provided SSL certificate is in allowed secure signature algorithms
    """
    secure_signature_algorithms = ["sha256WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption",
                                        "ecdsa-with-SHA256", "ecdsa-with-SHA384", "ecdsa-with-SHA512"]
    cert_sig_algo = get_signature_algorithm(cert)
    if cert_sig_algo in secure_signature_algorithms:
        return True
    else:
        return False


def check_secure_signature_algorithm_from_file(cert_path):
    """
    Check whether signature algorithm of provided SSL certificate (auto-loading from file) is in allowed secure signature algorithms
    :param cert_path: SSL certificate file path
    :return: whether signature algorithm of provided SSL certificate is in allowed secure signature algorithms
    """
    return check_secure_signature_algorithm(load_certificate(cert_path))


def load_private_key(key_path, password=None):
    """
    Load private key from provided SSL certificate file as cryptography format
    :param key_path: private key file path
    :param password: password phase for private key
    :return: private key content loaded as cryptography format
    """
    if password is not None and not password:
        password = None
    with open(key_path, 'rb') as key_file:
        key_data = key_file.read()
    return serialization.load_pem_private_key(key_data, password, default_backend())


def verify_key_match(cert, private_key):
    """
    Verify whether provided SSL certificate matches private key
    :param cert: SSL certificate loaded as cryptography format
    :param private_key: private key content loaded as cryptography format
    :return: whether provided cert matches private key
    """
    cert_sig_algo = get_signature_algorithm(cert)
    if "RSA" in cert_sig_algo:
        cert_sig_hash_algo_name = cert_sig_algo.split("With")[0].upper()
        cert_sig_hash_algo_type = "RSA"
    elif "ecdsa" in cert_sig_algo:
        cert_sig_hash_algo_name = cert_sig_algo.split("-")[-1].upper()
        cert_sig_hash_algo_type = "ECDSA"
    else:
        raise Exception(f'unknown signature algorithm: {cert_sig_algo}')
    if cert_sig_hash_algo_name == "SHA256":
        cert_sig_hash_algo = hashes.SHA256()
    elif cert_sig_hash_algo_name == "SHA384":
        cert_sig_hash_algo = hashes.SHA384()
    elif cert_sig_hash_algo_name == "SHA512":
        cert_sig_hash_algo = hashes.SHA512()
    else:
        raise Exception(f'unknown signature hash algorithm: {cert_sig_hash_algo_name}')
    data = b"This is some data I'd like to sign"
    public_key = cert.public_key()
    if cert_sig_hash_algo_type == "RSA":
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(cert_sig_hash_algo),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            cert_sig_hash_algo
        )
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(cert_sig_hash_algo),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    elif cert_sig_hash_algo_type == "ECDSA":
        signature = private_key.sign(
            data,
            ec.ECDSA(cert_sig_hash_algo)
        )
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False
    else:
        raise Exception(f'unknown signature hash algorithm type: {cert_sig_hash_algo_type}')


def verify_key_match_from_file(cert_path, private_key_path, private_key_password = None):
    """
    Verify whether provided SSL certificate (auto-loading from file) matches private key
    :param cert_path: SSL certificate file path
    :param private_key_path: private key file path
    :param private_key_password: password phase for private key
    :return: whether provided cert matches private key
    """
    cert_load = load_certificate(cert_path)
    key_load = load_private_key(private_key_path, private_key_password)
    return verify_key_match(cert_load, key_load)
