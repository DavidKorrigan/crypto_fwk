import base64

from OpenSSL import crypto

def sign(private_key_file, algorithm,string_to_sign):

    signing_bytes = string_to_sign.encode()

    private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(private_key_file).read())
    signature = base64.b64encode(crypto.sign(private_key, signing_bytes, algorithm))

    return signature

def verify(certificate_file, algorithm, signature, string_to_sign):
    try:
        signing_bytes = string_to_sign.encode()
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, open(certificate_file).read())
        verification = crypto.verify(certificate, base64.b64decode(signature), signing_bytes, algorithm)
        if verification is None:
            verification = "Verification passed"

    except crypto.Error:
        verification = "Verification failed"
    finally:
        return verification