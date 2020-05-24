import datetime
from configuration.import_configuration import load_configuration
from rsa.ca_service import *
from rsa.signature import *

# rsa_conf contains details about the issuer & the subject
conf_file = 'configuration/rsa_conf.json'

today = datetime.date.today()
duration = datetime.timedelta(days=365)
until = today + duration
start_date = datetime.datetime(today.year, today.month, today.day)
expiry_date = datetime.datetime(until.year, until.month, until.day)

# Load the details for the issuer from the configuration file,
# then generate the private key,
# init the issuer name
# and generate root ca certificate & key.
root_ca_conf = load_configuration(conf_file, 'root_ca')
issuer_private_key = genarate_private_key()
issuer_name = define_name(root_ca_conf)
create_root_ca(issuer_private_key, issuer_name, start_date, expiry_date, root_ca_conf)

# Load the details for the subject from the configuration file,
# then init the issuer name
# and generate subject certificate & key.
subject_conf = load_configuration(conf_file, 'subject')
subject_name = define_name(subject_conf)
create_subject(issuer_name, subject_name, issuer_private_key, start_date, expiry_date, subject_conf)

# Setup to play with RSA signature
string_to_sign = "Il était bien joli ce chemin de Provence."
algorithm = 'sha256'
private_key_file = 'certificates/' + subject_conf['key_filename']
certificate_file = 'certificates/' + subject_conf['cert_filename']

# Sign a String (converted in bytes in the function)
signature = sign(private_key_file, algorithm, string_to_sign)
print(signature)

# Verify the signature: Positive case
verification = verify(certificate_file, algorithm, signature, string_to_sign)
print(verification)

# Verify the signature: Negative case
string_to_sign = "Il était bien joli ce chemin de Provence"
verification = verify(certificate_file, algorithm, signature, string_to_sign)
print(verification)