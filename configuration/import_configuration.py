import json, os



def load_configuration(file, conf):
    CONFIGURATION_FILE = os.path.join(file)

    with open(CONFIGURATION_FILE, 'r') as fc:
        configuration_data = json.load(fc)
        configuration = {
            'folder': configuration_data[conf]['folder'],
            'cert_filename': configuration_data[conf]['cert_filename'],
            'key_filename': configuration_data[conf]['key_filename'],
            'country': configuration_data[conf]['country'],
            'state': configuration_data[conf]['state'],
            'locality': configuration_data[conf]['locality'],
            'org_name': configuration_data[conf]['org_name'],
            'org_unit_name': configuration_data[conf]['org_unit_name'],
            'common_name': configuration_data[conf]['common_name']
        }

    return configuration