#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '0.1',
                    'status': ['preview'],
                    'supported_by': 'pgindraud@gmail.com'}

DOCUMENTATION = '''
---

https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html

module: ejbca_endentity
short_description: Create/update/revoke EJBCA End Entity
description:
   - This module allows you to create, modify and delete Zabbix host entries and associated group and template data.
version_added: "2.0"
author:
    - 
requirements:
    - "python >= 2.6"
    - "zabbix-api >= 0.5.3"
options:
'''

try:
    import requests
except ImportError:
    HAS_REQUESTS_LIB = False
else:
    HAS_REQUESTS_LIB = True

try:
    import zeep
except ImportError:
    HAS_ZEEP_LIB = False
else:
    HAS_ZEEP_LIB = True

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils import crypto as crypto_utils
import base64
import datetime
import os
import tempfile

# available type of user match criteria
# https://www.ejbca.org/docs/ws/constant-values.html#org.ejbca.core.protocol.ws.client.gen.UserMatch.MATCH_TYPE_BEGINSWITH
EJBCA_CONSTANTS_USER_MATCH = dict({
  'MATCH_TYPE_BEGINSWITH': 1,
  'MATCH_TYPE_CONTAINS': 2,
  'MATCH_TYPE_EQUALS': 0,
  'MATCH_WITH_USERNAME': 0,
})

# endentity revocation reason
# http://ejbca.org/older_releases/ejbca_4_0/htdocs/ws/constant-values.html#org.ejbca.core.protocol.ws.client.gen.RevokeStatus.NOT_REVOKED
EJBCA_CONSTANTS_REVOCATION_REASON = dict({
    'NOT_REVOKED': -1,
    'AACOMPROMISE': 10,
    'AFFILIATIONCHANGED': 3,
    'CACOMPROMISE': 2,
    'CERTIFICATEHOLD': 6,
    'CESSATIONOFOPERATION': 5,
    'KEYCOMPROMISE': 1,
    'PRIVILEGESWITHDRAWN': 9,
    'REMOVEFROMCRL': 8,
    'SUPERSEDED': 4,
    'UNSPECIFIED': 0,
})

# ejbca endentity status constants
EJBCA_CONSTANTS_ENDENTITY_STATUS = dict({
    10: 'NEW', # New user
    11: 'FAILED', # Generation of user certificate failed
    20: 'INITIALIZED', # User has been initialized
    30: 'INPROCESS', # Generation of user certificate in process
    40: 'GENERATED', # A certificate has been generated for the user
    50: 'REVOKED', # The user has been revoked and should not have any more certificates issued
    60: 'HISTORICAL', # The user is old and archived
    70: 'KEYRECOVERY', # The user is should use key recovery functions in next certificate generation.
    80: 'WAITINGFORADDAPPROVAL', # the operation is waiting to be approved before execution.
})

# type of certificate input for certification request
# https://www.ejbca.org/docs/ws/constant-values.html#org.ejbca.core.protocol.ws.common.CertificateHelper.CERT_REQ_TYPE_PKCS10
EJBCA_CONSTANTS_REQUEST_TYPE = dict({
    'CRMF': 1,
    'PKCS10': 0,
    'PUBLICKEY': 3,
    'SPKAC': 2,
})

# Map between endentity keys
#   ansible format -> ejbca format
EJBCA_ANSIBLE_MAP = dict({
    'username': 'username',
    'subject_dn': 'subjectDN',
    'subject_alt_name': 'subjectAltName',
    'profile': 'endEntityProfileName',
    'certificate_profile': 'certificateProfileName',
    'ca': 'caName',
    'email': 'email',
    'notification': 'sendNotification'
})


def ansible_object_to_ejbca(ansible_object, ejbca_initial_object=dict()):
    changed = False
    output_object = dict(ejbca_initial_object)

    # Because function private void setUserDataVOWS(UserDataVOWS userdata)
    # at modules/ejbca-ws/src/org/ejbca/core/protocol/ws/EjbcaWS.java:2684
    # set this to false
    output_object['clearPwd'] = False
    output_object['keyRecoverable'] = False

    for ansible_key, ejbca_key in EJBCA_ANSIBLE_MAP.items():
        if (ansible_key in ansible_object and
             (ejbca_key not in output_object or
              output_object[ejbca_key] != ansible_object[ansible_key])):
            changed = True
            output_object[ejbca_key] = ansible_object[ansible_key]

    return output_object, changed

def ejbca_object_to_dict(ejbca_object):
    output = dict()
    for attribute in ejbca_object:
        output[attribute] = ejbca_object[attribute]
    if 'status' in ejbca_object:
        output['ejbca_status'] = 'unknown'
        if ejbca_object['status'] in EJBCA_CONSTANTS_ENDENTITY_STATUS:
            output['ejbca_status'] = EJBCA_CONSTANTS_ENDENTITY_STATUS[ejbca_object['status']]
        if ejbca_object['status'] in [40]:
            output['state'] = 'present'
        elif ejbca_object['status'] in [10, 20, 30, 80]:
            output['state'] = 'pending'
        elif ejbca_object['status'] in [50]:
            output['state'] = 'revoked'
    return output


def initial_diff(username, state, prev_state):
    diff = {'before': {'username': username},
            'after': {'username': username},
            }

    if prev_state != state:
        diff['before']['state'] = prev_state
        diff['after']['state'] = state

    return diff

def x509_subjects_equals(a, b):
    if not isinstance(a, str):
        a = ','.join(map(lambda x: x[0] + '=' + x[1], sorted(a, key=lambda x: x[0])))
    if not isinstance(b, str):
        b = ','.join(map(lambda x: x[0] + '=' + x[1], sorted(b, key=lambda x: x[0])))
    return a == b

def compare_asn1_timestamp(a, b):
    date_format = '%Y%m%d%H%M%SZ'
    date_a = datetime.datetime.strptime(a, date_format)
    date_b = datetime.datetime.strptime(b, date_format)
    if a > b:
      return 1
    elif a < b:
      return -1
    return 0

def get_certificate_state(path):
    """Find out current state"""
    state = dict(certificate=dict())

    if not os.path.exists(path):
        state['certificate']['state'] = 'absent'
    else:
        state['certificate']['state'] = 'present'
        with open(path, 'rb') as cert_file:
            try:
                state['certificate']['content'] = cert_file.read()
                cert = crypto_utils.crypto.load_certificate(crypto_utils.crypto.FILETYPE_PEM,
                                                            state['certificate']['content'])
                state['certificate']['format'] = 'PEM'
            except crypto_utils.crypto.Error as ex:
                try:
                    cert = crypto_utils.crypto.load_certificate(crypto_utils.crypto.FILETYPE_ASN1,
                                                                state['certificate']['content'])
                    state['certificate']['format'] = 'DER'
                except crypto_utils.crypto.Error as ex2:
                    module.fail_json(
                        msg="Unable to decode publickey format from path, error : {}".format(str(ex2)),
                    )
            except (IOError, OSError) as ex:
                module.fail_json(
                    msg="Unable to read existing certificate from path, error : {}".format(str(ex)),
                )
        state['certificate']['object'] = cert
    return state


class EjbcaClientWrapper(object):
    """A wrapper for soap ejbca client errors
    """

    def __init__(self, real_client, ansible_module):
        """new wrapper

        Args:
            real_client : the reference to the soap client (from zeep)
            ansible_module : the ansible module use to report error if needed
        """
        self.client = real_client
        self.ansible_module = ansible_module

    def __call__(self, func, *args, **kwargs):
        """magic call function, allow short syntax to call soap api

        Args:
            func : the api endpoint to call
        """
        try:
            return getattr(self.client.service, func)(*args, **kwargs)
        except (zeep.exceptions.Fault, zeep.exceptions.ValidationError) as ex:
            self.ansible_module.fail_json(
                msg='EJBCA error : {}'.format(str(ex.message)),
            )

def ensure_present(before_user, after_user, force=False):
    """ Create / update endentity
    """
    prev_state = before_user['state']
    changed = False
    result = dict()
    diff = initial_diff(before_user['username'], 'present', prev_state)

    # compute remote diffs : between ansible and EJBCA
    remote_diffs = False
    for key,value in after_user.items():
        if key not in before_user:
            diff['after'][key] = value
            remote_diffs = True
        elif before_user[key] != value:
            diff['before'][key] = before_user[key]
            diff['after'][key] = value
            remote_diffs = True
    # add error for existing entity
    if remote_diffs and prev_state in ['present'] and not force:
        if module.check_mode:
            result['warnings'] = 'This endentity already exists, without "force" a full run will fail'
        else:
            module.fail_json(msg='This endentity already exists, if you really want to change EJBCA attributes, use force=true')

    # compute local diffs : between EJBCA and local filesystem
    local_diffs = False
    # look for existing and valid certificate
    remote_certificate = None
    valid_certs = ejbcaclient('findCerts', before_user['username'], True)
    if valid_certs:
        # sort subject component
        required_components = sorted(
                                  map(lambda x: x.split('='),
                                      after_user['subjectDN'].split(',')),
                                  key=lambda x: x[0])
        # produce component string to make compare easier
        required_subject = ','.join(map(lambda x: x[0] + '=' + x[1], required_components))
        for c in valid_certs:
            cert = crypto_utils.crypto.load_certificate(crypto_utils.crypto.FILETYPE_ASN1,
                                                    base64.standard_b64decode(c.certificateData))
            
            # test if certificate subject is the same than required by ansible
            c_components = cert.get_subject().get_components()
            if x509_subjects_equals(required_subject, c_components):
                if remote_certificate is None:
                    remote_certificate = cert
                # TODO : add profiles to choose the certificate to keep
                # for now keep the one with the greatest expiry time
                elif compare_asn1_timestamp(cert.get_notAfter(), remote_certificate.get_notAfter()) == -1:
                    remote_certificate = cert

    if before_user['certificate']['state'] != 'present':
        local_diffs = True
        diff['before']['content'] = None
    else:
        if (remote_certificate and (
              before_user['certificate']['format'] != module.params['certificate_format']
              or before_user['certificate']['object'].get_serial_number() != remote_certificate.get_serial_number()
              or not x509_subjects_equals(before_user['certificate']['object'].get_subject().get_components(), remote_certificate.get_subject().get_components()))):
            diff['before']['content'] = before_user['certificate']['content']
            local_diffs = True

    # must be created in ejbca
    if prev_state not in ['present'] or remote_diffs or remote_certificate is None:
        # extract pubkey
        if module.params['publickey_path']:
            pubkey_type = EJBCA_CONSTANTS_REQUEST_TYPE['PUBLICKEY']
            try:
                with open(module.params['publickey_path'], 'rb') as pubkey_file:
                    pubkey = crypto_utils.crypto.load_publickey(crypto_utils.crypto.FILETYPE_PEM,
                                                                pubkey_file.read())
            except crypto_utils.crypto.Error as ex:
                try:
                    with open(module.params['publickey_path'], 'rb') as pubkey_file:
                        pubkey = crypto_utils.crypto.load_publickey(crypto_utils.crypto.FILETYPE_ASN1,
                                                                    pubkey_file.read())
                except crypto_utils.crypto.Error as ex2:
                    module.fail_json(
                        msg="Unable to decode publickey format from path, error : {}".format(str(ex2)),
                    )
            except (IOError, OSError) as ex:
                module.fail_json(msg="Unable to read publickey from path, error : {}".format(str(ex)))
            pubkey_der = crypto_utils.crypto.dump_publickey(crypto_utils.crypto.FILETYPE_ASN1, pubkey)
        elif module.params['publickey']:
            pubkey_type = EJBCA_CONSTANTS_REQUEST_TYPE['PUBLICKEY']
            try:
                pubkey = crypto_utils.crypto.load_publickey(crypto_utils.crypto.FILETYPE_PEM,
                                                            module.params['publickey'])
            except crypto_utils.crypto.Error as ex:
                module.fail_json(
                    msg="Unable to decode publickey format from argument, error : {}".format(str(ex)),
                )
            pubkey_der = crypto_utils.crypto.dump_publickey(crypto_utils.crypto.FILETYPE_ASN1, pubkey)
        else:
            module.fail_json(msg='You must supply a public key by a way')

        pubkey_content = base64.standard_b64encode(pubkey_der)

        ejbca_user = after_user.copy()
        ejbca_user['status'] = filter(lambda x: x[1] == 'NEW', EJBCA_CONSTANTS_ENDENTITY_STATUS.items())[0][0]
        diff['before']['status'] = None
        if 'status' in before_user:
            diff['before']['status'] = EJBCA_CONSTANTS_ENDENTITY_STATUS[before_user['status']]
        diff['after']['status'] = 'NEW'
        changed = True
        if not module.check_mode:
            response = ejbcaclient('certificateRequest', ejbca_user, pubkey_content, pubkey_type, None, 'CERTIFICATE')
            remote_certificate = crypto_utils.crypto.load_certificate(crypto_utils.crypto.FILETYPE_ASN1,
                                                                      base64.standard_b64decode(response.data))
            # consider new certificate as a local difference
            local_diffs = True

    if remote_certificate:
        result['serial'] = remote_certificate.get_serial_number()
        if module.params['certificate_format'] == 'DER':
            local_content = crypto_utils.crypto.dump_certificate(crypto_utils.crypto.FILETYPE_ASN1, remote_certificate)
        elif module.params['certificate_format'] == 'PEM':
            local_content = crypto_utils.crypto.dump_certificate(crypto_utils.crypto.FILETYPE_PEM, remote_certificate)
        else:
            module.fail_json(msg='Internal error, unknown certificate format')
    else:
        if module.check_mode:
            local_content = 'CURRENTLY EMPTY BUT SUPPOSED TO BE FILL ON FULL RUN'
        else:
            module.fail_json(msg='Internal error, the remote certificate cannot be null at this step')
    result['certificate'] = base64.standard_b64encode(local_content)

    # ensure local certificate is sync with ejbca one
    if local_diffs:
        diff['after']['content'] = local_content
        changed = True

        if not module.check_mode:
            fd, tmpsrc = tempfile.mkstemp()
            os.write(fd, local_content)
            os.close(fd)
            module.add_cleanup_file(tmpsrc) # Ansible will delete the file on exit
            try:
                module.atomic_move(tmpsrc, module.params['certificate_path'])
            except Exception as ex:
                module.fail_json(msg="Failed to write to file {} : {}".format(self.path, str(ex)))

    if os.path.exists(module.params['certificate_path']) or not module.check_mode:
        file_args = module.load_file_common_arguments(module.params)
        file_args['path'] = module.params['certificate_path']
        changed |= module.set_fs_attributes_if_different(file_args, changed, diff, expand=False)

    result.update({'changed': changed, 'diff': diff, 'filename': module.params['certificate_path']})
    return result


def ensure_revoked(before_user, delete=False):
    """Remove / revoke end entity 
    """
    prev_state = before_user['state']
    result = dict()

    if prev_state not in ['revoked', 'absent']:
        if not module.check_mode:
            ejbcaclient('revokeUser',
                        before_user['username'],
                        EJBCA_CONSTANTS_REVOCATION_REASON[module.params['revocation_reason']],
                        delete)
        if delete:
            new_state = 'absent'
        else:
            new_state = 'revoked'
        diff = initial_diff(before_user['username'], new_state, prev_state)
        result.update({'changed': True, 'diff': diff})
    else:
        result.update({'username': before_user['username'], 'changed': False})
    return result


def main():
    module_args = dict(
        username=dict(type='str', required=True),
        subject_dn=dict(type='str', required=True),
        subject_alt_name=dict(type='str', required=False),
        email=dict(type='str', required=False),
        ca=dict(type='str', required=True),
        profile=dict(type='str', required=True),
        certificate_profile=dict(type='str', required=True),
        publickey_path=dict(type='str'),
        publickey=dict(type='path'),
        path=dict(type='path', required=True, aliases=['certificate_path']),
        certificate_format=dict(type='str', choices=['PEM', 'DER'], default='DER'),
        remote_publickey_path=dict(type='bool', default=True),
        server_url=dict(type='str', required=True),
        client_cert=dict(type='path'),
        client_key=dict(type='path'),
        validate_certs=dict(type='bool', default=True),
        force=dict(type='bool', default=False),
        notification=dict(type='bool', default=True),
        state=dict(type='str', choices=['absent', 'revoked', 'present'], default='present'),
        revocation_reason=dict(type='str', choices=EJBCA_CONSTANTS_REVOCATION_REASON.keys(), default='CESSATIONOFOPERATION'),
    )

    global module

    module = AnsibleModule(
        argument_spec=module_args,
        mutually_exclusive=[['publickey_path', 'publickey']],
        add_file_common_args=True,
        supports_check_mode=True
    )

    if not HAS_ZEEP_LIB:
        module.fail_json(msg="Missing required zeep module (check docs or install with: pip install zeep)")
    if not HAS_REQUESTS_LIB:
        module.fail_json(msg="Missing required requests module (check docs or install with: pip install requests)")

    http_session = requests.Session()
    if module.params['validate_certs']:
        http_session.verify = '/etc/ssl/certs/ca-certificates.crt'
    else:
        http_session.verify = False

    if module.params['client_cert'] and module.params['client_key']:
        http_session.cert = (module.params['client_cert'], module.params['client_key'])
    elif module.params['client_cert']:
        http_session.cert = module.params['client_cert']
 
    transport = zeep.transports.Transport(session=http_session)
    global ejbcaclient
    try:
        ejbcaclient = EjbcaClientWrapper(
            zeep.Client(module.params['server_url'], transport=transport),
            module
        )
    except (IOError) as ex:
        module.fail_json(
            msg="Unable to initialize the soap client because of error: {}".format(str(ex)),
            exception=ex
        )

    # search for existing endentity
    _users = ejbcaclient('findUser', {
        'matchtype': EJBCA_CONSTANTS_USER_MATCH['MATCH_TYPE_EQUALS'],
        'matchvalue': module.params['username'],
        'matchwith': EJBCA_CONSTANTS_USER_MATCH['MATCH_WITH_USERNAME']})

    if len(_users) == 1:
        before_user = ejbca_object_to_dict(_users[0])
    elif len(_users) == 0:
        before_user = dict(username=module.params['username'], state='absent')
    else:
        module.fail_json(
            msg='Mutliple user match this username'
        )

    before_user.update(get_certificate_state(module.params['certificate_path']))
    state = module.params['state']
    force = module.params['force']

    ejbca_user, _ = ansible_object_to_ejbca(module.params)

    if state == 'present':
        result = ensure_present(before_user, ejbca_user, force)
    elif state == 'revoked':
        result = ensure_revoked(before_user, False)
    elif state == 'absent':
        result = ensure_revoked(before_user, True)

    module.exit_json(**result)

if __name__ == '__main__':
    main()
