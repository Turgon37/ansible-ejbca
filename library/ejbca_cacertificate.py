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

module: ejbca_cacertificate
short_description: Dump a CA certificate into a file
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

def get_state(path):
    """
    """
    state = dict(content=None)
    if os.path.exists(path):
        if os.path.isfile(path):
            state['state'] = 'present'
            with open(path, 'rb') as cert_file:
                state['content'] = cert_file.read()
        else:
            self.ansible_module.fail_json(
                msg='The current path exists but is not a file'
            )
    else:
        state['state'] = 'absent'
    return state

def x509_names_equals(a, b):
    if not isinstance(a, str):
        if not isinstance(a, list):
            a = a.get_components()
        a = ','.join(map(lambda x: x[0] + '=' + x[1], sorted(a, key=lambda x: x[0])))
    if not isinstance(b, str):
        if not isinstance(b, list):
            b = b.get_components()
        b = ','.join(map(lambda x: x[0] + '=' + x[1], sorted(b, key=lambda x: x[0])))
    return a == b

def initial_diff(path, state, prev_state):
    diff = {'before': {'path': path},
            'after': {'path': path},
            }

    if prev_state != state:
        diff['before']['state'] = prev_state
        diff['after']['state'] = state

    return diff


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

def ensure_present(path):
    """ 
    """
    prev_state = get_state(path)
    result = dict()
    changed = False
    diff = initial_diff(path, 'present', prev_state['state'])

    # search for existing endentity
    _cas = ejbcaclient('getLastCAChain', module.params['ca'])

    if len(_cas) == 0:
        module.fail_json(
            msg='This ca cannot be found or the current user may have not access to it'
        )

    local_content_parts = []
    result['serials'] = []
    for ca in _cas:
        remote_cacertificate = crypto_utils.crypto.load_certificate(crypto_utils.crypto.FILETYPE_ASN1,
                                                                    base64.standard_b64decode(ca.certificateData))
        if x509_names_equals(remote_cacertificate.get_subject(), remote_cacertificate.get_issuer()) and not module.params['include_root']:
            continue

        result['serials'].append(remote_cacertificate.get_serial_number())
        if module.params['certificate_format'] == 'DER':
            ca_content = crypto_utils.crypto.dump_certificate(crypto_utils.crypto.FILETYPE_ASN1, remote_cacertificate)
        elif module.params['certificate_format'] == 'PEM':
            ca_content = crypto_utils.crypto.dump_certificate(crypto_utils.crypto.FILETYPE_PEM, remote_cacertificate)
        else:
            module.fail_json(msg='Internal error, unknown certificate format')
        local_content_parts.append(ca_content)
    local_content = '\n'.join(local_content_parts)

    # compute local diffs : between EJBCA and local filesystem
    local_diffs = False
    if prev_state['state'] != 'present':
        local_diffs = True
        diff['before']['content'] = None
    else:
        if (prev_state['content'] != local_content):
            diff['before']['content'] = prev_state['content']
            local_diffs = True

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

def ensure_absent(path):
    """Remove / revoke file
    """
    prev_state = get_state(module.params['certificate_path'])
    result = dict()

    if prev_state['state'] != 'absent':
        if not module.check_mode:
            try:
                os.unlink(module.params['certificate_path'])
            except OSError as ex:
                module.fail_json(
                    msg='Unable to remove the file {} because : {}'.format(module.params['certificate_path'], str(ex))
                )
        diff = initial_diff(path, 'absent', prev_state['state'])
        result.update({'path': path, 'state': 'absent', 'changed': True, 'diff': diff})
    else:
        result.update({'path': path, 'state': 'absent', 'changed': False})
    return result


def main():
    module_args = dict(
        ca=dict(type='str', required=True),
        include_chain=dict(type='bool', default=True),
        include_root=dict(type='bool', default=False),
        path=dict(type='path', required=True, aliases=['certificate_path']),
        certificate_format=dict(type='str', choices=['PEM', 'DER'], default='DER'),
        server_url=dict(type='str', required=True),
        client_cert=dict(type='path'),
        client_key=dict(type='path'),
        validate_certs=dict(type='bool', default=True),
        state=dict(type='str', choices=['absent', 'present'], default='present'),
    )

    global module

    module = AnsibleModule(
        argument_spec=module_args,
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

    state = module.params['state']

    if state == 'present':
        if module.params['certificate_format'] not in ['PEM'] and module.params['include_chain']:
            module.fail_json(
                msg='Only PEM format allow multiple certificate in same file'
            )
        result = ensure_present(module.params['certificate_path'])
    elif state == 'absent':
        result = ensure_absent(module.params['certificate_path'])

    module.exit_json(**result)

if __name__ == '__main__':
    main()
