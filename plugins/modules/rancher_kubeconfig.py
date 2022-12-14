#!/usr/bin/python

# Copyright: (c) 2022, Wouter Moeken <wouter.moeken@rws.nl>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: rancher_kubeconfig

short_description: Obtain kubeconfig for given cluster

version_added: "0.0.6"

description: This module allows you to fetch the content of the kubeconfig for\
     the given rancher cluster

options:
    host:
        description: Hostname of rancher system
        required: true
        type: str

    cluster_name:
        description: Name of the cluster in rancher to operate on
        required: true
        type: str

    token:
        description: Token used for authentication
        required: false
        type: str

    username:
        description: Username for user/pass login instead of token
        required: false
        type: str

    password:
        description: Password for user/pass login instead of token
        required: false
        type: str

    full_response:
        description: Whether to return full api response
        required: false
        type: bool

    validate_certs:
        description: Verify SSL certificates
        required: false
        type: bool
        default: true

extends_documentation_fragment:
    - intellium.rancher.my_doc_fragment_name

author:
    - Wouter Moeken (@intellium)
'''

EXAMPLES = r'''
# Fetch config
- name: Obtain kubeconfig for test cluster
  intellium.rancher.rancher_kubeconfig:
    host: rancher.example.com
    token: "{{ login_out['token'] }}"
    cluster_name: test
    full_response: true
    validate_certs: false
  register: kubeconfig_out
'''

RETURN = r'''
# These are examples of possible return values,
kubeconfig:
    description: YAML content of the kubeconfig file
    type: yaml
    returned: always
full_response:
    description: The full API response of the last request
    type: json
    returned: optional
'''

import json

from ansible.module_utils._text import to_native, to_text
from ansible.module_utils.basic import AnsibleModule, sanitize_keys

import ansible_collections.intellium.rancher.plugins.module_utils.\
    rancher_globals as g
from ansible_collections.intellium.rancher.plugins.module_utils.rancher_api \
    import api_req, clusterid_by_name, api_login, api_exit


def main():
    argument_spec = {}
    argument_spec.update(
        host=dict(type='str', aliases=['rancher_host'], required=True),
        cluster_name=dict(type='str', aliases=[
                          'rancher_cluster'], required=True),
        token=dict(type='str', aliases=['rancher_token'], no_log=True),
        username=dict(type='str', aliases=['rancher_username']),
        password=dict(type='str', aliases=['rancher_password'], no_log=True),
        full_response=dict(type='bool'),
        validate_certs=dict(type='bool', default=True)
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[
            ('token', 'username'),
            ('token', 'password')
        ],
        required_together=[
            ('username', 'password')
        ],
        required_one_of=[
            ('token', 'username', 'password'),
        ]
    )

    # Do we have a token? If not, go and fetch it
    if not module.params['token']:
        module.params['token'] = api_login(module)

    # Fetch cluster id
    cluster_id = clusterid_by_name(module)

    # Set defaults
    _url = 'https://%s/v3/clusters/%s?action=generateKubeconfig' % (
        module.params['host'], cluster_id)
    _body = "{ }"

    # Make the request
    resp, content = api_req(
        module,
        url=_url,
        body=_body,
        body_format='json',
        method='POST',
        auth=module.params['token']
    )

    # Check status code
    if g.last_response['status'] in (200, 201):
        g.mod_returns.update(changed=False)
        g.mod_returns.update(kubeconfig=resp['json']['config'])
        api_exit(module)
    else:
        g.mod_returns.update(msg='Unexpected response: '
                             + to_text(g.last_response))
        api_exit(module, 'fail')


if __name__ == '__main__':
    main()
