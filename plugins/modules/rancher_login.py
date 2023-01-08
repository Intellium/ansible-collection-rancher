# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Wouter Moeken <wouter.moeken@rws.nl>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: rancher_login
short_description: Login with username/password to obtain token
description:
    - This module does a web login and returns an authentication token
version_added: "0.0.5"
requirements:
    - "python >= 3.10"
author:
    - Wouter Moeken (@intellium)

options:
    host:
        description: Hostname of rancher system
        aliases: [ rancher_host ]
        required: true
        type: str

    username:
        description: Username for user/pass login instead of token
        aliases: [ rancher_username ]
        required: false
        type: str

    password:
        description: Password for user/pass login instead of token
        aliases: [ rancher_password ]
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
'''

EXAMPLES = r'''
# Add repository
- name: Rancher Login
  intellium.rancher.rancher_login:
    host: rancher.example.com
    username: admin
    password: mysecretpassword
    full_response: true
    validate_certs: false
  register: login
'''

RETURN = r'''
# These are examples of possible return values,
# and in general should use other names for return values.
token:
    description: Authentication token for the logged in user
    type: dict
    returned: always
full_response:
    description: The full API response of the last request
    type: dict
    returned: optional
'''

import json

from ansible.module_utils.basic import AnsibleModule, sanitize_keys
from ansible.module_utils._text import to_native, to_text

import ansible_collections.intellium.rancher.plugins.module_utils.\
    rancher_globals as g
from ansible_collections.intellium.rancher.plugins.module_utils.rancher_api \
    import api_req, clusterid_by_name, api_login, api_exit


def main():
    argument_spec = {}
    argument_spec.update(
        host=dict(type='str', aliases=['rancher_host'], required=True),
        username=dict(type='str', aliases=['rancher_username']),
        password=dict(type='str', aliases=['rancher_password'], no_log=True),
        full_response=dict(type='bool'),
        validate_certs=dict(type='bool', default=True)
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=[
            ('username', 'password')
        ]
    )

    # Fetch token from login
    g.mod_returns.update(token=api_login(module))

    # Check status code
    if g.last_response['status'] in (200, 201):
        g.mod_returns.update(changed=False)
        api_exit(module)
    else:
        g.mod_returns.update(msg='Unexpected response: '
                             + to_text(g.last_response))
        api_exit(module, 'fail')


if __name__ == '__main__':
    main()
