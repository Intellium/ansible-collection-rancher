#!/usr/bin/python

# Copyright: (c) 2022, Wouter Moeken <wouter.moeken@rws.nl>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: rancher_login

short_description: Login with username/password to obtain token

version_added: "0.0.5"

description: This module does a web login and returns an authentication token

options:
    host:
        description: Hostname of rancher system
        required: true
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
# Add repository
- name: Test create repo
  intellium.rancher.rancher_login:
    host: rancher.example.com
    username: admin
    password: mysecretpassword
    full_response: true
    validate_certs: false
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
token:
    description: Authentication token for the logged in user
    type: string
    returned: always
full_response:
    description: The full API response of the last request
    type: json
    returned: optional
'''

import json
import ansible_collections.intellium.rancher.plugins.module_utils.rancher_globals as g

from ansible.module_utils.basic import AnsibleModule, sanitize_keys
from ansible.module_utils._text import to_native, to_text
from ansible_collections.intellium.rancher.plugins.module_utils.rancher_api import api_req, clusterid_by_name, api_login, api_exit

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
        required_together=[
            ('username','password')
        ]
    )

    # Fetch token from login
    g.mod_returns.update(token=api_login(module))

    # Check status code
    if g.last_reponse['status'] == 401:
        g.mod_returns.update(msg='Authentication failed. Check username / password / token')
        api_exit(module,'fail')
    elif g.last_reponse['status'] == 409:
        g.mod_returns.update(msg='Trying to create object that already exists.')
        api_exit(module,'fail')
    elif g.last_reponse['status'] == 201 or g.last_reponse['status'] == 200 or g.last_reponse['status'] == 204:
        g.mod_returns.update(changed=False)
        api_exit(module)
    else:
        g.mod_returns.update(msg='Unexpected status code: ' + to_text(g.last_response['status']))
        api_exit(module,'fail')

if __name__ == '__main__':
    main()