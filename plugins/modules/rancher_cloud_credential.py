#!/usr/bin/python

# Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: rancher_cloud_credential

short_description: Manage Rancher Cloud Credentials

version_added: "0.0.2"

description: This module allows you to manage the lifecycle of Cluster Repositories.

options:
    state:
        description: absent or present
        required: true
        type: str
    
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
        
    cred_name:
        description: Name of the credential
        required: true
        type: str
        
    cred_host:
        description: Host of the credential
        required: true
        type: str
        
    cred_username:
        description: Username of the credential
        required: true
        type: str

    cred_password:
        description: Password of the credential
        required: true
        type: str
    
    cred_port:
        description: Port number of the credential
        required: false
        default: 443
        type: str

    cred_type:
        description: Type of credential (only vsphere supported)
        required: false
        default: vsphere
        type: str

    full_response:
        description: Whether to return full api response
        required: false
        type: bool
extends_documentation_fragment:
    - intellium.rancher.my_doc_fragment_name

author:
    - Wouter Moeken (@intellium)
'''

EXAMPLES = r'''
# Add repository
- name: Test create cc
  intellium.rancher.rancher_cloud_credential:
    state: present
    host: rancher.example.com
    username: admin
    password: changeme12345
    cred_name: "mycred"
    cred_host: "vcenter.example.com"
    cred_username: "myuser"
    cred_password: "mysecretpass
    full_response: true
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
full_response:
    description: The full API response of the last request
    type: json
    returned: optional
'''

import json
import base64
import ansible_collections.intellium.rancher.plugins.module_utils.rancher_globals as g

from ansible.module_utils.basic import AnsibleModule, sanitize_keys
from ansible.module_utils._text import to_native, to_text
from ansible_collections.intellium.rancher.plugins.module_utils.rancher_api import api_req, clusterid_by_name, api_login, api_exit

def main():
    argument_spec = {}
    argument_spec.update(
        state=dict(type='str', choices=['present','absent'], required=True),
        host=dict(type='str', aliases=['rancher_host'], required=True),
        token=dict(type='str', aliases=['rancher_token'], no_log=True),
        username=dict(type='str', aliases=['rancher_username']),
        password=dict(type='str', aliases=['rancher_password'], no_log=True),
        cred_name=dict(type='str', aliases=['name'], required=True),
        cred_host=dict(type='str', required=True),
        cred_username=dict(type='str', required=True),
        cred_password=dict(type='str', required=True, no_log=False),
        cred_port=dict(type='str', default='443'),
        cred_type=dict(type='str', default='vsphere'),
        full_response=dict(type='bool')
    )
    
    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[
            ('token','username'),
            ('token','password')
        ],
        required_together=[
            ('username','password')
        ],
        required_one_of=[
            ('token','username','password'),
        ]
    )

    # Do we have a token? If not, go and fetch it
    if not module.params['token']:
        module.params['token'] = api_login(module)

    # Set defaults
    _action = 'POST'
    _url = 'https://%s/v3/cloudcredentials' % (module.params['host'])
    _body = json.dumps(
        {
            "type":"cloudcredential",
            "name":module.params['cred_name'],
            "vmwarevspherecredentialConfig": {
                "vcenter":module.params['cred_host'],
                "vcenterPort":module.params['cred_port'],
                "username":module.params['cred_username'],
                "password":module.params['cred_password']
            }
        }, 
        sort_keys=True
    )

    # Get current cc if it exists
    ccr, content = api_req(
        module,
        url = 'https://%s/v3/cloudCredentials/?name=%s' % (module.params['host'], module.params['cred_name']),
        method = 'GET',
        auth = module.params['token']
    )
    if ccr['status'] in (200,201) and len(ccr['json']['data']) > 0:
        # CC by this name exists
        
        # Fetch password
        ccp, content = api_req(
            module,
            url = 'https://%s/v1/secrets/%s' % (module.params['host'], ccr['json']['data'][0]['id'].replace(':','/')),
            method = 'GET',
            auth = module.params['token']
        )
        if (
            ccr['json']['data'][0]['vmwarevspherecredentialConfig']['username'] != module.params['cred_username'] or 
            ccr['json']['data'][0]['vmwarevspherecredentialConfig']['vcenter'] != module.params['cred_host'] or
            ccr['json']['data'][0]['vmwarevspherecredentialConfig']['vcenterPort'] != module.params['cred_port'] or
            to_text(base64.b64decode(ccp['json']['data']['vmwarevspherecredentialConfig-password'])) != module.params['cred_password']
        ):
            _action = 'PUT'
            _tmpbody = ccr['json']['data'][0]
            _tmpbody['vmwarevspherecredentialConfig']['username'] = module.params['cred_username']
            _tmpbody['vmwarevspherecredentialConfig']['vcenter'] = module.params['cred_host']
            _tmpbody['vmwarevspherecredentialConfig']['vcenterPort'] = module.params['cred_port']
            _tmpbody['vmwarevspherecredentialConfig']['password'] = module.params['cred_password']
            _body = json.dumps(_tmpbody)
            _url = 'https://%s/v3/cloudCredentials/%s' % (module.params['host'], ccr['json']['data'][0]['id'])
        else:
            # CC exists, but nothing changed
            if module.params['state'] == 'present':
                g.mod_returns.update(changed=False)
                api_exit(module)
            elif module.params['state'] == 'absent':
                _action = 'DELETE'
                _url = 'https://%s/v3/cloudCredentials/%s' % (module.params['host'], ccr['json']['data'][0]['id'])
    elif ccr['status'] in (200,201) and len(ccr['json']['data']) < 1:
        # CC doesn't exist
        if module.params['state'] == 'absent':
            g.mod_returns.update(changed=False)
            api_exit(module)
        elif module.params['state'] == 'present':
            _action = 'POST'
    else:
        # Something went wrong
        g.mod_returns.update(changed=False,msg='Something went wrong. Received status code ' + ccr['status'] + ' from API')
        api_exit(module,'fail')

    # Make the request
    resp, content = api_req(
        module,
        url = _url,
        body = _body,
        body_format = 'json',
        method = _action,
        auth = module.params['token']
    )

    # Check status code
    if resp['status'] == 401:
        g.mod_returns.update(msg='Authentication failed. Check username / password / token')
        api_exit(module,'fail')
    elif resp['status'] == 409:
        g.mod_returns.update(msg='Trying to create object that already exists.')
        api_exit(module,'fail')
    elif resp['status'] in (200,201,204):
        g.mod_returns.update(changed=True)
        api_exit(module)
    else:
        g.mod_returns.update(msg='Unexpected status code: ' + to_text(g.last_response['status']))
        g.mod_returns.update(full_api=g.last_response)
        api_exit(module,'fail')

if __name__ == '__main__':
    main()