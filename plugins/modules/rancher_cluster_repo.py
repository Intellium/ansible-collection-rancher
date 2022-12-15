# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Wouter Moeken <wouter.moeken@rws.nl>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: rancher_cluster_repo
short_description: Manage Rancher Cluster Repositories
description:
    - This module allows you to manage the lifecycle of Cluster Repositories.
version_added: "0.0.1"
requirements:
    - "python >= 3.10"
author:
    - Wouter Moeken (@intellium)

options:
    state:
        description: absent or present
        choices: ['present', 'absent']
        default: 'present'
        type: str

    cluster_name:
        description: Name of the cluster in rancher to operate on
        aliases: [ rancher_cluster ]
        required: true
        type: str

    host:
        description: Hostname of rancher system
        aliases: [ rancher_host ]
        required: true
        type: str

    token:
        description: Token used for authentication
        aliases: [ rancher_token ]
        required: false
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

    repo_name:
        description: Name of repository to operate on
        required: true
        type: str

    repo_url:
        description: URL of the repository
        required: true
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
- name: Test create repo
  intellium.rancher.rancher_cluster_repo:
    state: present
    host: rancher.example.com
    username: admin
    password: mysecretpassword
    cluster_name: downstream_cluster
    repo_name: "test-repo"
    repo_url: "https://test-repo.example.com"
    full_response: true
    validate_certs: false
'''

RETURN = r'''
# These are examples of possible return values,
# and in general should use other names for return values.
full_response:
    description: The full API response of the last request
    type: dict
    returned: optional
'''

import json
import ansible_collections.intellium.rancher.plugins.module_utils.\
    rancher_globals as g

from ansible.module_utils.basic import AnsibleModule, sanitize_keys
from ansible.module_utils.common.dict_transformations import recursive_diff
from ansible.module_utils._text import to_native, to_text
from ansible_collections.intellium.rancher.plugins.module_utils.rancher_api \
    import api_req, clusterid_by_name, api_login, api_exit


def main():
    argument_spec = {}
    argument_spec.update(
        state=dict(type='str', default="present",
                   choices=['present', 'absent']),
        host=dict(type='str', aliases=['rancher_host'], required=True),
        cluster_name=dict(type='str', aliases=[
                          'rancher_cluster'], required=True),
        token=dict(type='str', aliases=['rancher_token'], no_log=True),
        username=dict(type='str', aliases=['rancher_username']),
        password=dict(type='str', aliases=['rancher_password'], no_log=True),
        repo_name=dict(type='str', required=True),
        repo_url=dict(type='str', required=True),
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
    _url = 'https://%s/k8s/clusters/%s/v1/catalog.cattle.io.clusterrepos' % (
        module.params['host'], cluster_id)
    _body = json.dumps(
        {
            "type": "catalog.cattle.io.clusterrepo",
            "metadata": {
                "name": module.params['repo_name']
            },
            "spec": {
                "url": module.params['repo_url']
            }
        },
        sort_keys=True
    )

    # Get current repo if it exists
    ccr, content = api_req(
        module,
        url='https://%s/k8s/clusters/%s/v1/catalog.cattle.io.clusterrepos/%s'
            % (module.params['host'], cluster_id, module.params['repo_name']),
        method='GET',
        auth=module.params['token']
    )
    if ccr['status'] in (200, 201):
        # Repo by this name exists, check if we need to update anything
        if ccr['json']['spec']['url'] != module.params['repo_url']:
            _action = 'PUT'
            _tmpbody = ccr['json']
            _tmpbody['spec']['url'] = module.params['repo_url']
            _body = json.dumps(_tmpbody)
            _url = _url + '/' + module.params['repo_name']
        else:
            # Repo exists, nothing changed
            if module.params['state'] == 'present':
                g.mod_returns.update(changed=False)
                api_exit(module)
            elif module.params['state'] == 'absent':
                _action = 'DELETE'
                _url = _url + '/' + module.params['repo_name']
    elif ccr['status'] == 404:
        # Repo doesn't exist
        if module.params['state'] == 'absent':
            g.mod_returns.update(changed=False)
            api_exit(module)
        elif module.params['state'] == 'present':
            _action = 'POST'

    # Make the request
    resp, content = api_req(
        module,
        url=_url,
        body=_body,
        body_format='json',
        method=_action if _action else 'POST',
        auth=module.params['token']
    )

    # Check status code
    if g.last_response['status'] in (200, 201, 202):
        g.mod_returns.update(changed=True)
        api_exit(module)
    elif g.last_response['status'] == 403:
        g.mod_returns.update(
            msg='The authenticated user is not allowed access to the \
                requested resource. Check username / password ')
        api_exit(module, 'fail')
    elif g.last_response['status'] == 404:
        g.mod_returns.update(
            msg='The requested resource is not found')
        api_exit(module, 'fail')
    elif g.last_response['status'] == 409:
        g.mod_returns.update(
            msg='Trying to create object that exists.')
        api_exit(module, 'fail')
    else:
        g.mod_returns.update(msg='Unexpected response: '
                             + to_text(g.last_response))
        api_exit(module, 'fail')


if __name__ == '__main__':
    main()
