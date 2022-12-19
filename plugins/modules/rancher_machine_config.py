# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Cees Moerkerken <cees.moerkerken@rws.nl>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: rancher_machine_config_vsphere
short_description: Manage Rancher Machine configs
description:
    - This module allows you to manage the lifecycle of machine configs.
version_added: "0.1.0"
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
- name: Test create Machine Config
  intellium.rancher.rancher_machine_config:
    state: present
    host: rancher.example.com
    username: admin
    password: changeme12345


    full_response: true
    validate_certs: false
'''

RETURN = r'''
# These are examples of possible return values, and in general should
# use other names for return values.
full_response:
    description: The full API response of the last request
    type: dict
    returned: optional
'''

import json

from ansible.module_utils.common.dict_transformations \
    import recursive_diff, dict_merge
from ansible.module_utils.basic import AnsibleModule, sanitize_keys
from ansible.module_utils._text import to_native, to_text

from ansible_collections.intellium.rancher.plugins.module_utils.rancher_api \
    import api_req, clusterid_by_name, api_login, api_exit
import ansible_collections.intellium.rancher.plugins.module_utils.\
    rancher_globals as g


def main():
    argument_spec = {}
    argument_spec.update(
        state=dict(type='str', default="present",
                   choices=['present', 'absent']),
        host=dict(type='str', aliases=['rancher_host'], required=True),
        token=dict(type='str', aliases=['rancher_token'], no_log=True),
        username=dict(type='str', aliases=['rancher_username']),
        password=dict(type='str', aliases=['rancher_password'], no_log=True),
        name=dict(type='str', required=True),
        namespace=dict(type='str', default="fleet-default"),
        mc=dict(type='dict', required=True),
        full_response=dict(type='bool'),
        validate_certs=dict(type='bool', default=True)
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
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

    # Set defaults (_ = internal use and may change)
    _action = None
    api_path = "v1/rke-machine-config.cattle.io.vmwarevsphereconfigs"
    baseurl = f"https://{module.params['host']}/{api_path}"
    mcr_id = f"{module.params['namespace']}/{module.params['name']}"
    _url = baseurl
    _before = {}
    _after = {
        "metadata": {
            "name": module.params['name'],
            "namespace": module.params['namespace']
        },
        "apiVersion": "rke-machine-config.cattle.io/v1"
    }
    for item in module.params['mc']:
        _after.update({item: module.params['mc'][item]})

    # Get all mcs, filtering is not possible in api.
    # Using limit since we don't support pagination.
    mcr, content = api_req(
        module,
        url=f"{baseurl}?limit=1000",
        method='GET',
        auth=module.params['token']
    )

    if mcr['status'] in (200, 201):
        # check if mc by this name exists
        mc = next((i for i in mcr['json']['data'] if i["id"] == mcr_id), None)

        if mc is not None:
            # mc exists, only work with configured values
            # _before = mc
            _before = {
                "metadata": {
                    "name": mc['metadata']['name'],
                    "namespace": mc['metadata']['namespace']
                },
                "apiVersion": mc['apiVersion'],
                "kind": "VmwarevsphereConfig"
            }
            for item in module.params['mc']:
                _before.update({item: mc[item]})

            _url = f"{baseurl}/{mcr_id}"

            if module.params['state'] == 'absent':
                g.mod_returns.update(changed=True)
                _action = 'DELETE'
                _after = {}

            else:
                diff_result = recursive_diff(_before, _after)
                if diff_result is not None:
                    g.mod_returns.update(changed=True)
                    _action = 'PUT'
                    newversion = int(mc['metadata']['resourceVersion']) + 1
                    _after.update(
                        {
                            "metadata": {
                                "name": module.params['name'],
                                "namespace": module.params['namespace'],
                                "resourceVersion": to_text(newversion)
                            }
                        }
                    )

        else:
            # mc doesn't exist
            if module.params['state'] == 'absent':
                g.mod_returns.update(changed=False)
                api_exit(module)

            elif module.params['state'] == 'present':
                g.mod_returns.update(changed=True)
                _action = 'POST'

    else:
        # Something went wrong
        g.mod_returns.update(
            changed=False, msg='Something went wrong. Unexpected response: '
                               + to_text(g.last_response))
        api_exit(module, 'fail')

    if module._diff:
        g.mod_returns.update(diff=dict(before=_before, after=_after))

    if module.check_mode:
        api_exit(module)

    elif _action is not None:
        # Make the request
        action_req, content = api_req(
            module,
            url=_url,
            body=json.dumps(_after, sort_keys=True),
            body_format='json',
            method=_action,
            auth=module.params['token']
        )

        # Check status code
        if action_req['status'] in (200, 201, 202, 204):
            g.mod_returns.update(changed=True)
            api_exit(module)
        elif action_req['status'] == 403:
            g.mod_returns.update(
                msg='The authenticated user is not allowed amcess to the \
                    requested resource. Check username / password ')
            api_exit(module, 'fail')
        elif action_req['status'] == 404:
            g.mod_returns.update(
                msg='The requested resource is not found')
            api_exit(module, 'fail')
        elif action_req['status'] == 409:
            g.mod_returns.update(
                msg='Trying to create object that exists. \
                    ' + to_text(action_req['msg']) + '\
                    ' + to_text(action_req['body']))
            api_exit(module, 'fail')
        else:
            g.mod_returns.update(msg='Unexpected response: '
                                 + to_text(action_req))
            api_exit(module, 'fail')
    else:
        api_exit(module)


if __name__ == '__main__':
    main()
