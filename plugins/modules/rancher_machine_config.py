# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Cees Moerkerken <cees.moerkerken@rws.nl>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: rancher_machine_config
short_description: Manage Rancher Machine configs
description:
    - This module allows you to manage the lifecycle of machine configs.
    - Only tested on vmware vsphere configs!
version_added: "0.1.0"
author:
    - Wouter Moeken (@intellium)
    - Cees Moerkerken (@ceesios)

options:
    state:
        description: absent or present
        choices: ['present', 'absent']
        default: 'present'
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

    name:
        description: Name of the machine config
        required: true
        type: str

    namespace:
        description: Namespace of the machine config
        default: 'fleet-default'
        type: str

    type:
        description: Type of Machine config
        required: true
        type: str
        choices:
            - 'vsphere'
            - 'ec2'
            - 'azure'
            - 'digitalocean'
            - 'harvester'
            - 'linode'

    config:
        description:
            - Machine config to create in Rancher
            - Suboptions must be capitilazed correctly!
            - Only vsphere options are tested.
            - See v1/schemas/rke-machine-config.cattle.io.<type> for schema
        required: true
        type: dict
        suboptions:
            cloneFrom:
                description:
                    - vSphere cloneFrom
                    - Required when type=vsphere
                type: str

            cloudConfig:
                description:
                    - vSphere cloudConfig
                    - Required when type=vsphere
                type: str

            cloudinit:
                description:
                    - vSphere cloudinit
                    - Required when type=vsphere
                type: str

            contentLibrary:
                description:
                    - vSphere contentLibrary
                    - Required when type=vsphere
                type: str

            cpuCount:
                description:
                    - vSphere cpuCount
                    - Required when type=vsphere
                type: str

            creationType:
                description:
                    - vSphere creationType
                    - Required when type=vsphere
                type: str

            datacenter:
                description:
                    - vSphere datacenter
                    - Required when type=vsphere
                type: str

            datastore:
                description:
                    - vSphere datastore
                    - Required when type=vsphere
                type: str

            datastoreCluster:
                description:
                    - vSphere datastoreCluster
                    - Required when type=vsphere
                type: str

            diskSize:
                description:
                    - vSphere diskSize
                    - Required when type=vsphere
                type: str

            folder:
                description:
                    - vSphere folder
                    - Required when type=vsphere
                type: str

            hostsystem:
                description:
                    - vSphere hostsystem
                    - Required when type=vsphere
                type: str

            kind:
                description:
                    - vSphere kind
                    - Required when type=vsphere
                type: str

            memorySize:
                description:
                    - vSphere memorySize
                    - Required when type=vsphere
                type: str

            network:
                description:
                    - vSphere network
                    - Required when type=vsphere
                type: str

            os:
                description:
                    - vSphere os
                    - Required when type=vsphere
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
    token: "{{ login_out['token'] }}"
    name: "vsphere"
    type: vsphere
    config:
        cloneFrom: "Ubuntu"
        datacenter: "dc-example"
        datastore: "ds-example"
        folder: "example"
        cpuCount: "4"
        diskSize: "20480"
        memorySize: "4096"
    full_response: true
    validate_certs: false
'''

RETURN = r'''
# These are examples of possible return values, and in general should
# use other names for return values.
id:
    description: The ID of the machine config
    type: dict
    returned: always
output:
    description: The machine config object
    type: dict
    returned: always
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
    import api_req, api_login, api_exit
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
        type=dict(type='str', required=True, choices=[
            'vsphere', 'ec2', 'azure', 'digitalocean', 'harvester', 'linode']),
        config=dict(type='dict', required=True),
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
    typeinfo = determine_type(module)
    _action = None
    api_path = "v1/rke-machine-config.cattle.io." + typeinfo['type']
    baseurl = f"https://{module.params['host']}/{api_path}"
    v1_id = f"{module.params['namespace']}/{module.params['name']}"
    _url = baseurl
    _before = {}
    _after = {
        "apiVersion": "rke-machine-config.cattle.io/v1",
        "id": v1_id,
        "kind": typeinfo['type'],
        "metadata": {
            "name": module.params['name'],
            "namespace": module.params['namespace']
        }
    }
    # Only change defined options in config
    for item in module.params['config']:
        _after.update({item: module.params['config'][item]})

    # Get all items, filtering is not possible in v1 api.
    # Using limit since we don't support pagination.
    get, content = api_req(
        module,
        url=f"{baseurl}?limit=1000",
        method='GET',
        auth=module.params['token']
    )

    if get['status'] in (200, 201):
        # check if mc by this name exists
        mc = next((i for i in get['json']['data'] if i["id"] == v1_id), None)

        if mc is not None:
            # mc exists
            _before = {
                "apiVersion": mc['apiVersion'],
                "id": mc['id'],
                "kind": typeinfo['type'],
                "metadata": {
                    "name": mc['metadata']['name'],
                    "namespace": mc['metadata']['namespace'],
                }
            }
            # Only ckeck defined options in config
            for item in module.params['config']:
                try:
                    _before.update({item: mc[item]})
                except KeyError:
                    _before.update({item: ""})
                    g.mod_returns.update(msg=f'no config for {item} found')

            _url = f"{baseurl}/{v1_id}"

            if module.params['state'] == 'absent':
                g.mod_returns.update(changed=True)
                _action = 'DELETE'
                _after = {}

            else:
                diff_result = recursive_diff(_before, _after)
                if diff_result is not None:
                    g.mod_returns.update(changed=True)
                    _action = 'PUT'

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

        # Check status code and set id and output
        if action_req['check']:
            g.mod_returns.update(changed=True)
            api_exit(module)
        else:
            api_exit(module, 'fail')

    else:
        api_exit(module)


def determine_type(module):
    _type = module.params['type']
    if _type == "vsphere":
        typename = "vmwarevsphereconfigs"
    elif _type == "ec2":
        typename = "amazonec2configs"
    elif _type == "azure":
        typename = "azureconfigs"
    elif _type == "digitalocean":
        typename = "digitaloceanconfigs"
    elif _type == "harvester":
        typename = "harvesterconfigs"
    elif _type == "linode":
        typename = "linodeconfigs"
    else:
        g.mod_returns.update(changed=False,
                             msg=_type
                             + ' type not supported')
        api_exit(module, 'fail')

    body = {
        "metadata": {
            "name": module.params['name'],
            "namespace": module.params['namespace']
        },
        "apiVersion": "rke-machine-config.cattle.io/v1"
    }

    configitems = {}
    for item in module.params['config']:
        configitems.update({item: module.params['config'][item]})

    body.update({typename: configitems})

    return {"body": body, "type": typename}


if __name__ == '__main__':
    main()
