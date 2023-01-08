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
        description: Name (= rancher id) of the machine config, must be unique
        required: true
        type: str

    namespace:
        description: Namespace of the machine config
        default: 'fleet-default'
        type: str

    type:
        description: Type of Machine config. Only vsphere is tested
        required: true
        type: str
        choices:
            - 'vsphere'
            - 'amazonec2'
            - 'azure'
            - 'digitalocean'
            - 'harvester'
            - 'linode'

    labels:
        description: Labels to add to nodes created from this machine config
        required: false
        type: dict

    vsphereconfig:
        description:
            - vsphere Machine config to create in Rancher
            - Required when type=vsphere
        required: false
        type: dict
        suboptions:
            cloneFrom:
                description: clone VM From template or VM
                type: str
                required: true
            cloudConfig:
                description: cloudConfig
                type: str
                default: "#cloud-config"
            cloudinit:
                description: cloudinit config
                type: str
                default: ""
            contentLibrary:
                description: contentLibrary to clone from
                type: str
                default: ""
            cpuCount:
                description: VM cpuCount
                type: str
                required: true
            creationType:
                description: creationType
                type: str
                default: "template"
                choices:
                    - 'template'
                    - 'vm'
                    - 'library'
                    - 'legacy'
            datacenter:
                description: vSphere datacenter
                type: str
                required: true
            datastore:
                description: vSphere datastore
                type: str
                required: true
            datastoreCluster:
                description: vSphere datastoreCluster
                type: str
                default: ""
            diskSize:
                description: VM diskSize
                type: str
                required: true
            folder:
                description: vSphere VM folder
                type: str
                required: true
            hostsystem:
                description: vSphere host when not using vcenter
                type: str
                default: ""
            memorySize:
                description: vm memorySize
                type: str
                required: true
            network:
                description: vSphere network
                type: list
                required: true
                elements: str
            os:
                description: vm os
                type: str
                default: "linux"
            vcenter:
                description: vcenter server address
                type: str
                default: ""
            vcenterPort:
                description: vcenter server port
                type: str
                default: "443"
    amazonec2config:
        description:
            - amazonec2 Machine config to create in Rancher
            - Required when type=amazonec2
            - for valid subopions check schema at
            - v1/schemas/rke-machine-config.cattle.io.amazonec2config
        required: false
        type: dict
    azureconfig:
        description:
            - azure Machine config to create in Rancher
            - Required when type=azure
            - for valid subopions check schema at
            - v1/schemas/rke-machine-config.cattle.io.azureconfig
        required: false
        type: dict
    digitaloceanconfig:
        description:
            - digitalocean Machine config to create in Rancher
            - Required when type=digitalocean
            - for valid subopions check schema at
            - v1/schemas/rke-machine-config.cattle.io.digitaloceanconfig
        required: false
        type: dict
    harvesterconfig:
        description:
            - harvester Machine config to create in Rancher
            - Required when type=harvester
            - for valid subopions check schema at
            - v1/schemas/rke-machine-config.cattle.io.harvesterconfig
        required: false
        type: dict
    linodeconfig:
        description:
            - linode Machine config to create in Rancher
            - Required when type=linode
            - for valid subopions check schema at
            - v1/schemas/rke-machine-config.cattle.io.linodeconfig
        required: false
        type: dict


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
# create Machine Config
- name: Test create Machine Config
  intellium.rancher.rancher_machine_config:
    state: present
    host: rancher.example.com
    token: "{{ login['token'] }}"
    name: "vsphere_mc_1"
    type: vsphere
    vsphereconfig:
        cloneFrom: "Ubuntu"
        cpuCount: "4"
        datacenter: "dc-example"
        datastore: "ds-example"
        diskSize: "20480"
        folder: "example"
        memorySize: "4096"
        network: ["VM Network"]
        vcenter: "172.17.0.22"
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
idcol:
    description: The ID of the machine config separated by colon
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

from ansible.module_utils.basic import AnsibleModule, sanitize_keys
from ansible.module_utils._text import to_native, to_text

from ansible_collections.intellium.rancher.plugins.module_utils.rancher_api \
    import api_req, api_login, api_exit, v1_diff_object
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
        type=dict(type='str', required=True, choices=['vsphere', 'amazonec2',
                                                      'azure', 'digitalocean',
                                                      'harvester', 'linode']),
        labels=dict(type='dict', required=False),
        vsphereconfig=dict(
            type='dict',
            required=False,
            options=dict(
                cloneFrom=dict(type='str', required=True),
                cloudConfig=dict(type='str', default="#cloud-config"),
                cloudinit=dict(type='str', default=""),
                contentLibrary=dict(type='str', default=""),
                cpuCount=dict(type='str', required=True),
                creationType=dict(type='str', default="template", choices=[
                    'template', 'vm', 'library', 'legacy']),
                datacenter=dict(type='str', required=True),
                datastore=dict(type='str', required=True),
                datastoreCluster=dict(type='str', default=""),
                diskSize=dict(type='str', required=True),
                folder=dict(type='str', required=True),
                hostsystem=dict(type='str', default=""),
                memorySize=dict(type='str', required=True),
                network=dict(type='list', required=True, elements='str'),
                os=dict(type='str', default="linux"),
                vcenter=dict(type='str', default=""),
                vcenterPort=dict(type='str', default="443"),
            )
        ),
        amazonec2config=dict(
            type='dict',
            required=False,
        ),
        azureconfig=dict(
            type='dict',
            required=False,
        ),
        digitaloceanconfig=dict(
            type='dict',
            required=False,
        ),
        harvesterconfig=dict(
            type='dict',
            required=False,
        ),
        linodeconfig=dict(
            type='dict',
            required=False,
        ),
        full_response=dict(type='bool'),
        validate_certs=dict(type='bool', default=True)
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ("state", "present", ["type"]),
            ("type", "vsphere", ["vsphereconfig"])
        ],
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

    # Set defaults
    after_config = build_config(module)
    # _action = None
    api_path = after_config['api_path']
    baseurl = f"https://{module.params['host']}/{api_path}"
    v1_id = f"{module.params['namespace']}/{module.params['name']}"

    do = v1_diff_object(module, url=baseurl, id=v1_id, config=after_config)

    if module._diff:
        g.mod_returns.update(diff=dict(before=do["before"], after=do["after"]))

    if module.check_mode:
        api_exit(module)

    elif do["action"] is not None:
        # Make the request
        action_req, content = api_req(
            module,
            url=do["url"],
            body=json.dumps(do["after"], sort_keys=True),
            body_format='json',
            method=do["action"],
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


def build_config(module):
    body = {
        "apiVersion": "rke-machine-config.cattle.io/v1",
        "common": {
            "labels": {}
        },
        "id": f"{module.params['namespace']}/{module.params['name']}",
        "metadata": {
            "name": module.params['name'],
            "namespace": module.params['namespace']
        }
    }

    if module.params['type'] == "vsphere":
        body["kind"] = "VmwarevsphereConfig"
        body["type"] = "rke-machine-config.cattle.io.vmwarevsphereconfig"
        api_path = "v1/rke-machine-config.cattle.io.vmwarevsphereconfigs"
        config = module.params['vsphereconfig']

    elif module.params['type'] == "amazonec2":
        body["kind"] = "amazonec2configs"
        body["type"] = "rke-machine-config.cattle.io.amazonec2config"
        api_path = "v1/rke-machine-config.cattle.io.amazonec2configs"
        config = module.params['amazonec2config']

    elif module.params['type'] == "azure":
        body["kind"] = "azureconfigs"
        body["type"] = "rke-machine-config.cattle.io.azureconfig"
        api_path = "v1/rke-machine-config.cattle.io.azureconfigs"
        config = module.params['azureconfig']

    elif module.params['type'] == "digitalocean":
        body["kind"] = "digitaloceanconfigs"
        body["type"] = "rke-machine-config.cattle.io.digitaloceanconfig"
        api_path = "v1/rke-machine-config.cattle.io.digitaloceanconfigs"
        config = module.params['digitaloceanconfig']

    elif module.params['type'] == "harvester":
        body["kind"] = "harvesterconfigs"
        body["type"] = "rke-machine-config.cattle.io.harvesterconfig"
        api_path = "v1/rke-machine-config.cattle.io.harvesterconfigs"
        config = module.params['harvesterconfig']

    elif module.params['type'] == "linode":
        body["kind"] = "linodeconfigs"
        body["type"] = "rke-machine-config.cattle.io.linodeconfig"
        api_path = "v1/rke-machine-config.cattle.io.linodeconfigs"
        config = module.params['linodeconfig']

    else:
        g.mod_returns.update(changed=False,
                             msg=module.params['type']
                             + ' type not supported')
        api_exit(module, 'fail')

    # Create config
    for item in config:
        body.update({item: config[item]})

    config_items = config
    config_items.update({"common": ""})  # not in config or v1_diff_object

    # Set labels if defined
    if module.params['labels'] is not None:
        for k, v in module.params['labels'].items():
            body["common"]["labels"][k] = v

    return {"body": body, "api_path": api_path, "config_items": config_items}


if __name__ == '__main__':
    main()
