# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Cees Moerkerken <cees.moerkerken@rws.nl>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: rancher_cluster
short_description: Manage Rancher Clusters
description:
    - This module allows you to manage the lifecycle of Clusters.
    - Only tested on vmware vsphere clusters!
version_added: "0.1.0"
author:
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
        required: False
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
        description: Name of the cluster
        required: true
        type: str

    namespace:
        description: Namespace of the cluster
        default: 'fleet-default'
        type: str

    type:
        description: Type of Cluster
        default: 'vsphere'
        type: str
        choices:
            - 'vsphere'
            - 'amazonec2'
            - 'azure'
            - 'digitalocean'
            - 'harvester'
            - 'linode'

    vsphereconfig:
        description:
            - Vsphere config to create in Rancher
        type: dict
        suboptions:
            datacenter:
                description: vSphere datacenter
                type: str
            host:
                description: vcenter server address
                type: str
                default: ""
            username:
                description:
                    - vSphere username
                    - Required when type=vsphere
                type: str
            password:
                description:
                    - vSphere Password
                    - Required when type=vsphere
                type: str
            csi_datastoreurl:
                description:
                    - vSphere csi_datastoreurl
                type: str
    cni:
        description: cni
        default: 'calico'
        type: str
    cloud_credential:
        description: cni
        required: true
        type: str
    kubernetes_version:
        description: kubernetes version
        default: "v1.24.4+rke2r1"
        type: str
    machinePools:
        description: machinePools
        required: false
        type: list
        elements: dict
        suboptions:
            controlPlaneRole:
                description: controlPlaneRole
                type: bool
                default: True
            displayName:
                description: displayName
                type: str
            etcdRole:
                description: etcdRole
                type: bool
                default: True
            machineConfigRef:
                description: machineConfigRef
                required: false
                type: dict
                suboptions:
                    kind:
                        description: machineConfigRef kind
                        type: str
                        default: 'VmwarevsphereConfig'
                    name:
                        description: machineConfigRef name
                        type: str
            name:
                description: name
                type: str
            workerRole:
                description: workerRole
                type: bool
                default: True
            quantity:
                description: quantity
                type: int
                default: 3
    machineSelectorConfig:
        description: machineSelectorConfig
        required: false
        type: dict
        suboptions:
            config:
                description: machineSelectorConfig
                type: dict
                required: false
    upgradeStrategy:
        description: upgradeStrategy
        required: false
        type: dict
        suboptions:
            controlPlaneConcurrency:
                description: controlPlaneConcurrency
                type: str
                default: '10%'
            workerConcurrency:
                description: workerConcurrency
                type: str
                default: '10%'

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
- name: Test create cluster
  intellium.rancher.rancher_cluster:
    state: present
    host: rancher.example.com
    token: "{{ login['token'] }}"
    name: "vsphere_cl01"
    type: vsphere
    vsphereconfig:
        datacenter: "dc-example"
        vcenter: "vcenter.example.com"
        username: "myuser"
        password: "mysecretpass"
    machinePools:
      - displayName: "masters"
        machineConfigRef:
            name: "cl01-master"
        name: "masters"
        quantity: 3
        workerRole: False
      - controlPlaneRole: False
        displayName: "workers"
        machineConfigRef:
            name: "cl01-worker"
        name: "workers"
        workerRole: True
        quantity: 8
    full_response: true
    validate_certs: false
'''

RETURN = r'''
# These are examples of possible return values, and in general should
# use other names for return values.
id:
    description: The ID of the cluster
    type: dict
    returned: always
idcol:
    description: The ID of the cluster separated by colon
    type: dict
    returned: always
output:
    description: The cluster object
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
        type=dict(type='str', default="vsphere", choices=[
            'vsphere', 'amazonec2', 'azure', 'digitalocean', 'harvester', 'linode']),
        vsphereconfig=dict(
            type='dict',
            required=False,
            options=dict(
                datacenter=dict(type='str', required=False),
                host=dict(type='str', required=False),
                username=dict(type='str', required=False),
                password=dict(type='str', required=False, no_log=True),
                csi_datastoreurl=dict(type='str', required=False)
            )
        ),
        cni=dict(type='str', default="calico"),
        cloud_credential=dict(type='str', required=True),
        kubernetes_version=dict(type='str', default="v1.24.4+rke2r1"),
        machinePools=dict(
            type='list',
            required=False,
            elements='dict',
            options=dict(
                controlPlaneRole=dict(type='bool', default=True),
                displayName=dict(type='str', default=None),
                etcdRole=dict(type='bool', default=True),
                machineConfigRef=dict(
                    type='dict',
                    required=False,
                    options=dict(
                        kind=dict(type='str', default="VmwarevsphereConfig"),
                        name=dict(type='str', default=None)
                    )
                ),
                name=dict(type='str', default=None),
                workerRole=dict(type='bool', default=True),
                quantity=dict(type='int', default="3")
            )
        ),
        machineSelectorConfig=dict(
            type='dict',
            required=False,
            options=dict(
                config=dict(type='dict', required=False)
            )
        ),
        upgradeStrategy=dict(
            type='dict',
            required=False,
            options=dict(
                controlPlaneConcurrency=dict(type='str', default="10%"),
                workerConcurrency=dict(type='str', default="10%")
            )
        ),
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
    us = module.params['upgradeStrategy']

    body = {
        "apiVersion": "provisioning.cattle.io/v1",
        "id": f"{module.params['namespace']}/{module.params['name']}",
        "metadata": {
            "name": module.params['name'],
            "namespace": module.params['namespace']
        },
        "kind": "Cluster",
        "type": "provisioning.cattle.io.cluster",
        "spec": {
            # "agentEnvVars": {},
            "cloudCredentialSecretName": module.params['cloud_credential'],
            # "clusterAPIConfig": {},
            # "defaultClusterRoleForProjectMembers": "",
            # "defaultPodSecurityPolicyTemplateName": "",
            "enableNetworkPolicy": False,
            "kubernetesVersion": module.params['kubernetes_version'],
            "localClusterAuthEndpoint": {},
            # "redeploySystemAgentGeneration": "",
            "rkeConfig": {
                # "additionalManifest": "",
                "etcd": {
                    "snapshotScheduleCron": "0 */5 * * *",
                    "snapshotRetention": 5
                },
                # "etcdSnapshotCreate": {},
                # "etcdSnapshotRestore": {},
                # "infrastructureRef": {},
                "machinePools": [],
                "machineGlobalConfig": {
                    "cni": module.params['cni'],
                    "disable": [
                        "rke2-ingress-nginx"  # FIXME:
                    ],
                    "disable-kube-proxy": False,
                    "etcd-expose-metrics": False,
                    "profile": None
                },
                "machineSelectorConfig": [{
                    "config": {
                        "cloud-provider-name": "rancher-vsphere",
                        "protect-kernel-defaults": "false"
                    }
                }],
                # "provisionGeneration": "",
                # "registries": {},
                # "rotateCertificates": {},
                # "rotateEncryptionKeys": {},
                "upgradeStrategy": {
                    "controlPlaneConcurrency": us["controlPlaneConcurrency"],
                    "controlPlaneDrainOptions": {
                        "deleteEmptyDirData": False,
                        "disableEviction": False,
                        "enabled": False,
                        "force": False,
                        "gracePeriod": 0,
                        "ignoreDaemonSets": None,
                        "postDrainHooks": None,
                        "preDrainHooks": None,
                        "skipWaitForDeleteTimeoutSeconds": 0,
                        "timeout": 0
                    },
                    "workerConcurrency": us["workerConcurrency"],
                    "workerDrainOptions": {
                        "deleteEmptyDirData": False,
                        "disableEviction": False,
                        "enabled": False,
                        "force": False,
                        "gracePeriod": 0,
                        "ignoreDaemonSets": None,
                        "postDrainHooks": None,
                        "preDrainHooks": None,
                        "skipWaitForDeleteTimeoutSeconds": 0,
                        "timeout": 0
                    }
                }
            }
        }
    }

    api_path = "v1/provisioning.cattle.io.clusters"

    # chartValues
    if module.params['type'] == "vsphere":
        config = module.params['vsphereconfig']

        body["spec"]["rkeConfig"]['chartValues'] = {
            "rancher-vsphere-cpi": {
                "vCenter": {
                    "datacenters": config['datacenter'],
                    "host": config['host'],
                    "password": config['password'],
                    "username": config['username'],
                }
            }}

        if config['csi_datastoreurl'] is not None:
            body["spec"]["rkeConfig"]['chartValues'].update({
                "rancher-vsphere-csi": {
                    "storageClass": {
                        "datastoreURL": config['csi_datastoreurl']
                    },
                    "vCenter": {
                        "datacenters": config['datacenter'],
                        "host": config['host'],
                        "password": config['password'],
                        "username": config['username'],
                    }
                }})
    elif module.params['type'] == "azure":
        body["spec"]["rkeConfig"]['chartValues'] = {}
    else:
        g.mod_returns.update(changed=False,
                             msg=module.params['type']
                             + ' type not supported')
        api_exit(module, 'fail')

    if module.params['cni'] == "calico":
        body["spec"]["rkeConfig"]['chartValues'].update({
            "rke2-calico": {}
        })

    # "machinePools": [],
    if module.params['machinePools'] is not None:
        config = module.params['machinePools']
        for item in config:
            i = item
            i.update({
                "cloudCredentialSecretName": module.params['cloud_credential']
            })
            body["spec"]["rkeConfig"]["machinePools"].append(item)

    else:
        body["spec"]["rkeConfig"]['machinePools'] = {}

    # machineSelectorConfig
    if module.params['machineSelectorConfig'] is not None:
        config = module.params['machineSelectorConfig']
        for item in config:
            body["spec"]["rkeConfig"]["machineSelectorConfig"].update(
                {item: config[item]}
            )
    else:
        body["spec"]["rkeConfig"]['machineSelectorConfig'] = [
            {
                "config": {
                    "cloud-provider-name": "rancher-vsphere",
                    "protect-kernel-defaults": 'false'
                }
            }
        ]

    config_items = {"spec": {}}
    return {"body": body, "api_path": api_path, "config_items": config_items}


if __name__ == '__main__':
    main()
