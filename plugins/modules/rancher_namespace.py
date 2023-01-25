# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Cees Moerkerken <cees.moerkerken@rws.nl>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: rancher_namespace
short_description: Manage Rancher Namespaces
description:
    - This module allows you to manage the lifecycle of Namespaces.
version_added: "0.1.0"
requirements:
    - "python >= 3.10"
author:
    - Cees Moerkerken (@ceesios)

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

    name:
        description: Name of namespace
        required: true
        type: str

    description:
        description: description of namespace
        required: false
        type: str

    projectid:
        description: projectid of namespace
        required: false
        type: str

    annotations:
        description: annotations
        required: False
        type: dict

    labels:
        description: Labels to add
        required: false
        type: dict

    limits:
        description: limits
        type: dict
        suboptions:
            cpu:
                description: CPU limit
                required: false
                type: str

            memory:
                description: Memory limit
                required: false
                type: str

            gpu:
                description: NVIDIA GPU limit
                required: false
                type: str

    requests:
        description: requests
        type: dict
        suboptions:
            cpu:
                description: CPU Reservation
                required: false
                type: str

            memory:
                description: Memory Reservation
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
# Add namespace
- name: Test create namespace
  intellium.rancher.rancher_namespace:
    state: present
    host: rancher.example.com
    token: "{{ login['token'] }}"
    name: "testns"
    description: "example"
    projectid: "{{ project['id'] }}"
    limits:
      cpu: "10m"
      memory: "256Mi"
      gpu: 1
    requests:
      cpu: "1m"
      memory: 128Mi
    full_response: true
    validate_certs: false
'''

RETURN = r'''
id:
    description: The ID of the namespace
    type: dict
    returned: always
output:
    description: The complete json object
    type: dict
    returned: always
full_response:
    description: The full API response of the last request
    type: dict
    returned: optional
'''

import json
import ansible_collections.intellium.rancher.plugins.module_utils.\
    rancher_globals as g

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native, to_text
from ansible_collections.intellium.rancher.plugins.module_utils.rancher_api \
    import api_req, clusterid_by_name, api_login, api_exit, v1_diff_object


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
        name=dict(type='str', required=True),
        description=dict(type='str'),
        projectid=dict(type='str'),
        annotations=dict(type='dict', required=False),
        labels=dict(type='dict', required=False),
        limits=dict(
            type='dict',
            required=False,
            options=dict(
                cpu=dict(type='str'),
                memory=dict(type='str'),
                gpu=dict(type='str')
            )
        ),
        requests=dict(
            type='dict',
            required=False,
            options=dict(
                cpu=dict(type='str'),
                memory=dict(type='str')
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
            ('token', 'username', 'password')
        ]
    )

    # Do we have a token? If not, go and fetch it
    if not module.params['token']:
        module.params['token'] = api_login(module)

    # Set defaults
    after_config = build_config(module)
    api_path = after_config['api_path']
    baseurl = f"https://{module.params['host']}/{api_path}"

    do = v1_diff_object(module, url=baseurl, id=module.params['name'],
                        config=after_config,
                        annotations=[
                            "field.cattle.io/description",
                            "field.cattle.io/containerDefaultResourceLimit"])

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
        "apiVersion": "v1",
        "id": module.params['name'],
        "kind": "Namespace",
        "metadata": {
            "name": module.params['name'],
            "labels": {
                "kubernetes.io/metadata.name": module.params['name']
            }
        },
        "spec": {
            "finalizers": ["kubernetes"]
        },
        "type": "namespace"
    }

    # Set annotations if defined
    _annotations = {}
    if module.params['annotations'] is not None:
        for k, v in module.params['annotations'].items():
            _annotations[k] = v

    if module.params['limits'] is not None \
            or module.params['requests'] is not None:

        cdrl = {}
        if module.params['limits'] is not None:
            limits = module.params['limits']
            if limits['cpu'] is not None:
                cdrl.update({"limitsCpu": limits['cpu']})
            if limits['memory'] is not None:
                cdrl.update({"limitsMemory": limits['memory']})
            if limits['gpu'] is not None:
                cdrl.update({"limitsGpu": limits['gpu']})
        if module.params['requests'] is not None:
            req = module.params['requests']
            if req['cpu'] is not None:
                cdrl.update({"requestsCpu": req['cpu']})
            if req['memory'] is not None:
                cdrl.update({"requestsMemory": req['memory']})

        _annotations["field.cattle.io/containerDefaultResourceLimit"] =\
            json.dumps(cdrl, separators=(',', ':'))

    if module.params['description'] is not None:
        _annotations["field.cattle.io/description"] = \
            module.params['description']

    body["metadata"]["annotations"] = _annotations

    # Set labels if defined
    if module.params['labels'] is not None:
        for k, v in module.params['labels'].items():
            body["metadata"]["labels"][k] = v

    if module.params['projectid'] is not None:
        body["metadata"]["labels"]["field.cattle.io/projectId"] =\
            module.params['projectid']

    # Fetch cluster id
    cluster_id = clusterid_by_name(module)
    api_path = f"k8s/clusters/{cluster_id}/v1/namespaces"
    config_items = {
        "spec": {}
    }

    return {"body": body, "api_path": api_path, "config_items": config_items}


if __name__ == '__main__':
    main()
