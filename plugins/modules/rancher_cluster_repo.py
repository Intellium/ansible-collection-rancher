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

    repo_name:
        description: Name of repository to operate on
        required: true
        type: str

    repo_url:
        description: URL of the http type repository
        required: false
        type: str

    git_url:
        description: URL of the git type repository
        required: false
        type: str

    git_branch:
        description: Git branch
        default: "master"
        type: str

    git_secret:
        description:
            - Secret name to access repository
            - can be an ssh keypair or user/password secret
        required: false
        type: str

    git_secret_namespace:
        description: Namespace containing the secret
        default: "cattle-system"
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
    token: "{{ login['token'] }}"
    cluster_name: downstream_cluster
    repo_name: "test-repo"
    repo_url: "https://test-repo.example.com"
    full_response: true
    validate_certs: false
'''

RETURN = r'''
id:
    description: The ID of the cluster
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
        repo_name=dict(type='str', required=True),
        repo_url=dict(type='str'),
        git_url=dict(type='str'),
        git_branch=dict(type='str', default="master"),
        git_secret=dict(type='str', no_log=False),
        git_secret_namespace=dict(
            type='str',
            default='cattle-system',
            no_log=False),
        full_response=dict(type='bool'),
        validate_certs=dict(type='bool', default=True)
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ('token', 'username'),
            ('token', 'password'),
            ('repo_url', 'git_url')
        ],
        required_together=[
            ('username', 'password')
        ],
        required_one_of=[
            ('token', 'username', 'password'),
            ('repo_url', 'git_url'),
        ]
    )

    # Do we have a token? If not, go and fetch it
    if not module.params['token']:
        module.params['token'] = api_login(module)

    # Set defaults
    after_config = build_config(module)
    api_path = after_config['api_path']
    baseurl = f"https://{module.params['host']}/{api_path}"

    do = v1_diff_object(module, url=baseurl, id=module.params['repo_name'],
                        config=after_config)

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
        "apiVersion": "catalog.cattle.io/v1",
        "id": module.params['repo_name'],
        "kind": "ClusterRepo",
        "metadata": {
            "name": module.params['repo_name']
        },
        "type": "catalog.cattle.io.clusterrepo"
    }
    if module.params['git_url'] is not None:
        body["spec"] = {
            "gitBranch": module.params['git_branch'],
            "gitRepo": module.params['git_url'],
            "url": ""
        }
        if module.params['git_secret'] is not None:
            body["spec"]["clientSecret"] = {
                "name": module.params['git_secret'],
                "namespace": module.params['git_secret_namespace']
            }
    else:
        body["spec"] = {
            "url": module.params['repo_url']
        }

    # Fetch cluster id
    cluster_id = clusterid_by_name(module)
    api_path = f"k8s/clusters/{cluster_id}/v1/catalog.cattle.io.clusterrepos"
    config_items = {"spec": {}}

    return {"body": body, "api_path": api_path, "config_items": config_items}


if __name__ == '__main__':
    main()
