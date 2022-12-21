# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Wouter Moeken <wouter.moeken@rws.nl>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: rancher_cloud_credential
short_description: Manage Rancher Cloud Credentials
description:
    - This module allows you to manage the lifecycle of Cluster Repositories.
version_added: "0.0.2"
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
        description: Name of the credential
        required: true
        type: str

    type:
        description: Type of credential
        required: true
        type: str
        choices:
            - 'vsphere'
            - 'ec2'
            - 'azure'
            - 'digitalocean'
            - 'google'
            - 'harvester'
            - 'linode'
            - 's3'

    config:
        description:
            - Cloud Credential to create in Rancher
            - Suboptions must be capitilazed correctly!
        required: true
        type: dict
        suboptions:
            vcenter:
                description:
                    - vSphere IP/hostname for vCenter
                    - Required when type=vsphere
                type: str

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

            vcenterPort:
                description:
                    - vSphere Port number for vCenter
                default: "443"
                type: str

            defaultRegion:
                description:
                    - S3 / AWS EC2 Region
                required: false
                default: ""
                type: str

            accessKey:
                description:
                    - S3 / AWS EC2 Access Key
                    - Required when type=ec2 or s3
                type: str

            secretKey:
                description:
                    - S3 / AWS EC2 Secret Key
                    - Required when type=ec2 or s3
                type: str

            defaultBucket:
                description:
                    - S3 bucket
                    - Required when type=s3
                type: str

            defaultEndpoint:
                description:
                    - S3 endpoint
                type: str

            defaultEndpointCA:
                description:
                    - S3 endpointca
                type: str

            defaultFolder:
                description:
                    - S3 folder
                type: str

            defaultSkipSSLVerify:
                description:
                    - S3 skipsslverify
                type: str

            accessToken:
                description:
                    - Digital Ocean API access token
                    - Required when type=digitalocean
                type: str

            token:
                description:
                    - Linode API access token
                    - Required when type=linode
                type: str

            authEncodedJson:
                description:
                    - File contents for authEncodedJson
                    - Required when type=google
                type: str

            clusterId:
                description:
                    - harvester cluster id
                    - Required when type=harvester
                type: str

            clusterType:
                description:
                    - harvester cluster type
                    - Required when type=harvester
                type: str

            kubeconfigContent:
                description:
                    - contents of kubeconfig file for harvester cluster, base64
                    - Required when type=harvester
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
- name: Test create cc
  intellium.rancher.rancher_cloud_credential:
    host: rancher.example.com
    token: "{{ login_out['token'] }}"
    name: "mycred"
    type: vsphere
    config:
        vcenter: "vcenter.example.com"
        username: "myuser"
        password: "mysecretpass"
        vcenterPort: "443"
    validate_certs: true
    full_response: true
    register: cc

'''

RETURN = r'''
# These are examples of possible return values,
# and in general should use other names for return values.
id:
    description: The ID of the cloud credential
    type: dict
    returned: always
output:
    description: The cloud credential object
    type: dict
    returned: always
full_response:
    description: The full API response of the last request
    type: dict
    returned: optional
'''

import json
import base64

from ansible.module_utils.basic import AnsibleModule, sanitize_keys
from ansible.module_utils._text import to_native, to_text
from ansible.module_utils.common.dict_transformations \
    import recursive_diff, dict_merge

import ansible_collections.intellium.rancher.plugins.module_utils.\
    rancher_globals as g
from ansible_collections.intellium.rancher.plugins.module_utils.rancher_api \
    import api_req, api_login, api_exit


def credential_object(module):
    # credential = module.params['config']
    if module.params['type'] == "vsphere":
        typename = "vmwarevspherecredentialConfig"
    elif module.params['type'] == "ec2":
        typename = "amazonec2credentialConfig"
    elif module.params['type'] == "azure":
        typename = "azurecredentialConfig"
    elif module.params['type'] == "digitalocean":
        typename = "digitaloceancredentialConfig"
    elif module.params['type'] == "google":
        typename = "googlecredentialConfig"
    elif module.params['type'] == "harvester":
        typename = "harvestercredentialConfig"
    elif module.params['type'] == "linode":
        typename = "linodecredentialConfig"
    elif module.params['type'] == "s3":
        typename = "s3credentialConfig"
    else:
        g.mod_returns.update(changed=False,
                             msg=module.params['type']
                             + ' credential type not supported')
        api_exit(module, 'fail')

    body = {
        "name": module.params['name'],
        "type": "cloudcredential"
    }

    configitems = {}
    for item in module.params['config']:
        configitems.update({item: module.params['config'][item]})

    body.update({typename: configitems})

    return {"body": body, "type": typename}


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
        config=dict(type='dict', required=True),
        type=dict(type='str', required=True, choices=[
            'vsphere', 'ec2', 'azure', 'digitalocean', 'google',
            'harvester', 'linode', 's3']),
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
    api_path = "v3/cloudcredentials"
    baseurl = f"https://{module.params['host']}/{api_path}"
    _url = baseurl
    _before = {}
    ccparams = credential_object(module)
    cctype = ccparams['type']
    _after = ccparams['body']

    # Get current cc if it exists
    get, content = api_req(
        module,
        url=f"{baseurl}/?name={module.params['name']}",
        method='GET',
        auth=module.params['token']
    )

    # check if CC by this name exists
    if get['status'] in (200, 201) and len(get['json']['data']) > 0:
        # CC exists
        if module.params['state'] == 'absent':
            g.mod_returns.update(changed=True)
            _action = 'DELETE'
            _url = f"{baseurl}/{get['json']['data'][0]['id']}"
            _before = get['json']['data'][0]
            _after = {}

        else:
            # Check the type
            if cctype in get['json']['data'][0]:
                # Get secret
                sr, content = api_req(
                    module,
                    url='https://%s/v1/secrets/%s' % (
                        module.params['host'],
                        get['json']['data'][0]['id'].replace(':', '/')),
                    method='GET',
                    auth=module.params['token']
                )
                sr_data = sr['json']['data']

                if sr['status'] in (200, 201) and len(sr['json']['data']) > 0:
                    for key in list(sr_data):
                        k_new = key.replace(
                            cctype + '-', '')
                        sr_data[k_new] = to_text(
                            base64.b64decode(sr_data.pop(key)))

                # Merge config found in secret and in cloudconfig and diff
                cclive_config = dict_merge(
                    get['json']['data'][0][cctype],
                    sr_data)

                _before = {
                    "name": get['json']['data'][0]['name'],
                    "type": "cloudcredential",
                    cctype: cclive_config
                }
            else:
                # Something went wrong
                g.mod_returns.update(
                    changed=False, msg='Changing secret type is not supported')
                api_exit(module, 'fail')

            diff_result = recursive_diff(_before, _after)

            if diff_result is not None:
                g.mod_returns.update(changed=True)
                _action = 'PUT'
                _url = f"{baseurl}/{get['json']['data'][0]['id']}"

    elif get['status'] in (200, 201) and len(get['json']['data']) < 1:
        # CC doesn't exist
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


if __name__ == '__main__':
    main()
