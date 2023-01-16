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

    labels:
        description: labels
        required: False
        type: dict

    annotations:
        description: annotations
        required: False
        type: dict

    vsphereconfig:
        description: vsphere Cloud Credential to create in Rancher
        required: false
        type: dict
        suboptions:
            password:
                description:
                    - vSphere Password
                    - Required when type=vsphere
                type: str
            username:
                description:
                    - vSphere username
                    - Required when type=vsphere
                type: str
            vcenter:
                description:
                    - vSphere IP/hostname for vCenter
                    - Required when type=vsphere
                type: str
            vcenterPort:
                description:
                    - vSphere Port number for vCenter
                default: "443"
                type: str

    amazonec2config:
        description: amazon ec2 Cloud Credential to create in Rancher
        required: false
        type: dict
        suboptions:
            defaultRegion:
                description:
                    - AWS EC2 Region
                required: false
                default: ""
                type: str

            accessKey:
                description:
                    - AWS EC2 Access Key
                    - Required when type=ec2 or s3
                type: str

            secretKey:
                description:
                    - AWS EC2 Secret Key
                    - Required when type=ec2 or s3
                type: str

    azureconfig:
        description: azure Cloud Credential to create in Rancher
        required: false
        type: dict
        suboptions:
            clientId:
                description: clientId
                type: str
            clientSecret:
                description: clientSecret
                type: str
            environment:
                description: environment
                type: str
            subscriptionId:
                description: subscriptionId
                type: str
            tenantId:
                description: tenantId
                type: str

    digitaloceanconfig:
        description: Digital Ocean Cloud Credential to create in Rancher
        required: false
        type: dict
        suboptions:
            accessToken:
                description:
                    - Digital Ocean API access token
                    - Required when type=digitalocean
                type: str

    googleconfig:
        description: google Cloud Credential to create in Rancher
        required: false
        type: dict
        suboptions:
            authEncodedJson:
                description:
                    - File contents for authEncodedJson
                    - Required when type=google
                type: str

    harvesterconfig:
        description: harvester Cloud Credential to create in Rancher
        required: false
        type: dict
        suboptions:
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

    linodeconfig:
        description: linode Cloud Credential to create in Rancher
        required: false
        type: dict
        suboptions:
            token:
                description:
                    - Linode API access token
                    - Required when type=linode
                type: str

    s3config:
        description: s3 Cloud Credential to create in Rancher
        required: false
        type: dict
        suboptions:
            defaultRegion:
                description:
                    - S3 EC2 Region
                required: false
                default: ""
                type: str
            accessKey:
                description:
                    - S3 EC2 Access Key
                    - Required when type=ec2 or s3
                type: str
            secretKey:
                description:
                    - S3 EC2 Secret Key
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
    token: "{{ login['token'] }}"
    name: "mycred"
    type: vsphere
    vsphereconfig:
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
idcol:
    description: The ID of the cloud credential separated by colon
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

from ansible.module_utils.basic import AnsibleModule

import ansible_collections.intellium.rancher.plugins.module_utils.\
    rancher_globals as g
from ansible_collections.intellium.rancher.plugins.module_utils.rancher_api \
    import api_req, api_login, api_exit, v3_diff_object


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
        type=dict(type='str', required=True, choices=[
            'vsphere', 'ec2', 'azure', 'digitalocean', 'google',
            'harvester', 'linode', 's3']),
        labels=dict(type='dict', required=False),
        annotations=dict(type='dict', required=False),
        vsphereconfig=dict(
            type='dict',
            required=False,
            options=dict(
                password=dict(type='str', no_log=True),
                username=dict(type='str'),
                vcenter=dict(type='str'),
                vcenterPort=dict(type='str', default="443"),
            )
        ),
        amazonec2config=dict(
            type='dict',
            required=False,
            options=dict(
                defaultRegion=dict(type='str'),
                accessKey=dict(type='str', no_log=True),
                secretKey=dict(type='str', no_log=True),
            )
        ),
        azureconfig=dict(
            type='dict',
            required=False,
            options=dict(
                clientId=dict(type='str'),
                clientSecret=dict(type='str', no_log=True),
                environment=dict(type='str'),
                subscriptionId=dict(type='str'),
                tenantId=dict(type='str'),
            )
        ),
        digitaloceanconfig=dict(
            type='dict',
            required=False,
            options=dict(
                accessToken=dict(type='str', no_log=True)
            )
        ),
        googleconfig=dict(
            type='dict',
            required=False,
            options=dict(
                authEncodedJson=dict(type='str', no_log=True)
            )
        ),
        harvesterconfig=dict(
            type='dict',
            required=False,
            options=dict(
                clusterId=dict(type='str'),
                clusterType=dict(type='str'),
                kubeconfigContent=dict(type='str', no_log=True),
            )
        ),
        linodeconfig=dict(
            type='dict',
            required=False,
            options=dict(
                token=dict(type='str', no_log=True)
            )
        ),
        s3config=dict(
            type='dict',
            required=False,
            options=dict(
                defaultRegion=dict(type='str'),
                accessKey=dict(type='str', no_log=True),
                secretKey=dict(type='str', no_log=True),
                defaultBucket=dict(type='str'),
                defaultEndpoint=dict(type='str'),
                defaultEndpointCA=dict(type='str'),
                defaultFolder=dict(type='str'),
                defaultSkipSSLVerify=dict(type='str'),
            )
        ),
        full_response=dict(type='bool'),
        validate_certs=dict(type='bool', default=True)
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ("type", "vsphere", ["vsphereconfig"]),
            ("type", "ec2", ["amazonec2config"]),
            ("type", "azure", ["azureconfig"]),
            ("type", "digitalocean", ["vsphereconfig"]),
            ("type", "google", ["googleconfig"]),
            ("type", "harvester", ["harvesterconfig"]),
            ("type", "linode", ["linodeconfig"]),
            ("type", "s3", ["s3config"])
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
    api_path = after_config['api_path']
    baseurl = f"https://{module.params['host']}/{api_path}"

    do = v3_diff_object(module, url=baseurl, config=after_config,
                        secrets=["password"])

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
    api_path = "v3/cloudcredentials"
    body = {
        "name": module.params['name'],
        "baseType": "cloudCredential",
        "type": "cloudCredential",
    }

    if module.params['type'] == "vsphere":
        _type = "vmwarevspherecredentialConfig"
        body[_type] = {}
        config = module.params['vsphereconfig']

    elif module.params['type'] == "amazonec2":
        _type = "ramazonec2credentialConfig"
        body[_type] = {}
        config = module.params['amazonec2config']

    elif module.params['type'] == "azure":
        _type = "azurecredentialConfig"
        body[_type] = {}
        config = module.params['azureconfig']

    elif module.params['type'] == "digitalocean":
        _type = "digitaloceancredentialConfig"
        body[_type] = {}
        config = module.params['digitaloceanconfig']

    elif module.params['type'] == "google":
        _type = "googlecredentialConfig"
        body[_type] = {}
        config = module.params['googleconfig']

    elif module.params['type'] == "harvester":
        _type = "harvestercredentialConfig"
        body[_type] = {}
        config = module.params['harvesterconfig']

    elif module.params['type'] == "linode":
        _type = "linodecredentialConfig"
        body[_type] = {}
        config = module.params['linodeconfig']

    elif module.params['type'] == "s3":
        _type = "s3credentialConfig"
        body[_type] = {}
        config = module.params['s3config']

    else:
        g.mod_returns.update(changed=False,
                             msg=module.params['type']
                             + ' type not supported')
        api_exit(module, 'fail')

    # Create config
    for item in config:
        body[_type].update({item: config[item]})

    config_items = {}
    config_items = config

    # Set annotations if defined
    if module.params['annotations'] is not None:
        for k, v in module.params['annotations'].items():
            body["annotations"][k] = v

    # Set labels if defined
    if module.params['labels'] is not None:
        for k, v in module.params['labels'].items():
            body["common"]["labels"][k] = v

    return {"body": body, "api_path": api_path, "config_items": config_items,
            "config_type": _type}


if __name__ == '__main__':
    main()
