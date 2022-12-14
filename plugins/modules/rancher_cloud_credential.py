#!/usr/bin/python

# Copyright: (c) 2022, Wouter Moeken <wouter.moeken@rws.nl>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: rancher_cloud_credential

short_description: Manage Rancher Cloud Credentials

version_added: "0.0.2"

description:
    - This module allows you to manage the lifecycle of Cluster Repositories.

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

    credential:
        description: Cloud Credential to create in Rancher
        required: true
        type: dict
        default: []
        suboptions:
            name:
                description: Name of the credential
                required: true
                type: str

            type:
                description: Type of credential
                required: true
                default: vsphere
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

            host:
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

            port:
                description:
                    - vSphere Port number for vCenter
                default: 443
                type: str

            region:
                description:
                    - S3 / AWS EC2 Region
                required: false
                default: ""
                type: str

            accesskey:
                description:
                    - S3 / AWS EC2 Access Key
                    - Required when type=ec2 or s3
                type: str

            secretkey:
                description:
                    - S3 / AWS EC2 Secret Key
                    - Required when type=ec2 or s3
                type: str

            bucket:
                description:
                    - S3 bucket
                    - Required when type=s3
                type: str

            endpoint:
                description:
                    - S3 endpoint
                type: str

            endpointca:
                description:
                    - S3 endpointca
                type: str

            folder:
                description:
                    - S3 folder
                type: str

            skipsslverify:
                description:
                    - S3 skipsslverify
                type: str

            accesstoken:
                description:
                    - Digital Ocean / Linode API access token
                    - Required when type=digitalocean or type=linode
                type: str

            authencodedjson:
                description:
                    - File contents for authEncodedJson
                    - Required when type=google
                type: str

            clusterid:
                description:
                    - harvester cluster id
                    - Required when type=harvester
                type: str

            clustertype:
                description:
                    - harvester cluster type
                    - Required when type=harvester
                type: str

            kubeconfigcontent:
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

extends_documentation_fragment:
    - intellium.rancher.my_doc_fragment_name

author:
    - Wouter Moeken (@intellium)
    - Cees Moerkerken (@ceesios)
'''

EXAMPLES = r'''
# Add repository
- name: Test create cc
  intellium.rancher.rancher_cloud_credential:
    state: present
    host: rancher.example.com
    token: "{{ login_out['token'] }}"
    cred_name: "mycred"
    cred_host: "vcenter.example.com"
    cred_username: "myuser"
    cred_password: "mysecretpass"
    cred_port: 443
    cred_type: "vsphere"
    full_response: true
    validate_certs: false
'''

RETURN = r'''
# These are examples of possible return values,
# and in general should use other names for return values.
full_response:
    description: The full API response of the last request
    type: json
    returned: optional
'''

import json
import base64

from ansible.module_utils.basic import AnsibleModule, sanitize_keys
from ansible.module_utils._text import to_native, to_text

import ansible_collections.intellium.rancher.plugins.module_utils.\
    rancher_globals as g
from ansible_collections.intellium.rancher.plugins.module_utils.rancher_api \
    import api_req, clusterid_by_name, api_login, api_exit


def build_body(module):
    credential = module.params['credential']
    if credential['type'] == "vsphere":
        body = {
            "type": "cloudcredential",
            "name": credential['name'],
            "vmwarevspherecredentialConfig": {
                "vcenter": credential['host'],
                "vcenterPort": credential['port'],
                "username": credential['username'],
                "password": credential['password']
            }
        }
        return body
    elif credential['type'] == "ec2":
        body = {
            "type": "cloudcredential",
            "name": credential['name'],
            "amazonec2credentialconfig": {
                "accesskey": credential['accesskey'],
                "defaultregion": credential['region'],
                "secretkey": credential['secretkey']
            }
        }
        return body
    elif credential['type'] == "azure":
        body = {
            "type": "cloudcredential",
            "name": credential['name'],
            "azurecredentialconfig": {
                "clientid": credential['clientid'],
                "clientsecret": credential['clientsecret'],
                "environment": credential['environment'],
                "subscriptionid": credential['subscriptionid'],
                "tenantid": credential['tenantid']
            }
        }
        return body
    elif credential['type'] == "digitalocean":
        body = {
            "type": "cloudcredential",
            "name": credential['name'],
            "digitaloceancredentialconfig": {
                "accesstoken": credential['accesstoken']
            }
        }
        return body
    elif credential['type'] == "google":
        body = {
            "type": "cloudcredential",
            "name": credential['name'],
            "googlecredentialconfig": {
                "authencodedjson": credential['authencodedjson']
            }
        }
        return body
    elif credential['type'] == "harvester":
        body = {
            "type": "cloudcredential",
            "name": credential['name'],
            "harvestercredentialconfig": {
                "clusterid": credential['clusterid'],
                "clustertype": credential['clustertype'],
                "kubeconfigcontent": credential['kubeconfigcontent']
            }
        }
        return body
    elif credential['type'] == "linode":
        body = {
            "type": "cloudcredential",
            "name": credential['name'],
            "linodecredentialconfig": {
                "token": credential['accesstoken']
            }
        }
        return body
    elif credential['type'] == "s3":
        body = {
            "type": "cloudcredential",
            "name": credential['name'],
            "s3credentialconfig": {
                "accesskey": credential['accesskey'],
                "secretkey": credential['secretkey'],
                "defaultbucket": credential['bucket'],
                "defaultendpoint": credential['endpoint'],
                "defaultendpointca": credential['endpointca'],
                "defaultfolder": credential['folder'],
                "defaultregion": credential['region'],
                "defaultskipsslverify": credential['skipsslverify']
            }
        }
        return body
    else:
        g.mod_returns.update(changed=False, msg=credential['type']
                             + ' credential type not supported')
        api_exit(module, 'fail')


def main():
    argument_spec = {}
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], required=True),
        host=dict(type='str', aliases=['rancher_host'], required=True),
        token=dict(type='str', aliases=['rancher_token'], no_log=True),
        username=dict(type='str', aliases=['rancher_username']),
        password=dict(type='str', aliases=['rancher_password'], no_log=True),
        credential=dict(type='dict'),
        full_response=dict(type='bool'),
        validate_certs=dict(type='bool', default=True)
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        # supports_check_mode=True,
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
    _action = 'POST'
    _url = 'https://%s/v3/cloudcredentials' % (module.params['host'])
    # _body = {
    #         "type": "cloudcredential",
    #         "name":module.params['credential']['name'],
    #         "vmwarevspherecredentialConfig": {
    #             "vcenter":module.params['credential']['host'],
    #             "vcenterPort":module.params['credential']['port'],
    #             "username":module.params['credential']['username'],
    #             "password":module.params['credential']['password']
    #         }
    #     }

    _body = build_body(module)

    # Get current cc if it exists
    ccr, content = api_req(
        module,
        url='https://%s/v3/cloudCredentials/?name=%s' % (
            module.params['host'], module.params['credential']['name']),
        method='GET',
        auth=module.params['token']
    )
    if ccr['status'] in (200, 201) and len(ccr['json']['data']) > 0:
        # CC by this name exists

        # Fetch password
        ccp, content = api_req(
            module,
            url='https://%s/v1/secrets/%s' % (
                module.params['host'],
                ccr['json']['data'][0]['id'].replace(':', '/')),
            method='GET',
            auth=module.params['token']
        )

        # set ccr_data & ccr_pw
        ccr_data = ccr['json']['data'][0]['vmwarevspherecredentialConfig']
        ccr_pw = ccp['json']['data']['vmwarevspherecredentialConfig-password']

        if (
            ccr_data['username'] != module.params['credential']['username'] or
            ccr_data['vcenter'] != module.params['credential']['host'] or
            ccr_data['vcenterPort'] != module.params['credential']['port'] or
            to_text(base64.b64decode(ccr_pw)) != module.params['credential']['password']
        ):
            _action = 'PUT'
            _tmpbody = ccr['json']['data'][0]
            _tmpbody['vmwarevspherecredentialConfig']['username'] = \
                module.params['credential']['username']
            _tmpbody['vmwarevspherecredentialConfig']['vcenter'] = \
                module.params['credential']['host']
            _tmpbody['vmwarevspherecredentialConfig']['vcenterPort'] = \
                module.params['credential']['port']
            _tmpbody['vmwarevspherecredentialConfig']['password'] = \
                module.params['credential']['password']
            _body = _tmpbody
            _url = 'https://%s/v3/cloudCredentials/%s' % (
                module.params['host'], ccr['json']['data'][0]['id'])
        else:
            # CC exists, but nothing changed
            if module.params['state'] == 'present':
                g.mod_returns.update(changed=False)
                api_exit(module)
            elif module.params['state'] == 'absent':
                _action = 'DELETE'
                _url = 'https://%s/v3/cloudCredentials/%s' % (
                    module.params['host'], ccr['json']['data'][0]['id'])

    elif ccr['status'] in (200, 201) and len(ccr['json']['data']) < 1:
        # CC doesn't exist
        if module.params['state'] == 'absent':
            g.mod_returns.update(changed=False)
            api_exit(module)
        elif module.params['state'] == 'present':
            _action = 'POST'
    else:
        # Something went wrong
        g.mod_returns.update(
            changed=False, msg='Something went wrong. Received status code '
                               + ccr['status'] + ' from API')
        api_exit(module, 'fail')

    # Make the request
    resp, content = api_req(
        module,
        url=_url,
        body=json.dumps(_body, sort_keys=True),
        body_format='json',
        method=_action,
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
