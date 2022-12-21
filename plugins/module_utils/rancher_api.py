# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Wouter Moeken <wouter.moeken@rws.nl>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import datetime
import json
import os

# Globals
import ansible_collections.intellium.rancher.plugins.module_utils.\
    rancher_globals as g

from ansible.module_utils.basic import AnsibleModule, sanitize_keys
from ansible.module_utils.six import PY2, PY3, binary_type, iteritems
from ansible.module_utils._text import to_native, to_text
from ansible.module_utils.urls import fetch_url, url_argument_spec


def api_req(module, url='', body='', body_format='json', method='GET',
            headers=None, auth=''):
    kwargs = {}

    if headers is None:
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    # Construct Authentication
    if auth is not None:
        headers.update(
            Authorization='Bearer ' + auth
        )

    start = datetime.datetime.utcnow()

    # Execute request
    resp, info = fetch_url(module, url, data=body, headers=headers,
                           method=method, force=True, **kwargs)

    # Calculate elapsed time for API request
    end = datetime.datetime.utcnow()
    delta = end - start
    elapsed_ms = int(delta.total_seconds() * 1000)

    # Fetch content from request
    try:
        content = resp.read()
    except AttributeError:
        content = info.pop('body', '')

    # Construct output
    redirected = False
    redir_info = {}
    r = {}

    # Debug request
    r['req'] = dict(
        headers=headers,
        body=body,
        url=url,
        method=method
    )

    # Transmogrify the headers, replacing '-' with '_', since variables
    # don't work with dashes.
    # In python3, the headers are title cased.  Lowercase them to be
    # compatible with the python2 behaviour.
    for key, value in iteritems(r):
        ukey = key.replace("-", "_").lower()
        r[ukey] = value

    # "absolute_location" is not defined
    # if 'location' in r:
    #     r['location'] = absolute_location(url, r['location'])

    u_content = to_text(
        content, encoding='utf-8') if len(content) > 1 else '{}'
    js = json.loads(u_content)
    r['json'] = js if len(js) > 0 else '{}'

    r['redirected'] = redirected or info['url'] != url
    r['elapsed_ms'] = elapsed_ms
    r.update(redir_info)
    r.update(info)
    r['status'] = int(r['status'])

    # Set last_response
    g.last_response = r

    r['check'] = check_req(r, module)

    # Return result
    return r, content


def check_req(r, module):
    retval = False
    # Check status code
    if r['status'] in (200, 201, 202, 204):
        try:
            g.mod_returns.update(output=r['json'])
        except BaseException:
            g.mod_returns.update(output={})
        try:
            g.mod_returns.update(id=r['json']['id'])
        except BaseException:
            g.mod_returns.update(id="")
        retval = True
    elif r['status'] == 401:
        g.mod_returns.update(
            msg='Authentication error. Check username / password')
    elif r['status'] == 403:
        g.mod_returns.update(
            msg='The authenticated user is not allowed amcess to the \
                requested resource. Check username / password ')
    elif r['status'] == 404:
        g.mod_returns.update(
            msg='The requested resource is not found')
    elif r['status'] == 409:
        g.mod_returns.update(
            msg='Trying to create object that exists. \
                ' + to_text(r['msg']) + '\
                ' + to_text(r['body']))
    elif r['status'] == -1 and r['msg'].find("CERTIFICATE_VERIFY_FAILED"):
        g.mod_returns.update(msg='SSL Certificate verify failed')
    else:
        g.mod_returns.update(msg='Unexpected response: ' + to_text(r))

    return retval


def clusterid_by_name(module):
    # Fetch cluster info
    cresp, content = api_req(
        module,
        url='https://%s/v3/clusters?name=%s' % (
            module.params['host'], module.params['cluster_name']),
        method='GET',
        auth=module.params['token']
    )
    g.last_reponse = cresp

    # Ensure the API responds correctly
    if cresp['status'] not in (200, 202, 204):

        if cresp['status'] == -1:
            g.mod_returns.update(
                msg=to_text(g.last_response['msg']))
            api_exit(module, 'fail')
        if cresp['status'] == 401:
            g.mod_returns.update(
                msg='Authentication failed. Check username / password ')
            api_exit(module, 'fail')
        elif cresp['status'] == 403:
            g.mod_returns.update(
                msg='The authenticated user is not allowed access to the \
                    requested resource. Check username / password ')
            api_exit(module, 'fail')
        elif cresp['status'] == 404:
            g.mod_returns.update(
                msg='The requested resource is not found')
            api_exit(module, 'fail')
        elif cresp['status'] == 409:
            g.mod_returns.update(
                msg='Trying to create object that exists.')
            api_exit(module, 'fail')
        else:
            g.mod_returns.update(
                msg='Unexpected response. Use full_response=true to debug.')
            api_exit(module, 'fail')

    # Test to ensure we get exactly one result from our filtered
    # cluster lookup
    if len(cresp['json']['data']) != 1:
        g.mod_returns.update(
            msg='Error: Expected a single cluster result, but got: '
            + to_text(len(g.last_response['json']['data'])))
        api_exit(module, 'fail')

    if cresp['json']['data'][0]['id'] is not None:
        cluster_id = cresp['json']['data'][0]['id']
    else:
        g.mod_returns.update(
            msg='Failed obtaining cluster id from query response')
        api_exit(module, 'fail')

    return cluster_id


def api_login(module):
    # Set authentication URL and options
    url = 'https://%s/v3-public/localProviders/local?action=login' % (
        module.params['host'])
    body_format = 'json'  # We pass json
    body = '{"username":"%s","password":"%s"}' % (
        module.params['username'], module.params['password'])
    method = 'POST'

    # Make the request
    resp, content = api_req(module, url, body, body_format, method)

    # Set Last response
    g.last_reponse = resp

    # Ensure the API responds correctly
    if resp['check']:
        if resp['json']['token']:
            token = resp['json']['token']
        else:
            g.mod_returns.update(
                msg='Failed getting token from API response. \
                    Use full_response=true to debug.')
            api_exit(module, 'fail')
    else:
        g.mod_returns.update(
            msg='Failed login due to API error. '
                + to_text(resp))
        api_exit(module, 'fail')

    return token


def api_exit(module, type='normal'):
    if module.params['full_response']:
        g.mod_returns.update(full_response=g.last_response)

    if type == 'fail':
        module.fail_json(**g.mod_returns)
    else:
        module.exit_json(**g.mod_returns)
