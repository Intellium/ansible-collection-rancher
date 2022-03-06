#!/usr/bin/python

# Copyright: (c) 2022, Wouter Moeken <wouter.moeken@rws.nl>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import datetime
import json
import os

# Globals
import ansible_collections.intellium.rancher.plugins.module_utils.rancher_globals as g

from ansible.module_utils.basic import AnsibleModule, sanitize_keys
from ansible.module_utils.six import PY2, PY3, binary_type, iteritems, string_types
from ansible.module_utils._text import to_native, to_text
from ansible.module_utils.urls import fetch_url, url_argument_spec

def api_req(module, url='', body='', body_format='json', method='GET', headers={}, auth=''):
    kwargs = {}

    if headers == {}:
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
    }
    
    # Construct Authentication
    if auth != None:
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

    # Transmogrify the headers, replacing '-' with '_', since variables don't
    # work with dashes.
    # In python3, the headers are title cased.  Lowercase them to be
    # compatible with the python2 behaviour.
    for key, value in iteritems(r):
        ukey = key.replace("-", "_").lower()
        r[ukey] = value

    if 'location' in r:
        r['location'] = absolute_location(url, r['location'])

    u_content = to_text(content, encoding='utf-8') if len(content) > 1 else '{}'
    js = json.loads(u_content)
    r['json'] = js if len(js) > 0 else '{}'

    r['redirected'] = redirected or info['url'] != url
    r['elapsed_ms'] = elapsed_ms
    r.update(redir_info)
    r.update(info)
    r['status'] = int(r['status'])

    # Set last_response
    g.last_response = r

    # Return result
    return r, content

def clusterid_by_name(module):
  # Fetch cluster info
    cresp, content = api_req(
        module,
        url ='https://%s/v3/clusters?name=%s' % (module.params['host'], module.params['cluster_name']),
        method='GET',
        auth=module.params['token']
    )
    g.last_reponse = cresp

    # Ensure the API responds correctly
    if cresp['status'] not in (200,201):
        g.mod_returns.update(msg='Failed getting cluster ID by name')
        api_exit(module,'fail')

    # Test to ensure we get exactly one result from our filtered cluster lookup
    if len(cresp['json']['data']) != 1:
        g.mod_returns.update(msg='Error: Expected a single cluster result, but got ' + to_text(len(g.last_response['json']['data'])))
        api_exit(module,'fail')

    if cresp['json']['data'][0]['id'] != None:
        cluster_id = cresp['json']['data'][0]['id']
    else:
        g.mod_returns.update(msg='Failed obtaining cluster id from query response')
        api_exit(module,'fail')

    return cluster_id

def api_login(module):
    # Set authentication URL and options
    url = 'https://%s/v3-public/localProviders/local?action=login' % (module.params['host'])
    body_format = 'json'  # We pass json
    body = '{"username":"%s","password":"%s"}' % (module.params['username'], module.params['password'])
    method = 'POST'

    # Make the request
    resp, content = api_req(module, url, body, body_format, method)

    # Ensure the API responds correctly
    if resp['status'] not in (200,201):
        if resp['status'] == 401:
            g.mod_returns.update(msg='Authentication error. Check username / password')
            api_exit(module,'fail')
        else:
            g.mod_returns.update(msg='Failed login due to API error')
            api_exit(module,'fail')

    if resp['json']['token']:
        token = resp['json']['token']
    else:
        g.mod_returns.update(msg='Failed getting token from API response')
        api_exit(module,'fail')

    return token

def api_exit(module, type='normal'):
    if module.params['full_response']:
        g.mod_returns.update(full_response=g.last_response['json'])

    if type == 'fail':
        module.fail_json(**g.mod_returns)
    else:
        module.exit_json(**g.mod_returns)

