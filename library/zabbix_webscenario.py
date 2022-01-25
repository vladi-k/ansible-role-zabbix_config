#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, Vladimir Vasilev (@vladi-k)
# Copyright: (c) 2022, Angelina Vasileva (@lina-is-here)
# Copyright: (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: zabbix_webscenario
short_description: Create/update/delete Zabbix web scenarios
description:
  - Create, update or delete web scenarios.
author:
  - "Vladimir Vasilev (@vladi-k)"
  - "Angelina Vasileva (@lina-is-here)"
requirements:
  - "python >= 3.6"
  - "zabbix-api >= 0.5.4"
options:
  state:
    description:
      - Create/update or delete web scenarios.
    required: false
    type: str
    default: present
    choices:
      - present
      - absent
  host_name:
    description:
      - Name of the host that the web scenario belongs to.
    required: true
    type: str
  name:
    description:
      - Name of the web scenario.
    required: true
    type: str
    aliases:
      - web_scenario_name
  agent:
    description:
      - User agent string that will be used by the web scenario.
    type: str
    default: "Zabbix"
  authentication:
    description:
      - Authentication method that will be used by the web scenario.
        Possible values are
        "0" - none (default), "1" - Basic, "2" - NTLM, "3" - Kerberos, "4" - Digest.
    type: int
    default: 0
    choices:
      - 0
      - 1
      - 2
      - 3
      - 4
  delay:
    description:
      - Execution interval of the web scenario. Accepts seconds,
        time unit with suffix and user macro.
    type: str
    default: "1m"
  headers:
    description:
      - HTTP headers that will be sent when performing a request.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Name of header.
        type: str
        required: true
      value:
        description:
          - Value of header.
        type: str
        required: true
  http_password:
    description:
      - Password used for basic HTTP or NTLM authentication.
    type: str
  http_proxy:
    description:
      - Proxy that will be used by the web scenario given as
        http://[username[:password]@]proxy.example.com[:port].
    type: str
  http_user:
    description:
      - User name used for basic HTTP or NTLM authentication.
    type: str
  retries:
    description:
      - Number of times a web scenario will try to execute each step before failing.
    type: int
    default: 1
  ssl_cert_file:
    description:
      - Name of the SSL certificate file used for client authentication
        (must be in PEM format).
    type: str
  ssl_key_file:
    description:
      - Name of the SSL private key file used for client authentication
        (must be in PEM format).
    type: str
  ssl_key_password:
    description:
      - SSL private key password.
    type: str
  status:
    description:
      - Whether the web scenario is enabled.
        Possible values are "0 - enabled (default), "1" - disabled.
    type: int
    default: 0
  variables:
    description:
      - Web scenario variables.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Name of variable.
        type: str
        required: true
      value:
        description:
          - Value of variable.
        type: str
        required: true
  verify_host:
    description:
      - Whether to verify that the host name specified in the SSL certificate matches
        the one used in the scenario.
        Possible values are "0" - skip host verification (default), "1" - verify host.
    type: int
    default: 0
    choices:
      - 0
      - 1
  verify_peer:
    description:
      - Whether to verify the SSL certificate of the web server.
        Possible values are "0" - skip peer verification (default), "1" - verify peer.
    type: int
    default: 0
    choices:
      - 0
      - 1
  steps:
    description:
      - Defines a specific web scenario check. Required if I(state=present).
    type: list
    required: true
    elements: dict
    suboptions:
      name:
        description:
          - Name of the scenario step.
        type: str
        required: true
      number:
        description:
          - Sequence number of the step in a web scenario.
        type: int
        required: true
      url:
        description:
          - URL to be checked.
        type: str
        required: true
      follow_redirects:
        description:
          - Whether to follow HTTP redirects. Possible values are
            "0" - don't follow redirects, "1" - follow redirects (default).
        type: int
        default: 1
        choices:
          - 0
          - 1
      headers:
        description:
          - HTTP headers that will be sent when performing a request.
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of header.
            type: str
            required: true
          value:
            description:
              - Value of header.
            type: str
            required: true
      posts:
        description:
          - HTTP POST variables as a string (raw post data).
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of POST field.
            type: str
            required: true
          value:
            description:
              - Value of POST field.
            type: str
            required: true
      required:
        description:
          - Text that must be present in the response.
        type: str
      retrieve_mode:
        description:
          - Part of the HTTP response that the scenario step must retrieve.
            Possible values are "0" - only body (default), "1" - only headers,
            "2" - headers and body.
        type: int
        default: 0
        choices:
          - 0
          - 1
          - 2
      status_codes:
        description:
          - Ranges of required HTTP status codes separated by commas.
        type: str
      variables:
        description:
          - Scenario step variables.
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of variable.
            type: str
            required: true
          value:
            description:
              - Value of variable.
            type: str
            required: true
      query_fields:
        description:
          - Query fields.
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Name of query field.
            type: str
            required: true
          value:
            description:
              - Value of query field.
            type: str
            required: true
  tags:
    description:
      - Web scenario tags.
    type: list
    elements: dict
    suboptions:
      tag:
        description:
          - Web scenario tag name.
        type: str
        required: true
      value:
        description:
          - Web scenario tag value.
        type: str

extends_documentation_fragment:
- community.zabbix.zabbix

"""

EXAMPLES = r"""
# Create basic web scenario for HTTP respond code 200
- name: Create basic web scenario
  local_action:
    module: community.zabbix.zabbix_webscenario
    server_url: http://monitor.example.com
    login_user: username
    login_password: password
    host_name: my.server.com
    name: Site Availability
    steps:
      - name: Site is OK
        number: 1
        status_codes: 200
"""

RETURN = r"""
httptestids:
    description: Web scenario IDs.
    type: list
    elements: str
    returned: always
    sample: [
            "24",
        ]
"""

import traceback  # noqa: E402

try:
    from zabbix_api import Already_Exists  # noqa: F401

    HAS_ZABBIX_API = True
except ImportError:
    ZBX_IMP_ERR = traceback.format_exc()
    HAS_ZABBIX_API = False

from ansible.module_utils.basic import AnsibleModule, missing_required_lib  # noqa: E402

from ansible_collections.community.zabbix.plugins.module_utils.base import (  # noqa: E402
    ZabbixBase,
)
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils  # noqa: E402,E501


class WebScenario(ZabbixBase):
    # create or update web scenario
    def create_or_update_web_scenario(self, hostid, **kwargs):
        web_scenario_name = kwargs["name"]
        try:
            all_scenarios = self._zapi.httptest.get({"filter": {"hostids": hostid}})
            exists = any(
                web_scenario_name in sublist["name"] for sublist in all_scenarios
            )
            try:
                if self._module.check_mode:
                    self._module.exit_json(changed=True)
                if exists:
                    # web scenario exist, will update it
                    web_scenario_id = self._get_httptestid_by_name(
                        hostid, web_scenario_name
                    )
                    if not web_scenario_id:
                        self._module.fail_json(
                            msg="Failed to get web scenario id for '%s'"
                            % web_scenario_name
                        )
                    kwargs["httptestid"] = web_scenario_id
                    result = self._zapi.httptest.update(kwargs)
                else:
                    # web scenario does not exist, will create it
                    kwargs["hostid"] = hostid
                    result = self._zapi.httptest.create(kwargs)
            except Exception as e:
                self._module.fail_json(
                    msg="Failed to process web scenario '%s': %s"
                    % (web_scenario_name, e)
                )
        except Exception as e:
            self._module.fail_json(msg=e)

        return result

    # delete web scenario
    def delete_web_scenario(self, hostid, **kwargs):
        web_scenario_name = kwargs["name"]
        web_scenario_id = self._get_httptestid_by_name(hostid, web_scenario_name)
        if not web_scenario_id:
            return
            # self._module.exit_json(changed=False)
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            result = self._zapi.httptest.delete([web_scenario_id])
        except Exception as e:
            self._module.fail_json(
                msg="Failed to delete web scenario '%s': %s" % (web_scenario_name, e)
            )

        return result

    # get host id by name
    def get_hostid_by_name(self, host_name):
        hostid = self._zapi.host.get({"filter": {"host": [host_name]}})
        if not hostid:
            self._module.fail_json(msg="Host not found: %s" % host_name)
        else:
            return hostid[0]["hostid"]

    # get httptest id by name
    def _get_httptestid_by_name(self, hostid, web_scenario_name):
        # httptestid = ""
        all_scenarios = self._zapi.httptest.get({"filter": {"hostids": hostid}})
        for ws in all_scenarios:
            if ws["name"] == web_scenario_name:
                httptestid = ws["httptestid"]
                break
        else:
            return

        return httptestid


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(
        dict(
            host_name=dict(type="str", required=True),
            name=dict(type="str", aliases=["web_scenario_name"], required=True),
            state=dict(type="str", default="present", choices=["present", "absent"]),
            agent=dict(type="str", default="Zabbix"),
            authentication=dict(type="int", default=0, choices=[0, 1, 2, 3, 4]),
            delay=dict(type="str", default="1m"),
            headers=dict(
                type="list",
                elements="dict",
                options=dict(
                    name=dict(type="str", required=True),
                    value=dict(type="str", required=True),
                ),
                default=[],
            ),
            http_password=dict(type="str", default="", no_log=True),
            http_proxy=dict(type="str", default=""),
            http_user=dict(type="str", default=""),
            retries=dict(type="int", default=1),
            ssl_cert_file=dict(type="str", default=""),
            ssl_key_file=dict(type="str", default=""),
            ssl_key_password=dict(type="str", default="", no_log=True),
            status=dict(type="int", default=0, choices=[0, 1]),
            variables=dict(
                type="list",
                elements="dict",
                options=dict(
                    name=dict(type="str", required=True),
                    value=dict(type="str", required=True),
                ),
                default=[],
            ),
            verify_host=dict(type="int", default=0, choices=[0, 1]),
            verify_peer=dict(type="int", default=0, choices=[0, 1]),
            steps=dict(
                type="list",
                elements="dict",
                options=dict(
                    name=dict(type="str", required=True),
                    number=dict(type="int", required=True),
                    url=dict(type="str", required=True),
                    follow_redirects=dict(type="int", default=1),
                    headers=dict(
                        type="list",
                        elements="dict",
                        options=dict(
                            name=dict(type="str", required=True),
                            value=dict(type="str", required=True),
                        ),
                        default=[],
                    ),
                    posts=dict(
                        type="list",
                        elements="dict",
                        options=dict(
                            name=dict(type="str", required=True),
                            value=dict(type="str", required=True),
                        ),
                        default=[],
                    ),
                    required=dict(type="str", default=""),
                    retrieve_mode=dict(type="int", default=0),
                    status_codes=dict(type="str", default=""),
                    timeout=dict(type="str", default="15s"),
                    variables=dict(
                        type="list",
                        elements="dict",
                        options=dict(
                            name=dict(type="str", required=True),
                            value=dict(type="str", required=True),
                        ),
                        default=[],
                    ),
                    query_fields=dict(
                        type="list",
                        elements="dict",
                        options=dict(
                            name=dict(type="str", required=True),
                            value=dict(type="str", required=True),
                        ),
                        default=[],
                    ),
                ),
                default=[],
            ),
            tags=dict(
                type="list",
                elements="dict",
                options=dict(
                    tag=dict(type="str", required=True),
                    value=dict(type="str", default=""),
                ),
                default=[],
            ),
        )
    ),
    required_if = [
        ["state", "present", ["steps"]],
    ]
    module = AnsibleModule(
        argument_spec=argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_ZABBIX_API:
        module.fail_json(
            msg=missing_required_lib(
                "zabbix-api", url="https://pypi.org/project/zabbix-api/"
            ),
            exception=ZBX_IMP_ERR,
        )

    web_scenario_params = module.params.copy()
    web_scenario_params.pop("server_url")
    web_scenario_params.pop("login_user")
    web_scenario_params.pop("login_password")
    web_scenario_params.pop("http_login_password")
    web_scenario_params.pop("http_login_user")
    web_scenario_params.pop("validate_certs")
    web_scenario_params.pop("host_name")
    web_scenario_params.pop("state")
    web_scenario_params.pop("timeout")

    host_name = module.params["host_name"]
    state = module.params["state"]

    # converting "number" to "no" for scenario steps
    if module.params["steps"]:
        for i, step in enumerate(module.params["steps"]):
            web_scenario_params["steps"][i]["no"] = step["number"]
            web_scenario_params["steps"][i].pop("number")

    webScenario = WebScenario(module)

    hostid = webScenario.get_hostid_by_name(host_name)

    if state == "absent":
        # delete web scenario
        web_scenario_del = webScenario.delete_web_scenario(
            hostid, **web_scenario_params
        )
        if web_scenario_del:
            module.exit_json(changed=True, result=web_scenario_del)
        else:
            module.exit_json(changed=False)
    else:
        # create or update web scenario
        web_scenario_add = webScenario.create_or_update_web_scenario(
            hostid, **web_scenario_params
        )
        if web_scenario_add:
            module.exit_json(changed=True, result=web_scenario_add)
        else:
            module.exit_json(changed=False)


if __name__ == "__main__":
    main()
