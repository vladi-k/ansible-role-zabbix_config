ansible-role-zabbix_config
====

Manage Zabbix.

Requirements
------------

* Zabbix 5.4+

Based on modules from [community.zabbix](https://github.com/ansible-collections/community.zabbix) collection. Check their github repo for connection details and more info.

Role Variables
--------------

* `zabbix_config_login_user` - login user
* `zabbix_config_login_password` - login password
* `zabbix_config_templates` - list of templates
* `zabbix_config_host_groups` - list of host groups to create, example:

```yaml
zabbix_config_host_groups:
  - Web Servers
```

* `zabbix_config_hosts` - list of hosts to manage, example:

```yaml
zabbix_config_hosts:
  - host_name: www.example.com
    host_groups:
      - Web Servers
```

* `zabbix_config_actions` - list of actions
* `zabbix_config_web_scenarios` - list of web scenarios, example:

```yaml
zabbix_config_web_scenarios:
  - host_name: server.example.com
    name: Site Availability
    delay: 10m
    retries: 3
    steps:
     - name: "Main page"
       number: 1
       url: "https://server.example.com/"
       status_codes: 200
       required: "It's alive"
```

* `zabbix_config_media_types` - list of media types
* `zabbix_config_usergroups` - list of user groups
* `zabbix_config_user_roles` - list of user roles
* `zabbix_config_users` - list of users

Dependencies
------------

Collections:

* `community.zabbix` 2.1.0+

Example Playbook
----------------

```
- hosts: my_servers
  vars:
    zabbix_config_host_groups:
      - Web Servers
    zabbix_config_hosts:
      - host_name: www.example.com
        host_groups:
          - Web Servers
  roles:
    - ansible-role-zabbix_config
```

License
-------

GPLv3

Author Information
------------------

Vladimir Vasilev (@vladi-k)
