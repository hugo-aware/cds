---
title: "Global roles"
weight: 1
---

These roles allow users/groups to manage global CDS configuration:

* `manage-permission`: Allow users/groups to create/update/delete an permission
* `manage-organization`: Allow users/groups to create/delete an organization
* `manage-region`: Allow users/groups to create/delete a region
* `manage-hatchery`: Allow users/groups to create/update/delete a hatchery
* `create-project`: Allow users/groups to create/delete a project

Yaml example:
```yaml
name: my-permission-name
global:
  - role: manage-permission
    users: [foo,bar]
    groups: [grpFoo]
```

List of fields:

* `role`: <b>[mandatory]</b> role to applied
* `users`: list of usernames
* `groups`: list of groups
