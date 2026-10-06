# wyga/policy-validate

Checks the format of a host policy before any role acts on it. Every task
is an assertion with a message that names the old form and the new one;
nothing touches the host. When a policy format changes, its case is added
here, so an outdated policy stops the run at the start with one clear
message instead of failing somewhere inside a role.

- `tasks/policy.yaml` runs at the end of `wyga/load-policy`, on the merged
  policy of the host (`host`).
- `tasks/confidential.yaml` runs at the end of `wyga/load-confidential`,
  on the merged secrets (`confidential`).

Cases are kept as tasks, not as data: a condition of a few lines is easier
to read and to test as a task than as an expression in a list.
