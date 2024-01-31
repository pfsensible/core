# Testing pfsensible/core with plays

You must checkout this repository into a path of the form ../ansible_collections/pfsensible/core/.

The following collection dependencies are needed:
 * ansible.utils

You will need a fresh pfSense install available as `pfsense-test` or adjust the `hosts` file as needed.
You need to be able to ssh to it as `root` without a password or use `--ask-pass`, which you can use
the configure.yml play to do.

Update `host_vars/pfsense-test.yml` with IP addresses of your test pfSense install.
