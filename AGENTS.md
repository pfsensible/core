# Repository guide

This is the `pfsensible.core` Ansible collection. Its modules manage pfSense
configuration in `/cf/conf/config.xml` and call pfSense PHP functions to apply
changes.

## Find the relevant code

- Start at `plugins/modules/pfsense_<feature>.py` for the public options,
  examples, and entry point. Some modules implement their behavior there.
  Others delegate to a class in `plugins/module_utils/`.
- Read [module_base.py](plugins/module_utils/module_base.py) for shared parameter
  conversion, XML updates, and change reporting. Single-section configuration
  modules can use [module_config_base.py](plugins/module_utils/module_config_base.py).
  [pfsense.py](plugins/module_utils/pfsense.py) handles config I/O and PHP execution.
- Check [pfsense_aggregate.py](plugins/modules/pfsense_aggregate.py) or
  [pfsense_ipsec_aggregate.py](plugins/modules/pfsense_ipsec_aggregate.py) when
  changing a helper those modules share.
- Keep module documentation and argument specs in sync when changing options.
  Follow the examples in `changelogs/fragments/` for user-facing changes.
  See [GENERATING_MODULES.md](GENERATING_MODULES.md) for new module scaffolding.

## Verify changes

- Look for the matching test in `tests/unit/plugins/modules/` and its fixture
  in `tests/unit/plugins/modules/fixtures/`. Shared helper tests live in
  `tests/unit/plugins/module_utils/`. For configuration changes, use the
  existing tests to check saved XML, repeat-run idempotence, and check mode
  where applicable.
- Run `ansible-test` from a checkout at `ansible_collections/pfsensible/core`.
  The unit tests depend on `community.internal_test_tools`. See the
  [CI workflow](.github/workflows/main.yml) for dependencies, supported Python
  and Ansible versions, and the native XML serializer test commands.
- Start with a focused run, for example
  `ansible-test units --requirements tests/unit/plugins/modules/test_pfsense_dns_resolver.py`.
  CI also runs `ansible-test sanity`, `ruff check`, and `ruff format --check --diff`.
- For validation against a pfSense VM, see the [appliance test guide](tests/system/README.md).

## Pick up existing work

- Check `git status --short --branch` and `git worktree list` before editing.
  Work in the checkout for the task and keep searches scoped to it. Exclude
  `.worktrees/` from searches in the main checkout.
- When unfinished work needs to carry into a new chat, leave a short handoff
  with the branch or commit, verification results, and the next step.
