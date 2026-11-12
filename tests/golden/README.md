# Origin of the reference texts

- The texts are taken from `.orchestra/contracts.md`, sections 5.4 and 5.5.
- The section 5.4 references (`server_gate_awg0`, `server_gate_awg1`, `server_hub_awg2`,
  `hook_gate_awg1`, `hook_hub_awg2`, `client_phone`) match the output of the templates before the
  change (commit 753f270) with the variables `VARS` from section 5.3.
- `hook_gate_awg0_two.golden` is the new awg0 hook (section 5.5); other section 5.5 texts are derived
  in `tests/test_templates.py` by the substitutions described in the contract.
- Read the files as bytes; `.gitattributes` here disables line-ending conversion.
