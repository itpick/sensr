# Test fixtures

`opnsense/` holds test data copied verbatim from OPNsense core
(<https://github.com/opnsense/core>, revision pinned in `reference/REFS`), as
allowed by docs/CONTRIBUTING-AGENTS.md: data only, never code.

| File | Upstream path |
|---|---|
| `opnsense/FilterRuleTest/testDirection.conf` | `src/opnsense/mvc/tests/app/library/OPNsense/Firewall/FilterRuleTest/testDirection.conf` |
| `opnsense/FilterRuleTest/testIcmp.conf` | `…/FilterRuleTest/testIcmp.conf` |
| `opnsense/FilterRuleTest/testProtocol.conf` | `…/FilterRuleTest/testProtocol.conf` |

Upstream license (BSD 2-Clause):

```
Copyright (C) 2014-2026 Deciso B.V.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

`*.nft.json` files under `../golden/` are sensr's own outputs (regenerate with
`SENSR_GOLDEN_UPDATE=1 cargo test -p sensr-rules`); CI checks each one with
`nft -c -j -f`.
