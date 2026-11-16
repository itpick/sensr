# sensr-import-opnsense test fixtures

| Directory | Contents | Origin |
|---|---|---|
| `corpus/` | Synthetic, hand-written OPNsense `config.xml` files (home router, multi-WAN). See `corpus/README.md`. | sensr |
| `opnsense/` | OPNsense's own test fixtures, copied verbatim as test data. | OPNsense core |

## Upstream fixtures (`opnsense/`)

Copied unmodified from [opnsense/core](https://github.com/opnsense/core) at commit
`8b88393932c94b7dafea941803ae0fe34f966888` (`reference/REFS`). They are used as
test **data** only; no upstream code is copied into sensr.

| sensr path | Upstream path (under `src/`) | Used by |
|---|---|---|
| `opnsense/ConfigConfig/array.xml` | `opnsense/mvc/tests/app/library/OPNsense/Core/ConfigConfig/backup/array.xml` | T-0002 |
| `opnsense/ConfigConfig/object.xml` | `opnsense/mvc/tests/app/library/OPNsense/Core/ConfigConfig/backup/object.xml` | T-0003, T-0004 |
| `opnsense/ServiceTests/config.xml` | `opnsense/service/tests/config/config.xml` | T-0320, T-0321 |
| `opnsense/Sample/config.xml` | `etc/config.xml.sample` (factory default config) | corpus |
| `opnsense/AclConfig/config.xml` | `opnsense/mvc/tests/app/models/OPNsense/ACL/AclConfig/config.xml` | ACL tests |
| `opnsense/InterfacesConfig/config.xml` | `opnsense/mvc/tests/app/models/OPNsense/Interfaces/config/config.xml` | T-0306 |
| `opnsense/BaseModelConfig/config.xml` | `opnsense/mvc/tests/app/models/OPNsense/Base/BaseModelConfig/backup/config.xml` | BaseModel tests |
| `opnsense/<Name>FieldTest/config.xml` | `opnsense/mvc/tests/app/models/OPNsense/Base/FieldTypes/<Name>FieldTest/config.xml` for AuthGroup, AuthenticationServer, Certificate, Interface, ModelRelation, NetworkAlias, VirtualIP | field-type tests |

Every file here must parse (T-0347). Files OPNsense itself wrote round-trip
byte-exactly through the importer's writer; the hand-indented ones are listed in
`NON_CANONICAL` in `src/fixtures.rs` and only need to round-trip stably.

### License of the upstream fixtures

```
Copyright (c) 2014-2026 Deciso B.V.
Copyright (c) 2014-2026 Ad Schellevis <ad@opnsense.org>
Copyright (c) 2014-2026 Franco Fichtner <franco@opnsense.org>
(and the other contributors listed in opnsense/core LICENSE)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
