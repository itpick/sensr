# 03 — Test parity: every OPNsense test and its sensr equivalent

Status: research, 2026-11-15. Inventory taken from `opnsense/core` 8b88393 and
`opnsense/plugins` af4166a (`reference/opnsense/`, pinned in `reference/REFS`). Requirement: **sensr has all the
tests OPNsense has** — every PHPUnit method, every Python unittest, every lint/
style/sweep/plist check, the boot selftest and the plugin checks — re-expressed
as a sensr test with an ID, so the checklist can be tracked to completion.

Conventions used below:

- **Kind**: `unit` (Rust `#[test]`), `prop` (proptest/quickcheck), `golden`
  (fixture in, byte-exact output compared), `compat` (recorded OPNsense API
  response replayed against `sensr-api-compat`), `lint` (CI check: `cargo
  clippy -D warnings`, `cargo fmt --check`, custom `xtask lint-*`), `vm`
  (`nixosTest` QEMU integration), `pi` (QEMU aarch64 image boot test).
- **sensr test** is `crate::module::tests::name` for Rust tests, `xtask
  <name>` for CI checks, `nix/tests/<name>.nix` for VM suites.
- OPNsense paths are relative to `core/src/opnsense/mvc/tests/app/` for PHPUnit
  (`…/mvc/tests/app/`), `core/src/opnsense/` for Python, `core/` for make rules.
- Fixture `config.xml` files are copied verbatim into
  `crates/sensr-import-opnsense/tests/fixtures/opnsense/<Name>/config.xml` and
  loaded through the importer, so every config-backed field test also exercises
  the importer.

## 1. How OPNsense runs its tests (what must exist in sensr CI)

| OPNsense | Mechanism | sensr |
|---|---|---|
| `make test` (`core/Makefile:277`) | `cd src/opnsense/mvc/tests && phpunit` (`phpunit.xml`: bootstrap `setup.php`, notices→exceptions, excludes group `Ignore`) | `cargo nextest run --workspace` with `RUSTFLAGS=-D warnings` |
| `service/run_unittests.py`, `scripts/filter/run_unittests.py`, `python3 -m unittest tests` in `scripts/unbound-dnsbl/` | hand-written runners, **not** wired into `make test` | all Python-equivalents are Rust unit tests in the owning crate, so they run in the same `cargo nextest` invocation |
| `make lint` / `make style` / `make sweep` (`Mk/lint.mk`, `Mk/style.mk`, `Mk/sweep.mk`) | BSD make targets, run per repo and per plugin by `tools/build/test.sh` | `cargo xtask lint` (fails CI), `cargo fmt --check`, `cargo clippy`, `nix flake check` |
| `tools/build/test.sh` | in the build chroot: `pkg check -da`, `pkg check -sa`, then `make lint style test` for core and each plugin | `nix flake check` runs clippy/fmt/tests/VM tests for the whole workspace and for every plugin crate |
| `rc.syshook.d/early/99-selftest` | boot-time integrity checks | `sensr-selftest.service` + `nix/tests/selftest.nix` |

## 2. Inventory and mapping

### 2.1 PHPUnit — library (`…/mvc/tests/app/library/`)

Fixtures: `Core/ConfigConfig/backup/array.xml` (two `filter/rule`, one
`sysctl/item`, `unbound version="1.0.13" persisted_at=…` attributes, revision
block), `Core/ConfigConfig/backup/object.xml` (`<opnsense><dhcpdv6><lan><ramode>disabled`),
`Firewall/FilterRuleTest/{testDirection,testIcmp,testProtocol}.conf` (verbatim
in §2.1.1).

| ID | OPNsense test | Verifies | sensr crate | sensr test | Kind |
|---|---|---|---|---|---|
| T-0001 | `Core/ConfigTest::testCanBeArray` | Config loads from `configDefault` fallback copy of `array.xml`; `toArray(forceList=['rule'])` non-empty | sensr-config | `store::tests::load_falls_back_to_default_document` | unit |
| T-0002 | `Core/ConfigTest::test_to_from_array` | list semantics: single `sysctl/item` flattens to its keys unless force-listed; repeated `filter/rule` always a list; array→XML→string round-trips byte-exact with attributes (`version`, `persisted_at`) | sensr-import-opnsense | `xml::tests::listtags_single_vs_repeated_children`, `xml::tests::roundtrip_array_fixture_byte_exact` | golden |
| T-0003 | `Core/ConfigTest::testCanBeObject` | object view loads from `object.xml` | sensr-import-opnsense | `xml::tests::load_object_fixture` | unit |
| T-0004 | `Core/ConfigTest::test_to_from_object` | unset child leaves `<lan/>` self-closed; re-adding child restores byte-exact original | sensr-import-opnsense | `xml::tests::remove_and_readd_child_roundtrip` | golden |
| T-0005 | `Core/ShellTest::testit` | `Shell::exec_safe` formatting: `%s` → shell-quoted arg, `%%` → `%`, wrong arg count / `%d` / literal `/usr/bin/true` → fail sentinel; array formats joined; `null`/`''`/`0` quoting; injection strings quoted (27 assertions) | sensr-apply | `cmd::tests::safe_format_table` (one case per assertion) + `cmd::tests::prop_never_unquoted` | unit + prop |
| T-0006 | `Firewall/FilterRuleTest::testDirection` | 6 rules (`[]`, `''`, `null`, `in`, `out`, `any`) render `pass in quick from {any} to {any}` × 4, `pass out …`, `pass quick …` (any ⇒ no direction) | sensr-rules | `render::pf::tests::direction` (golden `testDirection.conf`) + `render::nft::tests::direction` (golden `direction.nft`) | golden |
| T-0007 | `Firewall/FilterRuleTest::testIcmp` | `icmp-type` list `mobregreq,skip,2` → `icmp-type {mobregreq,"skip",2}`; `skip,2`; `2`; `''` omits clause | sensr-rules | `render::pf::tests::icmp` + `render::nft::tests::icmp` (`icmp type { …}` with `skip` mapped per semantics table) | golden |
| T-0008 | `Firewall/FilterRuleTest::testProtocol` | `''` omits proto; `tcp`; `tcp/udp` → `{tcp udp}`; `skip` and `a/n` quoted | sensr-rules | `render::pf::tests::protocol` + `render::nft::tests::protocol` (`meta l4proto { tcp, udp }`) | golden |
| T-0009 | `Interface/IdassocTest::testPrefixId` | `calculatePrefix('2001:db8:1234:ab00::/56', id)` for id 0,1,10,15,16,255 → `…:ab00/ab01/ab0a/ab0f/ab10/abff::/64` | sensr-net | `ipv6::pd::tests::prefix_id_into_56` | unit |
| T-0010 | `Interface/IdassocTest::testDelegationSize` | /52 + id 16 → `a010::/64`; /48 + 16 → `10::/64`; /48 + 48879 → `beef::/64` | sensr-net | `ipv6::pd::tests::delegation_sizes` | unit |
| T-0011 | `Interface/IdassocTest::testPrefixLength` | `calculateUsablePrefixLength(56,id,range)`: range ''/1→64, 2→63, 4→62, 16→60, id 16 range 16→60, id 10 range 16→63 (alignment) | sensr-net | `ipv6::pd::tests::usable_prefix_length` + `prop_usable_length_alignment` | unit + prop |

#### 2.1.1 FilterRule fixtures (verbatim) and their nftables goldens

`FilterRuleTest/testDirection.conf`
```
pass in quick from {any} to {any}
pass in quick from {any} to {any}
pass in quick from {any} to {any}
pass in quick from {any} to {any}
pass out quick from {any} to {any}
pass quick from {any} to {any}
```
`FilterRuleTest/testIcmp.conf`
```
pass in quick from {any} to {any} icmp-type {mobregreq,"skip",2}
pass in quick from {any} to {any} icmp-type {"skip",2}
pass in quick from {any} to {any} icmp-type {2}
pass in quick from {any} to {any}
```
`FilterRuleTest/testProtocol.conf`
```
pass in quick from {any} to {any}
pass in quick proto tcp from {any} to {any}
pass in quick proto {tcp udp} from {any} to {any}
pass in quick proto "skip" from {any} to {any}
pass in quick proto "a/n" from {any} to {any}
```

How the upstream test builds its input: `new FilterRule($ifmap=[], $gwmap=[],
$conf)` with `$conf` already in the internal key space (`direction`,
`icmp-type`, `protocol`), no `interface`, so `reader()` yields exactly one
expansion with `from/to` defaulted to `any` and `quick` defaulted to true, and
`__toString()` walks the `procorder` table. The sensr equivalent keeps two
renderers over one IR (see 02-architecture.md §2.9): `render::pf` must
reproduce the three files byte-for-byte (this is a *differential* oracle for
the IR normalisation), and `render::nft` has sibling goldens
`crates/sensr-rules/tests/golden/{direction,icmp,protocol}.nft`. Expected
mapping for these three fixtures: `pass in quick` → `accept` in the
per-interface input chain, `pass out quick` → output chain, no direction
(`any`) → the rule appears in both chains; `proto {tcp udp}` → `meta l4proto
{ tcp, udp }`; `icmp-type {…}` → `icmp type { … }` / `icmpv6 type { … }`
depending on family; pf's quoted placeholders `"skip"` and `"a/n"` are
rejected by the nft renderer with a structured error (they are pf-only
sentinels). The semantics table in `sensr-rules/docs/pf-to-nft.md` is the
normative reference and every row of it gets a golden pair.

### 2.2 PHPUnit — ACL and models (`…/mvc/tests/app/models/OPNsense/`)

Fixtures: `ACL/AclConfig/config.xml` (groups `admins{page-all}`,
`testg1{user-config-readonly, member 2001}`, `testg2{page-diagnostics-arptable,
member 2002}`, `testg3{arptable,ndptable,limiter-info, member 2003}`; users
root/0, test1/2000 priv `user-config-readonly`, test2/2001 priv
`page-diagnostics-arptable`, test3/2002, test4/2003), plus
`Diagnostics/ACL/ACL.xml` patterns. `Base/BaseModel/TestModel.{php,xml}` +
`Base/BaseModel/Migrations/M0_0_1,M1_0_0,M1_0_1.php` (each prefixes
`general.FromEmail` with `001_`/`100_`/`101_`), `Base/BaseModelConfig/backup/config.xml`.

| ID | OPNsense test | Verifies | sensr crate | sensr test | Kind |
|---|---|---|---|---|---|
| T-0012 | `ACL/AclTest::testCanBeCreated` | ACL constructs from fixture config | sensr-auth | `acl::tests::fixture_loads` | unit |
| T-0013 | `ACL/AclTest::test_root_hasPrivilege_not` | root (page-all via admins) does **not** have `user-config-readonly` | sensr-auth | `acl::tests::root_lacks_readonly_priv` | unit |
| T-0014 | `ACL/AclTest::test_test1_hasPrivilege` | direct user priv grants | sensr-auth | `acl::tests::user_priv_direct` | unit |
| T-0015 | `ACL/AclTest::test_test2_hasPrivilege_via_group` | group `<member>` uid grants priv | sensr-auth | `acl::tests::user_priv_via_group_member` | unit |
| T-0016 | `ACL/AclTest::test_test3_hasPrivilege_not` | unrelated group priv does not grant | sensr-auth | `acl::tests::user_priv_denied` | unit |
| T-0017 | `ACL/AclTest::test_root_isPageAccessible_known` | `page-all` grants `/ui/diagnostics/interface/arp/` | sensr-auth | `acl::tests::page_all_known_url` | unit |
| T-0018 | `ACL/AclTest::test_root_isPageAccessible_unknown` | `page-all` grants unknown URL | sensr-auth | `acl::tests::page_all_unknown_url` | unit |
| T-0019 | `ACL/AclTest::test_test2_isPageAccessible` | direct page priv → URL pattern `ui/diagnostics/interface/arp/*` matches | sensr-auth | `acl::tests::page_priv_direct_url_match` | unit |
| T-0020 | `ACL/AclTest::test_test4_isPageAccessible_via_group` | page priv via group | sensr-auth | `acl::tests::page_priv_via_group` | unit |
| T-0021 | `ACL/AclTest::test_test1_isPageAccessible_unknown` | token-only priv (`user-config-readonly`) grants no page | sensr-auth | `acl::tests::token_priv_grants_no_page` | unit |
| T-0022 | `Base/BaseModelTest::testCanBeCreated` | model constructs against empty config dir (fallback) | sensr-schema | `model::tests::test_model_constructs_empty` | unit |
| T-0023 | `Base/BaseModelTest::testGeneralAvailable` | container node exists | sensr-schema | `model::tests::container_present` | unit |
| T-0024 | `Base/BaseModelTest::testRunMigrations` | chain 0.0.0→0.0.1→1.0.0 runs, 1.0.1 skipped: `FromEmail == 100_001_sample@example.com` | sensr-schema | `migrate::tests::chain_runs_in_order_and_stops_at_model_version` | unit |
| T-0025 | `Base/BaseModelTest::testCanSetStringValue` | set/get scalar | sensr-schema | `model::tests::set_get_scalar` | unit |
| T-0026 | `Base/BaseModelTest::testCanUseDefaultValue` | `getDefault/isDefault/applyDefault/setDefault` semantics | sensr-schema | `fields::tests::default_semantics` | unit |
| T-0027 | `Base/BaseModelTest::testCannotSetNonExistingField` | unknown attribute → error naming the field | sensr-schema | `model::tests::unknown_field_error` | unit |
| T-0028 | `Base/BaseModelTest::testCanAssignArrayType` | del all, add 10 items, serialize, save (backup disabled), reload: 10 items in insertion order | sensr-config | `store::tests::array_items_persist_in_order` | unit |
| T-0029 | `Base/BaseModelTest::testCanDeleteSpecificItem` | delete item by predicate → 9 remain, none with number 5 | sensr-schema | `array::tests::delete_by_predicate` | unit |
| T-0030 | `Base/BaseModelTest::testArrayIsKeydByUUID` | every item key is a uuid | sensr-schema | `array::tests::items_keyed_by_uuid` | unit |
| T-0031 | `Base/BaseModelTest::testValidationOk` | unchanged valid data serializes | sensr-schema | `model::tests::validate_ok` | unit |
| T-0032 | `Base/BaseModelTest::testValidationNOK` | `number="XXX"` → `Not a valid number.` (IntegerField 1..65535) | sensr-schema | `model::tests::validate_integer_message` | unit |
| T-0033 | `Base/BaseModelTest::testsetNodeByReferenceFound` | `general.FromEmail` dotted path set returns true | sensr-schema | `path::tests::set_by_reference_found` | unit |
| T-0034 | `Base/BaseModelTest::testsetNodeByReferenceNotFound` | bad path returns false | sensr-schema | `path::tests::set_by_reference_not_found` | unit |
| T-0035 | `Base/BaseModelTest::testGenerateXML` | `toXML()` tree shape `OPNsense/TestModel/{general,arraytypes/item×9}` | sensr-import-opnsense | `export::tests::model_to_xml_shape` (export side of compat) | unit |
| T-0036 | `Base/BaseModelTest::testSetNode` | `setNodes()` on each item via reference → all numbers >99 | sensr-schema | `path::tests::set_nodes_by_reference` | unit |
| T-0037 | `Base/BaseModelTest::testGetNodes` | `getNodes()` count 9 | sensr-schema | `array::tests::get_nodes_count` | unit |
| T-0038 | `Base/BaseModelTest::testConstraintsNok` | two items number 999 → `Number should be unique.` (Unique over `number`+`optfield`) | sensr-schema | `constraints::unique::tests::model_duplicate_message` | unit |
| T-0039 | `Base/BaseModelTest::testConstraintsOk` | renumbered → serializes | sensr-schema | `constraints::unique::tests::model_ok` | unit |
| T-0040 | `Base/BaseModelTest::testAllOrNoneInitial` | all empty → ok, readback `''` | sensr-schema | `constraints::all_or_none::tests::initial_empty` | unit |
| T-0041 | `Base/BaseModelTest::testAllOrNoneNok` | one of three set → `All fields should contain data or none of them` | sensr-schema | `constraints::all_or_none::tests::partial_fails` | unit |
| T-0042 | `Base/BaseModelTest::testAllOrNoneOk` | all set → readback | sensr-schema | `constraints::all_or_none::tests::all_set_ok` | unit |
| T-0043 | `Base/BaseModelTest::testSingleSelectInitial` | none set ok | sensr-schema | `constraints::single_select::tests::initial_empty` | unit |
| T-0044 | `Base/BaseModelTest::testSingleSelectNok` | two set → `Only one option could be selected` | sensr-schema | `constraints::single_select::tests::two_fail` | unit |
| T-0045 | `Base/BaseModelTest::testSingleSelectOk` | exactly one set ok | sensr-schema | `constraints::single_select::tests::one_ok` | unit |
| T-0046 | `Base/BaseModelTest::testSetConstraintInitial` | both empty ok | sensr-schema | `constraints::set::tests::initial_empty` | unit |
| T-0047 | `Base/BaseModelTest::testSetConstraintNok` | value1 set, value2 empty → `When "value1" is enabled, "value2" is required.` | sensr-schema | `constraints::set::tests::one_without_other_fails` | unit |
| T-0048 | `Base/BaseModelTest::testSetConstraintok` | both set ok | sensr-schema | `constraints::set::tests::both_set_ok` | unit |
| T-0049 | `Base/BaseModelTest::testDependConstraintInitial` | bool `0`, text empty ok | sensr-schema | `constraints::depend::tests::initial` | unit |
| T-0050 | `Base/BaseModelTest::testDependConstraintNok` | bool `1`, text empty → same message as T-0047 | sensr-schema | `constraints::depend::tests::enabled_requires_value` | unit |
| T-0051 | `Base/BaseModelTest::testDependConstraintOk1` | `1` + text ok | sensr-schema | `constraints::depend::tests::enabled_with_value_ok` | unit |
| T-0052 | `Base/BaseModelTest::testDependConstraintOk2` | `0` + text ok | sensr-schema | `constraints::depend::tests::disabled_with_value_ok` | unit |
| T-0053 | `Constraints/ComparedToFieldConstraintTest::…_lt_and_no_error` | 2 lt 3 → 0 messages | sensr-schema | `constraints::compared::tests::lt_ok` | unit |
| T-0054 | `…_lt_and_error` | 3 lt 3 → 1 message | sensr-schema | `constraints::compared::tests::lt_equal_fails` | unit |
| T-0055 | `…_gt_and_no_error` | 5 gt 3 → 0 | sensr-schema | `constraints::compared::tests::gt_ok` | unit |
| T-0056 | `…_gt_and_error` | 2 gt 3 → 1 | sensr-schema | `constraints::compared::tests::gt_fails` | unit |
| T-0057 | `…_zero_…_lt_and_error` | 2 lt 0 → 1 | sensr-schema | `constraints::compared::tests::zero_lt_fails` | unit |
| T-0058 | `…_zero_…_gt_and_error` | 0 gt 2 → 1 | sensr-schema | `constraints::compared::tests::zero_gt_fails` | unit |
| T-0059 | `…_zero_…_lt_and_no_error` | 0 lt 2 → 0 | sensr-schema | `constraints::compared::tests::zero_lt_ok` | unit |
| T-0060 | `…_zero_…_gt_and_no_error` | 2 gt 0 → 0 | sensr-schema | `constraints::compared::tests::zero_gt_ok` | unit |
| T-0061 | `…_node_empty_values_…` | node `''` → skipped (0) | sensr-schema | `constraints::compared::tests::empty_node_skips` | unit |
| T-0062 | `…_other_node_empty_values_…` | other `''` → skipped | sensr-schema | `constraints::compared::tests::empty_other_skips` | unit |
| T-0063 | `…_if_node_is_null_…` | null node → 0 | sensr-schema | `constraints::compared::tests::null_node_skips` | unit |
| T-0064 | `…_if_other_is_null_…` | null other → 0 | sensr-schema | `constraints::compared::tests::null_other_skips` | unit |
| T-0065 | `…_if_both_are_null_…` | both null → 0 | sensr-schema | `constraints::compared::tests::both_null_skip` | unit |
| T-0066 | `Constraints/UniqueConstraintTest::testNonEqualAndEqualValues` | distinct ok; duplicate → one message per offending item (2) | sensr-schema | `constraints::unique::tests::duplicate_reports_each_item` | unit |
| T-0067 | `…::testMultipleNonEqualAndEqualValues` | uniqueness over node+`addFields` tuple | sensr-schema | `constraints::unique::tests::composite_key` | unit |
| T-0068 | `…::testEmptyValuesNotRequiredAndRequired` | empty duplicates ignored unless required | sensr-schema | `constraints::unique::tests::empty_required_toggle` | unit |
| T-0069 | `…::testMultipleEmptyValuesNotRequiredAndRequired` | same for composite | sensr-schema | `constraints::unique::tests::empty_composite_required_toggle` | unit |
| T-0070 | `…::testFirstValueEmptyPassAll` | empty primary skips check unless required | sensr-schema | `constraints::unique::tests::empty_primary_skips` | unit |
| T-0071 | `…::testCaseInsensitiveDuplicatesFail` | `Value1` vs `value1` with caseInsensitive → fail | sensr-schema | `constraints::unique::tests::case_insensitive` | unit |
| T-0072 | `…::testCaseSensitiveDifferentCasePasses` | default case-sensitive passes | sensr-schema | `constraints::unique::tests::case_sensitive` | unit |

### 2.3 PHPUnit — field types (`…/models/OPNsense/Base/FieldTypes/`)

`Field_Framework_TestCase` provides `validate(field) -> [validator type names]`
and `validateThrow(field)` throwing `ValidationException` whose message is the
validator **type** (`PresenceOf`, `Regex`, `CallbackValidator`,
`MinMaxValidator`, `IntegerValidator`). sensr mirrors this with
`sensr_schema::testing::{validate, validate_err}` returning
`Vec<ValidatorKind>`; every "throws X" below asserts `ValidatorKind::X`.
Config-backed classes (`AuthenticationServerField`, `AuthGroupField`,
`CertificateField`, `InterfaceField`, `NetworkAliasField`, `VirtualIPField`,
`ModelRelationField`) switch `configDir` to a same-named fixture directory; in
sensr the fixture is imported once per test module into a `Document` and
reference fields resolve against it.

| ID | OPNsense test | Verifies | sensr crate | sensr test | Kind |
|---|---|---|---|---|---|
| T-0073 | `Field_Framework_TestCase::testIgnore` (`@group Ignore`) | placeholder; excluded by `phpunit.xml` | sensr-schema | `testing::tests::helpers_compile` (`#[ignore]`) | unit |
| T-0074 | `AuthenticationServerFieldTest::testCanBeCreated` | constructs; loads fixture (authservers `testcase 1`, `testcase 2`) | sensr-schema | `fields::auth_server::tests::fixture_loads` | unit |
| T-0075 | `…::testLocalExists` | options include built-in `Local Database` | sensr-schema | `fields::auth_server::tests::local_db_present` | unit |
| T-0076 | `…::testConfigItemsExists` | options include fixture servers | sensr-schema | `fields::auth_server::tests::config_items_present` | unit |
| T-0077 | `…::testSelectSetWithUnknownValue` | multi `testcase 1,testcase 2,testcase X` → Callback | sensr-schema | `fields::auth_server::tests::unknown_rejected` | unit |
| T-0078 | `…::testSelectSetWithoutUnknownValue` | multi all-known ok | sensr-schema | `fields::auth_server::tests::known_multi_ok` | unit |
| T-0079 | `…::testSelectSetOnSingleValue` | multiple=N with list → Callback | sensr-schema | `fields::auth_server::tests::single_rejects_list` | unit |
| T-0080 | `…::testSelectSingleValue` | single known ok | sensr-schema | `fields::auth_server::tests::single_ok` | unit |
| T-0081 | `…::testIsContainer` | not a container | sensr-schema | `fields::auth_server::tests::not_container` | unit |
| T-0082 | `AuthGroupFieldTest::testCanBeCreated` | constructs; fixture groups gid 100/101/102 | sensr-schema | `fields::auth_group::tests::fixture_loads` | unit |
| T-0083 | `…::testConfigItemsExists` | option keys contain 100 | sensr-schema | `fields::auth_group::tests::config_items_present` | unit |
| T-0084 | `…::testSelectSetWithUnknownValue` | `100,103,101` → Callback | sensr-schema | `fields::auth_group::tests::unknown_rejected` | unit |
| T-0085 | `…::testSelectSetWithoutUnknownValue` | `setValues(['101','100'])` → `101,100`, 2 values; `'101,,100'` keeps string but 2 values; `['101','','100']` → `101,100` (empties dropped) | sensr-schema | `fields::list::tests::empty_elements_dropped` | unit |
| T-0086 | `…::testSelectSetOnSingleValue` | multiple=N with `100,101` → Callback | sensr-schema | `fields::auth_group::tests::single_rejects_list` | unit |
| T-0087 | `…::testSelectSingleValue` | `100` ok | sensr-schema | `fields::auth_group::tests::single_ok` | unit |
| T-0088 | `…::testIsContainer` | not a container | sensr-schema | `fields::auth_group::tests::not_container` | unit |
| T-0089 | `AutoNumberFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::auto_number::tests::constructs` | unit |
| T-0090 | `…::testNumberGenerated` | 10 items, first set to 1, rest `applyDefault()` → ids 1..10 | sensr-schema | `fields::auto_number::tests::sequence_generated` | unit |
| T-0091 | `…::testFillGaps` | items 2,4,7 preset; defaults fill 1,3,5,6,8,9,10 in order | sensr-schema | `fields::auto_number::tests::fills_gaps` + `prop_fill_gaps_is_bijective` | unit + prop |
| T-0092 | `…::testNotANumber` | `X` → IntegerValidator | sensr-schema | `fields::auto_number::tests::not_a_number` | unit |
| T-0093 | `…::testValueNotInRange` | min 1 max 100: `101`, `0` → MinMax | sensr-schema | `fields::auto_number::tests::out_of_range` | unit |
| T-0094 | `Base64FieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::base64::tests::constructs` | unit |
| T-0095 | `…::testRequiredEmpty` | required + `''` → PresenceOf | sensr-schema | `fields::base64::tests::required_empty` | unit |
| T-0096 | `…::testRequiredNotEmpty` | `T1BOc2Vuc2U=` ok | sensr-schema | `fields::base64::tests::required_set` | unit |
| T-0097 | `…::testValidValues` | `T1BOc2Vuc2U=`, `RGVjaXNv`, `RGVj\naXNv` (embedded newline) ok | sensr-schema | `fields::base64::tests::valid_values` | unit |
| T-0098 | `…::testInValidValues` | `!2121`, `x2x`, `88766-1234` invalid | sensr-schema | `fields::base64::tests::invalid_values` | unit |
| T-0099 | `…::testIsContainer` | not container | sensr-schema | `fields::base64::tests::not_container` | unit |
| T-0100 | `BooleanFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::boolean::tests::constructs` | unit |
| T-0101 | `…::testShouldNotBeANumber` | `90` → Regex | sensr-schema | `fields::boolean::tests::rejects_number` | unit |
| T-0102 | `…::testShouldNotBeAString` | `xx` → Regex | sensr-schema | `fields::boolean::tests::rejects_string` | unit |
| T-0103 | `…::testRequiredEmpty` | PresenceOf | sensr-schema | `fields::boolean::tests::required_empty` | unit |
| T-0104 | `…::testRequiredNotEmpty` | `1` ok | sensr-schema | `fields::boolean::tests::required_set` | unit |
| T-0105 | `…::testValidValues` | `0`,`1` ok | sensr-schema | `fields::boolean::tests::valid_values` | unit |
| T-0106 | `…::testIsContainer` | not container | sensr-schema | `fields::boolean::tests::not_container` | unit |
| T-0107 | `CertificateFieldTest::testCanBeCreated` | constructs; `resetStaticOptions()`; fixture certs `5537f364ba123`,`55c382ee6020f`, CAs `1537f364ba123`,`15c382ee6020f` | sensr-schema | `fields::cert_ref::tests::fixture_loads` | unit |
| T-0108 | `…::testDefaultCertExists` | default type cert lists `5537f364ba123` | sensr-schema | `fields::cert_ref::tests::cert_options` | unit |
| T-0109 | `…::testConfigItemsExists` | type `ca` lists both CA refids | sensr-schema | `fields::cert_ref::tests::ca_options` | unit |
| T-0110 | `…::testSelectSetWithUnknownValue` | unknown refids → Callback | sensr-schema | `fields::cert_ref::tests::unknown_rejected` | unit |
| T-0111 | `…::testSelectSetWithoutUnknownValue` | multi known ok | sensr-schema | `fields::cert_ref::tests::known_multi_ok` | unit |
| T-0112 | `…::testSelectSetOnSingleValue` | multiple=N list → Callback | sensr-schema | `fields::cert_ref::tests::single_rejects_list` | unit |
| T-0113 | `…::testSelectSingleValue` | single ok | sensr-schema | `fields::cert_ref::tests::single_ok` | unit |
| T-0114 | `…::testIsContainer` | not container | sensr-schema | `fields::cert_ref::tests::not_container` | unit |
| T-0115 | `CountryFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::country::tests::constructs` | unit |
| T-0116 | `…::testRequiredEmpty` | PresenceOf | sensr-schema | `fields::country::tests::required_empty` | unit |
| T-0117 | `…::testRequiredNotEmpty` | `NL` ok | sensr-schema | `fields::country::tests::required_set` | unit |
| T-0118 | `…::testValidValues` | `NL`,`DE` | sensr-schema | `fields::country::tests::valid_values` | unit |
| T-0119 | `…::testInValidValues` | `XX`,`YY` | sensr-schema | `fields::country::tests::invalid_values` | unit |
| T-0120 | `…::testSelectSetWithUnknownValue` | `NL,DE,ZZ` → Callback | sensr-schema | `fields::country::tests::unknown_rejected` | unit |
| T-0121 | `…::testSelectSetWithoutUnknownValue` | `NL,DE` ok | sensr-schema | `fields::country::tests::known_multi_ok` | unit |
| T-0122 | `…::testInverseOption` | `AddInverted=Y`, `!NL` ok | sensr-schema | `fields::country::tests::inverted_option` | unit |
| T-0123 | `…::testSelectSetOnSingleValue` | multiple=N `NL,DE` → Callback | sensr-schema | `fields::country::tests::single_rejects_list` | unit |
| T-0124 | `…::testIsContainer` | not container | sensr-schema | `fields::country::tests::not_container` | unit |
| T-0125 | `CSVListFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::csv_list::tests::constructs` | unit |
| T-0126 | `…::testGeneric` | not container; `isList()` true | sensr-schema | `fields::csv_list::tests::is_list` | unit |
| T-0127 | `…::testValues` | empty → 0 values; `foo,bar` → 2; `foo,,bar` → string kept, 2 values | sensr-schema | `fields::csv_list::tests::values` | unit |
| T-0128 | `…::testMask` | mask `/[^o,]+/` applies to whole string unless `MaskPerItem=Y` | sensr-schema | `fields::csv_list::tests::mask_whole_vs_per_item` | unit |
| T-0129 | `EmailFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::email::tests::constructs` | unit |
| T-0130 | `…::testRequiredEmpty` | PresenceOf | sensr-schema | `fields::email::tests::required_empty` | unit |
| T-0131 | `…::testRequiredNotEmpty` | `user@domain.com` | sensr-schema | `fields::email::tests::required_set` | unit |
| T-0132 | `…::testValidValues` | `user@domain.local`, `user@my.domain`, mixed case | sensr-schema | `fields::email::tests::valid_values` | unit |
| T-0133 | `…::testInValidValues` | `xxx`, `YY`, `user@none`, `user@domain."x`, `` user`@my.domain `` | sensr-schema | `fields::email::tests::invalid_values` | unit |
| T-0134 | `…::testIsContainer` | not container | sensr-schema | `fields::email::tests::not_container` | unit |
| T-0135 | `HostnameFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::hostname::tests::constructs` | unit |
| T-0136 | `…::testGeneric` | not container, not list | sensr-schema | `fields::hostname::tests::generic` | unit |
| T-0137 | `…::testRequiredEmpty` | PresenceOf | sensr-schema | `fields::hostname::tests::required_empty` | unit |
| T-0138 | `…::testRequiredNotEmpty` | `test.opnsense.org` | sensr-schema | `fields::hostname::tests::required_set` | unit |
| T-0139 | `…::testValidValues` | `IsDNSName=Y`: `test`, fqdn, `_test.opnsense.org` | sensr-schema | `fields::hostname::tests::dns_name_values` | unit |
| T-0140 | `…::testZoneRoot` | `@`, `@.test` only with `ZoneRootAllowed=Y` | sensr-schema | `fields::hostname::tests::zone_root` | unit |
| T-0141 | `…::testWildcards` | `*`, `*.opnsense.org` only with host/fqdn wildcard flags | sensr-schema | `fields::hostname::tests::wildcards` | unit |
| T-0142 | `…::testAsList` | `test\|test.opnsense.org` invalid unless `AsList=Y` + separator `\|`; node data becomes array | sensr-schema | `fields::hostname::tests::as_list_separator` | unit |
| T-0143 | `…::testInValidValues` | `IsDNSName=N`: `!2121`, `x2&x`, `_88766-1234`, `@`, `*.test`, `@.test` | sensr-schema | `fields::hostname::tests::invalid_values` | unit |
| T-0144 | `…::testIpAddress` | `192.168.1.1` only with `IpAllowed=Y` | sensr-schema | `fields::hostname::tests::ip_allowed_toggle` | unit |
| T-0145 | `…::testIsContainer` | not container | sensr-schema | `fields::hostname::tests::not_container` | unit |
| T-0146 | `IntegerFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::integer::tests::constructs` | unit |
| T-0147 | `…::testValueLargerThenMax` | 120 > 100 → MinMax | sensr-schema | `fields::integer::tests::above_max` | unit |
| T-0148 | `…::testValueSmallerThenMin` | 5 < 10 → MinMax | sensr-schema | `fields::integer::tests::below_min` | unit |
| T-0149 | `…::testNotANumber` | `5x1` → IntegerValidator | sensr-schema | `fields::integer::tests::not_a_number` | unit |
| T-0150 | `…::testDecimalNumber` | `99.1` → IntegerValidator | sensr-schema | `fields::integer::tests::decimal_rejected` | unit |
| T-0151 | `…::testRequiredEmpty` | PresenceOf | sensr-schema | `fields::integer::tests::required_empty` | unit |
| T-0152 | `…::testRequiredNotEmpty` | `1` | sensr-schema | `fields::integer::tests::required_set` | unit |
| T-0153 | `…::testIsContainer` | not container | sensr-schema | `fields::integer::tests::not_container` | unit |
| T-0154 | `InterfaceFieldTest::testCanBeCreated` | constructs; fixture wan/lan/opt1/enc0(virtual), lagg0, vlan `if006_vlan4` | sensr-schema | `fields::iface_ref::tests::fixture_loads` | unit |
| T-0155 | `…::testConfigItemsExists` | options include `lan`, `wan` | sensr-schema | `fields::iface_ref::tests::config_items_present` | unit |
| T-0156 | `…::testSelectHasNoParents` | parent device `if006` rejected by default → Callback | sensr-schema | `fields::iface_ref::tests::parents_excluded_by_default` | unit |
| T-0157 | `…::testSelectHasParents` | `AddParentDevices=Y` adds `if006` | sensr-schema | `fields::iface_ref::tests::parents_included` | unit |
| T-0158 | `…::testFilters` | filters `ipaddr !~ dhcp`, `enable !~ ^0` keep lan/opt1, drop wan | sensr-schema | `fields::iface_ref::tests::regex_filters` | unit |
| T-0159 | `…::testSelectSetWithUnknownValue` | `lan,wan,opt99` → Callback | sensr-schema | `fields::iface_ref::tests::unknown_rejected` | unit |
| T-0160 | `…::testSelectSetWithoutUnknownValue` | `lan,opt1` ok | sensr-schema | `fields::iface_ref::tests::known_multi_ok` | unit |
| T-0161 | `…::testSelectSetOnSingleValue` | multiple=N list → Callback | sensr-schema | `fields::iface_ref::tests::single_rejects_list` | unit |
| T-0162 | `…::testSelectSingleValue` | `lan` ok | sensr-schema | `fields::iface_ref::tests::single_ok` | unit |
| T-0163 | `…::testIsContainer` | not container | sensr-schema | `fields::iface_ref::tests::not_container` | unit |
| T-0164 | `IPPortFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::ip_port::tests::constructs` | unit |
| T-0165 | `…::testGeneric` | not container, not list | sensr-schema | `fields::ip_port::tests::generic` | unit |
| T-0166 | `…::testRequiredEmpty` | PresenceOf | sensr-schema | `fields::ip_port::tests::required_empty` | unit |
| T-0167 | `…::testNotRequiredEmpty` | `''` ok when optional | sensr-schema | `fields::ip_port::tests::optional_empty_ok` | unit |
| T-0168 | `…::testRequiredNotEmpty` | `127.0.0.1:2056` | sensr-schema | `fields::ip_port::tests::required_set` | unit |
| T-0169 | `…::testValidValueIpv4` | `127.0.0.1:2056` | sensr-schema | `fields::ip_port::tests::v4_ok` | unit |
| T-0170 | `…::testValidValueAsListIpv4` | list of two v4 | sensr-schema | `fields::ip_port::tests::v4_list_ok` | unit |
| T-0171 | `…::testValidValueIpv6` | `[::1]:2056` | sensr-schema | `fields::ip_port::tests::v6_ok` | unit |
| T-0172 | `…::testValidValueAsListIpv6` | `[::1]:2056,[fe80::]:1111` | sensr-schema | `fields::ip_port::tests::v6_list_ok` | unit |
| T-0173 | `…::testInvalidValueIpv4` | `abcdefg` throws | sensr-schema | `fields::ip_port::tests::garbage_rejected` | unit |
| T-0174 | `…::testValidHostname` | `HostnameAllowed=Y`: `abcdefg:123`; list needs `AsList`; missing port needs `PortOptional` | sensr-schema | `fields::ip_port::tests::hostname_rules` | unit |
| T-0175 | `…::testValidPortOptional` | `[::1]` without port rejected even when optional; `[foobar]`, `[foobar]:123` rejected; `foobar:123` ok only if hostnames allowed | sensr-schema | `fields::ip_port::tests::port_optional_bracket_rules` | unit |
| T-0176 | `…::testInvalidValueAsListIpv4` | `127.0.0.1:2056,abcdefg` throws | sensr-schema | `fields::ip_port::tests::v4_list_garbage_rejected` | unit |
| T-0177 | `…::testInvalidValueIpv6` | `[::1]` throws | sensr-schema | `fields::ip_port::tests::v6_no_port_rejected` | unit |
| T-0178 | `…::testInvalidValueAsListIpv6` | `[::1]:2056,[fe80::]` throws | sensr-schema | `fields::ip_port::tests::v6_list_no_port_rejected` | unit |
| T-0179 | `…::testAddressFamilyIpv4` | family ipv4 rejects v6 | sensr-schema | `fields::ip_port::tests::family_v4_only` | unit |
| T-0180 | `…::testAddressFamilyIpv6` | family ipv6 rejects v4 | sensr-schema | `fields::ip_port::tests::family_v6_only` | unit |
| T-0181 | `ModelRelationFieldTest::testCanBeCreated` | constructs; fixture `tests/OPNsense/TestModel/simpleList/items` 6 uuids numbered 1..6 | sensr-schema | `fields::relation::tests::fixture_loads` | unit |
| T-0182 | `…::testSetSingleOk` | one valid uuid ok | sensr-schema | `fields::relation::tests::single_ok` | unit |
| T-0183 | `…::testSetMultipleNok` | two uuids, multiple=N → Callback | sensr-schema | `fields::relation::tests::single_rejects_list` | unit |
| T-0184 | `…::testSetNoneOk` | `''` optional ok | sensr-schema | `fields::relation::tests::none_optional_ok` | unit |
| T-0185 | `…::testSetNoneNok` | `''` required → PresenceOf | sensr-schema | `fields::relation::tests::none_required_fails` | unit |
| T-0186 | `…::testSetNoneMultiNok` | `'',uuid` multi → Callback | sensr-schema | `fields::relation::tests::empty_element_in_multi_fails` | unit |
| T-0187 | `…::testSetNoneBlankDescOk` | multi + BlankDesc, `''` ok | sensr-schema | `fields::relation::tests::blank_desc_empty_ok` | unit |
| T-0188 | `…::testSetNoneBlankDescNok` | BlankDesc + `Not an option` → Callback | sensr-schema | `fields::relation::tests::blank_desc_unknown_fails` | unit |
| T-0189 | `…::testSetNoneBlankDescSingleOk` | BlankDesc + valid uuid ok | sensr-schema | `fields::relation::tests::blank_desc_single_ok` | unit |
| T-0190 | `…::testSetNoneBlankDescValueOk` | node data `""` → `{value:"No selection.", selected:true}` | sensr-schema | `fields::relation::tests::blank_desc_option_payload` | unit |
| T-0191 | `…::testSetNoneBlankDescBlankValueOk` | BlankDesc `""` → `{value:"None", selected:true}` | sensr-schema | `fields::relation::tests::blank_desc_default_none` | unit |
| T-0192 | `…::testSetSingleNok` | malformed uuid → Callback | sensr-schema | `fields::relation::tests::bad_uuid_fails` | unit |
| T-0193 | `…::testSetMultiOk` | multi two valid ok | sensr-schema | `fields::relation::tests::multi_ok` | unit |
| T-0194 | `…::testSetMultiNok` | multi one bad → Callback | sensr-schema | `fields::relation::tests::multi_one_bad_fails` | unit |
| T-0195 | `…::testSetMultiNoNok` | multiple=N explicit, two valid → Callback | sensr-schema | `fields::relation::tests::explicit_single_rejects_list` | unit |
| T-0196 | `…::testSortedOk` | `Sorted=Y`: selected items first, in input order (index assertions) | sensr-schema | `fields::relation::tests::sorted_selected_first` | unit |
| T-0197 | `…::testSortedNoneOk` | single `''` sorting unchanged | sensr-schema | `fields::relation::tests::sorted_none_unchanged` | unit |
| T-0198 | `…::testSortedNoneWithMultipleOk` | multi with `''` element: index positions as fixture | sensr-schema | `fields::relation::tests::sorted_with_empty_element` | unit |
| T-0199 | `…::testSortedSelectAllOk` | all selected keeps model order | sensr-schema | `fields::relation::tests::sorted_all_selected` | unit |
| T-0200 | `…::testSortedSelectSomeOrderedOk` | `d1e7,4d0e,60e1,` → those first, rest model order | sensr-schema | `fields::relation::tests::sorted_some_ordered` | unit |
| T-0201 | `…::testSortedSelectSomeUnorderedOk` | `60e1,48be,4d0e,` input order preserved | sensr-schema | `fields::relation::tests::sorted_some_unordered` | unit |
| T-0202 | `…::testSortedSelectSomeInvalidOk` | invalid uuid ignored in sort | sensr-schema | `fields::relation::tests::sorted_ignores_invalid` | unit |
| T-0203 | `…::testIsContainer` | not container | sensr-schema | `fields::relation::tests::not_container` | unit |
| T-0204 | `NetworkAliasFieldTest::testCanBeCreated` | constructs; fixture ifaces + aliases `geoip_NL,network_alias,external_alias,host_alias,urltable_alias,port_alias` | sensr-schema | `fields::net_or_alias::tests::fixture_loads` | unit |
| T-0205 | `…::testDefaultsExists` | `any`, `(self)` ok | sensr-schema | `fields::net_or_alias::tests::builtin_tokens` | unit |
| T-0206 | `…::testConfigItemsExists` | `opt1`, `opt1ip`, address aliases ok | sensr-schema | `fields::net_or_alias::tests::interface_and_alias_tokens` | unit |
| T-0207 | `…::testValidHosts` | v4, v4/24, full v6, v6/32 ok | sensr-schema | `fields::net_or_alias::tests::literal_networks_ok` | unit |
| T-0208 | `…::testInvalidHosts` | `192.168.0.999`, `/64` on v4, `xxxx` hextet, `/300` | sensr-schema | `fields::net_or_alias::tests::literal_networks_bad` | unit |
| T-0209 | `…::testConfigItemsNotExists` | `enc0ip` (virtual iface) and `port_alias` rejected | sensr-schema | `fields::net_or_alias::tests::virtual_iface_and_port_alias_rejected` | unit |
| T-0210 | `…::testIsContainer` | not container | sensr-schema | `fields::net_or_alias::tests::not_container` | unit |
| T-0211 | `NetworkFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::network::tests::constructs` | unit |
| T-0212 | `…::testGeneric` | not container, not list | sensr-schema | `fields::network::tests::generic` | unit |
| T-0213 | `…::testRequiredEmpty` | count 0, PresenceOf | sensr-schema | `fields::network::tests::required_empty` | unit |
| T-0214 | `…::testRequiredNotEmpty` | `192.168.1.1` count 1 | sensr-schema | `fields::network::tests::required_set` | unit |
| T-0215 | `…::testValidValuesV4` | NetMaskRequired v4 `/24` | sensr-schema | `fields::network::tests::v4_with_mask` | unit |
| T-0216 | `…::testValidValuesMulti` | AsList sep `\n`, `192.168.1.1\n2000::1` → 2 values; `setValues([])`, `['','']` → 0; leading empties dropped | sensr-schema | `fields::network::tests::multi_newline_separator` | unit |
| T-0217 | `…::testValidValuesV6` | `2000::1/128`, `fe80::…/64` | sensr-schema | `fields::network::tests::v6_with_mask` | unit |
| T-0218 | `…::testInValidValuesV4` | no mask / v6 / `A` rejected for v4 | sensr-schema | `fields::network::tests::v4_bad` | unit |
| T-0219 | `…::testInValidValuesV6` | v4 / no-mask / `A` rejected for v6 | sensr-schema | `fields::network::tests::v6_bad` | unit |
| T-0220 | `…::testValidValuesStrict` | `Strict=Y`: network addresses only (`192.168.1.0/24`, `2000::0/64`) | sensr-schema | `fields::network::tests::strict_ok` | unit |
| T-0221 | `…::testInValidValuesStrict` | host bits set rejected | sensr-schema | `fields::network::tests::strict_host_bits_rejected` + `prop_strict_iff_network_address` | unit + prop |
| T-0222 | `…::testIsContainer` | not container | sensr-schema | `fields::network::tests::not_container` | unit |
| T-0223 | `OptionFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::option::tests::constructs` | unit |
| T-0224 | `…::testRequiredEmpty` | PresenceOf | sensr-schema | `fields::option::tests::required_empty` | unit |
| T-0225 | `…::testRequiredNotEmpty` | `o1` | sensr-schema | `fields::option::tests::required_set` | unit |
| T-0226 | `…::testValidValues` | `o1`,`o2` | sensr-schema | `fields::option::tests::valid` | unit |
| T-0227 | `…::testInValidValues` | `x1`,`x2` | sensr-schema | `fields::option::tests::invalid` | unit |
| T-0228 | `…::testToValidValues` | `normalizeValue()` drops unknowns; multi-select requires `Multiple=Y` | sensr-schema | `fields::option::tests::normalize_drops_unknown` | unit |
| T-0229 | `…::testIsContainer` | not container | sensr-schema | `fields::option::tests::not_container` | unit |
| T-0230 | `PortFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::port::tests::constructs` | unit |
| T-0231 | `…::testRequiredEmpty` | PresenceOf | sensr-schema | `fields::port::tests::required_empty` | unit |
| T-0232 | `…::testRequiredNotEmpty` | `80` | sensr-schema | `fields::port::tests::required_set` | unit |
| T-0233 | `…::testValidValues` | ranges+wellknown: `80`,`443`,`https`,`80-100` | sensr-schema | `fields::port::tests::valid_values` | unit |
| T-0234 | `…::testAllWellKnownValid` | every well-known name (upper-cased input) validates and lower-cases | sensr-schema | `fields::port::tests::all_well_known_names` (table from `/etc/services` subset frozen in `well_known.rs`) | unit |
| T-0235 | `…::testWhitespaceInvalid` | leading/trailing/inner spaces rejected | sensr-schema | `fields::port::tests::whitespace_rejected` | unit |
| T-0236 | `…::testValidValueList` | multiple list with ranges and names | sensr-schema | `fields::port::tests::list_ok` | unit |
| T-0237 | `…::testRangeNotExpected` | range rejected when `EnableRanges=N` | sensr-schema | `fields::port::tests::range_disabled` | unit |
| T-0238 | `…::testInValidValues` | `x1`,`x2`,`999999-88888888` | sensr-schema | `fields::port::tests::invalid_values` | unit |
| T-0239 | `…::testIsContainer` | not container | sensr-schema | `fields::port::tests::not_container` | unit |
| T-0240 | `…::testNormalizeValue` | `normalizedPort()`: `any`→``, `http`→`80`, `xxx` unchanged, `http,https` unchanged | sensr-schema | `fields::port::tests::normalized_port` | unit |
| T-0241 | `ProtocolFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::protocol::tests::constructs` | unit |
| T-0242 | `…::testRequiredEmpty` | PresenceOf | sensr-schema | `fields::protocol::tests::required_empty` | unit |
| T-0243 | `…::testRequiredNotEmpty` | `TCP` | sensr-schema | `fields::protocol::tests::required_set` | unit |
| T-0244 | `…::testValidValues` | `TCP`,`UDP`,`any`,`XXX`(AddOptions) upper-case default | sensr-schema | `fields::protocol::tests::valid_upper` | unit |
| T-0245 | `…::testValidValuesLower` | `ChangeCase=Lower`: `TcP`,`UDp`,`Any` | sensr-schema | `fields::protocol::tests::valid_lower` | unit |
| T-0246 | `…::testInvalidValues` | not required: `XX`,`YY`,`any`,`ANY`,`IPV6-ROUTE` rejected | sensr-schema | `fields::protocol::tests::invalid_incl_any_when_optional` | unit |
| T-0247 | `…::testIsContainer` | not container | sensr-schema | `fields::protocol::tests::not_container` | unit |
| T-0248 | `StrictTextFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::strict_text::tests::constructs` | unit |
| T-0249 | `…::testAllowSpacesDefault` | `foo bar\tbaz` rejected by default | sensr-schema | `fields::strict_text::tests::spaces_default_rejected` | unit |
| T-0250 | `…::testAllowSpacesEnabled` | allowed with flag | sensr-schema | `fields::strict_text::tests::spaces_enabled` | unit |
| T-0251 | `…::testAllowNewlinesDefault` | `\n\r` rejected | sensr-schema | `fields::strict_text::tests::newlines_default_rejected` | unit |
| T-0252 | `…::testAllowNewlinesEnabled` | allowed with flag | sensr-schema | `fields::strict_text::tests::newlines_enabled` | unit |
| T-0253 | `…::testAllowSpecialDefault` | `\0\v\f` rejected | sensr-schema | `fields::strict_text::tests::special_default_rejected` | unit |
| T-0254 | `…::testAllowSpecialEnabled` | allowed with flag | sensr-schema | `fields::strict_text::tests::special_enabled` | unit |
| T-0255 | `TextFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::text::tests::constructs` | unit |
| T-0256 | `…::testIsContainer` | not container | sensr-schema | `fields::text::tests::not_container` | unit |
| T-0257 | `…::testIsArrayType` | not array | sensr-schema | `fields::text::tests::not_array` | unit |
| T-0258 | `…::testIsVirtualFalse` | virtual flag default false | sensr-schema | `fields::text::tests::virtual_default_false` | unit |
| T-0259 | `…::testIsVirtualTrue` | set virtual | sensr-schema | `fields::text::tests::virtual_set` | unit |
| T-0260 | `…::testIsNotSetAndRequiredN` | `isRequired` false, `isSet` false | sensr-schema | `fields::text::tests::unset_optional` | unit |
| T-0261 | `…::testIsNotSetAndRequiredY` | required true, unset | sensr-schema | `fields::text::tests::unset_required` | unit |
| T-0262 | `…::testRequiredisSet` | set non-empty: `isSet`, node data, values, count 1 | sensr-schema | `fields::text::tests::required_set` | unit |
| T-0263 | `…::testRequiredEmpty` | count 0, PresenceOf | sensr-schema | `fields::text::tests::required_empty` | unit |
| T-0264 | `…::testEmptyValue` | `setValues([])` after set → empty, valid | sensr-schema | `fields::text::tests::set_values_empty` | unit |
| T-0265 | `…::testEmptyValueWithMask` | mask not applied to `''` | sensr-schema | `fields::text::tests::mask_skips_empty` | unit |
| T-0266 | `…::testValueWithMask` | `4bcd3fgh` vs `/^[a-z]{8}$/` → Regex | sensr-schema | `fields::text::tests::mask_fails` | unit |
| T-0267 | `…::testNonEmptyStringWithNonEmptyMask` | `abcdefgh` ok | sensr-schema | `fields::text::tests::mask_ok` | unit |
| T-0268 | `…::testIntegerStringValue` | `1234` ok | sensr-schema | `fields::text::tests::numeric_string` | unit |
| T-0269 | `…::testIntegerValue` | `setValues(['nope',1234])` → `nope`; `[1234,'nope']` → `1234`; `['']` → `''` | sensr-schema | `fields::text::tests::set_values_first_wins` | unit |
| T-0270 | `…::testIntegerValueWithMaskPass` | int 1234 vs `/^[0-9]{4}$/` ok | sensr-schema | `fields::text::tests::int_mask_ok` | unit |
| T-0271 | `…::testIntegerValueWithMaskFail` | int 1234 vs `/^[a-z]{4}$/` → Regex | sensr-schema | `fields::text::tests::int_mask_fails` | unit |
| T-0272 | `…::testValueChangeCaseUpper` | `aB cdE fgH` → upper | sensr-schema | `fields::text::tests::change_case_upper` | unit |
| T-0273 | `…::testValueChangeCaseLower` | → lower | sensr-schema | `fields::text::tests::change_case_lower` | unit |
| T-0274 | `…::testIntegerValueChangeCaseUpper` | `igb0` → `IGB0` | sensr-schema | `fields::text::tests::change_case_upper_alnum` | unit |
| T-0275 | `…::testIntegerValueChangeCaseLower` | `1024 Gigabytes` → lower | sensr-schema | `fields::text::tests::change_case_lower_alnum` | unit |
| T-0276 | `…::testValueChangeCaseUpperWithMaskMatch` | case change then mask match (upper) | sensr-schema | `fields::text::tests::upper_then_mask_ok` | unit |
| T-0277 | `…::testValueChangeCaseLowerWithMaskMatch` | lower then mask match | sensr-schema | `fields::text::tests::lower_then_mask_ok` | unit |
| T-0278 | `…::testValueChangeCaseUpperWithMaskFail` | mask checked **after** case change → Regex | sensr-schema | `fields::text::tests::mask_after_case_change` | unit |
| T-0279 | `…::testAllowSpacesDefault` | spaces allowed by default | sensr-schema | `fields::text::tests::spaces_default_ok` | unit |
| T-0280 | `…::testAllowSpacesDisabled` | `AllowSpaces=N` rejects | sensr-schema | `fields::text::tests::spaces_disabled` | unit |
| T-0281 | `…::testAllowNewlinesDefault` | newlines allowed by default | sensr-schema | `fields::text::tests::newlines_default_ok` | unit |
| T-0282 | `…::testAllowNewlinesDisabled` | rejects with flag | sensr-schema | `fields::text::tests::newlines_disabled` | unit |
| T-0283 | `…::testAllowSpecialDefault` | `\0\v\f` allowed by default | sensr-schema | `fields::text::tests::special_default_ok` | unit |
| T-0284 | `…::testAllowSpecialDisabled` | rejects with flag | sensr-schema | `fields::text::tests::special_disabled` | unit |
| T-0285 | `UpdateOnlyTextFieldTest::testCanBeCreated` | constructs | sensr-schema | `fields::update_only::tests::constructs` | unit |
| T-0286 | `…::testBasicExtensions` | `(string)` always `''` (never echoed), `getValue()` keeps last non-empty; empty set does not overwrite; mask still validated | sensr-schema | `fields::update_only::tests::write_only_semantics` | unit |
| T-0287 | `VirtualIPFieldTest::testCanBeCreated` | constructs; fixture 4 VIPs (ipalias/other/carp×2) | sensr-schema | `fields::vip_ref::tests::fixture_loads` | unit |
| T-0288 | `…::testCarp` | type carp lists `10.100.0.10` not `172.11.1.0` | sensr-schema | `fields::vip_ref::tests::filter_carp` | unit |
| T-0289 | `…::testIPAlias` | ipalias lists `172.11.1.0` | sensr-schema | `fields::vip_ref::tests::filter_ipalias` | unit |
| T-0290 | `…::testOther` | other lists `10.207.0.1` | sensr-schema | `fields::vip_ref::tests::filter_other` | unit |
| T-0291 | `…::testIsContainer` | not container | sensr-schema | `fields::vip_ref::tests::not_container` | unit |
| T-0292 | `CaptivePortal/FieldTypes/OriginFieldTest::testValidOrigins` | scheme+host[:port], IPv4, bracketed IPv6, comma list | sensr-services (captiveportal) | `captiveportal::origin::tests::valid` | unit |
| T-0293 | `…::testInvalidOrigins` | no scheme, ftp, userinfo, trailing `/`, path, query, fragment rejected | sensr-services | `captiveportal::origin::tests::invalid` | unit |
| T-0294 | `…::testNormalizeOrigin` | lower-case scheme/host, strip default ports 443/80, lower-case IPv6, `null`→None | sensr-services | `captiveportal::origin::tests::normalize` | unit |
| T-0295 | `…::testStoresNormalizedOrigins` | stored value is normalized list | sensr-services | `captiveportal::origin::tests::stores_normalized` | unit |
| T-0296 | `Dnsmasq/FieldTypes/HostnameFieldTest::testCanBeCreated` | constructs | sensr-services (dnsmasq) | `dnsmasq::hostname::tests::constructs` | unit |
| T-0297 | `…::testIsContainer` | not container | sensr-services | `dnsmasq::hostname::tests::not_container` | unit |
| T-0298 | `…::testRequiredEmpty` | throws | sensr-services | `dnsmasq::hostname::tests::required_empty` | unit |
| T-0299 | `…::testRequiredNotEmpty` | `example` | sensr-services | `dnsmasq::hostname::tests::required_set` | unit |
| T-0300 | `…::testAsList` | `test,host123` needs `AsList=Y`; data becomes array | sensr-services | `dnsmasq::hostname::tests::as_list` | unit |
| T-0301 | `…::testValidLabels` | `test`,`host123`,`valid-name`,`a1_b2`,`1a-2b` | sensr-services | `dnsmasq::hostname::tests::valid_labels` | unit |
| T-0302 | `…::testInvalidLabels` | `-bad`,`_bad`,`bad!`, 64-char label | sensr-services | `dnsmasq::hostname::tests::invalid_labels` + `prop_label_len_le_63` | unit + prop |
| T-0303 | `…::testInvalidDomain` | `IsDomain=Y`, 256 chars rejected | sensr-services | `dnsmasq::hostname::tests::domain_len_le_255` | unit |
| T-0304 | `…::testWildcardAllowed` | `*` only with flag | sensr-services | `dnsmasq::hostname::tests::wildcard_flag` | unit |
| T-0305 | `…::testLegacyXML` | `LegacyXML=Y` accepts `<aliases><item><host>www<domain>example.com` → contains `www.example.com` | sensr-import-opnsense | `dnsmasq::tests::legacy_alias_xml_joined` | unit |
| T-0306 | `Interfaces/NetworkInterfaceTest::testSingleChange` | change `lan.mtu` → todo file JSON has exactly key `lan` (change tracking for apply) | sensr-net | `interfaces::tests::changed_set_single_interface` | unit |
| T-0307 | `Kea/FieldTypes/KeaOptionDataFieldTest::testCanBeCreated` | constructs | sensr-services (kea) | `kea::option_data::tests::constructs` | unit |
| T-0308 | `…::testIsContainer` | not container | sensr-services | `kea::option_data::tests::not_container` | unit |
| T-0309 | `…::testEncodeHex` | `aa11ff` → `AA11FF` | sensr-services | `kea::option_data::tests::hex` | unit |
| T-0310 | `…::testEncodeIpv4` | `192.168.1.1` → `C0A80101`; two addrs (space tolerated) concatenated | sensr-services | `kea::option_data::tests::ipv4` | unit |
| T-0311 | `…::testEncodeIpv6` | `2001:db8::1` → 32 hex; two addrs → 64 | sensr-services | `kea::option_data::tests::ipv6` | unit |
| T-0312 | `…::testEncodeUInt` | uint8/16/32 of 255 → `FF`/`00FF`/`000000FF` | sensr-services | `kea::option_data::tests::uint` | unit |
| T-0313 | `…::testEncodeInt32` | int32 `1`/`-1` → `pack('l')` hex (host endian in PHP; sensr pins **big-endian** per Kea docs and documents the deviation) | sensr-services | `kea::option_data::tests::int32_be` | unit |
| T-0314 | `…::testEncodeBoolean` | `true/1` → `01`, `false/0` → `00` | sensr-services | `kea::option_data::tests::boolean` | unit |
| T-0315 | `…::testEncodeString` | `hello` → `68656C6C6F` | sensr-services | `kea::option_data::tests::string` | unit |
| T-0316 | `…::testEncodeFqdn` | length-prefixed labels + `00` | sensr-services | `kea::option_data::tests::fqdn` | unit |

### 2.4 Python unittests (`core/src/opnsense/`)

Fixtures: `service/tests/config/config.xml` (wan dhcp/dhcp6 with adv_dhcp*,
lan `10.211.55.100/24` track6, opt1, one empty filter rule),
`scripts/unbound-dnsbl/tests/dnsbl.json` (domains `block.{1,2}.local`,
`wildcard.{1,2}.local`, `0.beer`; policies `580e7f8b…` nets
`10.0.0.0/24,10.0.1.0/24,0::0/24` passlist `^always_allow\..*|.*localhost$`,
`709af075…` catch-all). `service/tests/core.py` uses an in-file `DummySocket`
with a fake `xucred` and the **real** `conf/actions.d`.

| ID | OPNsense test | Verifies | sensr crate | sensr test | Kind |
|---|---|---|---|---|---|
| T-0317 | `service/tests/core.py TestCoreMethods::test_escape_sequence` | reply to unknown command ends with `\n\0\0\0` | sensr-apply | `ipc::tests::reply_terminator` (typed IPC frame terminator) | unit |
| T-0318 | `…::test_command_unknown` | first line `Action not allowed or missing` | sensr-apply | `actions::tests::unknown_action_error` | unit |
| T-0319 | `…::test_configd_actions` | `configd actions json` lists >10 actions from real action files | sensr-apply | `actions::tests::registry_lists_all_builtin_actions` (asserts count == registered, > 10) | unit |
| T-0320 | `service/tests/template.py TestConfigMethods::test_type` | config parses to ordered dict | sensr-import-opnsense | `xml::tests::service_fixture_parses` | unit |
| T-0321 | `…::test_interface` | `interfaces.lan.ipaddr` present | sensr-import-opnsense | `xml::tests::service_fixture_lan_ipaddr` | unit |
| T-0322 | `TestTemplateMethods::test_sample` | `generate('OPNsense/Sample')` yields 4 files (upstream `Sample/` dir no longer exists — stale) | sensr-apply | `templates::tests::sample_module_renders_four_targets` (sensr ships its own `Sample` module so the test is live) | golden |
| T-0323 | `…::test_all` (`@unittest.skip`) | every `+TARGETS` destination is produced by `generate('*')` | sensr-apply | `templates::tests::all_targets_rendered` (**not skipped**: renders every module against `fixtures/full.sensr`) | golden |
| T-0324 | `scripts/filter/tests/alias_tests.py TestAliasMethods::test_parse_geoip` | GeoIP `NL` > 1000 networks (needs live DB) | sensr-rules | `alias::geoip::tests::nl_from_fixture_db` (bundled trimmed DB, exact count) | golden |
| T-0325 | `…::test_parse_arp` | MAC from live `arp -n -a` resolves to ≥1 address | sensr-rules | `alias::mac::tests::neighbour_table_lookup` (mock netlink neighbour table) | unit |
| T-0326 | `…::test_parse_asn` | AS13335 > 1000 networks (downloads asn.csv) | sensr-rules | `alias::asn::tests::as13335_from_fixture` | golden |
| T-0327 | `…::test_parse_interface` | add `2001:fff:faaa::4f31` on lo0, `::1005` suffix → `2001:0fff:faaa::1005/128` | sensr-rules | `alias::dynipv6::tests::prefix_plus_host_suffix` (pure function) + `nix/tests/alias-dynipv6.nix` (real interface) | unit + vm |
| T-0328 | `…::test_parse_uri` | spamhaus DROP > 100 entries (live HTTP) | sensr-rules | `alias::uri::tests::parse_drop_fixture` (recorded body) + `alias::uri::tests::http_fetch_with_auth` (wiremock) | golden |
| T-0329 | `…::test_host_address` | `192.168.1.1` → itself; `192.999.1.1` → none | sensr-rules | `alias::parse::tests::host_address` | unit |
| T-0330 | `…::test_host_network` | `/24` kept; bad octet → none | sensr-rules | `alias::parse::tests::host_network` | unit |
| T-0331 | `…::test_host_name` | hostname deferred to DNS; `resolve_dns()` > 1 result (live DNS) | sensr-rules | `alias::dns::tests::hostname_deferred_then_resolved` (hickory mock resolver, A+AAAA, CNAME follow, NXDOMAIN tolerated) | unit |
| T-0332 | `…::test_wildcard` | `192.168.0.0/0.0.255.0` → 256 networks | sensr-rules | `alias::parse::tests::wildcard_mask_expansion` + `prop_wildcard_count_is_pow2` | unit + prop |
| T-0333 | `…::test_external_alias_not_managed` | `type=external` → `is_managed()` false | sensr-rules | `alias::tests::external_is_unmanaged` | unit |
| T-0334 | `scripts/unbound-dnsbl/tests/dnsbl_tests.py TestDNSBLMethods::test_construct_query` | `Query` tuple fields + int timestamp | sensr-services (unbound-dnsbl) | `dnsbl::tests::query_construct` | unit |
| T-0335 | `…::test_net_matches` | client in policy nets → policy `580e7f8b…` for exact and wildcard domains | sensr-services | `dnsbl::tests::net_matches_policy` | unit |
| T-0336 | `…::test_net_wildcard_matches` | subdomain wildcard match; `always_allowx.` does **not** hit passlist | sensr-services | `dnsbl::tests::wildcard_and_passlist_boundary` | unit |
| T-0337 | `…::test_all_net_matches` | client outside nets → catch-all policy `709af075…` | sensr-services | `dnsbl::tests::catch_all_policy` | unit |
| T-0338 | `…::test_passlist_net` | `always_allow.wildcard.2.local` → no match | sensr-services | `dnsbl::tests::passlist_exempts` | unit |
| T-0339 | `logger_tests.py TestLoggerMethods::test_disabled` | no `stats` file → stats disabled | sensr-services | `dnsbl::logger::tests::stats_disabled_without_marker` | unit |
| T-0340 | `…::test_enabled` | `stats` file → enabled | sensr-services | `dnsbl::logger::tests::stats_enabled_with_marker` | unit |
| T-0341 | `utils_tests.py TestUtilsMethods::test_obj_path_exists_true` | dotted attribute path exists | sensr-services | `dnsbl::util::tests::path_exists` | unit |
| T-0342 | `…::test_obj_path_exists_false` | missing path false | sensr-services | `dnsbl::util::tests::path_missing` | unit |

### 2.5 Build-time lint / style / sweep / packaging checks (`core/Mk/*.mk`, `core/Makefile`, `plugins/Mk/*.mk`, `tools/`)

| ID | OPNsense check | Verifies | sensr equivalent | Kind |
|---|---|---|---|---|
| T-0343 | `lint-plist` (`Mk/lint.mk`) | committed `plist` equals generated package file list | `nix flake check`: `pkgs.sensr` closure manifest diff vs `nix/manifest.lock` (`xtask lint-manifest`) | lint |
| T-0344 | `lint-desc` | `pkg-descr` exists when `PLUGIN_DESC` defined | `xtask lint-plugin-manifest`: every plugin crate has `plugin.toml` with description + changelog | lint |
| T-0345 | `lint-shell` (shebang) | every `*.sh` starts with `#!` | `xtask lint-shell` over `nix/` and `scripts/` | lint |
| T-0346 | `lint-shell` (`sh -n`) | shell syntax | `shellcheck` + `sh -n` in `xtask lint-shell` | lint |
| T-0347 | `lint-xml` | every `*.xml*` is well-formed (`xmllint --noout`) | `xtask lint-fixtures`: every fixture XML parses with quick-xml; every `.sensr` fixture parses | lint |
| T-0348 | `lint-model` rule 1 | `<description/>` present, single line | `#[derive(SensrModel)]` compile error if `#[sensr(description = …)]` missing/multiline | lint |
| T-0349 | `lint-model` rule 2 | no `Default` on non-required field ("spurious default") | derive macro rejects `#[sensr(default)]` without `required` | lint |
| T-0350 | `lint-model` rule 3 | no empty `Default` | derive macro rejects `default = ""` | lint |
| T-0351 | `lint-model` rule 4 | `BlankDesc` must not be `None` (the default) | derive macro rejects `blank_desc = "None"` | lint |
| T-0352 | `lint-model` rule 5 | no `BlankDesc` on required field | derive macro rejects `blank_desc` + `required` | lint |
| T-0353 | `lint-model` rule 6 | no `BlankDesc` on multiple field | derive macro rejects `blank_desc` + `multiple` | lint |
| T-0354 | `lint-model` rule 7 | `Multiple=N` is default, must not be written | derive macro rejects `multiple = false` | lint |
| T-0355 | `lint-model` rule 8 | `Required=N` is default | derive macro rejects `required = false` | lint |
| T-0356 | `lint-model` rule 9 | option elements `default/multiple/required` must carry `value=` | enum-backed options cannot collide (type system); `xtask lint-schema` checks exported JSON Schema enums | lint |
| T-0357 | `lint-model` rule 10 | `CSVListField` with `Mask` must set `MaskPerItem` | `Csv<T>` has no whole-string mask (per-item by construction); `xtask lint-schema` asserts | lint |
| T-0358 | `lint-model` rule 11 | `CSVListField` must specify a `Mask` | `Csv<T>` requires `T: FromStr` with a validator — compile-time | lint |
| T-0359 | `lint-model` rule 12 | `FieldSeparator=,` is default for list field types | derive macro rejects `separator = ","` | lint |
| T-0360 | `lint-model` rule 13 | `AsList=N` is default | derive macro rejects `as_list = false` | lint |
| T-0361 | `lint-model` rule 14 | `ValidationMessage` ends with `.` | `xtask lint-messages` over all `ValidationMessage` consts (+ `#[test] all_messages_end_with_period`) | lint |
| T-0362 | `lint-model` rule 15 | `ValidationMessage` starts upper-case | same xtask / test | lint |
| T-0363 | `lint-model` rule 16 | option key must differ from display text | `xtask lint-schema`: enum variant name ≠ label | lint |
| T-0364 | `lint-acl` (`Scripts/dashboard-acl.sh` 1) | included widget source files exist | `xtask lint-ui-widgets`: widget manifest includes resolve | lint |
| T-0365 | `dashboard-acl.sh` 2 | every widget calls ≥1 `/api/` endpoint | same xtask (static analysis of widget TS) | lint |
| T-0366 | `dashboard-acl.sh` 3 | widget has metadata entry | same xtask | lint |
| T-0367 | `dashboard-acl.sh` 4 | registered endpoints == endpoints used in source | same xtask | lint |
| T-0368 | `dashboard-acl.sh` 5 | every endpoint matches an ACL `<pattern>` (exact or wildcard parent) | `sensr-auth::acl::tests::every_route_has_privilege` (iterates axum router of `sensr-api` + `sensr-api-compat`) | lint |
| T-0369 | `lint-class` (`Scripts/class-filename.sh`) | PHP class name == file name; warn on extra classes | Rust module system (`mod` ↔ file) + `clippy::module_inception`; N/A otherwise | lint |
| T-0370 | `lint-import` (`Scripts/class-import.sh`) | no stale `use` imports | `rustc` `unused_imports` with `-D warnings` | lint |
| T-0371 | `lint-exec` (perm) | files in `rc.d`, `rc.syshook.d`, `scripts/*` are executable | `xtask lint-exec`: `nix/hooks/**` and `scripts/**` mode `+x` | lint |
| T-0372 | `lint-exec` (grep) | no raw `exec(`/`shell_exec(`/`passthru(`/`system(` outside allow-list | `clippy.toml` `disallowed-methods` for `std::process::Command::new` outside `sensr-apply::cmd` + `xtask lint-exec` | lint |
| T-0373 | `lint-php` (`parallel-lint`) | PHP syntax | `cargo check --workspace --all-targets` | lint |
| T-0374 | `style-python` (`pycodestyle --ignore=E501`) | PEP8 for python | `ruff` on any remaining Python (`nix/tests/*.py` drivers) | lint |
| T-0375 | `style-php` (`phpcs --standard=ruleset.xml`, PSR-12) | PHP style | `cargo fmt --check` + `cargo clippy -D warnings` | lint |
| T-0376 | `sweep-whitespace` (`Scripts/cleanfile`) | strip trailing whitespace, normalise tabs, single final newline, no trailing blank lines | `xtask lint-whitespace` (check mode of the same normaliser; `editorconfig-checker`) | lint |
| T-0377 | `sweep-model` | canonical model XML formatting / tag casing | `cargo fmt` covers Rust; `xtask fmt-fixtures` canonicalises XML/JSON fixtures, check mode in CI | lint |
| T-0378 | `sweep-php` (`phpcbf`) | auto-fix style | `cargo fmt` (check mode in CI) | lint |
| T-0379 | `manifest-check` (`Makefile`) | every `%%REPLACEMENT%%` appears in `version/core.in` | `xtask lint-version`: `sensr-version.json` template contains every key the build injects | lint |
| T-0380 | `package-check` | refuse to package while a live mount is active | N/A (Nix builds are pure); `nix flake check` ensures no impure inputs | lint |
| T-0381 | `upgrade-check` | installed package exists and version differs before in-place upgrade | `sensr upgrade` refuses same-generation switch; `nix/tests/upgrade.nix` | vm |
| T-0382 | `make validate` (`pluginctl -v` → `run_validations.php`) | every non-volatile model validates against the live config | `sensr config validate` + `sensr-config::tests::every_fixture_validates` over corpus | unit |
| T-0383 | `make migrate` (`pluginctl -m` → `run_migrations.php`) | all models migrate to current version, report `Migrated/Failed/Left unversioned` | `sensr config migrate --dry-run` + `sensr-schema::migrate::tests::corpus_migrates_to_head` | unit |
| T-0384 | `make test` | phpunit runner, cleans `.phpunit.result.cache` | `cargo nextest run --workspace` in `nix flake check` | lint |
| T-0385 | plugins `check` (`Mk/plugins.mk`) | `PLUGIN_NAME/VERSION/COMMENT` set | `xtask lint-plugin-manifest`: `plugin.toml` required keys | lint |
| T-0386 | plugins `test` | run phpunit if a plugin ships `TESTDIR` (no upstream plugin does) | every plugin crate has at least one `#[test]`; `xtask lint-plugin-tests` fails on zero tests | lint |
| T-0387 | `tools/build/test.sh` `pkg check -da` | missing dependencies in installed packages | `nix flake check` (closure completeness by construction) + `nix/tests/selftest.nix` `systemctl --failed` empty | vm |
| T-0388 | `tools/build/test.sh` `pkg check -sa` | installed file checksums match package | `nix-store --verify --check-contents` in `nix/tests/selftest.nix` | vm |
| T-0389 | `tools/Makefile lint-steps` | `sh -n` every build step script | `xtask lint-shell` over `nix/` scripts | lint |
| T-0390 | `tools/Makefile lint-composite` | `sh -n` every composite script | same | lint |

### 2.6 Boot/upgrade self-tests and plugin runtime checks

| ID | OPNsense check | Verifies | sensr equivalent | Kind |
|---|---|---|---|---|
| T-0391 | `rc.syshook.d/early/99-selftest` 1 | core package name determinable (`opnsense-version -n`) | `sensr-selftest`: `/etc/sensr/version.json` parses, `product_id == "sensr"` | vm |
| T-0392 | `99-selftest` 2 | package manager binary present | N/A → replaced by: current generation symlink resolves (`/run/current-system`) | vm |
| T-0393 | `99-selftest` 3 | core package known to pkg DB | current closure contains `sensrd` store path recorded in `version.json` | vm |
| T-0394 | `99-selftest` 4 | `pkg` from trusted repo | Nix signature check of the system closure (`nix store verify --trusted-public-keys`) | vm |
| T-0395 | `99-selftest` 5 | core from trusted repo | same as T-0394 (single closure) | vm |
| T-0396 | `99-selftest` 6 | `pkg check -danq` no missing deps | `systemctl is-system-running` ∈ {running, degraded-with-known-units} and `nix-store -qR` complete | vm |
| T-0397 | `99-selftest` 7 | base and kernel version == `opnsense-update -v` | kernel `uname -r` equals `version.json.kernel`; initrd generation equals system generation | vm |
| T-0398 | `99-selftest` 8 | `*.mtree` for base/kernel present | `dm-verity`/`nix-store --verify` metadata present for image builds | vm |
| T-0399 | `99-selftest` 9 | `.mtree.sig` verifies (`opnsense-verify`) | verity root hash matches signed `image.json` | vm |
| T-0400 | `99-selftest` 10 | `pkg check -qs lighttpd openssl openssh opnsense-update` | `nix-store --verify --check-contents` for the web, TLS, ssh and updater closure paths | vm |
| T-0401 | `99-selftest` 11 | `pluginctl -g OPNsense` returns a JSON object (PHP + config operational) | `sensr config get / --json` returns an object before `sensr-apply` starts | vm |
| T-0402 | `rc.syshook.d/upgrade/10-sanity.sh` 1 | core package name determinable | `sensr upgrade --check`: version file parses | vm |
| T-0403 | `10-sanity.sh` 2 | package manager present | `nix` binary present and daemon reachable | vm |
| T-0404 | `10-sanity.sh` 3 | core package known to DB | current generation in `nix-env --list-generations -p /nix/var/nix/profiles/system` | vm |
| T-0405 | `10-sanity.sh` 4 | `pkg` from product repo | substituter + trusted key configured as `nix.settings` expects | vm |
| T-0406 | `plugins/www/nginx/…/ngx_testConfig.sh` | `nginx -t` on rendered config, "config is ok" | `sensr-services::nginx::tests::rendered_config_passes_nginx_t` (golden + `nginx -t` in sandbox) | golden + vm |
| T-0407 | `plugins/www/web-proxy-sso/…/kerberos_test.sh` | `kinit` + `negotiate_kerberos_auth` round trip for Squid SSO | `nix/tests/squid-kerberos.nix` (MIT KDC in VM, SPNEGO probe) | vm |
| T-0408 | `plugins/security/etpro-telemetry/testdata/*` | sample `rule-updater.config` + `eve.json` for manual `send_telemetry.py -c -l` runs | `sensr-services::ids::telemetry::tests::eve_sample_parses_and_batches` (same two files as fixtures, automated) | golden |

## 3. Totals

| Category | OPNsense count | IDs | Notes |
|---|---|---|---|
| PHPUnit test classes | 35 (+ `Field_Framework_TestCase`, `TestModel`, `UniqueTestContainer` helpers) | — | all under `core/src/opnsense/mvc/tests/app` |
| PHPUnit test methods | **316** declared = 315 executed + 1 `@group Ignore` | T-0001 – T-0316 | per-file counts: BaseModel 31, TextField 30, ModelRelation 23, IPPort 17, ComparedToField 13, Network 12, Hostname 11, Port 11, ACL 10, Country 10, InterfaceField 10, Dnsmasq Hostname 10, KeaOptionData 10, AuthServer 8, Cert 8, Integer 8, AuthGroup 7, Boolean 7, NetworkAlias 7, Option 7, Protocol 7, StrictText 7, Unique 7, Base64 6, Email 6, AutoNumber 5, VirtualIP 5, Config 4, CSVList 4, Origin 4, FilterRule 3, Idassoc 3, UpdateOnly 2, Shell 1, NetworkInterface 1, Field_Framework 1 |
| PHPUnit fixture files | 22 | folded into the rows above | 3 `.conf` (pf rule goldens), 11 `config.xml`, 2 `backup/*.xml` (array/object), `TestModel.{php,xml}` + 3 migrations, `AclConfig/config.xml` |
| Python unittest methods | **26** = 25 executed + 1 `@unittest.skip` | T-0317 – T-0342 | configd 3, template 4, alias 10, dnsbl 5, logger 2, utils 2; 6 alias tests need live network/root upstream, hermetic in sensr |
| Python fixtures | 2 | folded | `service/tests/config/config.xml`, `unbound-dnsbl/tests/dnsbl.json` (+ real `conf/actions.d`) |
| Build-time lint/style/sweep/packaging checks | **48** | T-0343 – T-0390 | `lint-model` expanded into its 16 XPath rules, `dashboard-acl.sh` into its 5 checks |
| Boot/upgrade self-tests | **15** | T-0391 – T-0405 | `99-selftest` 11 checks, `10-sanity.sh` 4 checks |
| Plugin runtime checks / sample data | **3** | T-0406 – T-0408 | nginx config test, kerberos SSO probe, etpro telemetry testdata |
| **Grand total** | **408 checklist items** | **T-0001 – T-0408** | |

sensr kinds across the 408 rows: unit 334 (327 plain, 6 with an additional
property test, 1 with an additional VM test), golden 12 (1 also VM-backed),
vm 19, lint 43. Several lint rows map to the same `xtask` or to the type
system; each still gets its own ID so parity is auditable.

Known upstream oddities carried into the mapping (do **not** "fix" silently):
`AuthGroupFieldTest::testConfigItemsExists` asserts gid 100 twice (we assert
100/101/102); `ComparedToFieldConstraintTest` "gt_and_no_error" uses `lt`
(we keep the behaviour, rename the test); `KeaOptionDataFieldTest::testEncodeInt32`
depends on host endianness (sensr pins big-endian, Kea's wire format);
`template.py::test_sample` references a deleted `Sample` template (sensr ships
one); `test_all` is skipped upstream (sensr runs it).

## 4. Test categories sensr needs that OPNsense lacks

OPNsense's suite covers field validation and a sliver of rule rendering; it
has no integration, API, migration, import or image tests in the repository
(upstream relies on manual QA on the release candidate). sensr adds:

### 4.1 NixOS VM integration (`nix/tests/*.nix`, `nixosTest`)
- `boot-first-run.nix`: fresh image boots, `sensr-selftest` passes (T-0391…),
  default config applied, LAN gets DHCP+DNS, WAN blocked, anti-lockout works.
- `firewall-policy.nix`: 3-node (wan-host, sensr, lan-host) topology; asserts
  default deny, user pass rule, NAT outbound, port forward, reject vs drop,
  logging produces structured journal entries with rule labels.
- `aliases.nix`: URL table served by a VM HTTP server, GeoIP fixture, nested
  aliases, TTL expiry and `alias_util` compat endpoints.
- `ha.nix`: two sensr nodes, VRRP failover, config section sync via compat
  XML-RPC and native API, conntrackd state carry-over of a TCP session.
- `services/*.nix`: unbound, kea (v4 lease to lan-host), dnsmasq, chrony,
  wireguard tunnel to peer VM, strongswan IKEv2, openvpn, syslog remote.
- `upgrade.nix`: generation N → N+1 switch with config migration, rollback.
- `selftest.nix`, `squid-kerberos.nix`, `alias-dynipv6.nix` (from §2.6).

### 4.2 Config migration round-trips (`sensr-schema`, `sensr-config`)
- For every `Migration`: `before.json` → migrate → equals `after.json`; then
  `after.json` validates at head; property: migrating an already-migrated doc
  is a no-op (idempotence); chain from every historical schema version in
  `corpus/versions/*.sensr` reaches head.
- `sensr config migrate --dry-run` output golden per corpus file.

### 4.3 OPNsense `config.xml` import corpus (`sensr-import-opnsense`)
- Corpus: `config.xml.sample`, all 13 upstream fixture configs, factory
  configs for each OPNsense release 21.1 → 26.7 (collected from the
  `changelog` repo era boundaries), anonymised community configs.
- Per file: import succeeds, report lists zero unexpected `unmapped` nodes
  (expected ones are enumerated), resulting document validates, and
  `export` back to XML re-imports to an identical document (lossless for the
  mapped subset). Golden `import-report.txt` per corpus file.
- Differential rule test: for each corpus file, legacy `filter/rule` and MVC
  `Filter` rules → IR → `render::pf` must equal the pf text an OPNsense VM
  produces for that config (`/tmp/rules.debug` captured in the lab, stored as
  golden) — this is the strongest guarantee that we understood the semantics
  before translating them to nftables.

### 4.4 API compatibility (`sensr-api-compat`)
- Recorded request/response pairs from OPNsense 26.7 for every Tier-1 endpoint
  (search/get/add/set/del/toggle envelopes, validation error maps, option
  expansion shape), replayed with `wiremock`-style matching on structure
  (uuids and timestamps normalised).
- Auth matrix: valid key, wrong secret, disabled user, expired user, key
  without privilege → 401/403 bodies byte-identical to upstream.
- Terraform acceptance: `terraform-provider-opnsense` test suite against a
  sensr VM in CI (nightly).
- OpenAPI contract test for the native API (`sensr-api`): every route in the
  router is documented; schema drift fails CI.

### 4.5 Fuzzing (`cargo fuzz`, nightly job)
- `fuzz_config_xml` (importer), `fuzz_sensr_doc` (document parser),
  `fuzz_rule_ir_from_json`, `fuzz_alias_list_parser` (URL table bodies, JSON
  path expressions), `fuzz_nflog_record`, `fuzz_compat_request` (body parsing
  of `/api/*`), `fuzz_port_field`/`fuzz_network_field`/`fuzz_hostname_field`
  (every `FromStr` in `sensr-schema` must never panic; proptest shadows for
  the same targets run in `cargo test`).

### 4.6 Pi-shaped QEMU image tests (`nix/tests/pi/`)
- Build the aarch64 SD image, boot it under `qemu-system-aarch64` (virt
  machine with the image's u-boot/UEFI path), wait for `sensr-selftest`,
  assert first-boot provisioning, serial console login, and that the LAN
  bridge config for the Pi's `end0` + USB NIC profile applies — same shape as
  `opnsense-pi`'s `vm/test.sh`, expressed as a `nixosTest` with `qemu-user`
  fallback for x86 CI runners.

### 4.7 Golden-file discipline (cross-cutting)
- Every template module: fixture document → rendered files compared to
  `tests/golden/<module>/<file>` (`insta` snapshots, reviewed in PRs).
- Every nft ruleset: `nft -c -f` syntax check in CI plus golden text.
- Every compat endpoint: golden JSON.
- `xtask golden-update` regenerates; CI runs in check mode.

### 4.8 Property tests worth having beyond parity
- Alias dependency graph: topological resolution never loops; cycles detected.
- Rule label hash stability: same normalised rule → same label (OPNsense
  `calcRuleHash` compatibility).
- Config store: concurrent commits serialise; history never loses a revision;
  `restore(rev)` followed by `commit` yields a new revision, never rewrites.
- ACL URL matcher: `urlMatch` semantics (`*` wildcard, `.`/`?` literal,
  fragment stripped) hold for generated URLs.
