# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-08-07

### Security

- Added a recursion-depth guard on the `JsonElement` canonicalization path. Deeply-nested attacker-controlled input passed through `Canonicalize(JsonElement)` / `CanonicalizeToUtf8(JsonElement)` could previously drive unbounded recursion into a `StackOverflowException`, which is uncatchable in .NET and terminates the whole process. Nesting is now limited to 64 levels, matching the effective cap the string entry points already enforce via the `System.Text.Json` `JsonDocument` default `MaxDepth`. Input deeper than 64 levels now fails with a catchable `JcsException` (derived from `JsonException`), so `TryCanonicalize` still returns `false` without throwing. Canonical output is unchanged for all non-deep input.

## [0.1.0] - 2026-08-03

### Added

- `JsonCanonicalizer` static API: `Canonicalize(string)`, `Canonicalize(JsonElement)`, `CanonicalizeToUtf8(string)`, `CanonicalizeToUtf8(JsonElement)`, and non-throwing `TryCanonicalize`.
- Full RFC 8785 canonicalization: recursive property sorting by UTF-16 code units of the raw property name, minimal RFC-exact string escaping with lowercase hex escapes, no inter-token whitespace, UTF-8 output.
- ECMAScript `Number::toString` number serialization: shortest round-trip digits, integer notation up to 10^21, lowercase `e` exponent notation with explicit sign, negative zero collapsed to `0`.
- Strict I-JSON input validation with descriptive `JcsException` (derived from `JsonException`): invalid JSON, duplicate object member names (including escaped spellings), `NaN`/`Infinity`/out-of-range number literals, and unpaired UTF-16 surrogates (literal or escaped) are all rejected.
- Verified against the RFC 8785 appendix B number table, the RFC section 3.2.3 sorting vector, the exact section 3.2.4 output bytes, the official `cyberphone/json-canonicalization` test suite, and 10,000 committed number vectors generated from the V8 engine (plus one million randomized bit patterns during development).
- Zero runtime dependencies; built on the in-box `System.Text.Json` reader.
- SourceLink (GitHub), deterministic CI builds and `.snupkg` symbol packages.
