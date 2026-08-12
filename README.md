# Jcs.NET

RFC 8785 JSON Canonicalization Scheme (JCS) for .NET. Deterministic JSON serialization for hashing and signing. Zero external dependencies.

Two JSON documents can be semantically identical and byte-for-byte different: property order, whitespace, `1E30` vs `1e+30`, `é` vs `é`. The moment you hash or sign JSON, those differences break everything. RFC 8785 fixes this by defining a single canonical byte sequence for any JSON document. The JavaScript implementation (`canonicalize`) is downloaded millions of times a month; on NuGet there has been no maintained, RFC-verified package. Jcs.NET is that implementation: strict, test-vector-verified, and dependency-free.

Where you need it:

- Webhook signature verification (HMAC over a canonical payload instead of fragile raw-body comparison)
- JWS/JWT with unencoded or detached payloads
- Verifiable credentials and decentralized identity (JCS is the canonicalization step in several W3C proof suites)
- Audit-trail and ledger hashing, content-addressed storage, deduplication

## Install

```
dotnet add package Jcs.Net
```

## Quickstart

```csharp
using System;
using Jcs.Net;

string canonical = JsonCanonicalizer.Canonicalize("""
    {
      "numbers": [1E30, 4.50],
      "b": "2",
      "a": "1"
    }
    """);

Console.WriteLine(canonical);
// {"a":"1","b":"2","numbers":[1e+30,4.5]}
```

The API is a single static class:

| Method | Purpose |
|---|---|
| `Canonicalize(string json)` | Canonical form as a string |
| `Canonicalize(JsonElement element)` | Canonicalize an already parsed element |
| `CanonicalizeToUtf8(string json)` | Canonical UTF-8 bytes, ready for hashing or signing |
| `CanonicalizeToUtf8(JsonElement element)` | Same, from a parsed element |
| `TryCanonicalize(string? json, out string? canonical)` | Non-throwing variant; false for any invalid input |

## Signing a webhook payload

```csharp
using System;
using System.Security.Cryptography;
using Jcs.Net;

string payload = """{"amount":4500,"currency":"NGN","reference":"inv-1042"}""";
byte[] secret = "webhook-secret"u8.ToArray();

byte[] canonical = JsonCanonicalizer.CanonicalizeToUtf8(payload);
byte[] signature = HMACSHA256.HashData(secret, canonical);

Console.WriteLine(Convert.ToHexString(signature));
```

The receiver canonicalizes the body it received and recomputes the HMAC. Reordered properties, added whitespace, or re-encoded numbers no longer invalidate the signature, and any semantic change still does.

## RFC 8785 compliance

Jcs.NET implements the full specification:

- Object members sorted recursively by the UTF-16 code units of the raw (unescaped) property name (section 3.2.3), including the surrogate-pair ordering cases
- Minimal string escaping (section 3.2.2.2): only `\"`, `\\`, the short escapes `\b` `\t` `\n` `\f` `\r`, and lowercase `\u00xx` for the remaining control characters; everything else, including non-ASCII, is emitted literally
- ECMAScript `Number::toString` serialization for numbers (section 3.2.2.3)
- No inter-token whitespace, UTF-8 output (sections 3.2.1, 3.2.4)

The library is strict about input, because a canonicalizer that silently accepts ambiguous data produces hashes you cannot trust. It rejects, with a descriptive `JcsException` (derived from `JsonException`):

| Rejected input | Why |
|---|---|
| Invalid JSON | Only well-formed JSON has a canonical form |
| Duplicate object member names, including escaped spellings such as `{"a":1,"a":2}` | I-JSON (RFC 7493) forbids them; accepting either order would let two different documents share a hash (section 3.1) |
| `NaN`, `Infinity`, and number literals outside IEEE 754 double range such as `1e400` | Not representable in JSON interchange (section 3.2.2.3) |
| Unpaired UTF-16 surrogates, literal or escaped (`"\uDEAD"`) | The RFC requires termination with an error because such data breaks signatures (section 3.2.2.2) |
| Nesting deeper than 64 levels | Bounds recursion so hostile deeply-nested input fails with a catchable `JcsException` rather than crashing the process |

Verified against the RFC 8785 appendix examples and the official test suite from the RFC author's repository (`cyberphone/json-canonicalization`), including exact output bytes.

## Numbers follow ECMAScript, not .NET

RFC 8785 requires numbers to serialize exactly as JavaScript's `Number::toString` would. That format differs from every stock .NET format (`"R"` gives `1E+30`, exponent thresholds differ, negative zero survives). Jcs.NET implements the ECMAScript algorithm and verifies it against 10,000 committed test vectors generated from the V8 engine, plus the RFC appendix table. A further one million randomized IEEE 754 bit patterns were verified against V8 during development with zero mismatches.

Samples of what conformance actually means:

| JSON input | Canonical output | Note |
|---|---|---|
| `1000000000000000000000` | `1e+21` | Integer notation ends at 10^21, exactly as in ECMAScript |
| `999999999999999900000` | `999999999999999900000` | One ulp below the boundary stays in integer notation |
| `0.0000001` | `1e-7` | Decimal notation ends below 10^-6 |
| `1424953923781206.25` | `1424953923781206.2` | Shortest round-trip digits with round-half-to-even |
| `-0` | `0` | Negative zero collapses to zero |

## Notes and limitations

- Nesting depth is capped at 64 levels on both entry points. The string overloads inherit the `System.Text.Json` `JsonDocument` default of 64; the `JsonElement` overloads enforce the same limit directly, so input nested deeper than 64 is rejected with a catchable `JcsException` (never an uncatchable `StackOverflowException`), even when the caller parsed the element with an elevated `MaxDepth`.
- The `JsonElement` overloads reject lone surrogates on the `JsonDocument.Parse` path: `System.Text.Json` parses such escapes lazily, and when Jcs.NET reads the value or property name the failure is translated into a `JcsException`. Elements produced by writer paths such as `JsonSerializer.SerializeToElement` are different: there `System.Text.Json` has already replaced unpaired surrogates with U+FFFD before Jcs.NET sees the data, so two distinct .NET strings can canonicalize identically. Use the string-input overloads for the strictest rejection semantics. Duplicate detection works on both paths.
- On the string-input path, a surrogate pair split across representations (a literal high surrogate followed by an escaped low surrogate, or the reverse) is rejected: the literal half makes the text invalid UTF-16 on its own, so there is no well-formed reading of such input.
- Numbers with more precision than an IEEE 754 double (money amounts, 64-bit IDs) are rounded by design, as in every JCS implementation. Follow RFC 8785 appendix D: transport such values as JSON strings.
- Property names are compared and sorted as UTF-16 code units, not by any locale or Unicode collation. That is what the RFC requires, so `"péché"` sorts after `"peach"` even though French collation says otherwise.
- Input strings are canonicalized as-is; no Unicode normalization is applied (the RFC forbids it).

## Roadmap

- `netstandard2.0` target for .NET Framework and older runtimes
- Streaming mode writing directly to `Utf8JsonWriter` / `IBufferWriter<byte>` to avoid intermediate strings
- Property-based fuzzing against the reference implementations in CI

## License

MIT. See [LICENSE](LICENSE).
