# PaymentWebhooks.NET

Verify inbound payment webhook signatures for Stripe, Paystack, Flutterwave, Shopify, GitHub, and Standard Webhooks, all through one interface. Constant-time comparison, timestamp-based replay protection, zero dependencies.

Every payment provider signs webhooks differently: Stripe puts a timestamp and HMAC in one header, Paystack just hashes the body, Flutterwave sends back a static value, GitHub prefixes its hex digest. Get any of it wrong, string comparison instead of constant-time, no replay window, wrong signing string, and you either reject real payments or accept forged ones. There is no single, current NuGet package that covers this set with a consistent API and a security-first default. Most projects end up with a hand-rolled `HMACSHA256` call copy-pasted from a blog post, no timestamp check, and a `==` string comparison that leaks timing information. PaymentWebhooks.NET is the package that should already exist: one contract, five schemes, and a signing-string implementation checked against vendor-documented or independently verified test vectors, not just eyeballed.

## Install

```
dotnet add package PaymentWebhooks.Net
```

## Usage

### Stripe

```csharp
using PaymentWebhooks;

var verifier = new StripeWebhookVerifier(signingSecret: "whsec_...");

var headers = new Dictionary<string, string>
{
    ["Stripe-Signature"] = request.Headers["Stripe-Signature"],
};

var result = verifier.Verify(rawRequestBody, headers);

if (!result.IsValid)
{
    return Results.BadRequest(result.FailureReason);
}
```

`rawRequestBody` must be the exact bytes as received, before any JSON parsing or re-serialization touches them. A five-minute timestamp tolerance is applied by default; pass a `TimeSpan` as the second constructor argument to change it.

### Paystack

```csharp
var verifier = new PaystackWebhookVerifier(secretKey: "sk_live_...");

var result = verifier.Verify(rawRequestBody, new Dictionary<string, string>
{
    ["X-Paystack-Signature"] = request.Headers["X-Paystack-Signature"],
});
```

Paystack has no timestamp in its scheme, so there is nothing to check for staleness; the HMAC-SHA512 comparison alone is what protects you.

### Shopify

```csharp
var verifier = new ShopifyWebhookVerifier(secret: "shpss_...");

var result = verifier.Verify(rawRequestBody, new Dictionary<string, string>
{
    ["X-Shopify-Hmac-Sha256"] = request.Headers["X-Shopify-Hmac-Sha256"],
});
```

The secret is the app's API secret (shared secret). Shopify computes HMAC-SHA256 over the raw body and sends the digest base64-encoded, not hex. There is no timestamp in the scheme, so the HMAC comparison alone is what protects you. The verifier base64-decodes the header to its raw 32 bytes and compares those in constant time, so header casing and padding differences never affect the result.

### Standard Webhooks (Standard Webhooks compliant providers)

```csharp
var verifier = new StandardWebhooksVerifier(signingSecret: "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

var result = verifier.Verify(rawRequestBody, new Dictionary<string, string>
{
    ["webhook-id"] = request.Headers["webhook-id"],
    ["webhook-timestamp"] = request.Headers["webhook-timestamp"],
    ["webhook-signature"] = request.Headers["webhook-signature"],
});

switch (result.FailureReason)
{
    case WebhookVerificationFailureReason.None:
        // process the event
        break;
    case WebhookVerificationFailureReason.TimestampOutOfTolerance:
        // likely a replay; log and drop
        break;
    default:
        // reject
        break;
}
```

## Why this exists

Payment webhook verification is security-critical and provider-specific, which is exactly the kind of code that gets copied from a blog post once and never revisited. Every scheme here has a subtly different signing string (`t.payload` for Stripe, `id.timestamp.payload` for Standard Webhooks, the raw body alone for GitHub and Paystack), and getting the concatenation order or the hash algorithm wrong produces a verifier that silently accepts forged requests. There was no maintained NuGet package covering this exact surface with constant-time comparison and replay protection built in by default, so this is that package.

## Zero dependencies, AOT-friendly

The library uses only `System.Security.Cryptography` and `System.Text.Json` (the in-box BCL implementation, no package reference) and has no runtime NuGet dependencies. It contains no reflection, no dynamic code generation, and no unbounded allocation on the hot path, so it works unmodified under Native AOT and trimming.

## Reference

| Verifier | Header(s) | Algorithm | Replay protection |
|---|---|---|---|
| `StripeWebhookVerifier` | `Stripe-Signature` | HMAC-SHA256 over `{timestamp}.{payload}` | Yes, configurable tolerance |
| `GitHubWebhookVerifier` | `X-Hub-Signature-256` | HMAC-SHA256 over the raw body | No (GitHub's scheme has no timestamp) |
| `PaystackWebhookVerifier` | `X-Paystack-Signature` | HMAC-SHA512 over the raw body | No (Paystack's scheme has no timestamp) |
| `ShopifyWebhookVerifier` | `X-Shopify-Hmac-Sha256` | HMAC-SHA256 over the raw body, base64 | No (Shopify's scheme has no timestamp) |
| `FlutterwaveWebhookVerifier` | `verif-hash` | Constant-time equality against a configured secret hash | No (Flutterwave's scheme has no timestamp) |
| `StandardWebhooksVerifier` | `webhook-id`, `webhook-timestamp`, `webhook-signature` | HMAC-SHA256 over `{id}.{timestamp}.{payload}`, base64 | Yes, configurable tolerance |

All signature comparisons use `CryptographicOperations.FixedTimeEquals`. Every verifier implements `IWebhookVerifier` and returns a `WebhookVerificationResult` carrying `IsValid` and a `WebhookVerificationFailureReason` you can branch or log on.

## License

MIT. See [LICENSE](LICENSE).
