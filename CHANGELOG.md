# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-12

### Added

- `IWebhookVerifier` interface: a single contract taking the raw request body and headers, returning a `WebhookVerificationResult`.
- `StripeWebhookVerifier`: verifies the `Stripe-Signature` header, HMAC-SHA256 over `{timestamp}.{payload}`, with configurable timestamp tolerance (default 300 seconds) and support for multiple `v1` signatures during secret rotation.
- `GitHubWebhookVerifier`: verifies the `X-Hub-Signature-256` header, HMAC-SHA256 hex of the raw body.
- `PaystackWebhookVerifier`: verifies the `X-Paystack-Signature` header, HMAC-SHA512 hex of the raw body.
- `FlutterwaveWebhookVerifier`: verifies the `verif-hash` header via constant-time equality against a configured secret hash.
- `StandardWebhooksVerifier`: verifies the `webhook-id` / `webhook-timestamp` / `webhook-signature` headers per the Standard Webhooks specification, HMAC-SHA256 over `{id}.{timestamp}.{payload}` with a base64 secret, configurable timestamp tolerance, and support for multiple space-separated signatures.
- `WebhookVerificationResult` and `WebhookVerificationFailureReason`, shared across every verifier, distinguishing missing headers, malformed headers, unsupported signature versions, stale timestamps, and signature mismatches.
- `WebhookVerificationDefaults.DefaultTimestampTolerance` (300 seconds), used by every timestamped scheme unless overridden.
- All signature comparisons use `CryptographicOperations.FixedTimeEquals` for constant-time behavior.
- Known-answer test fixtures for every scheme, including the official Standard Webhooks / Svix worked example, verified independently against Python `hmac`/`hashlib` output.
- Zero runtime dependencies; built entirely on `System.Security.Cryptography` and the in-box `System.Text.Json`.
- SourceLink (GitHub), deterministic CI builds, and `.snupkg` symbol packages.
