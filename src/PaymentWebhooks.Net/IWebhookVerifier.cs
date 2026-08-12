namespace PaymentWebhooks;

/// <summary>
/// Verifies the authenticity of an inbound payment webhook request by validating its
/// signature against the raw request body and headers.
/// </summary>
public interface IWebhookVerifier
{
    /// <summary>
    /// Verifies an inbound webhook request.
    /// </summary>
    /// <param name="payload">The raw, unmodified request body bytes exactly as received on the wire.</param>
    /// <param name="headers">
    /// The request headers, keyed by header name. Header lookups are performed case-insensitively
    /// regardless of the dictionary's own key comparer.
    /// </param>
    /// <returns>A <see cref="WebhookVerificationResult"/> describing whether the request is authentic.</returns>
    WebhookVerificationResult Verify(ReadOnlySpan<byte> payload, IReadOnlyDictionary<string, string> headers);
}
