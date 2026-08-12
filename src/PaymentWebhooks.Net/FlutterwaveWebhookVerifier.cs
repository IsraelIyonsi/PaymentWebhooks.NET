using PaymentWebhooks.Internal;

namespace PaymentWebhooks;

/// <summary>
/// Verifies webhook requests using Flutterwave's verif-hash scheme, where the sender echoes
/// back a pre-shared secret hash configured on the Flutterwave dashboard rather than signing
/// the request body.
/// </summary>
public sealed class FlutterwaveWebhookVerifier : IWebhookVerifier
{
    /// <summary>
    /// The name of the header Flutterwave uses to carry the secret hash.
    /// </summary>
    public const string SignatureHeaderName = "verif-hash";

    private readonly string _secretHash;

    /// <summary>
    /// Initializes a new instance of the <see cref="FlutterwaveWebhookVerifier"/> class.
    /// </summary>
    /// <param name="secretHash">The secret hash value configured in the Flutterwave dashboard.</param>
    public FlutterwaveWebhookVerifier(string secretHash)
    {
        ArgumentException.ThrowIfNullOrEmpty(secretHash);
        _secretHash = secretHash;
    }

    /// <inheritdoc />
    public WebhookVerificationResult Verify(ReadOnlySpan<byte> payload, IReadOnlyDictionary<string, string> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        if (!HeaderLookup.TryGetHeader(headers, SignatureHeaderName, out var headerValue))
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.MissingHeader);
        }

        return ConstantTimeComparer.Equals(headerValue, _secretHash)
            ? WebhookVerificationResult.Success()
            : WebhookVerificationResult.Failure(WebhookVerificationFailureReason.SignatureMismatch);
    }
}
