using System.Security.Cryptography;
using System.Text;
using PaymentWebhooks.Internal;

namespace PaymentWebhooks;

/// <summary>
/// Verifies webhook requests signed using Shopify's X-Shopify-Hmac-Sha256 scheme.
/// </summary>
/// <remarks>
/// Shopify signs the raw request body with HMAC-SHA256 keyed by the app's API secret
/// (the shared secret) and sends the digest base64-encoded in the header. The scheme
/// carries no timestamp and no signed-payload envelope, so verification is a single
/// constant-time comparison of the computed digest against the decoded header value.
/// </remarks>
public sealed class ShopifyWebhookVerifier : IWebhookVerifier
{
    /// <summary>
    /// The name of the header Shopify uses to carry the base64-encoded signature.
    /// </summary>
    public const string SignatureHeaderName = "X-Shopify-Hmac-Sha256";

    private const int Sha256DigestLength = 32;

    private readonly byte[] _secretBytes;

    /// <summary>
    /// Initializes a new instance of the <see cref="ShopifyWebhookVerifier"/> class.
    /// </summary>
    /// <param name="secret">
    /// The app's API secret (shared secret) configured for the Shopify app receiving the webhook.
    /// </param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="secret"/> is null or empty.</exception>
    public ShopifyWebhookVerifier(string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        _secretBytes = Encoding.UTF8.GetBytes(secret);
    }

    /// <inheritdoc />
    public WebhookVerificationResult Verify(ReadOnlySpan<byte> payload, IReadOnlyDictionary<string, string> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        if (!HeaderLookup.TryGetHeader(headers, SignatureHeaderName, out var headerValue))
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.MissingHeader);
        }

        if (!TryDecodeSignature(headerValue, out var providedDigest))
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.MalformedSignatureHeader);
        }

        var expectedDigest = HmacHexComputer.ComputeDigest(
            HashAlgorithmName.SHA256, _secretBytes, ReadOnlySpan<byte>.Empty, payload);

        return ConstantTimeComparer.Equals(providedDigest, expectedDigest)
            ? WebhookVerificationResult.Success()
            : WebhookVerificationResult.Failure(WebhookVerificationFailureReason.SignatureMismatch);
    }

    private static bool TryDecodeSignature(string headerValue, out byte[] digest)
    {
        digest = new byte[Sha256DigestLength];
        return Convert.TryFromBase64String(headerValue, digest, out var written)
            && written == Sha256DigestLength;
    }
}
