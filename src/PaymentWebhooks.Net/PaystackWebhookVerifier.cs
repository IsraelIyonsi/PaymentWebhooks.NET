using System.Security.Cryptography;
using System.Text;
using PaymentWebhooks.Internal;

namespace PaymentWebhooks;

/// <summary>
/// Verifies webhook requests signed using Paystack's X-Paystack-Signature scheme.
/// </summary>
public sealed class PaystackWebhookVerifier : IWebhookVerifier
{
    /// <summary>
    /// The name of the header Paystack uses to carry the signature.
    /// </summary>
    public const string SignatureHeaderName = "X-Paystack-Signature";

    private readonly byte[] _secretKeyBytes;

    /// <summary>
    /// Initializes a new instance of the <see cref="PaystackWebhookVerifier"/> class.
    /// </summary>
    /// <param name="secretKey">The Paystack secret key for the account receiving the webhook.</param>
    public PaystackWebhookVerifier(string secretKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(secretKey);
        _secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);
    }

    /// <inheritdoc />
    public WebhookVerificationResult Verify(ReadOnlySpan<byte> payload, IReadOnlyDictionary<string, string> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        if (!HeaderLookup.TryGetHeader(headers, SignatureHeaderName, out var headerValue))
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.MissingHeader);
        }

        var expectedHex = HmacHexComputer.ComputeHexDigest(HashAlgorithmName.SHA512, _secretKeyBytes, payload);

        return ConstantTimeComparer.Equals(headerValue, expectedHex)
            ? WebhookVerificationResult.Success()
            : WebhookVerificationResult.Failure(WebhookVerificationFailureReason.SignatureMismatch);
    }
}
