using System.Security.Cryptography;
using System.Text;
using PaymentWebhooks.Internal;

namespace PaymentWebhooks;

/// <summary>
/// Verifies webhook requests signed using GitHub's X-Hub-Signature-256 scheme.
/// </summary>
public sealed class GitHubWebhookVerifier : IWebhookVerifier
{
    /// <summary>
    /// The name of the header GitHub uses to carry the signature.
    /// </summary>
    public const string SignatureHeaderName = "X-Hub-Signature-256";

    private const string SignaturePrefix = "sha256=";

    private readonly byte[] _secretBytes;

    /// <summary>
    /// Initializes a new instance of the <see cref="GitHubWebhookVerifier"/> class.
    /// </summary>
    /// <param name="secret">The webhook secret configured on the GitHub webhook.</param>
    public GitHubWebhookVerifier(string secret)
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

        if (!headerValue.StartsWith(SignaturePrefix, StringComparison.Ordinal))
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.MalformedSignatureHeader);
        }

        var providedHex = headerValue[SignaturePrefix.Length..];
        var expectedHex = HmacHexComputer.ComputeHexDigest(HashAlgorithmName.SHA256, _secretBytes, payload);

        return ConstantTimeComparer.Equals(providedHex, expectedHex)
            ? WebhookVerificationResult.Success()
            : WebhookVerificationResult.Failure(WebhookVerificationFailureReason.SignatureMismatch);
    }
}
