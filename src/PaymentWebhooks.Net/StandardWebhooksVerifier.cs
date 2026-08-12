using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using PaymentWebhooks.Internal;

namespace PaymentWebhooks;

/// <summary>
/// Verifies webhook requests signed according to the Standard Webhooks specification
/// (see https://www.standardwebhooks.com).
/// </summary>
public sealed class StandardWebhooksVerifier : IWebhookVerifier
{
    /// <summary>
    /// The name of the header carrying the unique message identifier.
    /// </summary>
    public const string MessageIdHeaderName = "webhook-id";

    /// <summary>
    /// The name of the header carrying the message timestamp, in Unix seconds.
    /// </summary>
    public const string TimestampHeaderName = "webhook-timestamp";

    /// <summary>
    /// The name of the header carrying the space-separated list of versioned signatures.
    /// </summary>
    public const string SignatureHeaderName = "webhook-signature";

    private const string SecretPrefix = "whsec_";
    private const string SupportedSignatureVersion = "v1";
    private const char SignatureListDelimiter = ' ';
    private const char SignatureVersionDelimiter = ',';
    private const char SignedContentSeparator = '.';

    private readonly byte[] _secretKeyBytes;
    private readonly TimeSpan _timestampTolerance;

    /// <summary>
    /// Initializes a new instance of the <see cref="StandardWebhooksVerifier"/> class.
    /// </summary>
    /// <param name="signingSecret">
    /// The base64-encoded webhook signing secret, optionally prefixed with "whsec_" as issued
    /// by Standard Webhooks compliant providers.
    /// </param>
    /// <param name="timestampTolerance">
    /// The maximum allowed difference between the request timestamp and the current time.
    /// Defaults to <see cref="WebhookVerificationDefaults.DefaultTimestampTolerance"/>.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="signingSecret"/> is null, empty, or not valid base64
    /// once any "whsec_" prefix is removed.
    /// </exception>
    public StandardWebhooksVerifier(string signingSecret, TimeSpan? timestampTolerance = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(signingSecret);

        var base64Secret = signingSecret.StartsWith(SecretPrefix, StringComparison.Ordinal)
            ? signingSecret[SecretPrefix.Length..]
            : signingSecret;

        try
        {
            _secretKeyBytes = Convert.FromBase64String(base64Secret);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("The signing secret is not valid base64.", nameof(signingSecret), exception);
        }

        _timestampTolerance = timestampTolerance ?? WebhookVerificationDefaults.DefaultTimestampTolerance;
    }

    /// <inheritdoc />
    public WebhookVerificationResult Verify(ReadOnlySpan<byte> payload, IReadOnlyDictionary<string, string> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        if (!HeaderLookup.TryGetHeader(headers, MessageIdHeaderName, out var messageId))
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.MissingHeader);
        }

        if (!HeaderLookup.TryGetHeader(headers, TimestampHeaderName, out var timestampHeader))
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.MissingHeader);
        }

        if (!HeaderLookup.TryGetHeader(headers, SignatureHeaderName, out var signatureHeader))
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.MissingHeader);
        }

        if (!long.TryParse(timestampHeader, NumberStyles.Integer, CultureInfo.InvariantCulture, out var timestamp))
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.MalformedSignatureHeader);
        }

        var eventTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
        if ((DateTimeOffset.UtcNow - eventTime).Duration() > _timestampTolerance)
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.TimestampOutOfTolerance);
        }

        if (!TryParseSignatures(signatureHeader, out var candidateSignatures))
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.MalformedSignatureHeader);
        }

        if (candidateSignatures.Count == 0)
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.UnsupportedSignatureVersion);
        }

        var prefix = Encoding.UTF8.GetBytes(
            messageId + SignedContentSeparator + timestampHeader + SignedContentSeparator);
        var expected = HmacHexComputer.ComputeDigest(HashAlgorithmName.SHA256, _secretKeyBytes, prefix, payload);

        foreach (var candidate in candidateSignatures)
        {
            if (!TryDecodeBase64(candidate, out var candidateBytes))
            {
                continue;
            }

            if (ConstantTimeComparer.Equals(candidateBytes, expected))
            {
                return WebhookVerificationResult.Success();
            }
        }

        return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.SignatureMismatch);
    }

    private static bool TryParseSignatures(string signatureHeader, out List<string> supportedSignatures)
    {
        supportedSignatures = new List<string>();

        foreach (var token in signatureHeader.Split(SignatureListDelimiter, StringSplitOptions.RemoveEmptyEntries))
        {
            var separatorIndex = token.IndexOf(SignatureVersionDelimiter);
            if (separatorIndex <= 0 || separatorIndex == token.Length - 1)
            {
                return false;
            }

            var version = token[..separatorIndex];
            var signature = token[(separatorIndex + 1)..];

            if (version == SupportedSignatureVersion)
            {
                supportedSignatures.Add(signature);
            }
        }

        return true;
    }

    private static bool TryDecodeBase64(string value, out byte[] decoded)
    {
        try
        {
            decoded = Convert.FromBase64String(value);
            return true;
        }
        catch (FormatException)
        {
            decoded = Array.Empty<byte>();
            return false;
        }
    }
}
