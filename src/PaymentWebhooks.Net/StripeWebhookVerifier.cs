using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using PaymentWebhooks.Internal;

namespace PaymentWebhooks;

/// <summary>
/// Verifies webhook requests signed using Stripe's Stripe-Signature scheme.
/// </summary>
public sealed class StripeWebhookVerifier : IWebhookVerifier
{
    /// <summary>
    /// The name of the header Stripe uses to carry the timestamp and signatures.
    /// </summary>
    public const string SignatureHeaderName = "Stripe-Signature";

    private const string TimestampComponentKey = "t";
    private const string SignatureComponentKey = "v1";
    private const char ComponentDelimiter = ',';
    private const char ComponentAssignmentOperator = '=';
    private const char SignedPayloadSeparator = '.';

    private readonly byte[] _secretBytes;
    private readonly TimeSpan _timestampTolerance;

    /// <summary>
    /// Initializes a new instance of the <see cref="StripeWebhookVerifier"/> class.
    /// </summary>
    /// <param name="signingSecret">The Stripe webhook signing secret for the configured endpoint.</param>
    /// <param name="timestampTolerance">
    /// The maximum allowed difference between the request timestamp and the current time.
    /// Defaults to <see cref="WebhookVerificationDefaults.DefaultTimestampTolerance"/>.
    /// </param>
    public StripeWebhookVerifier(string signingSecret, TimeSpan? timestampTolerance = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(signingSecret);
        _secretBytes = Encoding.UTF8.GetBytes(signingSecret);
        _timestampTolerance = timestampTolerance ?? WebhookVerificationDefaults.DefaultTimestampTolerance;
    }

    /// <inheritdoc />
    public WebhookVerificationResult Verify(ReadOnlySpan<byte> payload, IReadOnlyDictionary<string, string> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        if (!HeaderLookup.TryGetHeader(headers, SignatureHeaderName, out var headerValue))
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.MissingHeader);
        }

        if (!TryParseSignatureHeader(headerValue, out var timestamp, out var signatures))
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.MalformedSignatureHeader);
        }

        if (signatures.Count == 0)
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.UnsupportedSignatureVersion);
        }

        var eventTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
        if ((DateTimeOffset.UtcNow - eventTime).Duration() > _timestampTolerance)
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.TimestampOutOfTolerance);
        }

        var prefix = Encoding.UTF8.GetBytes(
            timestamp.ToString(CultureInfo.InvariantCulture) + SignedPayloadSeparator);
        var expected = HmacHexComputer.ComputeDigest(HashAlgorithmName.SHA256, _secretBytes, prefix, payload);
        var expectedHex = Convert.ToHexString(expected).ToLowerInvariant();

        foreach (var candidate in signatures)
        {
            if (ConstantTimeComparer.Equals(candidate, expectedHex))
            {
                return WebhookVerificationResult.Success();
            }
        }

        return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.SignatureMismatch);
    }

    private static bool TryParseSignatureHeader(
        string headerValue,
        out long timestamp,
        out List<string> signatures)
    {
        timestamp = default;
        signatures = new List<string>();
        var timestampFound = false;

        foreach (var rawComponent in headerValue.Split(ComponentDelimiter))
        {
            var separatorIndex = rawComponent.IndexOf(ComponentAssignmentOperator);
            if (separatorIndex <= 0 || separatorIndex == rawComponent.Length - 1)
            {
                return false;
            }

            var key = rawComponent[..separatorIndex];
            var value = rawComponent[(separatorIndex + 1)..];

            if (key == TimestampComponentKey && !timestampFound)
            {
                if (!long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out timestamp))
                {
                    return false;
                }

                timestampFound = true;
            }
            else if (key == SignatureComponentKey)
            {
                signatures.Add(value);
            }
        }

        return timestampFound;
    }
}
