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

        if (!TryParseSignatureHeader(headerValue, out var rawTimestamp, out var timestamp, out var signatures))
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.MalformedSignatureHeader);
        }

        if (signatures.Count == 0)
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.UnsupportedSignatureVersion);
        }

        // The signed string is built from the timestamp's exact header substring (not a
        // re-serialized numeric value) so verification is byte-for-byte faithful to whatever
        // Stripe actually signed, per Stripe's own SDK.
        var prefix = Encoding.UTF8.GetBytes(rawTimestamp + SignedPayloadSeparator);
        var expectedDigest = HmacHexComputer.ComputeDigest(HashAlgorithmName.SHA256, _secretBytes, prefix, payload);

        // Signature is verified before the timestamp tolerance, matching Stripe's own SDK
        // ordering: an unauthenticated caller cannot distinguish "wrong secret" from "stale
        // timestamp" by reading the failure reason alone.
        var signatureValid = false;
        foreach (var candidate in signatures)
        {
            if (ConstantTimeComparer.HexEquals(candidate, expectedDigest))
            {
                signatureValid = true;
                break;
            }
        }

        if (!signatureValid)
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.SignatureMismatch);
        }

        var eventTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
        if ((DateTimeOffset.UtcNow - eventTime).Duration() > _timestampTolerance)
        {
            return WebhookVerificationResult.Failure(WebhookVerificationFailureReason.TimestampOutOfTolerance);
        }

        return WebhookVerificationResult.Success();
    }

    private static bool TryParseSignatureHeader(
        string headerValue,
        out string rawTimestamp,
        out long timestamp,
        out List<string> signatures)
    {
        rawTimestamp = string.Empty;
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

            if (key == TimestampComponentKey)
            {
                // A second t= component is malformed input, not a first-wins ambiguity: reject
                // it outright rather than silently picking one interpretation of the header.
                if (timestampFound)
                {
                    return false;
                }

                if (!long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out timestamp))
                {
                    return false;
                }

                rawTimestamp = value;
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
