using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace PaymentWebhooks.Tests.Support;

/// <summary>
/// Computes expected signatures using the plain, non-incremental HMAC APIs directly,
/// independently of the production code path under test, so tests catch regressions
/// in the library's signing-string construction rather than merely echoing it back.
/// </summary>
internal static class IndependentHmacOracle
{
    public static string StripeSignature(string secret, long timestamp, string payload)
    {
        return StripeSignature(secret, timestamp.ToString(CultureInfo.InvariantCulture), payload);
    }

    public static string StripeSignature(string secret, string rawTimestamp, string payload)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var signedPayload = rawTimestamp + "." + payload;
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(signedPayload));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string GitHubSignature(string secret, string payload)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
        return "sha256=" + Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string PaystackSignature(string secretKey, string payload)
    {
        using var hmac = new HMACSHA512(Encoding.UTF8.GetBytes(secretKey));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string StandardWebhooksSignature(
        string base64Secret,
        string messageId,
        long timestamp,
        string payload)
    {
        var secretBytes = Convert.FromBase64String(
            base64Secret.StartsWith("whsec_", StringComparison.Ordinal)
                ? base64Secret["whsec_".Length..]
                : base64Secret);
        using var hmac = new HMACSHA256(secretBytes);
        var signedContent = $"{messageId}.{timestamp.ToString(CultureInfo.InvariantCulture)}.{payload}";
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(signedContent));
        return "v1," + Convert.ToBase64String(hash);
    }
}
