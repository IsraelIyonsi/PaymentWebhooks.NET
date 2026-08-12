using System.Security.Cryptography;

namespace PaymentWebhooks.Internal;

/// <summary>
/// Computes HMAC digests over payloads that are optionally prefixed with a signing-string
/// header, without allocating a combined buffer.
/// </summary>
internal static class HmacHexComputer
{
    public static string ComputeHexDigest(
        HashAlgorithmName algorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> message)
    {
        var digest = ComputeDigest(algorithm, key, ReadOnlySpan<byte>.Empty, message);
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    public static byte[] ComputeDigest(
        HashAlgorithmName algorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> prefix,
        ReadOnlySpan<byte> payload)
    {
        using var incrementalHash = IncrementalHash.CreateHMAC(algorithm, key);

        if (!prefix.IsEmpty)
        {
            incrementalHash.AppendData(prefix);
        }

        incrementalHash.AppendData(payload);
        return incrementalHash.GetHashAndReset();
    }
}
