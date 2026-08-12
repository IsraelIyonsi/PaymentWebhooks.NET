using System.Security.Cryptography;
using System.Text;

namespace PaymentWebhooks.Internal;

/// <summary>
/// Compares secrets and signatures in constant time to avoid leaking information
/// through timing side channels.
/// </summary>
internal static class ConstantTimeComparer
{
    public static bool Equals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(left, right);
    }

    public static bool Equals(string left, string right)
    {
        return Equals(Encoding.UTF8.GetBytes(left), Encoding.UTF8.GetBytes(right));
    }

    /// <summary>
    /// Compares a caller-supplied hex string against an expected raw digest, tolerating any
    /// mix of upper- and lower-case hex digits in the caller-supplied value the way every
    /// supported vendor's own verification code does.
    /// </summary>
    public static bool HexEquals(string providedHex, ReadOnlySpan<byte> expectedDigest)
    {
        byte[] providedBytes;
        try
        {
            providedBytes = Convert.FromHexString(providedHex);
        }
        catch (FormatException)
        {
            return false;
        }

        return Equals(providedBytes, expectedDigest);
    }
}
