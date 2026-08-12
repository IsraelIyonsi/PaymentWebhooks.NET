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
}
