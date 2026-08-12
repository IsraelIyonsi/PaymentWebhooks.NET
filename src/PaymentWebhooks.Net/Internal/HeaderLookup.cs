namespace PaymentWebhooks.Internal;

/// <summary>
/// Performs case-insensitive header lookups regardless of the caller-supplied dictionary's
/// own key comparer, since HTTP header names are case-insensitive by specification.
/// </summary>
internal static class HeaderLookup
{
    public static bool TryGetHeader(
        IReadOnlyDictionary<string, string> headers,
        string headerName,
        out string value)
    {
        if (headers.TryGetValue(headerName, out var directMatch))
        {
            value = directMatch;
            return true;
        }

        foreach (var pair in headers)
        {
            if (string.Equals(pair.Key, headerName, StringComparison.OrdinalIgnoreCase))
            {
                value = pair.Value;
                return true;
            }
        }

        value = string.Empty;
        return false;
    }
}
