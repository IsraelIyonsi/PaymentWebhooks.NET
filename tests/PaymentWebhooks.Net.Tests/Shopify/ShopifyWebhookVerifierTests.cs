using System.Text;
using PaymentWebhooks.Tests.Support;

namespace PaymentWebhooks.Tests.Shopify;

public class ShopifyWebhookVerifierTests
{
    private static readonly ShopifyFixture Fixture = FixtureLoader.Load<ShopifyFixture>("shopify-known-answer.json");

    // Independently hand-computed vector: base64(HMAC-SHA256(secret, rawBody)).
    // secret    = "shopify_test_shared_secret"
    // body      = {"id":820982911946154508,"test":true}
    // signature = h6bYfKK+Mi6PVQLOqpCbwl0/FTD9VkOUwF7UGncpHtc=
    private const string HandVerifiedSecret = "shopify_test_shared_secret";
    private const string HandVerifiedPayload = "{\"id\":820982911946154508,\"test\":true}";
    private const string HandVerifiedSignature = "h6bYfKK+Mi6PVQLOqpCbwl0/FTD9VkOUwF7UGncpHtc=";

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Constructor_RejectsNullOrEmptySecret(string? secret)
    {
        Assert.ThrowsAny<ArgumentException>(() => new ShopifyWebhookVerifier(secret!));
    }

    [Fact]
    public void Verify_NullHeaders_ThrowsArgumentNullException()
    {
        var verifier = new ShopifyWebhookVerifier(Fixture.Secret);

        Assert.Throws<ArgumentNullException>(
            () => verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), null!));
    }

    [Fact]
    public void Verify_HandVerifiedKnownAnswer_Succeeds()
    {
        var verifier = new ShopifyWebhookVerifier(HandVerifiedSecret);
        var headers = new Dictionary<string, string>
        {
            [ShopifyWebhookVerifier.SignatureHeaderName] = HandVerifiedSignature,
        };

        var result = verifier.Verify(Encoding.UTF8.GetBytes(HandVerifiedPayload), headers);

        Assert.True(result.IsValid);
        Assert.Equal(WebhookVerificationFailureReason.None, result.FailureReason);
    }

    [Fact]
    public void Verify_OracleMatchesFixtureSignature_ConfirmsVectorIntegrity()
    {
        var oracleSignature = IndependentHmacOracle.ShopifySignature(Fixture.Secret, Fixture.Payload);

        Assert.Equal(Fixture.Signature, oracleSignature);
    }

    public static IEnumerable<object[]> KnownAnswerCases()
    {
        yield return new object[]
        {
            Fixture.Secret,
            Fixture.Payload,
            new Dictionary<string, string> { [ShopifyWebhookVerifier.SignatureHeaderName] = Fixture.Signature },
            true,
            WebhookVerificationFailureReason.None,
        };

        yield return new object[]
        {
            Fixture.Secret,
            Fixture.Payload + "-tampered",
            new Dictionary<string, string> { [ShopifyWebhookVerifier.SignatureHeaderName] = Fixture.Signature },
            false,
            WebhookVerificationFailureReason.SignatureMismatch,
        };

        yield return new object[]
        {
            "a-completely-different-secret",
            Fixture.Payload,
            new Dictionary<string, string> { [ShopifyWebhookVerifier.SignatureHeaderName] = Fixture.Signature },
            false,
            WebhookVerificationFailureReason.SignatureMismatch,
        };

        yield return new object[]
        {
            Fixture.Secret,
            Fixture.Payload,
            new Dictionary<string, string> { ["x-shopify-hmac-sha256"] = Fixture.Signature },
            true,
            WebhookVerificationFailureReason.None,
        };

        yield return new object[]
        {
            Fixture.Secret,
            Fixture.Payload,
            new Dictionary<string, string>(),
            false,
            WebhookVerificationFailureReason.MissingHeader,
        };

        yield return new object[]
        {
            Fixture.Secret,
            Fixture.Payload,
            new Dictionary<string, string> { [ShopifyWebhookVerifier.SignatureHeaderName] = "not-valid-base64!!!" },
            false,
            WebhookVerificationFailureReason.MalformedSignatureHeader,
        };

        // Valid base64 whose decoded length is not the 32 bytes an HMAC-SHA256 digest occupies.
        yield return new object[]
        {
            Fixture.Secret,
            Fixture.Payload,
            new Dictionary<string, string> { [ShopifyWebhookVerifier.SignatureHeaderName] = "aGVsbG8=" },
            false,
            WebhookVerificationFailureReason.MalformedSignatureHeader,
        };

        // Oversized: valid base64 that decodes to more than 32 bytes.
        yield return new object[]
        {
            Fixture.Secret,
            Fixture.Payload,
            new Dictionary<string, string>
            {
                [ShopifyWebhookVerifier.SignatureHeaderName] = Convert.ToBase64String(new byte[64]),
            },
            false,
            WebhookVerificationFailureReason.MalformedSignatureHeader,
        };
    }

    [Theory]
    [MemberData(nameof(KnownAnswerCases))]
    public void Verify_KnownAnswerAndEdgeCases_ReturnsExpectedResult(
        string secret,
        string payload,
        Dictionary<string, string> headers,
        bool expectedValid,
        WebhookVerificationFailureReason expectedReason)
    {
        var verifier = new ShopifyWebhookVerifier(secret);

        var result = verifier.Verify(Encoding.UTF8.GetBytes(payload), headers);

        Assert.Equal(expectedValid, result.IsValid);
        Assert.Equal(expectedReason, result.FailureReason);
    }

    [Fact]
    public void Verify_EmptyBody_IsHandledAndVerifiesAgainstMatchingSignature()
    {
        const string secret = "shopify_empty_body_secret";
        var signature = IndependentHmacOracle.ShopifySignature(secret, string.Empty);
        var verifier = new ShopifyWebhookVerifier(secret);
        var headers = new Dictionary<string, string>
        {
            [ShopifyWebhookVerifier.SignatureHeaderName] = signature,
        };

        var result = verifier.Verify(ReadOnlySpan<byte>.Empty, headers);

        Assert.True(result.IsValid);
        Assert.Equal(WebhookVerificationFailureReason.None, result.FailureReason);
    }

    [Fact]
    public void Verify_ConstantTimePath_AcceptsCorrectAndRejectsBitFlippedDigest()
    {
        var verifier = new ShopifyWebhookVerifier(Fixture.Secret);
        var payload = Encoding.UTF8.GetBytes(Fixture.Payload);

        var accepted = verifier.Verify(
            payload,
            new Dictionary<string, string> { [ShopifyWebhookVerifier.SignatureHeaderName] = Fixture.Signature });

        // Flip a single bit of the valid 32-byte digest, re-encode, and confirm the
        // constant-time comparison rejects it as a mismatch rather than accepting or throwing.
        var digest = Convert.FromBase64String(Fixture.Signature);
        digest[0] ^= 0x01;
        var flipped = Convert.ToBase64String(digest);

        var rejected = verifier.Verify(
            payload,
            new Dictionary<string, string> { [ShopifyWebhookVerifier.SignatureHeaderName] = flipped });

        Assert.True(accepted.IsValid);
        Assert.False(rejected.IsValid);
        Assert.Equal(WebhookVerificationFailureReason.SignatureMismatch, rejected.FailureReason);
    }

    [Fact]
    public void Verify_ImplementsIWebhookVerifier()
    {
        IWebhookVerifier verifier = new ShopifyWebhookVerifier(Fixture.Secret);
        var headers = new Dictionary<string, string>
        {
            [ShopifyWebhookVerifier.SignatureHeaderName] = Fixture.Signature,
        };

        var result = verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), headers);

        Assert.True(result.IsValid);
    }
}
