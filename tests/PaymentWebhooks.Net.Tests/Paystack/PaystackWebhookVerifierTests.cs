using System.Text;
using PaymentWebhooks.Tests.Support;

namespace PaymentWebhooks.Tests.Paystack;

public class PaystackWebhookVerifierTests
{
    private static readonly PaystackFixture Fixture = FixtureLoader.Load<PaystackFixture>("paystack-known-answer.json");

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Constructor_RejectsNullOrEmptySecretKey(string? secretKey)
    {
        Assert.ThrowsAny<ArgumentException>(() => new PaystackWebhookVerifier(secretKey!));
    }

    [Fact]
    public void Verify_NullHeaders_ThrowsArgumentNullException()
    {
        var verifier = new PaystackWebhookVerifier(Fixture.SecretKey);

        Assert.Throws<ArgumentNullException>(
            () => verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), null!));
    }

    public static IEnumerable<object[]> KnownAnswerCases()
    {
        yield return new object[]
        {
            Fixture.SecretKey,
            Fixture.Payload,
            new Dictionary<string, string> { [PaystackWebhookVerifier.SignatureHeaderName] = Fixture.Signature },
            true,
            WebhookVerificationFailureReason.None,
        };

        yield return new object[]
        {
            Fixture.SecretKey,
            Fixture.Payload + "-tampered",
            new Dictionary<string, string> { [PaystackWebhookVerifier.SignatureHeaderName] = Fixture.Signature },
            false,
            WebhookVerificationFailureReason.SignatureMismatch,
        };

        yield return new object[]
        {
            "sk_test_a_completely_different_secret_key",
            Fixture.Payload,
            new Dictionary<string, string> { [PaystackWebhookVerifier.SignatureHeaderName] = Fixture.Signature },
            false,
            WebhookVerificationFailureReason.SignatureMismatch,
        };

        yield return new object[]
        {
            Fixture.SecretKey,
            Fixture.Payload,
            new Dictionary<string, string> { ["x-paystack-signature"] = Fixture.Signature },
            true,
            WebhookVerificationFailureReason.None,
        };

        yield return new object[]
        {
            Fixture.SecretKey,
            Fixture.Payload,
            new Dictionary<string, string>(),
            false,
            WebhookVerificationFailureReason.MissingHeader,
        };

        yield return new object[]
        {
            Fixture.SecretKey,
            Fixture.Payload,
            new Dictionary<string, string> { [PaystackWebhookVerifier.SignatureHeaderName] = "0123456789abcdef" },
            false,
            WebhookVerificationFailureReason.SignatureMismatch,
        };
    }

    [Theory]
    [MemberData(nameof(KnownAnswerCases))]
    public void Verify_KnownAnswerAndEdgeCases_ReturnsExpectedResult(
        string secretKey,
        string payload,
        Dictionary<string, string> headers,
        bool expectedValid,
        WebhookVerificationFailureReason expectedReason)
    {
        var verifier = new PaystackWebhookVerifier(secretKey);

        var result = verifier.Verify(Encoding.UTF8.GetBytes(payload), headers);

        Assert.Equal(expectedValid, result.IsValid);
        Assert.Equal(expectedReason, result.FailureReason);
    }

    [Fact]
    public void Verify_UppercaseHexSignature_Succeeds()
    {
        var verifier = new PaystackWebhookVerifier(Fixture.SecretKey);
        var headers = new Dictionary<string, string>
        {
            [PaystackWebhookVerifier.SignatureHeaderName] = Fixture.Signature.ToUpperInvariant(),
        };

        var result = verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), headers);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Verify_NonHexCharacters_FailsAsSignatureMismatchWithoutThrowing()
    {
        var verifier = new PaystackWebhookVerifier(Fixture.SecretKey);
        var headers = new Dictionary<string, string>
        {
            [PaystackWebhookVerifier.SignatureHeaderName] = "not-hexadecimal-at-all",
        };

        var result = verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), headers);

        Assert.False(result.IsValid);
        Assert.Equal(WebhookVerificationFailureReason.SignatureMismatch, result.FailureReason);
    }

    [Fact]
    public void Verify_ImplementsIWebhookVerifier()
    {
        IWebhookVerifier verifier = new PaystackWebhookVerifier(Fixture.SecretKey);
        var headers = new Dictionary<string, string>
        {
            [PaystackWebhookVerifier.SignatureHeaderName] = Fixture.Signature,
        };

        var result = verifier.Verify(Encoding.UTF8.GetBytes(Fixture.Payload), headers);

        Assert.True(result.IsValid);
    }
}
