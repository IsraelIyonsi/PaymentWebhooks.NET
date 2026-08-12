using System.Text;
using PaymentWebhooks.Tests.Support;

namespace PaymentWebhooks.Tests.Flutterwave;

public class FlutterwaveWebhookVerifierTests
{
    private static readonly FlutterwaveFixture Fixture =
        FixtureLoader.Load<FlutterwaveFixture>("flutterwave-known-answer.json");

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Constructor_RejectsNullOrEmptySecretHash(string? secretHash)
    {
        Assert.ThrowsAny<ArgumentException>(() => new FlutterwaveWebhookVerifier(secretHash!));
    }

    [Fact]
    public void Verify_NullHeaders_ThrowsArgumentNullException()
    {
        var verifier = new FlutterwaveWebhookVerifier(Fixture.SecretHash);

        Assert.Throws<ArgumentNullException>(
            () => verifier.Verify(ReadOnlySpan<byte>.Empty, null!));
    }

    public static IEnumerable<object[]> VerificationCases()
    {
        yield return new object[]
        {
            new Dictionary<string, string> { [FlutterwaveWebhookVerifier.SignatureHeaderName] = Fixture.SecretHash },
            true,
            WebhookVerificationFailureReason.None,
        };

        yield return new object[]
        {
            new Dictionary<string, string> { ["verif-hash"] = Fixture.SecretHash },
            true,
            WebhookVerificationFailureReason.None,
        };

        yield return new object[]
        {
            new Dictionary<string, string> { ["Verif-Hash"] = Fixture.SecretHash },
            true,
            WebhookVerificationFailureReason.None,
        };

        yield return new object[]
        {
            new Dictionary<string, string> { [FlutterwaveWebhookVerifier.SignatureHeaderName] = "wrong-hash-value" },
            false,
            WebhookVerificationFailureReason.SignatureMismatch,
        };

        yield return new object[]
        {
            new Dictionary<string, string>(),
            false,
            WebhookVerificationFailureReason.MissingHeader,
        };
    }

    [Theory]
    [MemberData(nameof(VerificationCases))]
    public void Verify_ReturnsExpectedResult(
        Dictionary<string, string> headers,
        bool expectedValid,
        WebhookVerificationFailureReason expectedReason)
    {
        var verifier = new FlutterwaveWebhookVerifier(Fixture.SecretHash);
        var payload = Encoding.UTF8.GetBytes("{\"event\":\"charge.completed\"}");

        var result = verifier.Verify(payload, headers);

        Assert.Equal(expectedValid, result.IsValid);
        Assert.Equal(expectedReason, result.FailureReason);
    }

    [Fact]
    public void Verify_DoesNotDependOnPayloadContent()
    {
        var verifier = new FlutterwaveWebhookVerifier(Fixture.SecretHash);
        var headers = new Dictionary<string, string>
        {
            [FlutterwaveWebhookVerifier.SignatureHeaderName] = Fixture.SecretHash,
        };

        var resultWithEmptyPayload = verifier.Verify(ReadOnlySpan<byte>.Empty, headers);
        var resultWithLargePayload = verifier.Verify(
            Encoding.UTF8.GetBytes(new string('x', 10_000)), headers);

        Assert.True(resultWithEmptyPayload.IsValid);
        Assert.True(resultWithLargePayload.IsValid);
    }

    [Fact]
    public void Verify_ImplementsIWebhookVerifier()
    {
        IWebhookVerifier verifier = new FlutterwaveWebhookVerifier(Fixture.SecretHash);
        var headers = new Dictionary<string, string>
        {
            [FlutterwaveWebhookVerifier.SignatureHeaderName] = Fixture.SecretHash,
        };

        var result = verifier.Verify(ReadOnlySpan<byte>.Empty, headers);

        Assert.True(result.IsValid);
    }
}
