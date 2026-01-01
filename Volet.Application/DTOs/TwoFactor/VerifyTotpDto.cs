namespace Volet.Application.DTOs.TwoFactor
{
    public class VerifyTotpDto
    {
        public required string Email { get; set; }
        public required string Code { get; set; }
        public required string ChallengeToken { get; set; }
        public bool RememberMe { get; set; }
    }
}
