namespace Volet.Application.DTOs.TwoFactor
{
    public class LoginChallengeResponseDto
    {
        public required bool RequiresTwoFactor { get; set; }
        public required string TwoFactorMethod { get; set; }
        public required string ChallengeToken { get; set; }
        public required string Message { get; set; }
    }
}
