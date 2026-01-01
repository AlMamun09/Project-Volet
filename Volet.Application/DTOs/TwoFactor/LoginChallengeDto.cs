namespace Volet.Application.DTOs.TwoFactor
{
    public class LoginChallengeDto
    {
        public required string Email { get; set; }
        public required string Password { get; set; }
        public bool RememberMe { get; set; }
    }
}
