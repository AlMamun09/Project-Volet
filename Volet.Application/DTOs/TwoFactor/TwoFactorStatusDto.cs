namespace Volet.Application.DTOs.TwoFactor
{
    public class TwoFactorStatusDto
    {
        public required bool IsTwoFactorEnabled { get; set; }
        public string? TwoFactorMethod { get; set; }
        public required bool IsAuthenticatorConfirmed { get; set; }
    }
}
