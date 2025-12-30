namespace Volet.Application.DTOs.TwoFactor
{
    public class AuthenticatorSetupDto
    {
        public required string SecretKey { get; set; }
        public required string QrCodeDataUri { get; set; }
        public required string ManualEntryKey { get; set; }
    }
}
