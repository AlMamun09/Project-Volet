using Microsoft.AspNetCore.Identity;

namespace Volet.Domain.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public bool HasAcceptedUserAgreement { get; set; }
        public bool HasAcceptedPrivacyPolicy { get; set; }
        public bool HasAcceptedNewsletterAndAnalytics { get; set; }

        // Two-Factor Authentication Properties
        public bool IsTwoFactorEnabled { get; set; } = false;
        public string? TwoFactorMethod { get; set; } // "Authenticator" or "Email"
        public string? AuthenticatorSecretKey { get; set; } // Base32 encoded TOTP secret
        public bool IsAuthenticatorConfirmed { get; set; } = false;
    }
}