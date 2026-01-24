namespace Volet.Application.DTOs.TwoFactor
{
    /// <summary>
    /// Response model for current 2FA status
    /// </summary>
    public class TwoFactorStatusDto
    {
        /// <summary>
        /// Whether 2FA is currently enabled for the user
        /// </summary>
        public required bool IsTwoFactorEnabled { get; set; }

        /// <summary>
        /// Current 2FA method ('Authenticator', 'Email', or null if disabled)
        /// </summary>
        /// <example>Authenticator</example>
        public string? TwoFactorMethod { get; set; }

        /// <summary>
        /// Whether the authenticator app has been confirmed
        /// </summary>
        public required bool IsAuthenticatorConfirmed { get; set; }
    }
}
