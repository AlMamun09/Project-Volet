namespace Volet.Application.DTOs.TwoFactor
{
    /// <summary>
    /// Response model for login challenge when 2FA is required
    /// </summary>
    public class LoginChallengeResponseDto
    {
        /// <summary>
        /// Indicates if two-factor authentication is required
        /// </summary>
        public required bool RequiresTwoFactor { get; set; }

        /// <summary>
        /// The 2FA method configured for the user ('Email' or 'Authenticator')
        /// </summary>
        /// <example>Authenticator</example>
        public required string TwoFactorMethod { get; set; }

        /// <summary>
        /// Short-lived token to use for 2FA verification (valid for 10 minutes)
        /// </summary>
        public required string ChallengeToken { get; set; }

        /// <summary>
        /// User-friendly message about next steps
        /// </summary>
        /// <example>Please enter the code from your authenticator app.</example>
        public required string Message { get; set; }
    }
}
