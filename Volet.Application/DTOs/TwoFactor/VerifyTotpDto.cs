namespace Volet.Application.DTOs.TwoFactor
{
    /// <summary>
    /// Request model for TOTP verification (step 2 of authenticator-based 2FA)
    /// </summary>
    public class VerifyTotpDto
    {
        /// <summary>
        /// User's email address
        /// </summary>
        /// <example>john.doe@example.com</example>
        public required string Email { get; set; }

        /// <summary>
        /// 6-digit TOTP code from authenticator app
        /// </summary>
        /// <example>123456</example>
        public required string Code { get; set; }

        /// <summary>
        /// Challenge token received from login-challenge endpoint
        /// </summary>
        public required string ChallengeToken { get; set; }

        /// <summary>
        /// Keep user logged in with persistent cookie
        /// </summary>
        public bool RememberMe { get; set; }
    }
}
