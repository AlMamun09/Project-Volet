namespace Volet.Application.DTOs.TwoFactor
{
    /// <summary>
    /// Request model for login challenge (step 1 of authentication)
    /// </summary>
    public class LoginChallengeDto
    {
        /// <summary>
        /// User's email address
        /// </summary>
        /// <example>john.doe@example.com</example>
        public required string Email { get; set; }

        /// <summary>
        /// User's password
        /// </summary>
        /// <example>SecurePass123!</example>
        public required string Password { get; set; }

        /// <summary>
        /// Keep user logged in with persistent cookie (7 days)
        /// </summary>
        public bool RememberMe { get; set; }
    }
}
