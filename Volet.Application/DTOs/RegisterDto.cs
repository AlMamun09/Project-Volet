namespace Volet.Application.DTOs
{
    /// <summary>
    /// Request model for user registration
    /// </summary>
    public class RegisterDto
    {
        /// <summary>
        /// User's first name
        /// </summary>
        /// <example>John</example>
        public required string FirstName { get; set; }

        /// <summary>
        /// User's last name
        /// </summary>
        /// <example>Doe</example>
        public required string LastName { get; set; }

        /// <summary>
        /// User's email address (used for login)
        /// </summary>
        /// <example>john.doe@example.com</example>
        public required string Email { get; set; }

        /// <summary>
        /// Password (minimum 8 characters, requires digit)
        /// </summary>
        /// <example>SecurePass123!</example>
        public required string Password { get; set; }

        /// <summary>
        /// Must be true - User has accepted the User Agreement
        /// </summary>
        public required bool HasAcceptedUserAgreement { get; set; }

        /// <summary>
        /// Must be true - User has accepted the Privacy Policy
        /// </summary>
        public required bool HasAcceptedPrivacyPolicy { get; set; }

        /// <summary>
        /// Optional - User consents to newsletter and analytics
        /// </summary>
        public bool HasAcceptedNewsletterAndAnalytics { get; set; }
    }
}
