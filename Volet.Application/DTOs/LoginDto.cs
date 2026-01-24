namespace Volet.Application.DTOs
{
    /// <summary>
    /// Request model for user login (legacy endpoint)
    /// </summary>
    public class LoginDto
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
    }
}
