namespace Volet.Application.DTOs.TwoFactor
{
    /// <summary>
    /// Request model for setting 2FA preference
    /// </summary>
    public class Set2FAPreferenceDto
    {
        /// <summary>
        /// Preferred 2FA method: 'Authenticator' or 'Email'
        /// </summary>
        /// <example>Authenticator</example>
        public required string Method { get; set; }
    }
}
