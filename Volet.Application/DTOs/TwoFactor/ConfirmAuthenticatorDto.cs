namespace Volet.Application.DTOs.TwoFactor
{
    /// <summary>
    /// Request model for confirming authenticator setup
    /// </summary>
    public class ConfirmAuthenticatorDto
    {
        /// <summary>
        /// 6-digit verification code from authenticator app
        /// </summary>
        /// <example>123456</example>
        public required string Code { get; set; }
    }
}
