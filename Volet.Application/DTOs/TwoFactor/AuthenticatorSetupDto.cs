namespace Volet.Application.DTOs.TwoFactor
{
    /// <summary>
    /// Response model for authenticator setup containing QR code data
    /// </summary>
    public class AuthenticatorSetupDto
    {
        /// <summary>
        /// Base32-encoded secret key for authenticator
        /// </summary>
        public required string SecretKey { get; set; }

        /// <summary>
        /// Data URI for QR code image (can be used directly in img src)
        /// </summary>
        public required string QrCodeDataUri { get; set; }

        /// <summary>
        /// Human-readable key for manual entry in authenticator app
        /// </summary>
        /// <example>JBSW Y3DP EHPK 3PXP</example>
        public required string ManualEntryKey { get; set; }
    }
}
