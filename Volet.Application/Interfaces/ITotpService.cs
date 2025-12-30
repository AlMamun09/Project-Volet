namespace Volet.Application.Interfaces
{
    /// <summary>
    /// Service for TOTP (Time-based One-Time Password) operations
    /// Compatible with Google Authenticator and similar apps
    /// </summary>
    public interface ITotpService
    {
        /// <summary>
        /// Generate a new Base32 encoded secret key for the user
        /// </summary>
        string GenerateSecretKey();

        /// <summary>
        /// Generate the otpauth:// URI used by authenticator apps
        /// </summary>
        string GenerateQrCodeUri(string email, string secretKey, string issuer = "Volet");

        /// <summary>
        /// Generate QR code as Base64 data URI for embedding in HTML
        /// </summary>
        string GenerateQrCodeDataUri(string email, string secretKey, string issuer = "Volet");

        /// <summary>
        /// Validate a 6-digit TOTP code against the secret key
        /// </summary>
        bool ValidateCode(string secretKey, string code);

        /// <summary>
        /// Format the secret key for manual entry (groups of 4 characters)
        /// </summary>
        string FormatKeyForManualEntry(string secretKey);
    }
}
