namespace Volet.Application.Interfaces
{
    // Service for TOTP (Time-based One-Time Password) operations
    public interface ITotpService
    {
        // Generate a new Base32 encoded secret key for the user
        string GenerateSecretKey();
        
        // Generate the otpauth: URI used by authenticator apps
        string GenerateQrCodeUri(string email, string secretKey, string issuer = "Volet");

        // Generate QR code as Base64 data URI for embedding in HTML
        string GenerateQrCodeDataUri(string email, string secretKey, string issuer = "Volet");
        
        // Validate a 6-digit TOTP code against the secret key
        bool ValidateCode(string secretKey, string code);

        // Format the secret key for manual entry (groups of 4 characters)
        string FormatKeyForManualEntry(string secretKey);
    }
}
