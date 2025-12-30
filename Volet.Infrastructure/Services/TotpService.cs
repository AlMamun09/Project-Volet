using OtpNet;
using QRCoder;
using System.Text;
using Volet.Application.Interfaces;

namespace Volet.Infrastructure.Services
{
    /// <summary>
    /// Implementation of TOTP service using Otp.NET and QRCoder
    /// </summary>
    public class TotpService : ITotpService
    {
        private const int SecretKeyLength = 20; // 160 bits
        private const string Issuer = "Volet";

        /// <summary>
        /// Generate a new Base32 encoded secret key
        /// </summary>
        public string GenerateSecretKey()
        {
            var key = KeyGeneration.GenerateRandomKey(SecretKeyLength);
            return Base32Encoding.ToString(key);
        }

        /// <summary>
        /// Generate the otpauth:// URI for authenticator apps
        /// </summary>
        public string GenerateQrCodeUri(string email, string secretKey, string issuer = Issuer)
        {
            // Format: otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}
            var encodedEmail = Uri.EscapeDataString(email);
            var encodedIssuer = Uri.EscapeDataString(issuer);
            return $"otpauth://totp/{encodedIssuer}:{encodedEmail}?secret={secretKey}&issuer={encodedIssuer}";
        }

        /// <summary>
        /// Generate QR code as Base64 data URI
        /// </summary>
        public string GenerateQrCodeDataUri(string email, string secretKey, string issuer = Issuer)
        {
            var uri = GenerateQrCodeUri(email, secretKey, issuer);

            using var qrGenerator = new QRCodeGenerator();
            using var qrCodeData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            
            var qrCodeBytes = qrCode.GetGraphic(5);
            var base64 = Convert.ToBase64String(qrCodeBytes);
            
            return $"data:image/png;base64,{base64}";
        }

        /// <summary>
        /// Validate a 6-digit TOTP code
        /// </summary>
        public bool ValidateCode(string secretKey, string code)
        {
            if (string.IsNullOrWhiteSpace(code) || code.Length != 6)
                return false;

            try
            {
                var keyBytes = Base32Encoding.ToBytes(secretKey);
                var totp = new Totp(keyBytes);
                
                // Verify with a window of 1 step (30 seconds before/after)
                return totp.VerifyTotp(code, out _, new VerificationWindow(previous: 1, future: 1));
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Format key for manual entry (groups of 4 characters with spaces)
        /// </summary>
        public string FormatKeyForManualEntry(string secretKey)
        {
            var formatted = new StringBuilder();
            for (int i = 0; i < secretKey.Length; i += 4)
            {
                if (i > 0) formatted.Append(' ');
                formatted.Append(secretKey.Substring(i, Math.Min(4, secretKey.Length - i)));
            }
            return formatted.ToString();
        }
    }
}
