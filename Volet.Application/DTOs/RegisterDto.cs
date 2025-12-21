namespace Volet.Application.DTOs
{
    public class RegisterDto
    {
        public required string FirstName { get; set; }
        public required string LastName { get; set; }
        public required string Email { get; set; }
        public required string Password { get; set; }
        public required bool HasAcceptedUserAgreement { get; set; }
        public required bool HasAcceptedPrivacyPolicy { get; set; }
        public bool HasAcceptedNewsletterAndAnalytics { get; set; }
    }
}
