using Microsoft.AspNetCore.Identity;

namespace Volet.Domain.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public bool HasAcceptedUserAgreement { get; set; }
        public bool HasAcceptedPrivacyPolicy { get; set; }
        public bool HasAcceptedNewsletterAndAnalytics { get; set; }
    }
}