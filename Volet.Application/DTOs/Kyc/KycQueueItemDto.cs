namespace Volet.Application.DTOs.Kyc
{
    /// <summary>
    /// KYC queue item for admin list view
    /// </summary>
    public class KycQueueItemDto
    {
        public Guid Id { get; set; }

        /// <summary>
        /// User ID
        /// </summary>
        public string UserId { get; set; } = string.Empty;

        /// <summary>
        /// User's full name
        /// </summary>
        /// <example>John Doe</example>
        public string FullName { get; set; } = string.Empty;

        /// <summary>
        /// User's email address
        /// </summary>
        /// <example>john.doe@example.com</example>
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// ID document type submitted
        /// </summary>
        /// <example>Passport</example>
        public string DocumentType { get; set; } = string.Empty;

        /// <summary>
        /// User's nationality/country
        /// </summary>
        /// <example>United States</example>
        public string Country { get; set; } = string.Empty;

        /// <summary>
        /// Current status
        /// </summary>
        /// <example>Pending</example>
        public string Status { get; set; } = string.Empty;

        /// <summary>
        /// When submitted
        /// </summary>
        public DateTime SubmittedAt { get; set; }
    }
}
