namespace Volet.Application.DTOs.Kyc
{
    /// <summary>
    /// Response model for user's KYC verification status
    /// </summary>
    public class KycStatusResponseDto
    {
        /// <summary>
        /// Whether user has submitted KYC
        /// </summary>
        public bool HasSubmitted { get; set; }

        /// <summary>
        /// Current status: Pending, UnderReview, Approved, Rejected
        /// </summary>
        /// <example>Pending</example>
        public string? Status { get; set; }

        /// <summary>
        /// Rejection reason if status is Rejected
        /// </summary>
        public string? RejectionReason { get; set; }

        /// <summary>
        /// When the KYC was submitted
        /// </summary>
        public DateTime? SubmittedAt { get; set; }

        /// <summary>
        /// When the KYC was reviewed (approved/rejected)
        /// </summary>
        public DateTime? ReviewedAt { get; set; }
    }
}
