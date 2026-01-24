using System.ComponentModel.DataAnnotations;

namespace Volet.Application.DTOs.Kyc
{
    /// <summary>
    /// Request model for admin KYC review action
    /// </summary>
    public class KycReviewDto
    {
        /// <summary>
        /// Review action: Approve or Reject
        /// </summary>
        /// <example>Approve</example>
        [Required(ErrorMessage = "Action is required")]
        [RegularExpression("^(Approve|Reject)$", ErrorMessage = "Action must be Approve or Reject")]
        public string Action { get; set; } = string.Empty;

        /// <summary>
        /// Rejection reason (required if action is Reject)
        /// </summary>
        /// <example>Document is expired</example>
        [StringLength(500, ErrorMessage = "Rejection reason cannot exceed 500 characters")]
        public string? RejectionReason { get; set; }
    }
}
