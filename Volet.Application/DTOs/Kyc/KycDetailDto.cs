namespace Volet.Application.DTOs.Kyc
{
    /// <summary>
    /// Detailed KYC submission for admin review
    /// </summary>
    public class KycDetailDto
    {
        public Guid Id { get; set; }

        // User Info
        public string UserId { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;

        // Personal Information
        public DateTime DateOfBirth { get; set; }
        public string Nationality { get; set; } = string.Empty;
        public string PhoneNumber { get; set; } = string.Empty;
        public string StreetAddress { get; set; } = string.Empty;
        public string City { get; set; } = string.Empty;
        public string PostalCode { get; set; } = string.Empty;

        // Document Info
        public string DocumentType { get; set; } = string.Empty;
        public string AddressProofType { get; set; } = string.Empty;

        // Documents
        public List<KycDocumentDto> Documents { get; set; } = new();

        // Status
        public string Status { get; set; } = string.Empty;
        public string? RejectionReason { get; set; }
        public DateTime SubmittedAt { get; set; }
        public DateTime? ReviewedAt { get; set; }
    }

    /// <summary>
    /// Document info for admin review
    /// </summary>
    public class KycDocumentDto
    {
        public int Id { get; set; }

        /// <summary>
        /// Category: IdFront, IdBack, Selfie, AddressProof
        /// </summary>
        public string Category { get; set; } = string.Empty;

        /// <summary>
        /// Original file name
        /// </summary>
        public string FileName { get; set; } = string.Empty;

        /// <summary>
        /// URL to access the document
        /// </summary>
        public string Url { get; set; } = string.Empty;

        /// <summary>
        /// Content type (image/png, application/pdf, etc.)
        /// </summary>
        public string ContentType { get; set; } = string.Empty;
    }
}
