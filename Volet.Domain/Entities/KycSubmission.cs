namespace Volet.Domain.Entities
{
    /// <summary>
    /// KYC submission containing personal info and verification status
    /// </summary>
    public class KycSubmission
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        
        /// <summary>
        /// Foreign key to ApplicationUser
        /// </summary>
        public string UserId { get; set; } = string.Empty;
        
        // ==================== Personal Information (Step 1) ====================
        
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public DateTime DateOfBirth { get; set; }
        public string Nationality { get; set; } = string.Empty;
        public string PhoneNumber { get; set; } = string.Empty;
        public string StreetAddress { get; set; } = string.Empty;
        public string City { get; set; } = string.Empty;
        public string PostalCode { get; set; } = string.Empty;
        
        // ==================== Document Info (Step 2) ====================
        
        /// <summary>
        /// Document type: Passport, NID, DrivingLicense
        /// </summary>
        public string DocumentType { get; set; } = string.Empty;
        
        // ==================== Address Proof Info (Step 4) ====================
        
        /// <summary>
        /// Address proof type: UtilityBill, BankStatement, TaxBill, RentalAgreement
        /// </summary>
        public string AddressProofType { get; set; } = string.Empty;
        
        // ==================== Status ====================
        
        public KycStatus Status { get; set; } = KycStatus.Pending;
        
        /// <summary>
        /// Reason for rejection (if rejected)
        /// </summary>
        public string? RejectionReason { get; set; }
        
        public DateTime SubmittedAt { get; set; } = DateTime.UtcNow;
        public DateTime? ReviewedAt { get; set; }
        
        /// <summary>
        /// Admin who reviewed this submission
        /// </summary>
        public string? ReviewedBy { get; set; }
        
        // ==================== Navigation ====================
        
        public ApplicationUser User { get; set; } = null!;
        public ICollection<KycDocument> Documents { get; set; } = new List<KycDocument>();
    }
}
