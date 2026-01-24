using System.ComponentModel.DataAnnotations;

namespace Volet.Application.DTOs.Kyc
{
    /// <summary>
    /// Request model for KYC submission with all 4 steps data
    /// </summary>
    public class KycSubmissionDto
    {
        // ==================== Step 1: Personal Information ====================

        /// <summary>
        /// User's first name
        /// </summary>
        /// <example>John</example>
        [Required(ErrorMessage = "First name is required")]
        [StringLength(50, ErrorMessage = "First name cannot exceed 50 characters")]
        public string FirstName { get; set; } = string.Empty;

        /// <summary>
        /// User's last name
        /// </summary>
        /// <example>Doe</example>
        [Required(ErrorMessage = "Last name is required")]
        [StringLength(50, ErrorMessage = "Last name cannot exceed 50 characters")]
        public string LastName { get; set; } = string.Empty;

        /// <summary>
        /// Date of birth (must be 18+ years old)
        /// </summary>
        [Required(ErrorMessage = "Date of birth is required")]
        public DateTime DateOfBirth { get; set; }

        /// <summary>
        /// Nationality/Country
        /// </summary>
        /// <example>United States</example>
        [Required(ErrorMessage = "Nationality is required")]
        public string Nationality { get; set; } = string.Empty;

        /// <summary>
        /// Phone number with country code
        /// </summary>
        /// <example>+1 (555) 000-0000</example>
        [Required(ErrorMessage = "Phone number is required")]
        [Phone(ErrorMessage = "Invalid phone number format")]
        public string PhoneNumber { get; set; } = string.Empty;

        /// <summary>
        /// Street address
        /// </summary>
        /// <example>123 Main Street</example>
        [Required(ErrorMessage = "Street address is required")]
        [StringLength(200, ErrorMessage = "Street address cannot exceed 200 characters")]
        public string StreetAddress { get; set; } = string.Empty;

        /// <summary>
        /// City
        /// </summary>
        /// <example>New York</example>
        [Required(ErrorMessage = "City is required")]
        [StringLength(100, ErrorMessage = "City cannot exceed 100 characters")]
        public string City { get; set; } = string.Empty;

        /// <summary>
        /// Postal/ZIP code
        /// </summary>
        /// <example>10001</example>
        [Required(ErrorMessage = "Postal code is required")]
        [StringLength(20, ErrorMessage = "Postal code cannot exceed 20 characters")]
        public string PostalCode { get; set; } = string.Empty;

        // ==================== Step 2: Document Verification ====================

        /// <summary>
        /// ID document type: Passport, NID, or DrivingLicense
        /// </summary>
        /// <example>Passport</example>
        [Required(ErrorMessage = "Document type is required")]
        [RegularExpression("^(Passport|NID|DrivingLicense)$", ErrorMessage = "Document type must be Passport, NID, or DrivingLicense")]
        public string DocumentType { get; set; } = string.Empty;

        // Note: DocumentFront, DocumentBack are IFormFile - handled in controller

        // ==================== Step 4: Address Proof ====================

        /// <summary>
        /// Address proof document type: UtilityBill, BankStatement, TaxBill, or RentalAgreement
        /// </summary>
        /// <example>UtilityBill</example>
        [Required(ErrorMessage = "Address proof type is required")]
        [RegularExpression("^(UtilityBill|BankStatement|TaxBill|RentalAgreement)$", 
            ErrorMessage = "Address proof type must be UtilityBill, BankStatement, TaxBill, or RentalAgreement")]
        public string AddressProofType { get; set; } = string.Empty;
    }
}
