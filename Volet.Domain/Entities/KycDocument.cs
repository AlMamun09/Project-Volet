namespace Volet.Domain.Entities
{
    /// <summary>
    /// Stores uploaded KYC document files
    /// </summary>
    public class KycDocument
    {
        public int Id { get; set; }
        
        public Guid KycSubmissionId { get; set; }
        
        /// <summary>
        /// Document category: IdFront, IdBack, Selfie, AddressProof
        /// </summary>
        public string DocumentCategory { get; set; } = string.Empty;
        
        /// <summary>
        /// Original file name
        /// </summary>
        public string FileName { get; set; } = string.Empty;
        
        /// <summary>
        /// Stored file path relative to wwwroot
        /// </summary>
        public string FilePath { get; set; } = string.Empty;
        
        /// <summary>
        /// MIME type: image/png, image/jpeg, application/pdf
        /// </summary>
        public string ContentType { get; set; } = string.Empty;
        
        /// <summary>
        /// File size in bytes
        /// </summary>
        public long FileSize { get; set; }
        
        public DateTime UploadedAt { get; set; } = DateTime.UtcNow;
        
        // Navigation
        public KycSubmission KycSubmission { get; set; } = null!;
    }
}
