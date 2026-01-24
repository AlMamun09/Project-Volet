using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Volet.Application.DTOs.Kyc;
using Volet.Domain.Entities;
using Volet.Infrastructure.Data;

namespace Volet.Web.Controllers.Reports
{
    /// <summary>
    /// KYC verification controller for user submissions and admin review
    /// </summary>
    [Route("api/kyc")]
    [ApiController]
    [Produces("application/json")]
    public class KycController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _environment;
        private readonly ILogger<KycController> _logger;

        // File upload constraints
        private const long MaxFileSize = 10 * 1024 * 1024; // 10MB
        private static readonly string[] AllowedImageExtensions = { ".png", ".jpg", ".jpeg" };
        private static readonly string[] AllowedDocumentExtensions = { ".png", ".jpg", ".jpeg", ".pdf" };

        public KycController(
            ApplicationDbContext context,
            IWebHostEnvironment environment,
            ILogger<KycController> logger)
        {
            _context = context;
            _environment = environment;
            _logger = logger;
        }

        // ==================== User Endpoints ====================

        /// <summary>
        /// Submit complete KYC application with all documents
        /// </summary>
        /// <remarks>
        /// Multipart form data with personal info and file uploads.
        /// Required files: documentFront, selfie, addressProof.
        /// DocumentBack required only for NID or DrivingLicense.
        /// </remarks>
        /// <response code="200">KYC submitted successfully</response>
        /// <response code="400">Validation error or invalid files</response>
        /// <response code="401">User not authenticated</response>
        /// <response code="409">User already has a pending/approved KYC</response>
        [Authorize]
        [HttpPost("submit")]
        [Consumes("multipart/form-data")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status409Conflict)]
        [RequestSizeLimit(50 * 1024 * 1024)] // 50MB total request limit
        public async Task<IActionResult> Submit(
            [FromForm] KycSubmissionDto model,
            IFormFile documentFront,
            IFormFile? documentBack,
            IFormFile selfie,
            IFormFile addressProof)
        {
            var userId = User.FindFirst("UserId")?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            // Check for existing submission
            var existingSubmission = await _context.KycSubmissions
                .FirstOrDefaultAsync(k => k.UserId == userId && 
                    (k.Status == KycStatus.Pending || k.Status == KycStatus.Approved));
            
            if (existingSubmission != null)
            {
                return Conflict(new { 
                    Status = "Error", 
                    Message = existingSubmission.Status == KycStatus.Approved 
                        ? "Your KYC is already approved." 
                        : "You already have a pending KYC submission." 
                });
            }

            // Validate document front
            var frontValidation = ValidateFile(documentFront, AllowedDocumentExtensions, "Document front");
            if (frontValidation != null) return frontValidation;

            // Validate document back (required for NID and DrivingLicense)
            if (model.DocumentType is "NID" or "DrivingLicense")
            {
                if (documentBack == null)
                    return BadRequest(new { Status = "Error", Message = "Back side of document is required for NID and Driving License." });
                
                var backValidation = ValidateFile(documentBack, AllowedDocumentExtensions, "Document back");
                if (backValidation != null) return backValidation;
            }

            // Validate selfie (images only)
            var selfieValidation = ValidateFile(selfie, AllowedImageExtensions, "Selfie");
            if (selfieValidation != null) return selfieValidation;

            // Validate address proof
            var addressValidation = ValidateFile(addressProof, AllowedDocumentExtensions, "Address proof");
            if (addressValidation != null) return addressValidation;

            // Create KYC submission
            var submission = new KycSubmission
            {
                UserId = userId,
                FirstName = model.FirstName,
                LastName = model.LastName,
                DateOfBirth = model.DateOfBirth,
                Nationality = model.Nationality,
                PhoneNumber = model.PhoneNumber,
                StreetAddress = model.StreetAddress,
                City = model.City,
                PostalCode = model.PostalCode,
                DocumentType = model.DocumentType,
                AddressProofType = model.AddressProofType,
                Status = KycStatus.Pending,
                SubmittedAt = DateTime.UtcNow
            };

            _context.KycSubmissions.Add(submission);
            await _context.SaveChangesAsync();

            // Save files
            var uploadPath = Path.Combine(_environment.WebRootPath, "uploads", "KYC", userId);
            Directory.CreateDirectory(uploadPath);

            try
            {
                await SaveDocument(submission.Id, documentFront, "IdFront", uploadPath);
                
                if (documentBack != null)
                    await SaveDocument(submission.Id, documentBack, "IdBack", uploadPath);
                
                await SaveDocument(submission.Id, selfie, "Selfie", uploadPath);
                await SaveDocument(submission.Id, addressProof, "AddressProof", uploadPath);

                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving KYC documents for user {UserId}", userId);
                _context.KycSubmissions.Remove(submission);
                await _context.SaveChangesAsync();
                return StatusCode(500, new { Status = "Error", Message = "Failed to save documents. Please try again." });
            }

            _logger.LogInformation("KYC submitted for user {UserId}, submission ID {SubmissionId}", userId, submission.Id);

            return Ok(new { Status = "Success", Message = "KYC submitted successfully. We will review your application shortly." });
        }

        /// <summary>
        /// Get current user's KYC verification status
        /// </summary>
        /// <response code="200">KYC status returned</response>
        /// <response code="401">User not authenticated</response>
        [Authorize]
        [HttpGet("status")]
        [ProducesResponseType(typeof(KycStatusResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> GetStatus()
        {
            var userId = User.FindFirst("UserId")?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var submission = await _context.KycSubmissions
                .Where(k => k.UserId == userId)
                .OrderByDescending(k => k.SubmittedAt)
                .FirstOrDefaultAsync();

            return Ok(new KycStatusResponseDto
            {
                HasSubmitted = submission != null,
                Status = submission?.Status.ToString(),
                RejectionReason = submission?.RejectionReason,
                SubmittedAt = submission?.SubmittedAt,
                ReviewedAt = submission?.ReviewedAt
            });
        }

        // ==================== Admin Endpoints ====================

        /// <summary>
        /// Get KYC verification queue for admin review
        /// </summary>
        /// <param name="status">Filter by status (optional)</param>
        /// <response code="200">Queue items returned</response>
        /// <response code="401">Not authenticated</response>
        [Authorize]  // TODO: Add admin role check
        [HttpGet("admin/queue")]
        [ProducesResponseType(typeof(List<KycQueueItemDto>), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> GetQueue([FromQuery] string? status = null)
        {
            var query = _context.KycSubmissions
                .Include(k => k.User)
                .AsQueryable();

            if (!string.IsNullOrEmpty(status) && Enum.TryParse<KycStatus>(status, out var kycStatus))
            {
                query = query.Where(k => k.Status == kycStatus);
            }

            var items = await query
                .OrderByDescending(k => k.SubmittedAt)
                .Select(k => new KycQueueItemDto
                {
                    Id = k.Id,
                    UserId = k.UserId,
                    FullName = k.FirstName + " " + k.LastName,
                    Email = k.User.Email ?? "",
                    DocumentType = k.DocumentType,
                    Country = k.Nationality,
                    Status = k.Status.ToString(),
                    SubmittedAt = k.SubmittedAt
                })
                .ToListAsync();

            return Ok(items);
        }

        /// <summary>
        /// Get detailed KYC submission for admin review
        /// </summary>
        /// <param name="id">Submission ID</param>
        /// <response code="200">Submission details returned</response>
        /// <response code="404">Submission not found</response>
        [Authorize]  // TODO: Add admin role check
        [HttpGet("admin/{id:guid}")]
        [ProducesResponseType(typeof(KycDetailDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> GetDetail(Guid id)
        {
            var submission = await _context.KycSubmissions
                .Include(k => k.User)
                .Include(k => k.Documents)
                .FirstOrDefaultAsync(k => k.Id == id);

            if (submission == null)
                return NotFound(new { Status = "Error", Message = "KYC submission not found." });

            return Ok(new KycDetailDto
            {
                Id = submission.Id,
                UserId = submission.UserId,
                FullName = submission.FirstName + " " + submission.LastName,
                Email = submission.User.Email ?? "",
                DateOfBirth = submission.DateOfBirth,
                Nationality = submission.Nationality,
                PhoneNumber = submission.PhoneNumber,
                StreetAddress = submission.StreetAddress,
                City = submission.City,
                PostalCode = submission.PostalCode,
                DocumentType = submission.DocumentType,
                AddressProofType = submission.AddressProofType,
                Documents = submission.Documents.Select(d => new KycDocumentDto
                {
                    Id = d.Id,
                    Category = d.DocumentCategory,
                    FileName = d.FileName,
                    Url = "/" + d.FilePath.Replace("\\", "/"),
                    ContentType = d.ContentType
                }).ToList(),
                Status = submission.Status.ToString(),
                RejectionReason = submission.RejectionReason,
                SubmittedAt = submission.SubmittedAt,
                ReviewedAt = submission.ReviewedAt
            });
        }

        /// <summary>
        /// Approve a KYC submission
        /// </summary>
        /// <param name="id">Submission ID</param>
        /// <response code="200">KYC approved</response>
        /// <response code="404">Submission not found</response>
        [Authorize]  // TODO: Add admin role check
        [HttpPost("admin/{id:guid}/approve")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> Approve(Guid id)
        {
            var submission = await _context.KycSubmissions.FindAsync(id);
            if (submission == null)
                return NotFound(new { Status = "Error", Message = "KYC submission not found." });

            submission.Status = KycStatus.Approved;
            submission.ReviewedAt = DateTime.UtcNow;
            submission.ReviewedBy = User.FindFirst("UserId")?.Value;

            await _context.SaveChangesAsync();

            _logger.LogInformation("KYC {SubmissionId} approved by {AdminId}", id, submission.ReviewedBy);

            return Ok(new { Status = "Success", Message = "KYC approved successfully." });
        }

        /// <summary>
        /// Reject a KYC submission with reason
        /// </summary>
        /// <param name="id">Submission ID</param>
        /// <param name="model">Rejection reason</param>
        /// <response code="200">KYC rejected</response>
        /// <response code="400">Rejection reason required</response>
        /// <response code="404">Submission not found</response>
        [Authorize]  // TODO: Add admin role check
        [HttpPost("admin/{id:guid}/reject")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> Reject(Guid id, [FromBody] KycReviewDto model)
        {
            if (string.IsNullOrWhiteSpace(model.RejectionReason))
                return BadRequest(new { Status = "Error", Message = "Rejection reason is required." });

            var submission = await _context.KycSubmissions.FindAsync(id);
            if (submission == null)
                return NotFound(new { Status = "Error", Message = "KYC submission not found." });

            submission.Status = KycStatus.Rejected;
            submission.RejectionReason = model.RejectionReason;
            submission.ReviewedAt = DateTime.UtcNow;
            submission.ReviewedBy = User.FindFirst("UserId")?.Value;

            await _context.SaveChangesAsync();

            _logger.LogInformation("KYC {SubmissionId} rejected by {AdminId}: {Reason}", 
                id, submission.ReviewedBy, model.RejectionReason);

            return Ok(new { Status = "Success", Message = "KYC rejected." });
        }

        // ==================== Helper Methods ====================

        private IActionResult? ValidateFile(IFormFile file, string[] allowedExtensions, string fieldName)
        {
            if (file == null || file.Length == 0)
                return BadRequest(new { Status = "Error", Message = $"{fieldName} is required." });

            if (file.Length > MaxFileSize)
                return BadRequest(new { Status = "Error", Message = $"{fieldName} must be less than 10MB." });

            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
            if (!allowedExtensions.Contains(extension))
                return BadRequest(new { Status = "Error", Message = $"{fieldName} must be {string.Join(", ", allowedExtensions)}." });

            return null;
        }

        private async Task SaveDocument(Guid submissionId, IFormFile file, string category, string uploadPath)
        {
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
            var fileName = $"{category.ToLower()}_{timestamp}{extension}";
            var filePath = Path.Combine(uploadPath, fileName);

            using var stream = new FileStream(filePath, FileMode.Create);
            await file.CopyToAsync(stream);

            var document = new KycDocument
            {
                KycSubmissionId = submissionId,
                DocumentCategory = category,
                FileName = file.FileName,
                FilePath = Path.Combine("uploads", "KYC", User.FindFirst("UserId")!.Value, fileName),
                ContentType = file.ContentType,
                FileSize = file.Length,
                UploadedAt = DateTime.UtcNow
            };

            _context.KycDocuments.Add(document);
        }
    }
}
