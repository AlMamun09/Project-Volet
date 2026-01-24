namespace Volet.Domain.Entities
{
    /// <summary>
    /// KYC submission status
    /// </summary>
    public enum KycStatus
    {
        /// <summary>Waiting for admin review</summary>
        Pending,
        /// <summary>Admin is reviewing the submission</summary>
        UnderReview,
        /// <summary>KYC verified and approved</summary>
        Approved,
        /// <summary>KYC rejected with reason</summary>
        Rejected
    }
}
