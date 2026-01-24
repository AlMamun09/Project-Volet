using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Volet.Domain.Entities;

namespace Volet.Infrastructure.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<KycSubmission> KycSubmissions { get; set; }
        public DbSet<KycDocument> KycDocuments { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // KYC Submission configuration
            builder.Entity<KycSubmission>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasOne(e => e.User)
                      .WithMany()
                      .HasForeignKey(e => e.UserId)
                      .OnDelete(DeleteBehavior.Cascade);

                entity.HasMany(e => e.Documents)
                      .WithOne(d => d.KycSubmission)
                      .HasForeignKey(d => d.KycSubmissionId)
                      .OnDelete(DeleteBehavior.Cascade);
            });

            // KYC Document configuration
            builder.Entity<KycDocument>(entity =>
            {
                entity.HasKey(e => e.Id);
            });
        }
    }
}