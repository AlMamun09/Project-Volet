using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Volet.Domain.Entities;

namespace Volet.Infrastructure.Data
{
    // Fix: Inherit from IdentityDbContext<ApplicationUser> instead of DbContext
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
    }
}