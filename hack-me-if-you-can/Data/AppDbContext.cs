using Microsoft.EntityFrameworkCore;
using PasswordSecurityDemo.Models;

namespace PasswordSecurityDemo.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users { get; set; }
    
    // STEP 8: Security audit logs table
    public DbSet<SecurityLog> SecurityLogs { get; set; }
}
