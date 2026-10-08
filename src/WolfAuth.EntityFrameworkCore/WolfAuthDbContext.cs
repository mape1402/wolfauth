using Microsoft.EntityFrameworkCore;

namespace WolfAuth.EntityFrameworkCore;

/// <summary>
/// Provides the Entity Framework Core model for WolfAuth persistence.
/// </summary>
public sealed class WolfAuthDbContext : DbContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthDbContext"/> class.
    /// </summary>
    /// <param name="options">The context options.</param>
    public WolfAuthDbContext(DbContextOptions<WolfAuthDbContext> options)
        : base(options)
    {
    }

    /// <summary>
    /// Gets persisted subjects.
    /// </summary>
    public DbSet<WolfAuthSubjectEntity> Subjects => Set<WolfAuthSubjectEntity>();

    /// <summary>
    /// Gets persisted assignments.
    /// </summary>
    public DbSet<WolfAuthAssignmentEntity> Assignments => Set<WolfAuthAssignmentEntity>();

    /// <summary>
    /// Gets persisted audit records.
    /// </summary>
    public DbSet<WolfAuthAuditRecordEntity> AuditRecords => Set<WolfAuthAuditRecordEntity>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.Entity<WolfAuthSubjectEntity>(entity =>
        {
            entity.HasKey(subject => subject.SubjectId);
            entity.HasIndex(subject => new { subject.Provider, subject.ExternalUserId }).IsUnique();
            entity.Property(subject => subject.SubjectId).HasMaxLength(200);
            entity.Property(subject => subject.Provider).HasMaxLength(120);
            entity.Property(subject => subject.ExternalUserId).HasMaxLength(300);
            entity.Property(subject => subject.DisplayName).HasMaxLength(300);
            entity.Property(subject => subject.Email).HasMaxLength(320);
            entity.Property(subject => subject.UserPrincipalName).HasMaxLength(320);
        });

        modelBuilder.Entity<WolfAuthAssignmentEntity>(entity =>
        {
            entity.HasKey(assignment => assignment.AssignmentId);
            entity.Property(assignment => assignment.AssignmentId).HasMaxLength(200);
            entity.Property(assignment => assignment.SubjectId).HasMaxLength(200);
            entity.Property(assignment => assignment.ExternalGroupKey).HasMaxLength(300);
            entity.Property(assignment => assignment.PermissionKey).HasMaxLength(300);
            entity.Property(assignment => assignment.RoleKey).HasMaxLength(200);
            entity.Property(assignment => assignment.ScopeKey).HasMaxLength(300);
            entity.HasIndex(assignment => assignment.SubjectId);
            entity.HasIndex(assignment => assignment.ExternalGroupKey);
        });

        modelBuilder.Entity<WolfAuthAuditRecordEntity>(entity =>
        {
            entity.HasKey(record => record.AuditId);
            entity.Property(record => record.AuditId).HasMaxLength(64);
            entity.Property(record => record.SubjectId).HasMaxLength(200);
            entity.Property(record => record.ActorSubjectId).HasMaxLength(200);
            entity.HasIndex(record => record.OccurredAt);
            entity.HasIndex(record => record.SubjectId);
        });
    }
}
