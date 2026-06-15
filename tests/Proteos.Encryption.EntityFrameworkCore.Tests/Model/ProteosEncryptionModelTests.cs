using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Metadata;
using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.EntityFrameworkCore.Tests.Model;

internal sealed class ModelContext<TEntity> : DbContext
    where TEntity : class
{
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder) =>
        optionsBuilder
            .UseInMemoryDatabase("proteos-model-" + typeof(TEntity).Name)
            .ConfigureWarnings(w => w.Ignore(CoreEventId.ManyServiceProvidersCreatedWarning));

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<TEntity>();
        modelBuilder.UseProteosEncryptionModel();
    }
}

public sealed class ProteosEncryptionModelTests
{
    private static IEntityType EntityOf<TEntity>()
        where TEntity : class
    {
        using var context = new ModelContext<TEntity>();
        return context.Model.FindEntityType(typeof(TEntity))!;
    }

    [Fact]
    public void Searchable_CreatesShadowIndexProperty()
    {
        var index = EntityOf<ValidCustomer>().FindProperty("EmailIndex");

        Assert.NotNull(index);
        Assert.True(index!.IsShadowProperty());
        Assert.Equal(typeof(byte[]), index.ClrType);
        Assert.True(index.IsNullable);
        Assert.Equal(32, index.GetMaxLength());
    }

    [Fact]
    public void Searchable_ShadowIndex_HasNonUniqueDatabaseIndex()
    {
        var entity = EntityOf<ValidCustomer>();

        var index = entity.GetIndexes().Single(i => i.Properties.Count == 1 && i.Properties[0].Name == "EmailIndex");
        Assert.False(index.IsUnique);
    }

    [Fact]
    public void EncryptedOnlyProperty_GetsNoIndexProperty()
    {
        var entity = EntityOf<ValidCustomer>();

        Assert.Null(entity.FindProperty("PhoneIndex"));
        Assert.DoesNotContain(entity.GetIndexes(), i => i.Properties.Any(p => p.Name == "Phone"));
    }

    [Fact]
    public void EncryptedValueColumn_IsNotRemapped_NoRuntimeEncryption()
    {
        // Step 10 only configures the index columns; the encrypted value column stays as-is (string).
        var email = EntityOf<ValidCustomer>().FindProperty("Email");

        Assert.NotNull(email);
        Assert.Equal(typeof(string), email!.ClrType);
        Assert.False(email.IsShadowProperty());
    }

    [Fact]
    public void PlainProperty_IsUnchanged()
    {
        var entity = EntityOf<ValidCustomer>();
        var plain = entity.FindProperty("PlainName");

        Assert.NotNull(plain);
        Assert.False(plain!.IsShadowProperty());
        Assert.DoesNotContain(entity.GetIndexes(), i => i.Properties.Any(p => p.Name == "PlainName"));
    }

    [Fact]
    public void ExplicitIndexProperty_IsUsed_AndIndexed()
    {
        var entity = EntityOf<CustomerWithExplicitIndex>();

        var index = entity.FindProperty("EmailIndex");
        Assert.NotNull(index);
        Assert.False(index!.IsShadowProperty()); // existing CLR property, not a shadow
        Assert.Equal(typeof(byte[]), index.ClrType);
        Assert.Contains(entity.GetIndexes(), i => i.Properties.Count == 1 && i.Properties[0].Name == "EmailIndex" && !i.IsUnique);
    }

    [Fact]
    public void MultipleSearchableProperties_EachGetAShadowIndex()
    {
        var entity = EntityOf<CustomerMultiple>();

        Assert.True(entity.FindProperty("EmailIndex")!.IsShadowProperty());
        Assert.True(entity.FindProperty("AliasIndex")!.IsShadowProperty());
        Assert.Null(entity.FindProperty("PhoneIndex"));
        Assert.Null(entity.FindProperty("SsnIndex"));
    }

    [Fact]
    public void PlainEntity_IsUntouched()
    {
        var entity = EntityOf<PlainEntity>();

        Assert.Empty(entity.GetProperties().Where(p => p.IsShadowProperty() && p.Name.EndsWith("Index", StringComparison.Ordinal)));
        Assert.Empty(entity.GetIndexes());
    }

    [Fact]
    public void InvalidMetadata_FailsAtModelBuild()
    {
        Assert.Throws<EncryptedEntityMetadataException>(() =>
        {
            using var context = new ModelContext<CustomerMissingEntityName>();
            _ = context.Model;
        });
    }

    [Fact]
    public void WrongIndexType_FailsAtModelBuild()
    {
        Assert.Throws<EncryptedEntityMetadataException>(() =>
        {
            using var context = new ModelContext<CustomerIndexWrongType>();
            _ = context.Model;
        });
    }

    [Fact]
    public void UseProteosEncryptionModel_WithNullBuilder_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => ((ModelBuilder)null!).UseProteosEncryptionModel());
    }
}
