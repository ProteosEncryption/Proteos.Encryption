using Microsoft.CodeAnalysis;
using Proteos.Encryption.Analyzers;
using Xunit;

namespace Proteos.Encryption.Analyzers.Tests;

public sealed class ProteosEncryptionAnalyzerTests
{
    // Declares the attribute hierarchy under the real metadata name the analyzer looks for, plus an
    // entity with an encrypted (Email) and a non-encrypted (Id, Name) property. No reference to the
    // EF assembly is needed — the analyzer resolves the marker by metadata name.
    private const string Prelude = @"
using System.Linq;

namespace Proteos.Encryption.EntityFrameworkCore
{
    public class EncryptedAttribute : System.Attribute { public EncryptedAttribute(string name) { } }
    public class EncryptedSearchableAttribute : EncryptedAttribute { public EncryptedSearchableAttribute(string name) : base(name) { } }
    public sealed class EncryptedEmailAttribute : EncryptedSearchableAttribute { public EncryptedEmailAttribute(string name) : base(name) { } }
}

namespace App
{
    using Proteos.Encryption.EntityFrameworkCore;

    public class Customer
    {
        public int Id { get; set; }

        [EncryptedEmail(""email"")]
        public string Email { get; set; } = """";

        public string Name { get; set; } = """";
    }
}
";

    private static string Query(string expression) => Prelude + @"
namespace App
{
    using System.Linq;

    public static class Queries
    {
        public static object Run(System.Linq.IQueryable<Customer> source) => " + expression + @";
    }
}
";

    [Fact]
    public async Task PENC001_Warns_WhenEncryptedPropertyIsProjected()
    {
        var diagnostics = await AnalyzerRunner.RunAsync(Query("source.Select(x => x.Email)"));

        var diagnostic = Assert.Single(diagnostics, d => d.Id == "PENC001");
        Assert.Equal(DiagnosticSeverity.Warning, diagnostic.Severity);
        Assert.Contains("Email", diagnostic.GetMessage());
        Assert.DoesNotContain(diagnostics, d => d.Id == "AD0001"); // the analyzer did not crash
    }

    [Fact]
    public async Task PENC001_NoWarning_WhenNonEncryptedPropertyIsProjected()
    {
        var diagnostics = await AnalyzerRunner.RunAsync(Query("source.Select(x => x.Id)"));

        Assert.DoesNotContain(diagnostics, d => d.Id == "PENC001");
    }

    [Fact]
    public async Task PENC002_Warns_WhenEncryptedPropertyIsComparedForEquality()
    {
        var diagnostics = await AnalyzerRunner.RunAsync(Query("source.Where(x => x.Email == \"max@example.com\")"));

        var diagnostic = Assert.Single(diagnostics, d => d.Id == "PENC002");
        Assert.Equal(DiagnosticSeverity.Warning, diagnostic.Severity);
        Assert.Contains("Email", diagnostic.GetMessage());
        Assert.DoesNotContain(diagnostics, d => d.Id == "AD0001");
    }

    [Fact]
    public async Task PENC002_NoWarning_WhenNonEncryptedPropertyIsComparedForEquality()
    {
        var diagnostics = await AnalyzerRunner.RunAsync(Query("source.Where(x => x.Id == 5)"));

        Assert.DoesNotContain(diagnostics, d => d.Id == "PENC002");
    }

    [Fact]
    public async Task EnumerableProjection_IsNotFlagged_OnlyQueryableIsInScope()
    {
        // Post-materialization (IEnumerable) entities are already decrypted, so projecting Email is fine.
        var source = Prelude + @"
namespace App
{
    using System.Collections.Generic;
    using System.Linq;

    public static class Queries
    {
        public static object Run(IEnumerable<Customer> source) => source.Select(x => x.Email);
    }
}
";
        var diagnostics = await AnalyzerRunner.RunAsync(source);

        Assert.DoesNotContain(diagnostics, d => d.Id == "PENC001");
    }

    // Fluent configuration lives in OnModelCreating, not on the property. This prelude declares the
    // real fluent extension type and a minimal EF builder shape, and configures Email encrypted
    // *fluently only* (no attribute), so any warning proves the analyzer saw the fluent configuration.
    private const string FluentPrelude = @"
using System;
using System.Linq;
using System.Linq.Expressions;

namespace Proteos.Encryption.EntityFrameworkCore
{
    public class EncryptedAttribute : System.Attribute { public EncryptedAttribute(string name) { } }
}

namespace Microsoft.EntityFrameworkCore
{
    public class PropertyBuilder { }

    public class EntityTypeBuilder<T>
    {
        public PropertyBuilder Property<TProp>(Expression<Func<T, TProp>> selector) => new PropertyBuilder();
    }

    public class ModelBuilder
    {
        public EntityTypeBuilder<T> Entity<T>() => new EntityTypeBuilder<T>();
    }

    public static class ProteosEncryptionPropertyBuilderExtensions
    {
        public static PropertyBuilder IsEncrypted(this PropertyBuilder builder, string name) => builder;
        public static PropertyBuilder IsEncryptedSearchable(this PropertyBuilder builder, string name) => builder;
        public static PropertyBuilder IsEncryptedEmail(this PropertyBuilder builder, string name) => builder;
    }
}

namespace App
{
    using Microsoft.EntityFrameworkCore;

    public class Customer
    {
        public int Id { get; set; }
        public string Email { get; set; } = """";
        public string Name { get; set; } = """";
    }

    public static class Model
    {
        public static void Configure(ModelBuilder builder)
        {
            builder.Entity<Customer>().Property(x => x.Email).IsEncryptedEmail(""email"");
        }
    }
}
";

    private static string FluentQuery(string expression) => FluentPrelude + @"
namespace App
{
    using System.Linq;

    public static class Queries
    {
        public static object Run(System.Linq.IQueryable<Customer> source) => " + expression + @";
    }
}
";

    [Fact]
    public async Task PENC001_Warns_WhenFluentlyEncryptedPropertyIsProjected()
    {
        var diagnostics = await AnalyzerRunner.RunAsync(FluentQuery("source.Select(x => x.Email)"));

        var diagnostic = Assert.Single(diagnostics, d => d.Id == "PENC001");
        Assert.Contains("Email", diagnostic.GetMessage());
        Assert.DoesNotContain(diagnostics, d => d.Id == "AD0001"); // the analyzer did not crash
    }

    [Fact]
    public async Task PENC001_NoWarning_WhenFluentlyNonEncryptedPropertyIsProjected()
    {
        var diagnostics = await AnalyzerRunner.RunAsync(FluentQuery("source.Select(x => x.Name)"));

        Assert.DoesNotContain(diagnostics, d => d.Id == "PENC001");
    }

    [Fact]
    public async Task PENC002_Warns_WhenFluentlyEncryptedPropertyIsComparedForEquality()
    {
        var diagnostics = await AnalyzerRunner.RunAsync(FluentQuery("source.Where(x => x.Email == \"max@example.com\")"));

        var diagnostic = Assert.Single(diagnostics, d => d.Id == "PENC002");
        Assert.Contains("Email", diagnostic.GetMessage());
        Assert.DoesNotContain(diagnostics, d => d.Id == "AD0001");
    }

    [Fact]
    public void PENC003_DiagnosticId_Exists_AndIsReservedDisabled()
    {
        var descriptor = Assert.Single(new ProteosEncryptionAnalyzer().SupportedDiagnostics, d => d.Id == "PENC003");

        Assert.False(descriptor.IsEnabledByDefault); // reserved for future use, off by default
    }
}
