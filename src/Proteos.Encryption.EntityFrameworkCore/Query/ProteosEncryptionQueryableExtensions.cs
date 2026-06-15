using System.Linq.Expressions;
using System.Reflection;
using System.Text;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Proteos.Encryption.EntityFrameworkCore;

namespace Microsoft.EntityFrameworkCore;

/// <summary>
/// Equality search over encrypted properties. The helpers turn plaintext search terms into the blind
/// index of the selected property and filter the (internal) blind index column for them, so the
/// developer never has to know or name that column. The whole predicate translates to SQL — terms are
/// hashed on the client into query parameters and the comparison runs in the database; there is no
/// client-side evaluation. Every helper is rotation-aware: a term is matched under all known key
/// versions.
/// </summary>
public static class ProteosEncryptionQueryableExtensions
{
    private const string SelectorParameterName = "propertySelector";

    private static readonly MethodInfo EfPropertyByteArrayMethod =
        typeof(EF).GetMethod(nameof(EF.Property), BindingFlags.Public | BindingFlags.Static)!
            .MakeGenericMethod(typeof(byte[]));

    private static readonly FieldInfo BlindIndexBoxValueField =
        typeof(BlindIndexBox).GetField(nameof(BlindIndexBox.Value))!;

    /// <summary>
    /// Filters <paramref name="source"/> to the rows whose encrypted, searchable property selected
    /// by <paramref name="propertySelector"/> equals <paramref name="value"/>. The property's
    /// normalizer and blind index are applied exactly as on write, so the comparison hits the same
    /// blind index column the save interceptor fills. Combine several calls to AND multiple
    /// conditions.
    /// </summary>
    /// <param name="source">The query to filter.</param>
    /// <param name="dbContext">The context the query belongs to; supplies the per-operation tenant and the encryption services.</param>
    /// <param name="propertySelector">A direct property access, e.g. <c>x =&gt; x.Email</c>. Anything else is rejected.</param>
    /// <param name="value">The plaintext search term. A <c>null</c> value is rejected (see remarks).</param>
    /// <remarks>
    /// A <c>null</c> search term is a hard error, not <c>WHERE … IS NULL</c>: a blind index of null
    /// does not exist, and "the field equals null" is a different, easily-misfired intent. To find
    /// rows whose value is null, use the native <c>.Where(x =&gt; x.Property == null)</c> instead.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="source"/>, <paramref name="dbContext"/>, <paramref name="propertySelector"/> or <paramref name="value"/> is null.</exception>
    /// <exception cref="ArgumentException">The selector is not a direct property access, or the property is not encrypted or not searchable.</exception>
    /// <exception cref="InvalidOperationException">The context has no application service provider with Proteos encryption registered.</exception>
    /// <exception cref="ProteosEncryptionException">No tenant could be resolved.</exception>
    public static IQueryable<TEntity> WhereEncryptedEquals<TEntity>(
        this IQueryable<TEntity> source,
        DbContext dbContext,
        Expression<Func<TEntity, string?>> propertySelector,
        string? value)
        where TEntity : class
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(dbContext);
        ArgumentNullException.ThrowIfNull(propertySelector);

        if (value is null)
        {
            throw new ArgumentNullException(
                nameof(value),
                "WhereEncryptedEquals does not accept a null search value: a blind index of null does not exist. "
                + "To find rows whose value is null, use .Where(x => x.Property == null).");
        }

        var search = PrepareSearch(source, dbContext, propertySelector);
        var blindIndexes = ComputeBlindIndexes(search, value);

        return source.Where(BuildIndexMatchPredicate<TEntity>(search.Descriptor.IndexPropertyName!, blindIndexes));
    }

    /// <summary>
    /// Filters <paramref name="source"/> to the rows whose encrypted, searchable property equals any of
    /// the given <paramref name="values"/> — the encrypted-search equivalent of <c>IN (...)</c>. Each
    /// term is normalized and blind-indexed exactly as on write and under every known key version, and
    /// all resulting indexes are OR-ed into one server-side predicate. An empty collection matches
    /// nothing.
    /// </summary>
    /// <param name="source">The query to filter.</param>
    /// <param name="dbContext">The context the query belongs to; supplies the per-operation tenant and the encryption services.</param>
    /// <param name="propertySelector">A direct property access, e.g. <c>x =&gt; x.Email</c>. Anything else is rejected.</param>
    /// <param name="values">The plaintext search terms. The collection may be empty; a <c>null</c> entry is rejected.</param>
    /// <exception cref="ArgumentNullException"><paramref name="source"/>, <paramref name="dbContext"/>, <paramref name="propertySelector"/> or <paramref name="values"/> is null.</exception>
    /// <exception cref="ArgumentException">The selector is not a direct property access, the property is not encrypted or not searchable, or a value is null.</exception>
    /// <exception cref="InvalidOperationException">The context has no application service provider with Proteos encryption registered.</exception>
    /// <exception cref="ProteosEncryptionException">No tenant could be resolved.</exception>
    public static IQueryable<TEntity> WhereEncryptedIn<TEntity>(
        this IQueryable<TEntity> source,
        DbContext dbContext,
        Expression<Func<TEntity, string?>> propertySelector,
        IEnumerable<string> values)
        where TEntity : class
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(dbContext);
        ArgumentNullException.ThrowIfNull(propertySelector);
        ArgumentNullException.ThrowIfNull(values);

        var search = PrepareSearch(source, dbContext, propertySelector);

        // De-duplicate identical indexes so repeated or equal-normalizing terms (and shared key
        // versions) do not bloat the OR. An empty value set yields no indexes -> matches nothing.
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var blindIndexes = new List<BlindIndexValue>();
        foreach (var value in values)
        {
            if (value is null)
            {
                throw new ArgumentException(
                    "WhereEncryptedIn does not accept a null search value: a blind index of null does not exist. "
                    + "Filter nulls out of the collection, or query them separately with .Where(x => x.Property == null).",
                    nameof(values));
            }

            foreach (var blindIndex in ComputeBlindIndexes(search, value))
            {
                if (seen.Add(Convert.ToBase64String(blindIndex.ToArray())))
                {
                    blindIndexes.Add(blindIndex);
                }
            }
        }

        return source.Where(BuildIndexMatchPredicate<TEntity>(search.Descriptor.IndexPropertyName!, blindIndexes));
    }

    /// <summary>
    /// Convenience wrapper over <see cref="WhereEncryptedEquals{TEntity}"/> for an encrypted email
    /// field. The mechanics are identical — the property's configured Email normalizer (lower-case,
    /// trim, NFC) is applied — this overload just makes intent explicit at the call site.
    /// </summary>
    /// <exception cref="ArgumentNullException">An argument is null (a null search value is rejected, as with <see cref="WhereEncryptedEquals{TEntity}"/>).</exception>
    /// <exception cref="ArgumentException">The selector is not a direct property access, or the property is not encrypted or not searchable.</exception>
    public static IQueryable<TEntity> WhereEncryptedEmail<TEntity>(
        this IQueryable<TEntity> source,
        DbContext dbContext,
        Expression<Func<TEntity, string?>> propertySelector,
        string? value)
        where TEntity : class =>
        source.WhereEncryptedEquals(dbContext, propertySelector, value);

    private static SearchPreparation PrepareSearch<TEntity>(
        IQueryable<TEntity> source,
        DbContext dbContext,
        Expression<Func<TEntity, string?>> propertySelector)
        where TEntity : class
    {
        var property = ExtractSingleProperty(propertySelector);
        var services = GetApplicationServices(dbContext);

        var entityType = dbContext.Model.FindEntityType(typeof(TEntity));
        var metadata = entityType is null ? null : EncryptedModelMetadata.Find(entityType);
        var descriptor = ResolveSearchableDescriptor(metadata, typeof(TEntity), property);

        var tenant = services.GetRequiredService<ITenantResolver>().Resolve(services);
        var encryptionContext = new EncryptionContext(tenant, descriptor.Scope);
        var normalizer = BlindIndexNormalizerResolver.Resolve(descriptor.NormalizerKind!.Value);

        return new SearchPreparation(descriptor, services, encryptionContext, normalizer);
    }

    private static IReadOnlyCollection<BlindIndexValue> ComputeBlindIndexes(SearchPreparation search, string value)
    {
        var normalized = search.Normalizer.Normalize(value);

        // Rotation-aware: compute the term's blind index under every known key version, so rows
        // written before a key rotation are still matched. A single-version provider returns one.
        return search.Services.GetRequiredService<IBlindIndexProvider>()
            .ComputeForAllKnownKeys(Encoding.UTF8.GetBytes(normalized), BlindIndexDescriptor.ExactMatch, search.Context);
    }

    private static PropertyInfo ExtractSingleProperty<TEntity>(Expression<Func<TEntity, string?>> selector)
    {
        var body = selector.Body;
        if (body is UnaryExpression { NodeType: ExpressionType.Convert or ExpressionType.ConvertChecked } convert)
        {
            body = convert.Operand;
        }

        // Only `x => x.Property` is allowed: the member must read directly off the lambda parameter.
        // This rejects nested access (x => x.A.B), method calls (x => x.Email.Trim()) and computed
        // expressions, none of which have a single, stable encrypted property to index.
        if (body is MemberExpression { Member: PropertyInfo property } member
            && member.Expression == selector.Parameters[0])
        {
            return property;
        }

        throw new ArgumentException(
            $"The property selector must be a direct property access such as 'x => x.Email', but was '{selector.Body}'.",
            SelectorParameterName);
    }

    private static EncryptedPropertyDescriptor ResolveSearchableDescriptor(EncryptedEntityMetadata? metadata, Type entityType, PropertyInfo property)
    {
        if (metadata is null)
        {
            throw new ArgumentException(
                $"Entity '{entityType.Name}' has no Proteos encryption metadata. Ensure it has encrypted properties and that UseProteosEncryptionModel() was called in OnModelCreating.",
                SelectorParameterName);
        }

        EncryptedPropertyDescriptor? descriptor = null;
        foreach (var candidate in metadata.Properties)
        {
            if (string.Equals(candidate.PropertyName, property.Name, StringComparison.Ordinal))
            {
                descriptor = candidate;
                break;
            }
        }

        if (descriptor is null)
        {
            throw new ArgumentException(
                $"Property '{entityType.Name}.{property.Name}' is not an encrypted property; only encrypted, searchable properties can be queried with WhereEncryptedEquals.",
                SelectorParameterName);
        }

        if (!descriptor.IsSearchable)
        {
            throw new ArgumentException(
                $"Encrypted property '{entityType.Name}.{property.Name}' is not searchable. Mark it with [EncryptedSearchable] or [EncryptedEmail] to enable equality search.",
                SelectorParameterName);
        }

        return descriptor;
    }

    private static Expression<Func<TEntity, bool>> BuildIndexMatchPredicate<TEntity>(string indexPropertyName, IReadOnlyCollection<BlindIndexValue> blindIndexes)
    {
        var parameter = Expression.Parameter(typeof(TEntity), "e");

        var indexAccess = Expression.Call(
            EfPropertyByteArrayMethod,
            parameter,
            Expression.Constant(indexPropertyName, typeof(string)));

        // One equality per known key version, OR-ed together: EmailIndex == idxV1 || ... || idxVn.
        Expression? body = null;
        foreach (var blindIndex in blindIndexes)
        {
            // Box each blind index behind a member access so EF Core lifts it into a query parameter
            // rather than inlining the bytes as a SQL literal — this keeps the index value out of the
            // SQL text (and out of query logs) and lets the database reuse the query plan.
            var indexValue = Expression.Field(Expression.Constant(new BlindIndexBox(blindIndex.ToArray())), BlindIndexBoxValueField);
            var equality = Expression.Equal(indexAccess, indexValue);
            body = body is null ? equality : Expression.OrElse(body, equality);
        }

        // Defensive: a provider returning no known keys (or an empty value set) matches nothing rather than throwing.
        body ??= Expression.Constant(false);

        return Expression.Lambda<Func<TEntity, bool>>(body, parameter);
    }

    private static IServiceProvider GetApplicationServices(DbContext dbContext)
    {
        var applicationServices = dbContext
            .GetService<IDbContextOptions>()
            .FindExtension<CoreOptionsExtension>()
            ?.ApplicationServiceProvider;

        if (applicationServices is null)
        {
            throw new InvalidOperationException(
                "WhereEncryptedEquals needs the application's encryption services. Register the DbContext with AddDbContext and "
                + "call AddProteosEncryption(...) plus options.UseProteosEncryption(sp); this context has no application service provider.");
        }

        return applicationServices;
    }

    private readonly struct SearchPreparation
    {
        public SearchPreparation(EncryptedPropertyDescriptor descriptor, IServiceProvider services, EncryptionContext context, IBlindIndexNormalizer normalizer)
        {
            Descriptor = descriptor;
            Services = services;
            Context = context;
            Normalizer = normalizer;
        }

        public EncryptedPropertyDescriptor Descriptor { get; }

        public IServiceProvider Services { get; }

        public EncryptionContext Context { get; }

        public IBlindIndexNormalizer Normalizer { get; }
    }

    private sealed class BlindIndexBox
    {
        public readonly byte[] Value;

        public BlindIndexBox(byte[] value) => Value = value;
    }
}
