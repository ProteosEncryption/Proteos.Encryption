using System.Collections.Concurrent;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Proteos.Encryption.Analyzers;

/// <summary>
/// Flags the two compile-time footguns of encrypted properties in database-translated LINQ:
/// projecting an encrypted property directly (PENC001, returns ciphertext) and comparing one with
/// <c>==</c>/<c>!=</c> in a query (PENC002, never matches). A property is recognised as encrypted when
/// it carries an <c>[Encrypted*]</c> attribute or is configured by the simple fluent form
/// <c>.Property(x =&gt; x.P).IsEncrypted(...)</c> / <c>.IsEncryptedSearchable(...)</c> / <c>.IsEncryptedEmail(...)</c>.
/// </summary>
/// <remarks>
/// Because fluent configuration usually lives in a different file from the query, the rules run as a
/// whole-compilation pass: fluent-encrypted properties are collected, query usages are collected, and
/// diagnostics are reported at compilation end once both are known. Foundation limits: only the
/// directly chained fluent form is recognised (not a builder stored in a local first); only a direct
/// <c>x =&gt; x.Prop</c> projection and direct member operands of an equality are inspected (not
/// <c>new { x.Email }</c>, method calls or navigation chains); only <c>Queryable</c> (not
/// <c>Enumerable</c>) is in scope.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class ProteosEncryptionAnalyzer : DiagnosticAnalyzer
{
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
        ImmutableArray.Create(
            DiagnosticDescriptors.EncryptedProjection,
            DiagnosticDescriptors.EncryptedEqualityFilter,
            DiagnosticDescriptors.StrictModeReserved);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterCompilationStartAction(OnCompilationStart);
    }

    private static void OnCompilationStart(CompilationStartAnalysisContext context)
    {
        var known = ProteosKnownSymbols.TryCreate(context.Compilation);
        if (known is null)
        {
            // The compilation does not reference Proteos encryption — nothing to analyze.
            return;
        }

        // Per-compilation state: properties configured encrypted via the fluent API, and the candidate
        // query usages to judge once the fluent set is complete.
        var fluentEncrypted = new ConcurrentDictionary<IPropertySymbol, byte>(SymbolEqualityComparer.Default);
        var candidates = new ConcurrentBag<QueryCandidate>();

        context.RegisterSyntaxNodeAction(
            nodeContext => AnalyzeInvocation(nodeContext, known, fluentEncrypted, candidates),
            SyntaxKind.InvocationExpression);

        context.RegisterCompilationEndAction(endContext =>
        {
            foreach (var candidate in candidates)
            {
                if (known.IsEncryptedProperty(candidate.Property) || fluentEncrypted.ContainsKey(candidate.Property))
                {
                    endContext.ReportDiagnostic(candidate.Diagnostic);
                }
            }
        });
    }

    private static void AnalyzeInvocation(
        SyntaxNodeAnalysisContext context,
        ProteosKnownSymbols known,
        ConcurrentDictionary<IPropertySymbol, byte> fluentEncrypted,
        ConcurrentBag<QueryCandidate> candidates)
    {
        var invocation = (InvocationExpressionSyntax)context.Node;
        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
        {
            return;
        }

        var methodName = memberAccess.Name.Identifier.ValueText;

        // Fluent configuration: .Property(x => x.P).IsEncrypted/IsEncryptedSearchable/IsEncryptedEmail(...)
        if (methodName is "IsEncrypted" or "IsEncryptedSearchable" or "IsEncryptedEmail")
        {
            CollectFluentEncryptedProperty(context, known, memberAccess, invocation, fluentEncrypted);
            return;
        }

        var isSelect = methodName == "Select";
        var isWhere = methodName == "Where";
        if (!isSelect && !isWhere)
        {
            return;
        }

        if (context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol is not IMethodSymbol method
            || !known.IsQueryableMethod(method))
        {
            return;
        }

        if (GetSingleLambda(invocation) is not { } lambda)
        {
            return;
        }

        if (isSelect)
        {
            CollectProjectionCandidate(context, lambda, candidates);
        }
        else
        {
            CollectEqualityCandidates(context, lambda, candidates);
        }
    }

    private static void CollectFluentEncryptedProperty(
        SyntaxNodeAnalysisContext context,
        ProteosKnownSymbols known,
        MemberAccessExpressionSyntax memberAccess,
        InvocationExpressionSyntax invocation,
        ConcurrentDictionary<IPropertySymbol, byte> fluentEncrypted)
    {
        // Confirm this is the Proteos fluent method, not a same-named method on another type.
        if (context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol is not IMethodSymbol method
            || !known.IsFluentEncryptionMethod(method))
        {
            return;
        }

        // Only the directly chained form is recognised: the receiver must be a .Property(x => x.P) call
        // whose lambda body is a direct member access.
        if (memberAccess.Expression is not InvocationExpressionSyntax propertyCall
            || propertyCall.Expression is not MemberAccessExpressionSyntax { Name.Identifier.ValueText: "Property" }
            || GetSingleLambda(propertyCall) is not { Body: MemberAccessExpressionSyntax propertyAccess })
        {
            return;
        }

        if (GetMemberProperty(context, propertyAccess) is { } property)
        {
            fluentEncrypted.TryAdd(property, 0);
        }
    }

    private static void CollectProjectionCandidate(SyntaxNodeAnalysisContext context, LambdaExpressionSyntax lambda, ConcurrentBag<QueryCandidate> candidates)
    {
        // Only a direct projection of the property, e.g. x => x.Email.
        if (lambda.Body is MemberAccessExpressionSyntax memberAccess && GetMemberProperty(context, memberAccess) is { } property)
        {
            candidates.Add(new QueryCandidate(
                property,
                Diagnostic.Create(DiagnosticDescriptors.EncryptedProjection, memberAccess.GetLocation(), property.Name)));
        }
    }

    private static void CollectEqualityCandidates(SyntaxNodeAnalysisContext context, LambdaExpressionSyntax lambda, ConcurrentBag<QueryCandidate> candidates)
    {
        if (lambda.Body is null)
        {
            return;
        }

        foreach (var binary in lambda.Body.DescendantNodesAndSelf().OfType<BinaryExpressionSyntax>())
        {
            if (!binary.IsKind(SyntaxKind.EqualsExpression) && !binary.IsKind(SyntaxKind.NotEqualsExpression))
            {
                continue;
            }

            AddEqualityOperand(context, binary.Left, candidates);
            AddEqualityOperand(context, binary.Right, candidates);
        }
    }

    private static void AddEqualityOperand(SyntaxNodeAnalysisContext context, ExpressionSyntax operand, ConcurrentBag<QueryCandidate> candidates)
    {
        if (operand is MemberAccessExpressionSyntax memberAccess && GetMemberProperty(context, memberAccess) is { } property)
        {
            candidates.Add(new QueryCandidate(
                property,
                Diagnostic.Create(DiagnosticDescriptors.EncryptedEqualityFilter, memberAccess.GetLocation(), property.Name)));
        }
    }

    private static IPropertySymbol? GetMemberProperty(SyntaxNodeAnalysisContext context, ExpressionSyntax expression) =>
        context.SemanticModel.GetSymbolInfo(expression, context.CancellationToken).Symbol as IPropertySymbol;

    private static LambdaExpressionSyntax? GetSingleLambda(InvocationExpressionSyntax invocation)
    {
        var arguments = invocation.ArgumentList.Arguments;
        return arguments.Count == 1 ? arguments[0].Expression as LambdaExpressionSyntax : null;
    }

    private readonly struct QueryCandidate
    {
        public QueryCandidate(IPropertySymbol property, Diagnostic diagnostic)
        {
            Property = property;
            Diagnostic = diagnostic;
        }

        public IPropertySymbol Property { get; }

        public Diagnostic Diagnostic { get; }
    }
}
