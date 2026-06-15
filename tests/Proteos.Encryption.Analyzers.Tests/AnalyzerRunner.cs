using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Proteos.Encryption.Analyzers;

namespace Proteos.Encryption.Analyzers.Tests;

/// <summary>
/// Compiles a source string and runs <see cref="ProteosEncryptionAnalyzer"/> over it, returning the
/// real analyzer diagnostics. References come from the running runtime's trusted platform assemblies,
/// so the snippets can use the BCL and LINQ without any extra reference packages.
/// </summary>
internal static class AnalyzerRunner
{
    private static readonly MetadataReference[] References =
        ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
        .Split(Path.PathSeparator)
        .Where(path => path.Length > 0)
        .Select(path => (MetadataReference)MetadataReference.CreateFromFile(path))
        .ToArray();

    public static async Task<ImmutableArray<Diagnostic>> RunAsync(string source)
    {
        var syntaxTree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Latest));
        var compilation = CSharpCompilation.Create(
            "ProteosAnalyzerTest",
            new[] { syntaxTree },
            References,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable));

        var withAnalyzers = compilation.WithAnalyzers(ImmutableArray.Create<DiagnosticAnalyzer>(new ProteosEncryptionAnalyzer()));
        return await withAnalyzers.GetAnalyzerDiagnosticsAsync();
    }
}
