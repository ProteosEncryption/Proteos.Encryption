namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Marks a string or <c>byte[]</c> property as deliberately stored in plaintext. It has no runtime
/// effect on its own — values are written as-is — but it is an explicit classification: under strict
/// mode such a property is not flagged as unclassified, and it appears as <c>plaintext</c> in the
/// audit report. Marking a property both <see cref="PlaintextAttribute"/> and encrypted is a hard
/// error at model build.
/// </summary>
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
public sealed class PlaintextAttribute : Attribute
{
}
