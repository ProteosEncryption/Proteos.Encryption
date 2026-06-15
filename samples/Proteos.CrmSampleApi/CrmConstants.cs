namespace Proteos.CrmSampleApi;

/// <summary>Shared constants for the CRM sample, used by Program.cs and the admin service.</summary>
internal static class CrmConstants
{
    /// <summary>Single-tenant id every row is encrypted under.</summary>
    public const string Tenant = "crm-sample";

    public const string DatabaseFile = "crm-sample.db";

    public const string ConnectionString = $"Data Source={DatabaseFile}";
}
