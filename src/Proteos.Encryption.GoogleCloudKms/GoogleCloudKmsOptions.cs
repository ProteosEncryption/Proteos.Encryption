namespace Proteos.Encryption.GoogleCloudKms;

/// <summary>
/// Options for registering the Google Cloud KMS key provider. <see cref="KeyName"/> is the KEK's full
/// Cloud KMS <c>CryptoKey</c> resource name; authentication defaults to Application Default Credentials
/// (ADC) and can be overridden with <see cref="CredentialsPath"/> or <see cref="JsonCredentials"/>
/// (at most one). <see cref="Endpoint"/> overrides the KMS service endpoint (for VPC Service Controls,
/// a regional endpoint or tests).
/// </summary>
public sealed class GoogleCloudKmsOptions
{
    /// <summary>
    /// The Cloud KMS <c>CryptoKey</c> resource name of the key-encryption-key, in the form
    /// <c>projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{cryptoKey}</c>. It must
    /// reference a symmetric <c>ENCRYPT_DECRYPT</c> key and must <b>not</b> include a
    /// <c>/cryptoKeyVersions/{version}</c> suffix — KMS selects the primary version on encrypt and the
    /// matching version on decrypt automatically.
    /// </summary>
    public string? KeyName { get; set; }

    /// <summary>
    /// Optional path to a service-account JSON key file. When neither this nor
    /// <see cref="JsonCredentials"/> is set, Application Default Credentials are used. Mutually exclusive
    /// with <see cref="JsonCredentials"/>.
    /// </summary>
    public string? CredentialsPath { get; set; }

    /// <summary>
    /// Optional inline service-account JSON credentials. When neither this nor
    /// <see cref="CredentialsPath"/> is set, Application Default Credentials are used. Mutually exclusive
    /// with <see cref="CredentialsPath"/>.
    /// </summary>
    public string? JsonCredentials { get; set; }

    /// <summary>
    /// Optional Cloud KMS service endpoint override (for example a VPC Service Controls or regional
    /// endpoint). When null, the SDK default endpoint is used.
    /// </summary>
    public string? Endpoint { get; set; }
}
