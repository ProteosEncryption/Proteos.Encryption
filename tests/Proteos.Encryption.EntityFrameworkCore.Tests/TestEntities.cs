using Proteos.Encryption.EntityFrameworkCore;

namespace Proteos.Encryption.EntityFrameworkCore.Tests;

[EncryptedEntity("customer")]
internal sealed class ValidCustomer
{
    public int Id { get; set; }

    [EncryptedEmail("email")]
    public string? Email { get; set; } = "";

    [Encrypted("phone")]
    public string Phone { get; set; } = "";

    [Encrypted("ssn")]
    public byte[] Ssn { get; set; } = [];

    public string PlainName { get; set; } = "";
}

[EncryptedEntity("customer")]
internal sealed class CustomerWithExplicitIndex
{
    public int Id { get; set; }

    [EncryptedSearchable("email", IndexProperty = nameof(EmailIndex))]
    public string Email { get; set; } = "";

    public byte[] EmailIndex { get; set; } = [];
}

[EncryptedEntity("customer")]
internal sealed class CustomerMultiple
{
    public int Id { get; set; }

    [EncryptedEmail("email")]
    public string Email { get; set; } = "";

    [EncryptedSearchable("alias", Normalizer = BlindIndexNormalizerKind.Default)]
    public string Alias { get; set; } = "";

    [Encrypted("phone")]
    public string Phone { get; set; } = "";

    [Encrypted("ssn")]
    public byte[] Ssn { get; set; } = [];

    public string PlainName { get; set; } = "";
}

internal sealed class PlainEntity
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public int Count { get; set; }
}

internal sealed class CustomerMissingEntityName
{
    public int Id { get; set; }

    [Encrypted("email")]
    public string Email { get; set; } = "";
}

[EncryptedEntity("customer")]
internal sealed class CustomerEmptyPropertyName
{
    public int Id { get; set; }

    [Encrypted("   ")]
    public string Email { get; set; } = "";
}

[EncryptedEntity("customer")]
internal sealed class CustomerUnsupportedType
{
    public int Id { get; set; }

    [Encrypted("age")]
    public int Age { get; set; }
}

[EncryptedEntity("customer")]
internal sealed class CustomerReadOnlyProperty
{
    public int Id { get; set; }

    [Encrypted("email")]
    public string Email { get; } = "";
}

[EncryptedEntity("customer")]
internal sealed class CustomerWriteOnlyProperty
{
    public int Id { get; set; }

    private string _email = "";

    [Encrypted("email")]
    public string Email
    {
        set => _email = value;
    }

    public string Read() => _email;
}

[EncryptedEntity("customer")]
internal sealed class CustomerSearchableNonString
{
    public int Id { get; set; }

    [EncryptedSearchable("data")]
    public byte[] Data { get; set; } = [];
}

[EncryptedEntity("customer")]
internal sealed class CustomerIndexWrongType
{
    public int Id { get; set; }

    [EncryptedSearchable("email", IndexProperty = nameof(EmailIndex))]
    public string Email { get; set; } = "";

    public string EmailIndex { get; set; } = "";
}

[EncryptedEntity("customer")]
internal sealed class CustomerIndexSelf
{
    public int Id { get; set; }

    [EncryptedSearchable("email", IndexProperty = nameof(Email))]
    public string Email { get; set; } = "";
}

[EncryptedEntity("customer")]
internal sealed class CustomerShadowCollision
{
    public int Id { get; set; }

    [EncryptedSearchable("email")]
    public string Email { get; set; } = "";

    public string EmailIndex { get; set; } = "";
}

[EncryptedEntity("customer")]
internal sealed class CustomerDuplicateAttributes
{
    public int Id { get; set; }

    [Encrypted("email")]
    [EncryptedSearchable("email")]
    public string Email { get; set; } = "";
}

[EncryptedEntity("customer")]
internal sealed class CustomerUnknownNormalizer
{
    public int Id { get; set; }

    [EncryptedSearchable("email", Normalizer = (BlindIndexNormalizerKind)99)]
    public string Email { get; set; } = "";
}
