# Changelog

All notable changes to Proteos Encryption are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-preview.1] - 2026-06-14

First public preview. The cryptographic core, the `PENC` envelope format and the key model are stable;
the surrounding APIs may still change before `1.0.0`.

### Added

- **Cryptographic core** — AES-256-GCM value encryption, HKDF-SHA256 subkey derivation with
  purpose/scope domain separation, HMAC-SHA256 blind index, and a versioned, length-prefixed `PENC`
  ciphertext envelope.
- **EF Core integration** — transparent encrypt-on-save / decrypt-on-materialize interceptors;
  attribute and fluent configuration unified into one metadata model; `[Plaintext]` classification;
  hard failures when the model convention or tenant is missing; and a write-side guard that rejects
  already-encrypted values (no double encryption).
- **Querying** — `WhereEncryptedEquals`, `WhereEncryptedIn` and `WhereEncryptedEmail` blind-index
  search: exact-match only, fully server-side, rotation-aware.
- **Analyzer** — Roslyn analyzers (`PENC001`/`PENC002`) flagging encrypted-property projection and
  `==` filtering at compile time, for both attribute and simple fluent configuration.
- **Audit report & strict mode** — model-derived classification of every `string`/`byte[]` property,
  plus an opt-in strict mode that fails on unclassified properties at the save boundary.
- **Key rotation & rotation-aware search** — multiple key versions, decryption by the envelope's key
  id, and search across all known versions.
- **Re-encrypt / re-index foundation** — planner and service, plus batch/progress/resume value
  objects (no background worker yet).
- **KMS foundation** — neutral tenant key catalogue (`TenantKeyRecord`, `ITenantKeyRegistry`,
  `ProviderKeyReference`, `KeyProviderKind`) and the `RegistryKeyMaterialProvider`.
- **Azure Key Vault provider** — `Proteos.Encryption.AzureKeyVault`: an `IKeyProvider` adapter that
  wraps and unwraps tenant master keys with RSA-OAEP-256.
- **AWS KMS provider** — `Proteos.Encryption.AwsKms`: an `IKeyProvider` adapter using symmetric KMS
  `Encrypt`/`Decrypt`.
- **Packaging** — NuGet packages with README, SourceLink, symbol packages and a bundled analyzer, plus
  CI build/test and pack workflows.
- **Sample projects** — three runnable samples under `samples/`: `Proteos.SampleApi` (quickstart Web
  API), `Proteos.FeatureShowcase` (console feature tour) and `Proteos.CrmSampleApi` (realistic CRM Web
  API with related entities, `Include`, `WhereEncryptedIn`, strict mode and admin endpoints).

### Security

- Licensed under **Apache-2.0**. See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

Maintainer: Georgios Smyrlis

[0.1.0-preview.1]: https://github.com/ProteosEncryption/Proteos.Encryption/releases/tag/v0.1.0-preview.1
