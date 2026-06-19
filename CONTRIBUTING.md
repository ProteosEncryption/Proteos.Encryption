# Contributing to Proteos

Thanks for your interest in improving Proteos. Contributions are welcome.

## Pull requests

- Pull requests are welcome. For anything non-trivial, please open an issue first to discuss it.
- Keep the build and **all tests green** — `dotnet test` on `Proteos.Encryption.sln` must pass before a
  PR is merged.
- Add or update tests for any behaviour you change.

## No breaking changes without discussion

The cryptographic core, the `PENC` envelope format and the key model are stable. Do **not** change
crypto behaviour, the envelope format, or the public API without opening an issue and agreeing on the
approach first. Extensions should be additive (a new `SuiteId`, `AadSchemeId`, key version, or package).

## Public API surface

The packable libraries track their public API with `Microsoft.CodeAnalysis.PublicApiAnalyzers`. Each
project carries two files:

- `PublicAPI.Shipped.txt` — API that has already been published.
- `PublicAPI.Unshipped.txt` — public API added since the last release, not yet published.

Every public type and member must appear in one of these files, so any change to the public surface shows
up as a deliberate diff in your pull request. The analyzer fails the build (these diagnostics are errors)
when the files and the code disagree:

- **`RS0016`** — a public API exists in the code but is not declared in the files. Add it.
- **`RS0017`** — a public API is declared in the files but no longer exists in the code. Remove it.

What to do:

- **Adding public API:** add the new entries to that project's `PublicAPI.Unshipped.txt`.
- **Removing or changing public API before 1.0** (still allowed while on `0.x`): adjust
  `PublicAPI.Shipped.txt` accordingly and explain the breaking change clearly in the pull request.
- **After 1.0:** avoid breaking changes — the public surface is frozen for the major version (a
  PackageValidation baseline will additionally enforce this later).

A plain build reports the diagnostics:

```
dotnet build -c Release
```

To regenerate the entries, run this **from the project's own folder** (a solution-wide run has not
reliably populated every project):

```
dotnet format analyzers --diagnostics RS0016
```

Do **not** update the `PublicAPI.*.txt` files blindly just to make the build green — the diff is part of
the review, and an unexpected entry usually means a type or member was made public by accident.

## Coding style

Match the existing style: explicit and small responsibilities, `sealed` by default, nullable reference
types on, a minimal public surface, and no narrative comments. Keep the code looking like the code
around it.

## Security issues

**Do not report security vulnerabilities through public issues or pull requests.** Report them
privately as described in [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0 — the same
license as the project (see [LICENSE](LICENSE)).

---

Maintainer: Georgios Smyrlis
