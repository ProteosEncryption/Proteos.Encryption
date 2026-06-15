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
