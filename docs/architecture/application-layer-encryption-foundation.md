# Proteos — Application Layer Encryption: Foundation-Spezifikation

| | |
|---|---|
| **Produkt** | Proteos — Application Layer Encryption für .NET |
| **Dokument** | Foundation-Spezifikation (Initial Production Release) |
| **Status** | Akzeptiert — fundamentale Entscheidungen stabil |
| **Version** | v1 (erste produktionsfähige Architektur- und Implementierungsbasis) |
| **Stand** | 2026-06-11 |

> **Was „v1“ bzw. „Foundation Release“ hier bedeutet:** die **erste produktionsfähige
> Architektur- und Implementierungsbasis** des Produkts — **keine** Wegwerfversion und
> **kein** schneller Prototyp. Spätere Erweiterungen sind geplant und erwünscht, aber die
> fundamentalen Entscheidungen (Threat Model, Key Model, Envelope-Format, AAD, EF-Core-
> Integration, Projektstruktur, Open-Source-Modell) sind so geschnitten, dass sie **nicht**
> nach kurzer Zeit ersetzt werden müssen. Erweiterung erfolgt additiv über `SuiteId`,
> `AadSchemeId`, `TmkVersion` und neue Pakete — nicht durch Aufbrechen der Architektur.

---

## Inhalt

1. [Produktvision](#1-produktvision)
2. [Problemstellung](#2-problemstellung)
3. [Zielgruppe](#3-zielgruppe)
4. [Threat Model](#4-threat-model)
5. [Nicht-Ziele](#5-nicht-ziele)
6. [Key Model](#6-key-model)
7. [Ciphertext Envelope](#7-ciphertext-envelope)
8. [AAD-Regeln](#8-aad-regeln)
9. [Kryptografische Entscheidungen](#9-kryptografische-entscheidungen)
10. [EF Core Integration](#10-ef-core-integration)
11. [Suchkonzept](#11-suchkonzept)
12. [Open-Source-Modell](#12-open-source-modell)
13. [Architekturregeln](#13-architekturregeln)
14. [Foundation Release (Initial Production Release)](#14-foundation-release-initial-production-release)
15. [Roadmap & Implementierungsreihenfolge](#15-roadmap--implementierungsreihenfolge)
16. [Risiken und Fallstricke](#16-risiken-und-fallstricke)
17. [Spätere kommerzielle Module](#17-spätere-kommerzielle-module)

---

## 1. Produktvision

Proteos bringt **Application Layer Encryption (ALE)** in bestehende .NET-Anwendungen — so
einfach, dass sie **nachträglich** und mit minimaler Code-Änderung eingeführt werden kann.

Leitsatz: **„Die Datenbank sieht nur Ciphertext — die Anwendung bleibt fast unverändert.“**

Sensible Felder werden in der Anwendung verschlüsselt, **bevor** sie in Datenbank, Blob
Storage oder Cloud-Systeme gelangen. Bei Verlust der Datenbank, eines Backups oder eines
Cloud-Snapshots bleiben die Inhalte geschützt — solange die Schlüssel (im KMS) und der
App-Server intakt sind (siehe [Threat Model](#4-threat-model)).

**Produktprinzipien:**

1. **Keine Eigenkryptografie** — ausschließlich bewährte, standardisierte Verfahren.
2. **Keine Magie** — Entwickler sollen verstehen, *was* passiert; Stabilität vor Transparenz.
3. **Kein Vendor-Lock-in** — der Open-Source-Core kann Daten eigenständig mit eigenen
   Schlüsseln entschlüsseln, dauerhaft.
4. **Erweiterbar ohne Bruch** — Format und Schlüsselmodell sind von v1 an versioniert.

---

## 2. Problemstellung

Sensible Daten liegen in Datenbanken, Backups und Cloud-Speichern heute meist im **Klartext**
oder nur durch *Transparent Data Encryption (TDE)* geschützt. TDE schützt jedoch nur den
Datenträger, nicht gegen jemanden, der die Datenbank **liest** (DBA, Cloud-Operator,
geleaktes Backup, lesende Datenpipeline).

**Kernprobleme:**

1. **DB-, Backup- und Cloud-Storage-Leaks** exponieren Klartext.
2. **Neugierige oder privilegierte Administratoren** sehen alles.
3. **Unbeabsichtigte Klartextspeicherung** (Logs, Replicas, Dev-Kopien von Produktionsdaten).
4. **Lesende Datenpipelines** (Analytics, ETL, KI/externe Systeme) konsumieren Klartext direkt aus der DB.
5. **Datenschutz/Compliance** verlangt Pseudonymisierung, Löschbarkeit, Datenminimierung.

**Warum bestehende Mittel nicht reichen:**

- *TDE / Disk-Encryption:* falsches Threat-Model — schützt nicht gegen DB-Lesezugriff.
- *Datenbank-spezifische Spaltenverschlüsselung:* an einen DB-Hersteller gebunden, starre
  Such-Limits, schwer nachträglich/portabel einzuführen.
- *Selbstbau pro Projekt:* führt zu Eigenkryptografie, fehlender Rotation, instabilem
  Envelope-Format und Lock-in.

Proteos füllt die Lücke: **portable, DB-unabhängige, nachrüstbare Feld-Verschlüsselung auf
Anwendungsebene** mit sauberem Schlüssel- und Format-Modell.

---

## 3. Zielgruppe

Teams, die **bestehende** .NET-Anwendungen mit sensiblen Daten betreiben und nachträglich
absichern müssen — ohne Rewrite:

- SaaS-Anbieter mit Mandanten-/Kundendaten
- ERP-, CRM-, HR-, DMS-Systeme
- Unternehmen mit Compliance-Druck (DSGVO, Branchenauflagen)
- Teams, die Daten in Cloud-Datenbanken/Blob halten und das Provider-Risiko senken wollen

**Käufer-Kernsorge, die Proteos adressiert:** „Was passiert, wenn unsere DB / unser Backup /
unser Cloud-Account leakt?“ — und zunehmend: „Wie verhindern wir, dass Kundendaten von
Analyse-/KI-Pipelines im Klartext gelesen werden?“

### 3.1 Definition: Tenant

> **Ein Tenant ist eine Organisation, Firma oder ein Mandantenkontext.**
> **Ein Tenant ist *nicht* ein einzelner Endbenutzer.**

Ein **Tenant Key** gehört also logisch zu einer **Organisation / Firma / Mandanten**.

**Begründung:** Würde pro Endbenutzer ein eigener Root-/Tenant-Key entstehen, würden
Key-Management, Rotation, Recovery und Performance unnötig kompliziert (Schlüssel-Explosion
bei vielen Nutzern). Die Isolationseinheit ist bewusst die Organisation. Eine feinere
Granularität (z. B. Per-Subjekt-Crypto-Shred) ist ein **späteres**, separat zu lösendes
Thema und in v1 ausdrücklich kein Ziel.

---

## 4. Threat Model

**Vertrauensanker:** Die gesamte Sicherheit reduziert sich auf **Geheimhaltung des KEK im
KMS** + **Integrität des App-Servers**. Fällt eines von beiden, gibt es keine Vertraulichkeit
für *lebende* (zur Laufzeit entschlüsselte) Daten.

### 4.1 Schützt gegen

- Gestohlene DB-Dateien, Backups, Snapshots, Replicas, Produktionskopien in Dev — der
  Angreifer sieht nur Ciphertext-Envelopes.
- Cloud-Storage-/Blob-Leaks der persistierten Ciphertexts.
- Lesende SQL-Injection / Exfiltration (liefert Ciphertext).
- Direkt-DB-lesende Pipelines (Analytics, ETL, **KI/externe Systeme**) — sehen Ciphertext.
- Neugieriger / böswilliger DBA und Cloud-DB-Operator — **nur**, wenn er **keinen
  KMS-*Use*-Zugriff** besitzt.
- Unbeabsichtigte Klartextspeicherung (Magic-Marker erkennt unverschlüsselte Altwerte).
- Ermöglicht **Crypto-Shredding** (Schlüssel zerstören → Daten unwiederbringlich) als
  logische Löschung.

### 4.2 Schützt ausdrücklich **nicht** gegen

- **Kompromittierter App-Server (RCE):** abgeleitete Schlüssel liegen im RAM, KMS-Aufrufe
  sind möglich → voller Klartext. **Das ist die wichtigste Grenze.**
- **Prozess-Memory / Memory-Dumps:** Schlüssel und entschlüsselte Werte sind präsent.
  (Zeroization ist unter .NET/GC nur begrenzt möglich — kein Anspruch.)
- **Gestohlene App-Credentials mit KMS-Zugriff** (= Entschlüsselungs-Orakel).
- **Kompromittierte Clients / Browser** (dort bereits entschlüsselt).
- **Gestohlener KEK** (deshalb HSM-backed, non-exportable).
- **Aktive DB-Manipulation:** Replay alter Ciphertexts, Row-Delete, Reorder. Die Integrität
  ist **per-Value**, **nicht** datenbankweit.
- **Side-Channels** (Timing/Cache) — Verlass auf Plattform-Primitive, kein eigener Anspruch.

### 4.3 Erlaubte Marketing-Aussagen

- „Sensible Felder werden auf Anwendungsebene verschlüsselt, *bevor* sie die Datenbank
  erreichen — ein DB-, Backup- oder Storage-Leak offenbart nur Ciphertext.“
- „Standard-Kryptografie (AES-256-GCM), keine Eigenentwicklung.“
- „Kryptografische Löschung (Crypto-Shredding) für Datenlöschung.“
- „DBA und Cloud-Storage-Betreiber können geschützte Felder ohne KMS-Zugriff nicht lesen.“
- „Kein Vendor-Lock-in: Daten mit dem Open-Source-Core und eigenen Schlüsseln entschlüsselbar.“

### 4.4 Zu vermeidende Aussagen

- „End-to-End-verschlüsselt“ · „Zero-Knowledge“ / „wir sehen Ihre Daten nie“
- „Schützt vor Hackern“ · „unknackbar“ / „100 % sicher“
- „DSGVO-konform“ (als Absolutaussage — Proteos ist ein Baustein, kein Siegel)
- „Schützt Daten *in use*“ / „homomorph“
- Jede Implikation von Schutz gegen App-Server-Kompromittierung oder Speicherzugriff
- Die Behauptung, blind-indizierte/deterministische Felder seien so geheim wie randomisierte
  (sie leaken Gleichheit/Häufigkeit).

---

## 5. Nicht-Ziele

- Kein Schutz gegen kompromittierte App-Server (RCE) oder Prozess-Memory.
- Kein Schutz kompromittierter Clients/Browser.
- Keine Transport-Sicherheit (das ist TLS).
- Keine datenbankweite Integrität gegen aktive Manipulation (Replay/Delete/Reorder).
- Keine Volltext-, Range- oder Fuzzy-Suche über verschlüsselte Felder.
- Keine Eigenkryptografie oder exotischen Verfahren (OPE/ORE, FPE, homomorph) in v1.
- Keine automatische Compliance — Proteos ist ein Baustein, kein Compliance-Siegel.
- Keine Per-Endbenutzer-Schlüsselisolation in v1 (Tenant = Organisation).
- Keine Ableitung kryptografischer Identität (Scope, Entity-/Property-Logical-Name, Normalizer)
  aus CLR-Namen — diese bleiben **explizit** (Rename-Sicherheit, siehe 10.2).
- Kein stiller Default-Tenant: ohne aufgelösten Tenant erfolgt ein **harter Fehler**, niemals
  Verschlüsselung unter einem Fallback-Schlüssel (siehe 10.4).

---

## 6. Key Model

**Hierarchie (drei Ebenen, zwei gespeicherte Schlüssel + Ableitung):**

1. **KEK (Key Encryption Key)** — im **KMS/HSM**, **non-exportable**, rotierbar. Wurzel des
   Vertrauens. Wrappt/entwrappt TMKs.
2. **TMK (Tenant Master Key)** — zufälliger 256-Bit-Schlüssel, **vom KEK gewrappt**,
   gespeichert in `proteos_keys`. **Einheit der Tenant-Isolation und des Crypto-Shred.**
   Single-Tenant-Deployment = ein TMK. (Tenant = Organisation, siehe [3.1](#31-definition-tenant).)
3. **Feld-Subkey** — `HKDF-SHA256(ikm = TMK, info = canonical(purpose | entityLogical | propertyLogical))`,
   mit `purpose ∈ {enc, idx}`. **Zur Laufzeit abgeleitet, nie gespeichert**, gecacht.

**Begründung der Ableitung statt Per-Value-Data-Key:** minimaler gespeicherter Schlüssel-
Bestand, kryptografische Domain-Separation (Encrypt-Key ≠ Index-Key, zwingend), niedrigeres
GCM-Nonce-Budget.

- **Tenant-Isolation = TMK-Auswahl** (nicht über AAD/`info`). Ein Ciphertext eines Tenants
  ist mit dem TMK eines anderen Tenants nicht entschlüsselbar.
- **KeyId-Schema (opak, vendor-neutral):** `TmkId (16 B GUID) ‖ TmkVersion (u16)`. Mappt über
  `proteos_keys` auf die KMS-Referenz — **niemals die rohe KMS-URI** im Envelope (das wäre
  Vendor-Lock-in in den gespeicherten Daten).

| Aspekt | Direkt in v1 | Später vorbereitet | Bewusst nicht |
|---|---|---|---|
| KEK in KMS | über `IKeyProvider`; Azure Key Vault + AWS KMS Adapter ✅ **implementiert** | Google KMS Adapter, Multi-Region-KEK | exportierbarer KEK |
| Local Development Key Provider | ✅ (nur Entwicklung/Test) | — | Dev-Provider in Produktion |
| TMK pro Tenant, KEK-gewrappt | ✅ | — | client-gehaltene Keys / echtes E2E |
| HKDF-Subkeys | ✅ | — | — |
| Key Rotation (mehrere TMK-Versionen, Current + lesbare Altdaten) | ✅ **implementiert** (6.1) | Rotations-Orchestrierung, Re-Encrypt-Worker (Phase 6) | Per-Endbenutzer-Keys |
| Crypto-Shred (TMK zerstören) | ✅ | Per-Subjekt-Shred | — |

- **Rotation (implementiert, siehe 6.1):** KEK-Rotation → TMKs neu wrappen (keine Daten-Re-Encryption).
  TMK-Rotation → neue `TmkVersion`, **neue Writes immer mit dem Current Key**, Altdaten über die
  **`KeyId` im Envelope-Header** weiter entschlüsselbar — **ohne** Envelope-Änderung. Die
  **Orchestrierung** (Re-Encrypt-Worker) kommt in Phase 6; ihre Foundation steht (6.5).
- **Recovery / Key-Verlust:** **KEK-Verlust = totaler, unwiderruflicher Datenverlust** →
  Kunden-Betriebspflicht (KMS-Durability, Multi-Region, Break-Glass), explizit dokumentiert.
  TMK ist wiederherstellbar, solange KEK + gewrappter Blob existieren; gewrappte TMKs sind
  sicher mit-backupbar (ohne KEK nutzlos).

### 6.1 Key Rotation & Rotation-Aware Search (implementiert)

Rotation ist mehrversionig und **ohne Spezialfälle pro Version**:

- **Encryption** nutzt **immer** den Current Key (`GetCurrentKeyId(tenant)`).
- **Decryption** nutzt die **`KeyId` aus dem Envelope-Header** → Altdaten bleiben nach einer Rotation
  lesbar. `KeyId = TmkId ‖ TmkVersion` **reicht aus**; das Envelope-Format muss nicht geändert werden.
- **Kein `if (version == n)`:** der Provider löst die Version generisch aus der KeyId auf.
- **Rotation-aware Search:** der Suchbegriff wird unter **allen** bekannten Versionen indiziert
  (`IBlindIndexProvider.ComputeForAllKnownKeys`, gespeist aus `IKeyMaterialProvider.GetKnownKeyIds(tenant)`);
  `WhereEncryptedEquals` baut daraus ein OR-Prädikat (Details in 11).

### 6.2 KMS-Schichten: zwei getrennte Nähte

Produktion trennt zwei Ebenen sauber — Vendor-Adapter implementieren **nur** die KEK-Naht:

- **`IKeyProvider` — KEK / Wrap / Unwrap.** Wrappt/entwrappt den TMK; vendor-spezifisch (später
  Azure Key Vault, AWS KMS, Google KMS, HashiCorp Vault). Kennt **keine** Ableitung, **kein** EF.
- **`IKeyMaterialProvider` — Working-Key-Ableitung.** `Tenant + KeyId + Scope + Purpose → AES/HMAC
  Working Key` (HKDF). Vendor-neutral, framework-frei.

### 6.3 Key-Katalog-Modell (neutral, kein DB-Zwang) (implementiert)

Ein neutrales Modell beschreibt den Schlüsselbestand eines Tenants — ohne Cloud-SDK, ohne erzwungene DB:

```text
Tenant A
 ├── TmkId (stabil, 16 B GUID)
 ├── Version 1 → ProviderKeyReference + WrappedTenantMasterKey
 ├── Version 2 → ProviderKeyReference + WrappedTenantMasterKey
 └── CurrentVersion = 2
```

- **`TenantKeyRecord`** — TmkId + Versionen + Current; baut die KeyIds (`TmkId ‖ Version`) und
  `GetKnownKeyIds()`; `TryGetVersion(keyId)` löst eine KeyId zurück auf ihre Version auf.
- **`TenantKeyVersion`** — Version + `ProviderKeyReference` + **optional** `WrappedTenantMasterKey`
  (KEK-gewrappter TMK; nur für die Ableitung nötig, sicher speicherbar).
- **`ProviderKeyReference`** — `KeyProviderKind` + opake Vendor-Referenz (Key-Vault-URI/KMS-ARN/…).
- **`KeyProviderKind`** — LocalDevelopment / AzureKeyVault / AwsKms / GoogleKms / Custom.
- **`ITenantKeyRegistry`** — Quelle der `TenantKeyRecord`s (in-memory / Datei / Tabelle).

### 6.4 RegistryKeyMaterialProvider (implementiert)

Der produktionsförmige `IKeyMaterialProvider`, der das Modell mit der KEK-Naht verbindet:

1. `TenantKeyRecord` aus der `ITenantKeyRegistry` holen.
2. KeyId → Version auflösen (`TryGetVersion`).
3. TMK über den passenden `IKeyProvider` **unwrappen** (Routing per `KeyProviderKind`).
4. Working Key per **HKDF** ableiten; **TMK danach nullen**, nie cachen.

Bleibt **KMS-neutral**: ein echter Cloud-Provider muss später **nur** `IKeyProvider` implementieren.

### 6.5 ReEncrypt / ReIndex Foundation (implementiert, ohne Worker)

Bausteine, um Altdaten kontrolliert auf den Current Key zu heben — **kein** Worker, **keine** DB-weite Migration:

- **Detection per Envelope-Header, ohne Entschlüsselung** (`IEncryptionMigrationPlanner`):
  `Header.KeyId != GetCurrentKeyId(tenant)` ⇒ Migration nötig. string-Properties: **Base64**-Envelope;
  `byte[]`-Properties: **roher** Envelope; `null` ⇒ keine Migration; ungültiges Envelope ⇒ **Fehler**.
- **ReEncrypt = Decrypt(alt) + Encrypt(current)** (`IEncryptionMigrationService`) — **kein** In-Place-
  Header-Rewrite (kryptografisch unmöglich). **ReIndex:** der Blind Index wird aus dem Klartext mit dem
  **Current-Index-Key** neu berechnet (nur so möglich).
- Arbeitet auf **gespeicherten Rohwerten** (nicht über getrackte Entities), damit die Interceptoren
  nicht doppelt verschlüsseln; ein späterer Worker liest/schreibt roh und batcht (Phase 6).
- **Worker-Foundation (nur Value Objects, keine Ausführung/Persistenz):** `ReEncryptBatchOptions`
  (Batch-Größe), `ReEncryptBatchResult` (Batch-Ergebnis: re-encrypted/skipped/failed + NextResume +
  HasMore), `ReEncryptProgress` (kumulativer Fortschritt, `AfterBatch` faltet ein Batch-Ergebnis ein und
  setzt `IsComplete`), `ReEncryptResumeToken` (opaker Cursor; `Beginning` startet neu). Der eigentliche
  `RunBatch`-Schritt (DB-Lesen/Schreiben) bleibt dem Worker (Phase 6) überlassen.

---

## 7. Ciphertext Envelope

**Entscheidung: kompaktes binäres Format**, gespeichert als `varbinary` / `bytea`.

*Nicht* JSON (Per-Value-Größe + Parse-Kosten bei Millionen Feldern, ~33 % Base64-Overhead),
*nicht* Protobuf (zusätzliche Abhängigkeit + Overhead im Hot Path). Binär = minimal,
deterministisch, versioniert.

| # | Feld | Größe | Pflicht | Zweck |
|---|---|---|---|---|
| 1 | Magic `"PENC"` (`0x50 0x45 0x4E 0x43`) | 4 B | ✅ | fester Marker + „ist verschlüsselt?“-Erkennung |
| 2 | EnvelopeVersion = `0x01` | 1 B | ✅ | Format-Version (getrennt vom Algorithmus) |
| 3 | SuiteId | 1 B | ✅ | Cipher-Suite → Krypto-Agilität ohne Format-Bruch |
| 4 | AadSchemeId | 1 B | ✅ | wie die AAD gebildet wird |
| 5 | KeyIdLength = N | 1 B | ✅ | `1..255` |
| 6 | KeyId = `TmkId(16) ‖ TmkVersion(2)` | N B | ✅ | opak, vendor-neutral |
| 7 | NonceLength = M | 1 B | ✅ | `1..255` (AES-GCM: 12) |
| 8 | Nonce | M B | ✅ | GCM 96-bit, CSPRNG |
| 9 | TagLength = T | 1 B | ✅ | `1..255` (AES-GCM: 16) |
| 10 | Tag | T B | ✅ | GCM Auth-Tag |
| 11 | CiphertextLength | 4 B | ✅ | `UInt32` **Big-Endian** (`0..2³²−1`) |
| 12 | Ciphertext | L B | ✅ | length-präfixiert (nicht mehr „Rest“) |

- **Größen:** Die fixen Overhead-Bytes (Magic + Version + SuiteId + AadSchemeId + alle
  Length-Prefixe) ergeben **`FixedOverheadLength` = 14 B**; der kleinstmögliche Envelope
  (Min-KeyId/Nonce/Tag à 1 B, leerer Ciphertext) ist **`MinimumEnvelopeLength` = 17 B**.
- **Framing vs. AAD:** Magic und **alle** Length-Prefixe sind reines Format-Framing und gehen
  **nicht** in die AAD ein; authentifiziert wird der Header
  `Version ‖ SuiteId ‖ AadSchemeId ‖ KeyId` (siehe [§8](#8-aad-regeln)).
- **Optionale/zukünftige Felder:** keine im Byte-Layout — Erweiterung läuft über **neue
  `SuiteId`**, **neue `AadSchemeId`** und (als letzter Ausweg) **`EnvelopeVersion`**. `KeyId`,
  `Nonce` und `Tag` sind längen-präfixiert → künftige Key-Schemata und Suites mit anderer
  Nonce-/Tag-Länge passen ohne Format-Bruch.
- **Regeln:** `null` → `null` (Nulls werden nicht verschlüsselt); leerer String wird normal
  verschlüsselt. Unbekannte Version/Suite → **laut ablehnen**, kein Silent-Fallback. Eine
  `SuiteId` wird nie umgewidmet.
- **Suite-Registry:**

  | SuiteId | Verfahren | Status |
  |---|---|---|
  | `0x01` | AES-256-GCM | **v1** |
  | `0x02` | AES-256-GCM-SIV | reserviert (High-Volume) |
  | `0x03` | XChaCha20-Poly1305 | reserviert |
  | `0x10` | AES-256-SIV (deterministisch) | reserviert |

> **Hinweis:** Zum Entschlüsseln werden Envelope **plus** Row-Kontext (für die
> Schlüsselableitung: Entity/Property; für die TMK-Auswahl: Tenant) benötigt. Für
> Export/Datenportabilität muss dieser Decryption-Context mitgeführt werden.

---

## 8. AAD-Regeln

**Entscheidung: AAD = der Envelope-Header** (`EnvelopeVersion ‖ SuiteId ‖ AadSchemeId ‖ KeyId`).
Magic-Marker und Length-Prefixe sind Format-Framing und gehen **nicht** in die AAD ein.
Zweck: **Metadaten-Integrität + Downgrade-Schutz** — das Suite-/Versions-Byte kann nicht
unbemerkt manipuliert werden. Die **Kontextbindung wandert in die Schlüsselableitung** — das
ist kryptografisch stärker und löst eine konkrete EF-Restriktion (ein ValueConverter sieht
keine TenantId).

| Wert | Verdikt | Wo gebunden | Begründung |
|---|---|---|---|
| **TenantId** | gebunden, **nicht in AAD** | TMK-Auswahl (per-Tenant-Key) | Falscher Tenant → falscher TMK → entschlüsselt nicht. |
| **EntityName** | gebunden | HKDF-`info` (**stabiler Logical Name**) | Cross-Column-Verschiebung scheitert. Logical Name ≠ CLR-Name → **rename-sicher**. |
| **PropertyName** | gebunden | HKDF-`info` (Logical Name) | dito |
| **EntityId / Primary Key** | **deferred** | — | DB-generiert beim INSERT (Henne-Ei) + mutabel → würde Migrationen brechen. Opt-in später via `AadSchemeId 0x02`. |

**Schutz vor Sackgassen bei Umbenennung/Migration:** Logical Names werden in der
Fluent-Konfiguration **gepinnt** (entkoppelt von CLR-Klassen-/Property-Namen). Ein C#-Rename
bricht damit **keine** gespeicherten Daten. Eine echte Daten-Migration zwischen Spalten
erfordert bewusste Re-Encryption (Decrypt mit altem Kontext, Encrypt mit neuem) — was
semantisch korrekt ist. Es dürfen **keine veränderlichen Werte** (z. B. `UpdatedAt`,
RowVersion) in die Bindung einfließen, sonst wird der Wert nach Kontextänderung
unentschlüsselbar.

---

## 9. Kryptografische Entscheidungen

| Verfahren | Status | Anmerkung |
|---|---|---|
| **AES-256-GCM** | **v1** | `System.Security.Cryptography.AesGcm`, Default-AEAD |
| **HKDF (RFC 5869)** | **v1** | TMK → Subkey, Domain-Separation; nativ in .NET |
| **HMAC-SHA256** | **v1** | nur *unter* HKDF und Blind Index, nie als Ad-hoc-KDF |
| **Blind Index** | **v1** | `truncate(HMAC-SHA256(idxKey, normalize(plaintext)))`, Exact-Match; `idxKey` via `purpose=idx` |
| **AES-256-GCM-SIV** | vorbereitet (Suite `0x02`) | nonce-misuse-resistant für High-Volume-Spalten |
| **Deterministic Encryption** | vorbereitet, **nicht empfohlen** (Suite `0x10`, AES-SIV) | nur bei Unique-Constraint-Zwang; leakt Gleichheit + Häufigkeit; opt-in mit Warnung; **nie GCM mit fixer Nonce/ECB** |
| **Token / Partial Search** | **nicht in v1**, späteres Search-Modul | n-Gram-Blind-Indizes; hohe Leakage/Storage-Kosten |

**Nonce-Budget (operative Grenze):** Random-96-Bit-Nonce ist sicher bis ~2³² Werte *pro
(Tenant, Spalte, TmkVersion)*. Darüber → `TmkVersion` rotieren oder GCM-SIV (Suite `0x02`).
Für typische PII-Spalten unkritisch; für Milliarden-Zeilen-Spalten dokumentiert.
**RNG: ausschließlich `RandomNumberGenerator`.** Vergleiche über
`CryptographicOperations.FixedTimeEquals`. **Vermeiden:** OPE/ORE, FPE/FF1 (außer
spezifischem PAN-Bedarf), homomorphe/SSE-Verfahren, jede Eigenkryptografie.

---

## 10. EF Core Integration

**Primärmechanismus: `SaveChangesInterceptor` (Verschlüsseln) + `IMaterializationInterceptor`
(Entschlüsseln).** Ein reiner **ValueConverter wird für die Verschlüsselung verworfen** — er
sieht nur den Einzelwert, **nicht** die TenantId/den Row-Kontext, und nicht-deterministische
Konvertierung zerstört das Change-Tracking. Nur die Interceptors haben über ChangeTracker +
DbContext + Tenant-Accessor den vollständigen Kontext.

- **Konfiguration: deklarativ über Attribute *oder* Fluent-API — gleichwertig und beide
  implementiert** (Details und Beispiele siehe 10.1). Beide werden beim Model-Build in **dasselbe
  Metadatenmodell** überführt; keine der beiden ist „nur Sugar" oder zweite Klasse.
  Widersprüchliche kryptografische Identität (Scope/Normalizer) zwischen Attribut und Fluent ist
  ein **harter Fehler** beim Model-Build, kein stilles Überschreiben.
- **Eine Laufzeit-Wahrheitsquelle = das EF-Core-Modell:** `UseProteosEncryptionModel()` führt
  Attribut- und Fluent-Konfiguration beim Model-Build zu **einem** validierten Metadatensatz
  zusammen und legt ihn als Annotation am EF-`IEntityType` ab. **Interceptors und Query-Extensions
  lesen die Metadaten zur Laufzeit aus dem EF-Modell** — quellen-blind (sie wissen nicht, ob die
  Konfiguration aus Attribut oder Fluent stammt) und **ohne separaten Reflection-/Metadaten-Cache**.
  Fehlt die Convention auf einem schreibenden Context, schlägt der Save **hart** fehl (kein
  stiller Klartext).
- **Speicherung:** `[Encrypted]`-Properties werden per Model-Convention auf `varbinary` /
  `bytea` gemappt (Spalte hält den Envelope).
- **Change-Tracking:** Re-Encryption nur bei **tatsächlich geänderten** Werten (Vergleich
  entschlüsselter Original-Snapshot ↔ aktueller Wert) → keine Spurious-Updates, keine
  Doppel-Verschlüsselung.

| EF-Szenario | Verhalten in v1 | Entscheidung |
|---|---|---|
| Tracked CRUD | Encrypt/Decrypt automatisch | ✅ unterstützt |
| `AsNoTracking` | Materialization-Interceptor feuert → Decrypt | ✅ unterstützt |
| `FromSqlRaw` (Entity-Read) | Materialization → Decrypt | ✅ unterstützt |
| Raw-SQL-Writes (INSERT/UPDATE) | umgeht SaveChanges → kein Encrypt | ❌ verboten, Guard |
| `ExecuteUpdate` / `ExecuteDelete`, Bulk-Extensions | umgehen ChangeTracker → kein Encrypt/Decrypt | ❌ nicht unterstützt, Guard |
| LINQ-Filter/Sort auf verschlüsselter Property | nicht übersetzbar (Random-Nonce) | ❌ Guard/Analyzer → Blind Index nutzen |
| Projektion `Select(x => x.Email)` | kein Entity materialisiert → kein Decrypt (Ciphertext!) | ❌ kritische Grenze, dokumentiert + Guard + Analyzer (PENC001) |

**Grenze der automatischen Entschlüsselung:** Decrypt erfolgt **nur über vollständige
Entity-Materialisierung**. Projektionen auf anonyme Typen/DTOs, die eine verschlüsselte
Property selektieren, werden **nicht** entschlüsselt. Dies ist die wichtigste
Nutzer-Stolperstelle und gehört prominent in die Anwenderdokumentation.

### 10.1 Konfiguration: Attribute und Fluent (gleichwertig)

Verschlüsselung wird deklarativ konfiguriert — über **Attribute** oder die **Fluent-API**,
**gleichwertig** (beide implementiert). Keine ist „nur Sugar" oder zweite Klasse; **beide werden
beim Model-Build in dasselbe Metadatenmodell überführt**, das als Annotation im EF-Core-Modell
liegt und zur Laufzeit die **einzige** Metadaten-Quelle ist (siehe 10). Attribute
(DataAnnotations-Stil) machen Sensitivität direkt am Feld sichtbar und sind schwerer zu vergessen;
die Fluent-API hält das Domänenmodell attributfrei und skaliert für große Projekte.

```csharp
// Attribute
[EncryptedEntity("customer")]
public class Customer
{
    [EncryptedEmail("email")]   // verschlüsselt + Blind Index (Email-Normalizer)
    public string Email { get; set; } = "";

    [Encrypted("phone")]        // nur verschlüsselt
    public string Phone { get; set; } = "";
}
```

```csharp
// Fluent (gleichwertig) — EF-Core-nativ auf EntityTypeBuilder / PropertyBuilder
modelBuilder.Entity<Customer>()
    .IsEncryptedEntity("customer")
    .Property(x => x.Email)
    .IsEncryptedEmail("email");

modelBuilder.Entity<Customer>()
    .Property(x => x.Phone)
    .IsEncrypted("phone");

// am Ende von OnModelCreating, nachdem Entities und Fluent konfiguriert sind:
modelBuilder.UseProteosEncryptionModel();
```

**Konflikt = harter Fehler:** Definieren Attribut und Fluent für dieselbe Property eine
unterschiedliche **kryptografische Identität** (Scope/Normalizer), wird das **nicht** still
überschrieben, sondern beim Model-Build abgelehnt — z. B. `[Encrypted("email")]` +
`.Property(x => x.Email).IsEncrypted("primaryEmail")` → Fehler (verhindert eine
Datenmigrations-Falle). Eine **identische** Doppelkonfiguration ist erlaubt (idempotent).

### 10.2 Kryptografische Identität bleibt explizit

Diese Werte gehen in Key Derivation bzw. Blind Index ein und werden **nie aus CLR-Namen
abgeleitet** — ein C#-Rename darf gespeicherte Daten nicht unlesbar/unsuchbar machen:

- **Entity Logical Name** — `[EncryptedEntity("customer")]`, einmal pro Entity.
- **Property Logical Name** — `[Encrypted("phone")]` (explizit; **nicht** parameterlos `[Encrypted]`).
- **Normalizer** — explizit, nie aus dem Property-Namen erraten.

Der Scope ergibt sich aus beiden Logical Names und entspricht `EncryptedDataScope(entityLogical,
propertyLogical)`:

```text
entityLogical = "customer"  ·  propertyLogical = "phone"  ·  scope = customer.phone
```

**Semantische Attribute** verkürzen die Schreibweise und wählen den Normalizer **explizit über
den Attributtyp** (keine Namens-Magie):

```csharp
[EncryptedEmail("email")]   // ≙ [EncryptedSearchable("email", Normalizer = BlindIndexNormalizerKind.Email)]
```

Bewusst **sparsam**: nur sehr häufige, eindeutige Fälle (v1: `[EncryptedEmail]`; optional später
z. B. `[EncryptedCaseInsensitive("displayName")]`). Kein eigenes Attribut pro Spezialfall — der
generische `[EncryptedSearchable(…, Normalizer = …)]` bleibt für alles andere.

### 10.3 Blind-Index-Spalten: Shadow Property als Default

Eine durchsuchbare Property braucht eine Schattenspalte für den Blind Index. **Standardmäßig
wird sie als EF-Core-Shadow-Property angelegt** — **keine** CLR-`byte[]`-Property mehr nötig:

```csharp
[EncryptedEmail("email")]
public string Email { get; set; } = "";
// → interne Shadow-Spalte "EmailIndex" (varbinary / bytea)
```

- **Auto-Index:** auf die Blind-Index-Spalte wird **automatisch ein nicht-unique DB-Index**
  gelegt. Einziger Zweck ist Equality-Search (`WHERE EmailIndex = @index`); ohne Index gute DX,
  aber schlechte Performance.
- **Nullable:** die Blind-Index-Spalte ist **nullable**; Regel `null` Wert → `null` Blind Index.
- **Power-User** dürfen weiterhin **explizit eine CLR-Index-Property** angeben (wenn der
  Indexwert im Modell sichtbar sein soll). Die Shadow-Property ist nur der Default.
- **Gilt für beide Konfigurationswege:** Attribut (`[EncryptedEmail]` / `[EncryptedSearchable]`)
  **und** Fluent (`.IsEncryptedEmail(...)` / `.IsEncryptedSearchable(...)`) laufen durch dieselbe
  Model-Convention — gleiche Shadow-Property, gleicher Auto-Index, gleiche Nullable-Regel.

### 10.4 Tenant Resolution

Der Interceptor braucht **pro Operation** eine `TenantId` (Tenant = Organisation, siehe 3.1):

- Auflösung über eine **konfigurierte Resolver-Funktion / ein Interface**.
- **Kein stiller Default-Tenant, kein Fallback, kein global-statischer Tenant.** Fehlt der
  Tenant → **harter Fehler** (ein leerer Tenant würde unter falschem/geteiltem Schlüssel
  schreiben → Tenant-Isolation kaputt).
- Tenant wird **pro Operation** aus dem aktuellen Scope aufgelöst, **nicht** im `DbContext`
  gecacht — sonst nutzt ein gepoolter Context (`AddDbContextPool`) einen veralteten Tenant aus
  einem früheren Request.
- Proteos konsumiert idealerweise die **bestehende** Tenant-Abstraktion der App (kein zweiter,
  konkurrierender Tenant-Begriff neben einem vorhandenen Query-Filter).

```csharp
services.AddProteosEncryption(options =>
{
    options.UseTenant(sp => sp.GetRequiredService<ITenantContext>().TenantId);
});
```

Single-Tenant-Deployments erhalten einen expliziten Einzeiler (ein fixer TMK), nie einen
impliziten Default.

### 10.5 Schutz vor „versehentlichem Klartext": Audit Report & Strict Mode (implementiert)

Eine neu hinzugefügte sensible Property **ohne** Klassifizierung würde **still als Klartext**
gespeichert. Dagegen gibt es zwei **implementierte** Laufzeit-Mechanismen; der Roslyn Analyzer ist mit den Regeln
PENC001/PENC002 implementiert, nur die Compile-Zeit-Klassifizierungsprüfung (PENC003) bleibt Roadmap
(siehe 15.3).

**Audit Report (implementiert).** `UseProteosEncryptionModel()` wertet das **finalisierte
EF-Modell** aus und erzeugt einen strukturierten Report, der jede `string`/`byte[]`-Property
klassifiziert als **`encrypted`**, **`encrypted searchable`**, **`plaintext`** oder
**`unclassified`** (Blind-Index-Spalten und Nicht-`string`/`byte[]`-Properties werden
ausgelassen). Er ist programmatisch abrufbar und kann optional geloggt werden:

```csharp
var report = dbContext.GetEncryptionAuditReport();
// report.Entries       -> alle Properties + Klassifizierung
// report.Unclassified  -> die (noch) nicht klassifizierten
// report.ToString()    -> lesbare Tabelle, z. B. "Customer.Email  encrypted searchable"
```

**Strict Mode Foundation (implementiert, optional).** Aktivierung über die DI-Options:

```csharp
services.AddProteosEncryption(options =>
{
    options.UseLocalDevelopmentKeyProvider();
    options.UseTenant(sp => /* ... */);
    options.EnableStrictMode();
});
```

Ist Strict Mode aktiv, **muss** jede relevante `string`/`byte[]`-Property explizit klassifiziert
sein — als **encrypted**, **encrypted searchable** oder **plaintext**. Eine unklassifizierte
Property ist ein **harter Fehler**; es gibt **keine Namensheuristiken, keine Blacklists, keine
stillen Defaults**.

**Aggregierte Fehler.** Strict Mode bricht **nicht beim ersten** Fund ab, sondern meldet **alle**
unklassifizierten Properties gemeinsam:

```text
Customer.DisplayName is unclassified
Employee.Notes is unclassified
Company.Logo is unclassified
```

**Timing — ehrlich: Strict Mode wird am Save-Boundary durchgesetzt, nicht beim Model-Build.**
`EnableStrictMode()` ist eine **DI-Option**, `UseProteosEncryptionModel()` hingegen
**ModelBuilder-basiert ohne DI-Zugriff**. Der `SaveChangesInterceptor` hat beides — DI **und** das
EF-Modell —, und der Save ist genau der Moment, an dem Klartext persistiert würde. Folgen, die man
kennen muss:

- Für **reine Read-only-Kontexte** löst Strict Mode **nicht automatisch** aus (es wird nichts
  geschrieben → kein Klartext-Leak). Wer **beim Startup hart prüfen** will, wertet den Audit Report
  selbst aus, z. B. `if (dbContext.GetEncryptionAuditReport().Unclassified.Count > 0) throw …`.
- Eine echte **Compile-/Build-Zeit**-Klassifizierungsprüfung ist Aufgabe des Roslyn Analyzers — diese
  Regel (PENC003) ist reserviert und noch nicht aktiv (15.3); Strict Mode ist die **Laufzeit-Foundation**.

**`[Plaintext]` — bewusste Entscheidung, nicht „egal".** Properties, die absichtlich im Klartext
liegen, werden explizit markiert (Attribut **oder** Fluent, gleichwertig):

```csharp
[Plaintext]
public string DisplayName { get; set; } = "";
```

```csharp
modelBuilder.Entity<Customer>()
    .Property(x => x.DisplayName)
    .IsPlaintext();
```

Eine Property gleichzeitig verschlüsselt **und** `[Plaintext]` zu markieren ist ein **harter
Fehler** beim Model-Build (widersprüchliche Klassifizierung). Technische `byte[]`-Felder (z. B. ein
`[Timestamp]`/RowVersion-Token) müssen unter Strict Mode ebenfalls klassifiziert werden — in der
Regel als `[Plaintext]`.

---

## 11. Suchkonzept

- **Warum Suche auf Ciphertext nicht zuverlässig funktioniert:** Durch die zufällige Nonce
  erzeugt derselbe Klartext **unterschiedliche** Ciphertexts → Gleichheit ist nicht
  feststellbar; es gibt keine Ordnung → kein Range, kein `LIKE`, kein Sortieren.
- **Exakte Suche = Blind Index:** searchable Properties bekommen eine Schattenspalte `{Prop}Index` =
  `HMAC-SHA256(idxKey, normalize(value))` (volle 32 B, keine Truncation in v1). Der SaveChanges-
  Interceptor befüllt sie. Abfrage über den **expliziten** Query-Helper
  (`.WhereEncryptedEquals(db, x => x.Email, term)`), der den Blind Index des Suchbegriffs berechnet
  und auf die (indizierbare) Schattenspalte filtert — übersetzt sauber nach SQL. Ergänzend:
  `.WhereEncryptedIn(db, x => x.Email, terms)` (Mehrwert-Suche = `IN`, OR über alle Term-/Versions-
  Indexe, dedupliziert, leere Menge = kein Treffer) und `.WhereEncryptedEmail(...)` (Convenience-
  Wrapper über `WhereEncryptedEquals`) — beide rotation-aware, ohne Client-Evaluation.
- **Rotation-aware Search (implementiert):** Nach einer Key-Rotation liegen Blind Indexe unter
  verschiedenen Versionen. Der Suchbegriff wird daher unter **allen** bekannten Key-Versionen
  berechnet (`ComputeForAllKnownKeys`, gespeist aus `GetKnownKeyIds(tenant)`) und zu einem
  **OR-Prädikat** kombiniert: `EmailIndex == idxV1 OR EmailIndex == idxV2 OR …`. Bei nur **einer**
  Version bleibt es ein einfacher Equality-Vergleich (keine Regression). Unbekannte Versionen werden
  nicht gefunden, aber die Query **explodiert nicht** (jeder Term ist ein Parameter). Mit wachsender
  Versionszahl steigen die OR-Kosten; **ReEncrypt/ReIndex** (6.5) senkt sie später wieder.
- **Normalisierung** (lowercase/trim/Unicode-NFC) deterministisch und kultur-invariant, pro
  Feld konfigurierbar; dokumentiert (beeinflusst Treffer).
- **Wann Deterministic Encryption erlaubt wäre:** ausschließlich bei zwingendem
  Unique-Constraint oder Equality ohne Schattenspalte — explizit opt-in, mit Leakage-Warnung,
  über AES-SIV. **Nicht** der Default.
- **Nicht unterstützt:** Range, `LIKE`/Substring, `ORDER BY`/Sortierung, Aggregation, FK,
  `UNIQUE` auf verschlüsselten Spalten (Unique nur deterministisch), Volltext, Fuzzy.
  Token-/Partial-Suche ist ein **späteres** Modul.

---

## 12. Open-Source-Modell

**Modell: Open Core, Lizenz Apache-2.0** (expliziter Patent-Grant → Enterprise-Legal-Komfort;
**nicht** AGPL, da AGPL eine eingebettete Library für die Zielgruppe vergiften würde).

### 12.1 Open Source

- Crypto Core
- Abstractions
- EF Core Integration
- Attribute
- Interceptors
- Envelope Format
- Blind Index Logik
- Key Provider Interfaces
- Local Dev Key Provider
- **Azure Key Vault Adapter**
- **AWS KMS Adapter**

> Die Cloud-Key-Provider (Azure Key Vault, AWS KMS) sind **langfristig Teil des
> Open-Source-Cores**, werden aber **nicht in der ersten Implementierungsphase** gebaut
> (siehe [Roadmap, Phase 4](#15-roadmap--implementierungsreihenfolge)). Begründung: Sie sind
> wichtig für Vertrauen und Adoption, aber der **kryptografische Core und das Envelope-Format
> müssen zuerst stabil stehen**.

### 12.2 Später kommerziell / geschlossen möglich

- Dashboard
- Monitoring
- Migration UI
- Rotation Orchestrierung
- Hosted Services
- SaaS Control Plane
- Support
- SLA
- Enterprise-Funktionen

### 12.3 Feste Versprechen

1. **Der offene Core bleibt vollständig funktionsfähig**, auch wenn alle kommerziellen
   Komponenten verschwinden.
2. **Ein Kunde darf niemals seine Daten verlieren oder nicht mehr entschlüsseln können**, nur
   weil ein kommerzieller Dienst nicht mehr verfügbar ist. Daten sind jederzeit mit dem
   Open-Source-Core und den eigenen Schlüsseln entschlüsselbar.
3. Der offene Core wird **nicht relizenziert oder geschlossen** (Vermeidung des
   Re-Licensing-Backlash).

---

## 13. Architekturregeln

Proteos umfasst zwei klar getrennte Architektur-Domänen. Welche Regeln gelten, hängt vom
**Projekttyp** ab — sie dürfen **nicht** vermischt werden.

| Projekttyp | Geltende Architektur |
|---|---|
| **Library / NuGet** — `Proteos.Encryption.Abstractions`, `Core`, `EntityFrameworkCore`, `Search` | Library-Architektur (13.1) |
| **SampleApi, Demo-Apps, spätere SaaS-Komponenten, Control Plane** | API-/Backend-Architektur (13.2) |

Das eigentliche Produkt ist die **Library**. Dort gibt es **keine** Controller, HTTP-Endpunkte,
Manager, Commands oder Query Services; die API-/Backend-Regeln aus 13.2 gelten dort
ausdrücklich **nicht**.

### 13.1 Library-Architektur — das eigentliche Produkt

Die NuGet-Bibliotheken folgen einer komponentenbasierten Library-Architektur, verdrahtet über
Dependency Injection (`AddProteosEncryption()`). Bausteine:

- **Interfaces** — Verträge in `Proteos.Encryption.Abstractions` (z. B. `IKeyProvider`,
  Encryptor- und Blind-Index-Verträge); Implementierungen in `Core`/Adaptern.
- **Kleine Services** — eng begrenzte Einzelverantwortung (AEAD-Verschlüsselung, HKDF-Ableitung,
  Blind-Index-Berechnung); keine God-Services.
- **Provider** — austauschbare Schlüsselquellen hinter `IKeyProvider` (Local Dev, Azure Key
  Vault, AWS KMS).
- **Options** — Konfiguration über typisierte Options-Objekte; kein verstecktes globales State.
- **Factories** — dort, wo Objektkonstruktion nicht trivial ist (z. B. Aufbau abgeleiteter
  Schlüssel oder Encryptor-Instanzen).
- **Value Objects** — unveränderliche Typen für Envelope-Header, KeyId und AAD-Kontext.
- **Interceptors** — EF-Core-`SaveChanges`/`Materialization`-Interceptors als Integrationspunkt
  (siehe [EF Core Integration](#10-ef-core-integration)).
- **Serializer / Parser** — der Envelope-Codec serialisiert und parst das binäre
  Ciphertext-Format (siehe [Ciphertext Envelope](#7-ciphertext-envelope)).

Grundsätze: kleine Verantwortlichkeiten, testbare Klassen, klare und minimale Public-Surface —
**keine** Controller-, Manager- oder Command-Schichten.

### 13.2 API-/Backend-Architektur — nur SampleApi, Demo, SaaS, Control Plane

Diese Regel gilt **ausschließlich** für API-/Backend-Projekte: `Proteos.Encryption.SampleApi`,
Demo-Anwendungen sowie spätere **SaaS-Komponenten** und die **Control Plane**. Sie gilt
**nicht** für die NuGet-Bibliotheken (siehe 13.1).

**Controller → Manager → Command Handler / Query Service**

- Controller sind **dünn** und **mappen nur** Response auf HTTP; **keine Businesslogik**.
- Controller rufen **ausschließlich** Manager auf.
- Manager **orchestrieren** und entscheiden zwischen:
  - **Command Handler** für schreibende Operationen
  - **Query Services / Services** für lesende Operationen
- **Zentrales Logging** und **zentrale Fehlerbehandlung** (Try/Catch) sitzen im Manager.
- **Keine direkten Save-Operationen** in Services; **Persistenz erfolgt über Command Handler.**

Damit wirkt der Beispiel-/Backend-Code nicht wie zusammengeworfener Beispielcode.

### 13.3 Coding Guidelines (für alle Projekttypen)

- Saubere, explizite C#-API; klare Interfaces; minimale Public-Surface; `sealed` by default.
- Kleine Verantwortlichkeiten, keine God-Services; Interfaces in `Abstractions`,
  Implementierungen in `Core`/Adaptern.
- Keine unnötige Magie; keine kryptografischen Eigenexperimente — nur
  `System.Security.Cryptography`-Primitive.
- `RandomNumberGenerator` für Nonces; `CryptographicOperations.FixedTimeEquals` für Vergleiche;
  `CryptographicOperations.ZeroMemory` für transientes Schlüsselmaterial (best-effort,
  dokumentierte Grenze).
- Deterministische, kultur-invariante Kodierung (UTF-8, längen-präfixiert; kein
  kultursensitives `ToString`).
- Nullable Reference Types an, Analyzer an, Warnings-as-Errors.
- **Kommentare nur** dort, wo sie fachlich oder kryptografisch wirklich helfen
  (Sicherheitsinvarianten, nicht offensichtliche Entscheidungen) — keine erzählenden
  Kommentare. Verständliche Namen, testbare Klassen. Der Code soll **nicht wie generierter
  Code** wirken.

---

## 14. Foundation Release (Initial Production Release)

Der **Foundation Release** ist die **erste produktionsfähige Architektur- und
Implementierungsbasis** — keine Wegwerfversion, kein Prototyp. Er etabliert den
produktionsreifen Crypto-Core, das stabile Envelope-Format, die EF-Core-Integration und die
Blind-Index-Suche (entspricht **Phase 1–3** der [Roadmap](#15-roadmap--implementierungsreihenfolge)).

**Wichtige, ehrliche Einordnung zum Schlüsselprovider:**

- In Phase 1–3 ist der **Local Development Key Provider** der Referenz-Provider — **ausdrücklich
  nur für Entwicklung und Tests**, nicht für den Produktionsbetrieb.
- Ein **echter Produktionsbetrieb** erfordert zusätzlich einen produktiven KMS-Provider
  (Phase 4: Azure Key Vault / AWS KMS) **oder** eine kundeneigene `IKeyProvider`-Implementierung,
  die denselben Wrap/Unwrap-Vertrag erfüllt.
- „Produktionsfähig“ bezieht sich auf **Qualität und Stabilität der Architektur und des Codes**;
  die `IKeyProvider`-Abstraktion ist die bewusste Naht, an der der reale KMS angebunden wird.

---

## 15. Roadmap & Implementierungsreihenfolge

Die fundamentalen Entscheidungen müssen zuerst stehen; alles Weitere wird **additiv**
angebaut. Empfohlene Reihenfolge:

> **Stand (implementiert):** Phasen 1–3 vollständig. Aus den Folge-Phasen sind die **Foundations**
> erledigt: **Key Rotation Foundation**, **Rotation-Aware Search**, **KMS Foundation** (neutrales
> Key-Katalog-Modell + Registry), **Registry-based Key Material Provider**, **ReEncrypt/ReIndex
> Foundation** (Details 6.1–6.5). Zusätzlich sind die **Cloud-Provider Azure Key Vault (RSA-OAEP-256)
> und AWS KMS (symmetrisch)** als eigene Pakete **implementiert** (Phase 4), der **Roslyn Analyzer**
> (PENC001/PENC002; PENC003 reserviert) und **drei Sample-Projekte** unter `samples/`
> (`Proteos.SampleApi`, `Proteos.FeatureShowcase`, `Proteos.CrmSampleApi`). **Weiterhin offen:**
> Google-KMS-Provider, ReEncrypt-Worker / Batch-Runner (Phase 6), Veröffentlichung auf NuGet,
> Analyzer-Code-Fixes, optional Source-Generator / Compiled-Model-Support.

### Phase 1 — Core Foundation
- Solution-Struktur
- Abstractions
- Crypto Core
- Ciphertext Envelope
- Key Provider Interfaces
- Local Development Key Provider
- Unit Tests
- Crypto Test Vectors
- Envelope Regression Tests

### Phase 2 — EF Core Integration
- Attribute **und** Fluent-API (gleichwertig, ein Metadatenmodell; Konflikt = harter Fehler)
- Entity-/Property-Logical-Name + semantische Attribute (`[EncryptedEmail]`)
- SaveChangesInterceptor
- MaterializationInterceptor
- Blind-Index-Spalten als **Shadow Property** (Default) + Auto-Index + nullable
- Tenant-Resolution (Resolver pro Operation, kein stiller Default; siehe 10.4)
- Integration Tests mit SQL Server / PostgreSQL

### Phase 3 — Search Foundation
- Blind Index
- HMAC-basierte exakte Suche
- Query Extensions
- Klare Grenzen für LINQ, `LIKE`, `ORDER BY` und Volltext

### Phase 4 — Cloud Key Providers
_Foundation erledigt: KMS-Modell, Registry und `RegistryKeyMaterialProvider` (6.2–6.4). Azure Key Vault und AWS KMS sind implementiert; Google KMS ist offen._
- Azure Key Vault Adapter ✅ **implementiert** (`Proteos.Encryption.AzureKeyVault`, RSA-OAEP-256; `AddProteosAzureKeyVault(...)`)
- AWS KMS Adapter ✅ **implementiert** (`Proteos.Encryption.AwsKms`, symmetrisch `Encrypt`/`Decrypt`; `AddProteosAwsKms(...)`)
- Google Cloud KMS Adapter (offen)

### Phase 5 — File Encryption
- Stream-/Chunk-basierte Dateiverschlüsselung
- Storage-agnostische API

### Phase 6 — Rotation & Operations
_Foundation erledigt: Key Rotation, Rotation-Aware Search und ReEncrypt/ReIndex (6.1, 6.5). Offen: Worker/Orchestrierung._
- Key Rotation ✅ (Foundation)
- Rotation Orchestrierung / ReEncrypt-Worker (offen)
- Monitoring
- Audit
- Spätere kommerzielle Module

> **Reihenfolge-Hinweis (Komponenten):** Core → Abstractions → Envelope → Tests → EF Core
> Integration → Blind Index / Search → Azure Key Vault / AWS KMS → File Encryption → Rotation.
> Innerhalb von Phase 1 werden die **Abstractions vor dem Crypto Core** fertiggestellt, da der
> Core auf den Abstractions aufbaut (dependency-freie unterste Schicht).

### 15.1 Empfohlene Solution-Struktur

```
Proteos.Encryption.Abstractions          # Interfaces, Attribute, Envelope-Typen, SuiteId/AadSchemeId,
                                          #   AAD-Kontext, Exceptions. Keine Abhängigkeiten.
Proteos.Encryption.Core                   # AEAD (AES-GCM), HKDF, EnvelopeCodec, BlindIndexer,
                                          #   TMK-Lifecycle, LocalDevKeyProvider, DI. -> Abstractions
Proteos.Encryption.EntityFrameworkCore    # Convention, Fluent-API, Interceptor-Paar, Shadow-Columns,
                                          #   Query-Helper, Guards. -> Core + Abstractions
Proteos.Encryption.AzureKeyVault          # IKeyProvider via Key Vault.  -> Abstractions (+ Azure SDK)   ✅ implementiert
Proteos.Encryption.AwsKms                 # IKeyProvider via KMS.        -> Abstractions (+ AWS SDK)     ✅ implementiert
Proteos.Encryption.Tests                  # Unit + Crypto-Vektoren + Envelope-Regression
Proteos.Encryption.IntegrationTests       # Testcontainers: SQL Server + PostgreSQL
samples/Proteos.SampleApi                 # Quickstart-Web-API (Controller -> Service -> DbContext)   ✅ vorhanden
samples/Proteos.FeatureShowcase           # Konsolen-Feature-Tour (10 Szenarien)                      ✅ vorhanden
samples/Proteos.CrmSampleApi              # Realistische CRM-Web-API (mehrere Entities, Include)      ✅ vorhanden
Proteos.Encryption.Benchmarks             # BenchmarkDotNet
```

- **Blind Index** liegt im **Core** (kein eigenes Search-Paket). Token-/Partial-Suche ist ein
  mögliches späteres Modul, aktuell nicht Teil des Releases.
- **KMS-Adapter sind dünn** (rohes Wrap/Unwrap); die TMK-Logik bleibt im Core, frei von
  Vendor-SDKs.

### 15.2 Testing-Strategie (Überblick)

- **Unit:** Crypto-Primitive, Envelope-Round-Trip, HKDF-Determinismus, Blind-Index-Normalisierung.
- **Crypto-Vektoren (Known-Answer-Tests):** NIST AES-GCM, RFC 5869 HKDF, RFC 4231 HMAC.
- **Golden-Envelope-Fixtures:** fixe Key+Nonce+Plaintext → exakte Bytes (fängt Format-Regression).
- **Property-based (FsCheck):** Round-Trip für beliebige Inputs; jedes geflippte Byte → Auth-Fehler.
- **EF-Integration (Testcontainers, SQL Server + PostgreSQL):** CRUD, `AsNoTracking`, `FromSql`,
  Projektions-Grenze, kein Spurious-Update, Blind-Index-Query, Guards.
- **Security:** Tamper-Detection, Cross-Context-Reject, Downgrade-Resistenz, Nonce-Eindeutigkeit,
  „kein Klartext in Logs“.
- **Performance (BenchmarkDotNet):** Encrypt/Decrypt-Durchsatz, Key-Ableitungs-Cache, Blind Index.
- **Mutation-Testing (Stryker.NET)** auf Crypto-/Envelope-Code.

### 15.3 Developer Experience & Safety

**Implementiert (siehe 10.5):**

- **Audit Report** über das finalisierte EF-Modell (`dbContext.GetEncryptionAuditReport()`):
  klassifiziert jede `string`/`byte[]`-Property als encrypted / encrypted searchable / plaintext /
  unclassified; programmatisch abrufbar.
- **Strict Mode Foundation** (`options.EnableStrictMode()`): erzwingt explizite Klassifizierung,
  meldet alle unklassifizierten Properties aggregiert, durchgesetzt am **Save-Boundary**
  (keine Namensheuristiken/Blacklists/stillen Defaults).
- **`[Plaintext]` / `.IsPlaintext()`** als bewusste Klartext-Klassifizierung (Attribut und Fluent
  gleichwertig); verschlüsselt **und** plaintext = harter Fehler.
- **Roslyn Analyzer (PENC001/PENC002)** — Compile-Zeit-Warnungen für die stillen Footguns:
  `Select(x => x.Email)` (liefert Ciphertext, **PENC001**) und `==`/`!=`-Filter auf verschlüsselten
  Properties (**PENC002**). Erkennt Attribut- **und** einfache Fluent-Konfiguration; im EF-Paket
  gebündelt. **PENC003** (Compile-Zeit-„forgot-to-classify"-Prüfung) ist reserviert.

**Weiterhin geplant (Roadmap):**

- **Analyzer-Code-Fixes und PENC003** — automatische Korrekturen zu den Analyzer-Warnungen sowie die
  reservierte **Compile-/Build-Zeit**-Variante der „forgot-to-classify"-Prüfung (PENC003) als Ergänzung
  zum Laufzeit-Strict-Mode. (Die Regeln PENC001/PENC002 selbst sind implementiert, siehe oben.)
- **Logical-Name-Snapshot (v2, ausdrücklich KEINE Foundation-Voraussetzung):** analog zum
  EF-Migrations-Snapshot Logical Names einfrieren, um Rename-Drift früh (Build-Zeit) zu erkennen
  und perspektivisch parameterlose Attribute (`[Encrypted]`) sicher zu erlauben. Später prüfen,
  nicht jetzt, keine Voraussetzung für die Runtime-Integration.
- **Source-Generator (später):** Metadaten/Registrierung zur Compile-Zeit (Startup-Performance,
  NativeAOT).

---

## 16. Risiken und Fallstricke

| Risiko / Sackgasse | Vermeidung in dieser Architektur |
|---|---|
| Envelope ohne Version/Suite/AadScheme/KeyId | alle vier ab v1 enthalten |
| KeyId = rohe KMS-URI | opaker, vendor-neutraler Identifier über `proteos_keys` |
| Kryptografische Identität (Scope/Normalizer) aus CLR-Namen | stabile, **explizite** Logical Names + expliziter Normalizer, in Attribut **oder** Fluent gepinnt (10.2) |
| Bindung an veränderliche Felder | nur lebenslang-stabile Werte |
| gleicher Key für Encrypt + Index | HKDF-Domain-Separation (`purpose`) |
| GCM mit fixer/Low-Entropy-Nonce | Random-96-Bit + HKDF-Subkeys; SIV reserviert |
| „Endbenutzer = Tenant“ | Tenant = Organisation (siehe 3.1) |
| Text-/Base64-Spalten im Core | `varbinary` / `bytea` |
| kein „ist verschlüsselt?“-Marker | Magic (4 B, „PENC“) + Version |
| KMS-Orakel ignorieren | im Threat Model offen benannt |
| DB-weite Integrität angenommen | per-Value benannt; Replay/Delete out of scope |
| Projektionen/Bulk/Raw-Writes liefern Klartext/Ciphertext | dokumentiert + Guards + Analyzer PENC001/PENC002 (15.3) |
| Vergessen, eine sensible Property zu klassifizieren → stiller Klartext | **Audit Report implementiert** (`GetEncryptionAuditReport()`) + **Strict Mode implementiert** (aggregiert); Compile-Zeit-Analyzer bleibt Roadmap (10.5 / 15.3) |
| Strict Mode greift nicht bei reinen Read-only-Kontexten | bewusster Trade-off: Durchsetzung am **Save-Boundary** (DI + Modell); für Startup-Prüfung Audit Report selbst auswerten (10.5) |
| Technisches `byte[]` (z. B. `[Timestamp]`/RowVersion) unter Strict Mode unklassifiziert | bewusst `[Plaintext]` markieren (10.5) |
| Stiller Default-Tenant → falscher/geteilter Schlüssel | kein Default/Fallback; fehlender Tenant = harter Fehler (10.4) |
| Gepoolter `DbContext` → veralteter Tenant | Tenant **pro Operation** aufgelöst, nie im Context gecacht (10.4) |
| Attribut/Fluent mit widersprüchlichem Scope/Normalizer | **harter Fehler** beim Model-Build, kein stilles Überschreiben (10.1) |
| Nonce-Budget überschritten | Grenze dokumentiert; TmkVersion-Rotation / GCM-SIV |
| Mehrere Key-Versionen → höhere Query-Kosten (OR über mehrere Blind Indexe) | bewusst; **ReEncrypt/ReIndex** (6.5) hebt Altdaten auf den Current Key und reduziert die OR-Terme |
| ReEncrypt über getrackte Entities → Interceptoren verschlüsseln doppelt | Migration arbeitet auf **gespeicherten Rohwerten** (lesen/schreiben ohne Interceptor), nicht über getrackte Entities (6.5) |
| KMS-Unwrap pro `DeriveKey` teuer (Netz-Roundtrip) | Foundation nullt den TMK nach Ableitung und cacht ihn nicht; später optionaler TMK-Cache mit klaren Security-Regeln (Phase 4) |
| Löschen alter Key-Versionen → Altdaten unlesbar | Versionen sind append-only / nie automatisch entfernt; Löschen ist bewusster Crypto-Shred, kein Default (6.1) |
| KEK-Verlust = Totalverlust | Kunden-Betriebspflicht klar dokumentiert |
| Klartext-Leak über Logging/Telemetry | Serialisierung verschlüsselter Entities prüfen |
| Decryption-Context-Kopplung | Context muss bei Export mitgeführt werden |
| Re-Licensing-Backlash | feste Versprechen (12.3) |

---

## 17. Spätere kommerzielle Module

Als separate Spur (eigenes Repository / eigene Lizenz), **nachdem** der offene Core steht:

- **Dashboard** — Überblick über verschlüsselte Felder, Schlüssel, Nutzung.
- **Monitoring** — Betriebskennzahlen, Alarme.
- **Migration UI** — geführte Backfill-Migration bestehender Daten (gemischter Zustand).
- **Rotation Orchestrierung** — automatisierte KEK-/TMK-Rotation + Background-Re-Encrypt.
- **Hosted Services / SaaS Control Plane** — verwaltete Schlüssel- und Policy-Verwaltung.
- **Support / SLA / Enterprise-Funktionen.**

**Unverrückbar:** Keines dieser Module darf zur Voraussetzung dafür werden, dass ein Kunde
seine Daten lesen kann. Der offene Core bleibt eigenständig voll funktionsfähig (siehe 12.3).

---

*Ende der Foundation-Spezifikation. Erweiterungen erfolgen additiv über `SuiteId`,
`AadSchemeId`, `TmkVersion` und neue Pakete — die fundamentalen Entscheidungen dieses
Dokuments bleiben stabil.*
