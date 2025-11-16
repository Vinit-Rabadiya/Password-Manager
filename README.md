# Password Manager (Keychain)

This repo contains a simple keychain-style password manager implemented in JavaScript.
The primary implementation is in `Password ManagerStarter/password-manager.js`.

**Summary**
- The Keychain stores encrypted passwords using AES-GCM and derives the encryption key from a passphrase using PBKDF2.
- Domain names are not stored in plain text; they are hashed with SHA-256 before use as keys.
- The serialized dump format is a JSON object `{ publicData, kvs, salt }` with a SHA-256 checksum.

**Functions & Behavior**

- **`Keychain` (constructor)**: Initializes an in-memory keychain object.
  - Inputs: `publicData` (object), `secretData` (object).
  - Stores public metadata in `this.data` and private fields in `this.secrets` (including `salt`, `key`, and `passwordDB`).

- **`static async init(password)`**
  - Purpose: Create a new, empty keychain for the supplied password.
  - Inputs: `password` (string).
  - Returns: A `Keychain` instance with a derived AES-GCM CryptoKey and empty `passwordDB`.
  - Notes: Uses PBKDF2 (SHA-256) with a random salt to derive the key.

- **`static async load(password, repr, trustedDataCheck)`**
  - Purpose: Restore a Keychain from a serialized representation and verify integrity and correct password.
  - Inputs: `password` (string), `repr` (JSON string from `dump()`), `trustedDataCheck` (optional checksum).
  - Returns: A `Keychain` instance on success.
  - Behavior: Verifies checksum (if provided), reconstructs `passwordDB` from `kvs` and `salt`, derives the key, and validates the password by attempting to decrypt one stored entry. Throws an error on checksum mismatch or incorrect password.

- **`async dump()`**
  - Purpose: Serialize the Keychain for storage and produce an integrity checksum.
  - Returns: `[jsonStr, checksum]` where `jsonStr` is JSON of `{ publicData, kvs, salt }` and `checksum` is SHA-256 hex across `jsonStr`.
  - Notes: `kvs` contains the encrypted entries (hashed keys → { iv, ciphertext }), `salt` is root-level. The derived CryptoKey is not serialized.

- **`async get(name)`**
  - Purpose: Retrieve the plaintext password for `name`.
  - Inputs: `name` (string domain/service).
  - Returns: Plaintext password string, or `null` if not found.
  - Behavior: Hashes `name` with SHA-256 to derive the lookup key, decodes and decrypts the stored ciphertext with AES-GCM, and returns the plaintext.

- **`async set(name, value)`**
  - Purpose: Insert or update a password entry.
  - Inputs: `name` (string), `value` (string password).
  - Behavior: Hashes `name`, generates a fresh IV, encrypts `value` with AES-GCM, and stores `{ iv, ciphertext }` under the hashed key.

- **`async remove(name)`**
  - Purpose: Remove an entry by name.
  - Inputs: `name` (string).
  - Returns: `true` if removed, `false` if no entry existed.
  - Behavior: Hashes `name` and deletes the hashed key from the `passwordDB`.

- **`async _hashName(name)`** (helper)
  - Purpose: Compute SHA-256 hex of the domain name to avoid storing names in plaintext.

**Data Layout (runtime)**
- `this.data` → public metadata
- `this.secrets` → { `salt` (encoded), `key` (CryptoKey, not serialized), `passwordDB` (hashedKey → { iv, ciphertext }) }

**Serialized Layout (dump)**
- `{ publicData, kvs, salt }` with `kvs` holding all encrypted entries and `salt` at root.

**Running Tests**
From the `Password ManagerStarter` directory run:

```powershell
cd "Password ManagerStarter"
npm test
```
