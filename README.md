📜 Secret Keeper Smart Contract
Overview

The Secret Keeper Contract is a Clarity smart contract for securely storing, sharing, and managing encrypted secrets on the Stacks blockchain. It ensures that only authorized users can access sensitive data, while also supporting expiration rules and access management.

✨ Features

🔒 Encrypted Storage: Store secrets as encrypted data with unique salts.

🕒 Optional Expiration: Secrets can be time-limited with an expiration block height.

👤 Ownership Control: Only the creator (owner) can delete or grant access to a secret.

👥 Access Management: Owners can grant and revoke access to specific principals.

🚫 Expiration Cleanup: Anyone can remove expired secrets to save storage.

📊 Tracking & Metadata:

Count of secrets per user.

Access history (who granted access, when).

Expiration status checks.

📂 Data Structures

secrets – Stores secret metadata (owner, encrypted-data, salt, created-at, expires-at).

user-secret-count – Tracks the number of secrets owned by each user.

secret-access – Records granted access to secrets with timestamp and grantor.

🔑 Key Functions
Public Functions

store-secret – Store a new encrypted secret.

store-secret-with-expiration – Store a secret with an expiration block height.

get-secret – Retrieve a secret (only if owner or authorized).

delete-secret – Delete a secret (owner only).

grant-access – Grant another user access to a secret (owner only).

revoke-access – Revoke access from a user (owner only).

cleanup-expired-secret – Remove expired secrets (anyone can call).

Read-only Functions

owns-secret – Check if a user owns a secret.

has-secret-access – Check if a user has access to a secret.

is-expired – Check if a secret has expired.

get-access-info – Get access details for a user.

get-user-secret-count – Get number of secrets owned by a user.

get-contract-owner – Retrieve contract owner.

⚠️ Error Codes

u100 – Not owner.

u101 – Secret not found.

u102 – Secret already exists.

u103 – Not authorized.

u104 – Secret expired.

u105 – Invalid expiration.

u106 – Invalid data.

🚀 Usage Flow

User encrypts data off-chain and generates a salt.

Calls store-secret or store-secret-with-expiration to save the encrypted payload.

Owner may grant other users access with grant-access.

Authorized users retrieve the secret with get-secret.

Owner may revoke access or delete the secret.

Expired secrets can be cleaned up by anyone.

🔐 Security Notes

Encryption/decryption must be handled off-chain. The contract only stores encrypted bytes.

Expiration ensures automatic cleanup opportunities but does not prevent premature deletion by the owner.

📜 License

MIT License – Open for educational and production use.