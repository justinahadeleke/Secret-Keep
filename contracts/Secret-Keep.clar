;; Secret Keeper Contract
;; Encrypts and stores secrets unlockable only by owner

;; Error constants
(define-constant ERR-NOT-OWNER (err u100))
(define-constant ERR-SECRET-NOT-FOUND (err u101))
(define-constant ERR-ALREADY-EXISTS (err u102))
(define-constant ERR-NOT-AUTHORIZED (err u103))
(define-constant ERR-SECRET-EXPIRED (err u104))
(define-constant ERR-INVALID-EXPIRATION (err u105))
(define-constant ERR-INVALID-DATA (err u106))

;; Data variables
(define-data-var contract-owner principal tx-sender)

;; Data maps
(define-map secrets
  { secret-id: uint }
  { 
    owner: principal,
    encrypted-data: (buff 1024),
    salt: (buff 32),
    created-at: uint,
    expires-at: (optional uint)
  }
)

(define-map user-secret-count principal uint)

(define-map secret-access
  { secret-id: uint, user: principal }
  { granted-at: uint, granted-by: principal }
)

;; Private functions
(define-private (is-owner (user principal))
  (is-eq user (var-get contract-owner))
)

(define-private (get-next-secret-id (user principal))
  (+ (default-to u0 (map-get? user-secret-count user)) u1)
)

(define-private (is-secret-expired (secret-data {owner: principal, encrypted-data: (buff 1024), salt: (buff 32), created-at: uint, expires-at: (optional uint)}))
  (match (get expires-at secret-data)
    expiry (>= block-height expiry)
    false
  )
)

(define-private (has-access (user principal) (secret-id uint))
  (let (
    (secret-data (map-get? secrets { secret-id: secret-id }))
  )
    (match secret-data
      secret (or 
        (is-eq user (get owner secret))
        (is-some (map-get? secret-access { secret-id: secret-id, user: user }))
      )
      false
    )
  )
)

;; Public functions

;; Store a new encrypted secret
(define-public (store-secret (encrypted-data (buff 1024)) (salt (buff 32)))
  (let (
    (user tx-sender)
    (secret-id (get-next-secret-id user))
  )
    (asserts! (> (len encrypted-data) u0) ERR-INVALID-DATA)
    (asserts! (is-eq (len salt) u32) ERR-INVALID-DATA)
    (asserts! (is-none (map-get? secrets { secret-id: secret-id })) ERR-ALREADY-EXISTS)
    (map-set secrets
      { secret-id: secret-id }
      {
        owner: user,
        encrypted-data: encrypted-data,
        salt: salt,
        created-at: block-height,
        expires-at: none
      }
    )
    (map-set user-secret-count user secret-id)
    (ok secret-id)
  )
)

;; Store a new encrypted secret with expiration
(define-public (store-secret-with-expiration (encrypted-data (buff 1024)) (salt (buff 32)) (expires-at uint))
  (let (
    (user tx-sender)
    (secret-id (get-next-secret-id user))
  )
    (asserts! (> (len encrypted-data) u0) ERR-INVALID-DATA)
    (asserts! (is-eq (len salt) u32) ERR-INVALID-DATA)
    (asserts! (> expires-at block-height) ERR-INVALID-EXPIRATION)
    (asserts! (is-none (map-get? secrets { secret-id: secret-id })) ERR-ALREADY-EXISTS)
    (map-set secrets
      { secret-id: secret-id }
      {
        owner: user,
        encrypted-data: encrypted-data,
        salt: salt,
        created-at: block-height,
        expires-at: (some expires-at)
      }
    )
    (map-set user-secret-count user secret-id)
    (ok secret-id)
  )
)

;; Retrieve an encrypted secret (owner or authorized users only)
(define-public (get-secret (secret-id uint))
  (let (
    (secret-data (unwrap! (map-get? secrets { secret-id: secret-id }) ERR-SECRET-NOT-FOUND))
  )
    (asserts! (> secret-id u0) ERR-INVALID-DATA)
    (asserts! (not (is-secret-expired secret-data)) ERR-SECRET-EXPIRED)
    (asserts! (has-access tx-sender secret-id) ERR-NOT-AUTHORIZED)
    (ok secret-data)
  )
)

;; Delete a secret (owner only)
(define-public (delete-secret (secret-id uint))
  (let (
    (secret-data (unwrap! (map-get? secrets { secret-id: secret-id }) ERR-SECRET-NOT-FOUND))
  )
    (asserts! (> secret-id u0) ERR-INVALID-DATA)
    (asserts! (is-eq tx-sender (get owner secret-data)) ERR-NOT-OWNER)
    (map-delete secrets { secret-id: secret-id })
    (ok true)
  )
)

;; Grant access to a secret to another user (owner only)
(define-public (grant-access (secret-id uint) (user principal))
  (let (
    (secret-data (unwrap! (map-get? secrets { secret-id: secret-id }) ERR-SECRET-NOT-FOUND))
  )
    (asserts! (> secret-id u0) ERR-INVALID-DATA)
    (asserts! (not (is-eq user tx-sender)) ERR-INVALID-DATA)
    (asserts! (is-eq tx-sender (get owner secret-data)) ERR-NOT-OWNER)
    (asserts! (not (is-secret-expired secret-data)) ERR-SECRET-EXPIRED)
    (map-set secret-access
      { secret-id: secret-id, user: user }
      { granted-at: block-height, granted-by: tx-sender }
    )
    (ok true)
  )
)

;; Revoke access to a secret from another user (owner only)
(define-public (revoke-access (secret-id uint) (user principal))
  (let (
    (secret-data (unwrap! (map-get? secrets { secret-id: secret-id }) ERR-SECRET-NOT-FOUND))
  )
    (asserts! (> secret-id u0) ERR-INVALID-DATA)
    (asserts! (not (is-eq user tx-sender)) ERR-INVALID-DATA)
    (asserts! (is-eq tx-sender (get owner secret-data)) ERR-NOT-OWNER)
    (map-delete secret-access { secret-id: secret-id, user: user })
    (ok true)
  )
)

;; Clean up expired secret (anyone can call)
(define-public (cleanup-expired-secret (secret-id uint))
  (let (
    (secret-data (unwrap! (map-get? secrets { secret-id: secret-id }) ERR-SECRET-NOT-FOUND))
  )
    (asserts! (> secret-id u0) ERR-INVALID-DATA)
    (asserts! (is-secret-expired secret-data) ERR-SECRET-EXPIRED)
    (map-delete secrets { secret-id: secret-id })
    (ok true)
  )
)

;; Read-only functions

;; Check if user owns a secret
(define-read-only (owns-secret (user principal) (secret-id uint))
  (match (map-get? secrets { secret-id: secret-id })
    secret-data (is-eq user (get owner secret-data))
    false
  )
)

;; Check if user has access to a secret (owner or granted access)
(define-read-only (has-secret-access (user principal) (secret-id uint))
  (has-access user secret-id)
)

;; Check if secret is expired
(define-read-only (is-expired (secret-id uint))
  (match (map-get? secrets { secret-id: secret-id })
    secret-data (is-secret-expired secret-data)
    false
  )
)

;; Get access info for a secret
(define-read-only (get-access-info (secret-id uint) (user principal))
  (map-get? secret-access { secret-id: secret-id, user: user })
)

;; Get user's secret count
(define-read-only (get-user-secret-count (user principal))
  (default-to u0 (map-get? user-secret-count user))
)

;; Get contract owner
(define-read-only (get-contract-owner)
  (var-get contract-owner)
)