;; AIIdentity Verification - Privacy-preserving identity verification system

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u200))
(define-constant err-not-registered (err u201))
(define-constant err-already-registered (err u202))
(define-constant err-not-authorized (err u203))
(define-constant err-invalid-issuer (err u204))
(define-constant err-verification-expired (err u205))
(define-constant err-attribute-not-found (err u206))

;; Verification validity period in blocks
(define-constant verification-validity u52560)

;; Data Variables
(define-data-var next-verification-id uint u0)

;; Data Maps
(define-map identities
  { user: principal }
  {
    registered-block: uint,
    active: bool,
    verification-count: uint
  }
)

(define-map issuers
  { issuer: principal }
  {
    name: (string-ascii 50),
    active: bool,
    verifications-issued: uint
  }
)

(define-map verifications
  { verification-id: uint }
  {
    user: principal,
    issuer: principal,
    attribute-type: (string-ascii 30),
    issued-block: uint,
    expiry-block: uint,
    valid: bool
  }
)

(define-map user-verifications
  { user: principal, attribute-type: (string-ascii 30) }
  {
    verification-id: uint,
    issuer: principal
  }
)

;; Read-only functions
(define-read-only (get-identity (user principal))
  (map-get? identities { user: user })
)

(define-read-only (get-issuer (issuer principal))
  (map-get? issuers { issuer: issuer })
)

(define-read-only (get-verification (verification-id uint))
  (map-get? verifications { verification-id: verification-id })
)

(define-public (has-valid-attribute (user principal) (attribute-type (string-ascii 30)))
  (match (map-get? user-verifications { user: user, attribute-type: attribute-type })
    verification-ref
      (match (get-verification (get verification-id verification-ref))
        verification-data
          (ok (and 
            (get valid verification-data)
            (< stacks-block-height (get expiry-block verification-data))
          ))
        (ok false)
      )
    (ok false)
  )
)

(define-read-only (is-registered (user principal))
  (match (get-identity user)
    identity-data (ok (get active identity-data))
    (ok false)
  )
)

(define-read-only (get-user-verification-count (user principal))
  (match (get-identity user)
    identity-data (ok (get verification-count identity-data))
    err-not-registered
  )
)

(define-read-only (get-issuer-verification-count (issuer principal))
  (match (get-issuer issuer)
    issuer-data (ok (get verifications-issued issuer-data))
    err-invalid-issuer
  )
)

(define-public (is-verification-expired (verification-id uint))
  (match (get-verification verification-id)
    verification-data 
      (ok (>= stacks-block-height (get expiry-block verification-data)))
    err-attribute-not-found
  )
)