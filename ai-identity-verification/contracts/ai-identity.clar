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

;; Public functions
(define-public (register-identity)
  (let
    (
      (existing (get-identity tx-sender))
    )
    (asserts! (is-none existing) err-already-registered)
    (map-set identities
      { user: tx-sender }
      {
        registered-block: stacks-block-height,
        active: true,
        verification-count: u0
      }
    )
    (ok true)
  )
)

;; #[allow(unchecked_data)]
(define-public (register-issuer (name (string-ascii 50)))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (map-set issuers
      { issuer: tx-sender }
      {
        name: name,
        active: true,
        verifications-issued: u0
      }
    )
    (ok true)
  )
)

;; #[allow(unchecked_data)]
(define-public (authorize-issuer (issuer principal) (name (string-ascii 50)))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (map-set issuers
      { issuer: issuer }
      {
        name: name,
        active: true,
        verifications-issued: u0
      }
    )
    (ok true)
  )
)

;; #[allow(unchecked_data)]
(define-public (issue-verification (user principal) (attribute-type (string-ascii 30)))
  (let
    (
      (verification-id (var-get next-verification-id))
      (issuer-info (unwrap! (get-issuer tx-sender) err-invalid-issuer))
      (user-identity (unwrap! (get-identity user) err-not-registered))
    )
    (asserts! (get active issuer-info) err-not-authorized)
    (asserts! (get active user-identity) err-not-registered)
    
    (map-set verifications
      { verification-id: verification-id }
      {
        user: user,
        issuer: tx-sender,
        attribute-type: attribute-type,
        issued-block: stacks-block-height,
        expiry-block: (+ stacks-block-height verification-validity),
        valid: true
      }
    )
    
    (map-set user-verifications
      { user: user, attribute-type: attribute-type }
      {
        verification-id: verification-id,
        issuer: tx-sender
      }
    )
    
    (map-set issuers
      { issuer: tx-sender }
      (merge issuer-info { verifications-issued: (+ (get verifications-issued issuer-info) u1) })
    )
    
    (map-set identities
      { user: user }
      (merge user-identity { verification-count: (+ (get verification-count user-identity) u1) })
    )
    
    (var-set next-verification-id (+ verification-id u1))
    (ok verification-id)
  )
)