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