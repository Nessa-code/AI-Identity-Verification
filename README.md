# AIIdentity Verification

A privacy-preserving identity verification system built on Stacks blockchain, enabling users to prove specific attributes without revealing unnecessary personal information.

## Overview

AIIdentity Verification implements a decentralized trust model where authorized issuers can verify user attributes. Users can prove they possess certain credentials (age, education, skills) without exposing sensitive personal data.

## Features

- **Privacy-First Design**: Prove attributes without revealing underlying personal information
- **Trusted Issuer Network**: Only authorized entities can issue verifications
- **Attribute System**: Support for multiple verification types (age, education, skills, etc.)
- **Time-Limited Verifications**: Automatic expiry ensures freshness of credentials
- **Revocation Support**: Issuers can revoke verifications if needed
- **On-Chain Transparency**: All verifications are publicly auditable

## Smart Contract Functions

### Read-Only Functions

- `get-identity (user principal)`: Retrieve user's identity information
- `get-issuer (issuer principal)`: Get issuer details and statistics
- `get-verification (verification-id uint)`: View specific verification details
- `has-valid-attribute (user principal, attribute-type string)`: Check if user has valid attribute
- `is-registered (user principal)`: Check if user is registered

### Public Functions

- `register-identity ()`: Register as a new user in the system
- `register-issuer (name)`: Register as an issuer (owner only for initial setup)
- `authorize-issuer (issuer, name)`: Authorize a new issuer (owner only)
- `issue-verification (user, attribute-type)`: Issue a verification to a user
- `revoke-verification (verification-id)`: Revoke a previously issued verification
- `deactivate-identity ()`: Deactivate your identity

## Getting Started

### Prerequisites

- [Clarinet](https://github.com/hirosystems/clarinet) installed
- Stacks wallet

### Installation
```bash
git clone <repository-url>
cd ai-identity-verification
clarinet check
```

### Testing
```bash
clarinet test
clarinet console
```

## Usage Example
```clarity
;; Register as a user
(contract-call? .ai-identity register-identity)

;; Authorize an issuer (contract owner only)
(contract-call? .ai-identity authorize-issuer 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM "University")

;; Issue verification (as issuer)
(contract-call? .ai-identity issue-verification 'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5 "education")

;; Check if user has valid attribute
(contract-call? .ai-identity has-valid-attribute 'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5 "education")

;; Revoke verification (as issuer)
(contract-call? .ai-identity revoke-verification u0)
```

## Attribute Types

Common attribute types include:
- `age-over-18`: User is over 18 years old
- `age-over-21`: User is over 21 years old
- `education`: Educational credentials
- `professional-license`: Professional certifications
- `employment`: Employment verification
- `credit-score`: Credit rating tier
- `kyc-verified`: KYC compliance

## Technical Details

- **Verification Validity**: 52,560 blocks (~1 year assuming 10-minute blocks)
- **Issuer Authorization**: Only contract owner can authorize new issuers
- **Privacy Model**: Zero-knowledge proofs can be built on top of this system
- **Revocation**: Issuers can revoke their own verifications at any time

## Security Considerations

- Users must register before receiving verifications
- Only authorized issuers can issue verifications
- Verifications automatically expire after validity period
- Issuers can only revoke their own verifications
- Identity deactivation prevents new verifications

## Future Enhancements

- Integration with zero-knowledge proof systems
- Reputation scoring for issuers
- Verification cost/fee structure
- Cross-chain verification bridging
- Delegated verification checking