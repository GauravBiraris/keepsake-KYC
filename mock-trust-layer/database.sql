-- This table stores the DIDs and public keys of trusted issuers
-- The Verifier service will query this to verify a credential's signature.
CREATE TABLE issuers (
    id SERIAL PRIMARY KEY,
    issuer_did VARCHAR(255) UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- This table stores the serial numbers (jti) of credentials that have been revoked.
-- The Verifier service will query this to ensure a credential is still valid.
CREATE TABLE revocation_list (
    id SERIAL PRIMARY KEY,
    jti VARCHAR(255) UNIQUE NOT NULL, -- jti (JWT ID) is the credential serial number
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);