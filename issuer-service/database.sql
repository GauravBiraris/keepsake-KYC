-- Stores this service's own identity (its DID and keys)
-- In a real system, this would be a highly secure wallet/HSM.
CREATE TABLE issuer_identity (
    id SERIAL PRIMARY KEY,
    issuer_did VARCHAR(255) UNIQUE NOT NULL,
    -- We will store the keys as JSON Web Keys (JWK)
    private_key_jwk JSONB NOT NULL,
    public_key_jwk JSONB NOT NULL
);

-- A mock table of "verified users" this issuer has on file.
-- This simulates the bank's "source of truth" database.
CREATE TABLE mock_user_data (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(100) UNIQUE NOT NULL, -- A simple ID to find the user
    full_name VARCHAR(255) NOT NULL,
    pan_number VARCHAR(10) NOT NULL,
    dob DATE NOT NULL,
    address_street VARCHAR(255),
    address_district VARCHAR(255),
    address_state VARCHAR(255),
    address_postal_code VARCHAR(10)
);

-- Pre-populate with a test user for easy prototyping
INSERT INTO mock_user_data 
(user_id, full_name, pan_number, dob, address_street, address_district, address_state, address_postal_code)
VALUES
('user123', 'Rohan Kumar', 'ABCDE1234F', '1990-05-15', '456 Park Ave', 'Pune', 'Maharashtra', '411001');