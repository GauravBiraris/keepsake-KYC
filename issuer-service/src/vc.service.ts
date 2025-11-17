import * as jose from 'node-jose';
import { v4 as uuidv4 } from 'uuid'; // We need UUID for jti

/**
 * Creates a signed Verifiable Credential in JWT format.
 * @param issuerDid - The 'iss' (issuer) field, e.g., "did:example:bank123"
 * @param userDid - The 'sub' (subject) field, e.g., "did:example:user-rohan-xyz"
 * @param privateKeyJwk - The issuer's private key as a JWK object
 * @param credentialSubject - The JSON object for the schema (e.g., PanVerification)
 * @param credentialType - The 'type' of the credential (e.g., "PanVerificationCredential")
 * @returns {Promise<string>} - The signed VC-JWT as a compact string
 */
export const createSignedVcJwt = async (
  issuerDid: string,
  userDid: string,
  privateKeyJwk: any,
  credentialSubject: object,
  credentialType: string
): Promise<string> => {
  try {
    // 1. Load the private key into the keystore
    const key = await jose.JWK.asKey(privateKeyJwk);

    // 2. Define the VC Payload (following the schema we defined)
    const now = Math.floor(Date.now() / 1000);
    const oneYear = 365 * 24 * 60 * 60;
    
    const payload = {
      iss: issuerDid, // Issuer's DID
      sub: userDid,   // User's DID
      nbf: now,       // Not Before
      iat: now,       // Issued At
      exp: now + oneYear, // Expiration (e.g., 1 year)
      jti: `urn:uuid:${uuidv4()}`, // Unique Credential ID (for revocation)
      
      vc: {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://example.com/schemas/kyc/v1" // Our custom schema context
        ],
        type: ["VerifiableCredential", credentialType],
        issuer: issuerDid,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: userDid,
          ...credentialSubject,
        },
      },
    };

    // 3. Define the JWT header (Removed manual header)

    // 4. Create and sign the JWT
    // We let the 'key' object provide the 'alg' and 'kid'
    // We only need to specify the 'typ' (type) field.
    const tokenResult = await jose.JWS.createSign({ format: 'compact', fields: { typ: 'vc+jwt' } }, key)
      .update(JSON.stringify(payload))
      .final();
    
    // --- THIS IS THE DEBUGGING STEP ---
    // We will log this object to the Render console to see its structure.
    console.log("--- DEBUG: Full 'tokenResult' from node-jose ---");
    console.log(tokenResult);
    console.log("-------------------------------------------------");
    // --- END DEBUGGING STEP ---

    // The demo will still fail, but the log will tell us the fix.
    // We are now explicitly returning the object property we *think* is right.
    // If this fails, the log above will tell us the *correct* property.
    return (tokenResult as any).jws as string;

  } catch (error) {
    console.error("Error creating signed VC:", error);
    throw new Error("VC signing failed");
  }
};
