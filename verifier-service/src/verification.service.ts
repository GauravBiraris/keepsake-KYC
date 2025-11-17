import axios from 'axios';
import * as jose from 'node-jose';
import * as dotenv from 'dotenv';

dotenv.config();

const MOCK_TRUST_LAYER_URL = process.env.MOCK_TRUST_LAYER_URL;

interface VerificationResult {
  isValid: boolean;
  payload?: any;
  error?: string;
}

/**
 * Verifies a VC-JWT.
 * This is the core logic: checks signature, revocation, and trust.
 * @param token The compact VC-JWT string
 * @returns {Promise<VerificationResult>}
 */
export const verifyVcJwt = async (token: string): Promise<VerificationResult> => {
  try {
    // --- Step 1: Decode the token (unprotected) to get 'iss' and 'jti' ---
    // A JWT is in three parts: [header].[payload].[signature]
    const payloadB64 = token.split('.')[1];
    if (!payloadB64) {
      throw new Error('Invalid JWT format');
    }
    
    // This payload is NOT trusted yet. We only use it to find out
    // *who* the issuer is and *what* the token's serial number is.
    const unprotectedPayload = JSON.parse(
      Buffer.from(payloadB64, 'base64').toString('utf-8')
    );

    const issuerDid: string = unprotectedPayload.iss;
    const jti: string = unprotectedPayload.jti;

    if (!issuerDid || !jti) {
      throw new Error('Token is missing required "iss" or "jti" claims');
    }
    
    // --- Step 2: Check Revocation (Fail-Fast) ---
    // We check this *before* the expensive crypto verification.
    try {
      // FIX: Manually URL-encode the JTI to handle special chars like ':'
      const encodedJti = encodeURIComponent(jti);
      
      const revocationRes = await axios.get(
        `${MOCK_TRUST_LAYER_URL}/is_revoked/${encodedJti}` // <-- NOW FIXED
      );
      if (revocationRes.data.is_revoked === true) {
        throw new Error('Credential has been revoked');
      }
    } catch (err: any) {
      console.error('Revocation check failed:', err.message);
      throw new Error('Revocation check failed');
    }

    // --- Step 3: Fetch the Issuer's Public Key from the Trust Layer ---
    let publicKeyJwk: any;
    try {
      const issuerRes = await axios.get(
        `${MOCK_TRUST_LAYER_URL}/issuers/${issuerDid}`
      );
      // The public key is stored as a JSON string in our mock DB
      publicKeyJwk = JSON.parse(issuerRes.data.public_key);
    } catch (err: any) {
      if (err.response && err.response.status === 404) {
        throw new Error(`Issuer ${issuerDid} is not trusted`);
      }
      console.error('Issuer key fetch failed:', err.message);
      throw new Error('Could not fetch issuer public key');
    }

    // --- Step 4: Cryptographically Verify the Signature ---
    const key = await jose.JWK.asKey(publicKeyJwk);
    
    // This performs the actual signature verification
const verificationResult = await jose.JWS.createVerify(key)
  .verify(token);

    // If we are here, the signature is valid.
    const verifiedPayload = JSON.parse(verificationResult.payload.toString());

    // --- Step 5: Final Sanity Check (e.g., Expiry) ---
    const now = Math.floor(Date.now() / 1000);
    if (verifiedPayload.exp && verifiedPayload.exp < now) {
      throw new Error('Token is expired');
    }

    // --- Success! ---
    return {
      isValid: true,
      payload: verifiedPayload,
    };

  } catch (err: any) {
    console.error('Verification failed:', err.message);
    return {
      isValid: false,
      error: err.message,
    };
  }
};