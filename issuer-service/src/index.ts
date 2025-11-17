import express, { Request, Response } from 'express';
import * as dotenv from 'dotenv';
import cors from 'cors';
import axios from 'axios';
import db from './db';
import { generateEcKeyPair } from './crypto';
import { createSignedVcJwt } from './vc.service';

// --- Setup ---
dotenv.config();
const app = express();
const PORT = process.env.PORT || 3002;
const MOCK_TRUST_LAYER_URL = process.env.MOCK_TRUST_LAYER_URL;

// --- Middleware ---
app.use(cors());
app.use(express.json());

// --- API ENDPOINTS ---

/**
 * [ADMIN] POST /register-issuer
 * One-time setup. Generates this service's keys, saves them to its
 * local DB, and registers its public key with the Mock Trust Layer.
 */
app.post('/register-issuer', async (req: Request, res: Response) => {
  try {
    // 1. Check if already registered
    const existing = await db.query('SELECT * FROM issuer_identity', []);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Issuer is already registered.' });
    }

    // 2. Generate new keys
    const { privateKeyJwk, publicKeyJwk } = await generateEcKeyPair();
    const issuerDid = `did:example:issuer-${Date.now()}`;

    // 3. Register with the Mock Trust Layer
    await axios.post(`${MOCK_TRUST_LAYER_URL}/issuers`, {
      issuer_did: issuerDid,
      public_key: JSON.stringify(publicKeyJwk), // Send public key as a string
    });
    
    // 4. Save *both* keys to our local DB
    await db.query(
      'INSERT INTO issuer_identity (issuer_did, private_key_jwk, public_key_jwk) VALUES ($1, $2, $3)',
      [issuerDid, privateKeyJwk, publicKeyJwk]
    );

    res.status(201).json({ 
      message: 'Issuer registered successfully!', 
      issuerDid: issuerDid 
    });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Issuer registration failed', details: err.message });
  }
});


/**
 * [USER] POST /issue/pan
 * Issues a PAN Verification Credential (Schema 2)
 * Body: { "userId": "user103", "userDid": "did:example:user-rohan-xyz" }
 */
app.post('/issue/pan', async (req: Request, res: Response) => {
  const { userId, userDid } = req.body;
  if (!userId || !userDid) {
    return res.status(400).json({ error: 'userId and userDid are required' });
  }

  try {
    // 1. Get this issuer's identity
    const issuerRow = await db.query('SELECT * FROM issuer_identity LIMIT 1', []);
    if (issuerRow.rows.length === 0) {
      return res.status(500).json({ error: 'Issuer not registered. Run POST /register-issuer first.' });
    }
    const issuer = issuerRow.rows[0];

    // 2. Get the "source of truth" data for this user
    const userRow = await db.query('SELECT * FROM mock_user_data WHERE user_id = $1', [userId]);
    if (userRow.rows.length === 0) {
      return res.status(404).json({ error: 'User not found in issuer database.' });
    }
    const userData = userRow.rows[0];

    // 3. Build the Credential Subject (Schema 2)
    const credentialSubject = {
      type: "PanVerification",
      pan: userData.pan_number,
      nameAsPerPan: userData.full_name,
      verificationSource: "InternalBankDB-NSDL-Simulated"
    };

    // 4. Create and sign the token
    const token = await createSignedVcJwt(
      issuer.issuer_did,
      userDid,
      issuer.private_key_jwk,
      credentialSubject,
      "PanVerificationCredential"
    );

    res.status(200).json({ vcJwt: token });

  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Failed to issue credential', details: err.message });
  }
});

/**
 * [USER] POST /issue/address
 * Issues an Address Verification Credential (Schema 4, with 'district')
 * Body: { "userId": "user103", "userDid": "did:example:user-rohan-xyz" }
 */
app.post('/issue/address', async (req: Request, res: Response) => {
  const { userId, userDid } = req.body;
  if (!userId || !userDid) {
    return res.status(400).json({ error: 'userId and userDid are required' });
  }

  try {
    // 1. Get this issuer's identity
    const issuerRow = await db.query('SELECT * FROM issuer_identity LIMIT 1', []);
    if (issuerRow.rows.length === 0) {
      return res.status(500).json({ error: 'Issuer not registered. Run POST /register-issuer first.' });
    }
    const issuer = issuerRow.rows[0];

    // 2. Get the "source of truth" data
    const userRow = await db.query('SELECT * FROM mock_user_data WHERE user_id = $1', [userId]);
    if (userRow.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }
    const userData = userRow.rows[0];
    
    // 3. Build the Credential Subject (Schema 4 - updated)
    const credentialSubject = {
      type: "AddressVerification",
      address: {
        street: userData.address_street,
        district: userData.address_district,
        state: userData.address_state,
        postalCode: userData.address_postal_code
      },
      verificationMethod: "Bank-Internal-Record",
      verificationDate: new Date().toISOString().split('T')[0] // YYYY-MM-DD
    };

    // 4. Create and sign the token
    const token = await createSignedVcJwt(
      issuer.issuer_did,
      userDid,
      issuer.private_key_jwk,
      credentialSubject,
      "AddressVerificationCredential"
    );

    res.status(200).json({ vcJwt: token });

  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Failed to issue credential', details: err.message });
  }
});


// --- Server Start ---
app.listen(PORT, () => {
  console.log(`Issuer Service running on http://localhost:${PORT}`);
});