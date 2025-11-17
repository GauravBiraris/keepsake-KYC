import express, { Request, Response } from 'express';
import * as dotenv from 'dotenv';
import cors from 'cors';
import axios from 'axios';
import chalk from 'chalk'; // We need to import chalk
import db from './db';
import { generateEcKeyPair } from './crypto';
import { createSignedVcJwt } from './vc.service';

// --- Setup ---
dotenv.config(); // Load .env file
const app = express();
const PORT = process.env.PORT || 3002;

// --- ENVIRONMENT VARIABLE CHECK ---
console.log(chalk.blue("--- Issuer Service Starting ---"));
const MOCK_TRUST_LAYER_URL = process.env.MOCK_TRUST_LAYER_URL;
const DATABASE_URL = process.env.DATABASE_URL;

if (!MOCK_TRUST_LAYER_URL) {
  console.error(chalk.red.bold("FATAL ERROR: MOCK_TRUST_LAYER_URL is not defined."));
  console.error("Please check this in the Render Environment tab.");
} else {
  console.log(chalk.green(`MOCK_TRUST_LAYER_URL: ${MOCK_TRUST_LAYER_URL}`));
}

if (!DATABASE_URL) {
  console.error(chalk.red.bold("FATAL ERROR: DATABASE_URL is not defined."));
  console.error("Please check this in the Render Environment tab.");
} else {
  // Don't log the full password
  console.log(chalk.green(`DATABASE_URL: ${DATABASE_URL.substring(0, 30)}...`));
}
// --- END CHECK ---

// --- Middleware ---
app.use(cors());
app.use(express.json());

// --- Health Check Endpoint ---
app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// --- API ENDPOINTS ---

/**
 * [ADMIN] POST /register-issuer
 */
app.post('/register-issuer', async (req: Request, res: Response) => {
  try {
    if (!MOCK_TRUST_LAYER_URL) {
      throw new Error("Service is misconfigured: MOCK_TRUST_LAYER_URL is not set.");
    }
    const existing = await db.query('SELECT * FROM issuer_identity', []);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Issuer is already registered.' });
    }
    const { privateKeyJwk, publicKeyJwk } = await generateEcKeyPair();
    const issuerDid = `did:example:issuer-${Date.now()}`;
    
    await axios.post(`${MOCK_TRUST_LAYER_URL}/issuers`, {
      issuer_did: issuerDid,
      public_key: JSON.stringify(publicKeyJwk), 
    });
    
    await db.query(
      'INSERT INTO issuer_identity (issuer_did, private_key_jwk, public_key_jwk) VALUES ($1, $2, $3)',
      [issuerDid, privateKeyJwk, publicKeyJwk]
    );

    res.status(201).json({ 
      message: 'Issuer registered successfully!', 
      issuerDid: issuerDid 
    });
  } catch (err: any) {
    console.error(err.message); 
    res.status(500).json({ error: 'Issuer registration failed', details: err.message });
  }
});


/**
 * [USER] POST /issue/pan
 */
app.post('/issue/pan', async (req: Request, res: Response) => {
  const { userId, userDid } = req.body;
  if (!userId || !userDid) {
    return res.status(400).json({ error: 'userId and userDid are required' });
  }

  try {
    const issuerRow = await db.query('SELECT * FROM issuer_identity LIMIT 1', []);
    if (issuerRow.rows.length === 0) {
      return res.status(500).json({ error: 'Issuer not registered. Run POST /register-issuer first.' });
    }
    const issuer = issuerRow.rows[0];

    const userRow = await db.query('SELECT * FROM mock_user_data WHERE user_id = $1', [userId]);
    if (userRow.rows.length === 0) {
      return res.status(404).json({ error: 'User not found in issuer database.' });
    }
    const userData = userRow.rows[0];

    const credentialSubject = {
      type: "PanVerification",
      pan: userData.pan_number,
      nameAsPerPan: userData.full_name,
      verificationSource: "InternalBankDB-NSDL-Simulated"
    };

    const token = await createSignedVcJwt(
      issuer.issuer_did,
      userDid,
      issuer.private_key_jwk,
      credentialSubject,
      "PanVerificationCredential"
    );

    res.status(200).json({ vcJwt: token });

  } catch (err: any)
  {
    console.error(err.message); 
    res.status(500).json({ error: 'Failed to issue credential', details: err.message });
  }
});

/**
 * [USER] POST /issue/address
 */
app.post('/issue/address', async (req: Request, res: Response) => {
  const { userId, userDid } = req.body;
  if (!userId || !userDid) {
    return res.status(400).json({ error: 'userId and userDid are required' });
  }

  try {
    const issuerRow = await db.query('SELECT * FROM issuer_identity LIMIT 1', []);
    if (issuerRow.rows.length === 0) {
      return res.status(500).json({ error: 'Issuer not registered. Run POST /register-issuer first.' });
    }
    const issuer = issuerRow.rows[0];

    const userRow = await db.query('SELECT * FROM mock_user_data WHERE user_id = $1', [userId]);
    if (userRow.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }
    const userData = userRow.rows[0];
    
    const credentialSubject = {
      type: "AddressVerification",
      address: {
        street: userData.address_street,
        district: userData.address_district,
        state: userData.address_state,
        postalCode: userData.address_postal_code
      },
      verificationMethod: "Bank-Internal-Record",
      verificationDate: new Date().toISOString().split('T')[0] 
    };

    const token = await createSignedVcJwt(
      issuer.issuer_did,
      userDid,
      issuer.private_key_jwk,
      credentialSubject,
      "AddressVerificationCredential"
    );
    
    res.status(200).json({ vcJwt: token });

  } catch (err: any) {
    console.error(err.message); 
    res.status(500).json({ error: 'Failed to issue credential', details: err.message });
  }
});


// --- Server Start Function ---
const startServer = async () => {
  // Test DB connection on startup
  try {
    // This query will wake up a sleeping Neon DB
    console.log(chalk.yellow("Attempting database connection..."));
    const result = await db.query('SELECT NOW()', []);
    console.log(chalk.green(`Database connected successfully at ${result.rows[0].now}`));
  } catch (err: any) {
    console.error(chalk.red.bold('FATAL ERROR: Database connection failed.'));
    console.error(chalk.red(err.message));
    process.exit(1); // Exit the process
  }

  app.listen(PORT, () => {
    // Render requires listening on 0.0.0.0, which app.listen does by default.
    console.log(chalk.green.bold(`Issuer Service is now listening on port ${PORT}`));
  });
};

// Check for required variables before starting
if (DATABASE_URL && MOCK_TRUST_LAYER_URL) {
  startServer();
} else {
  console.error(chalk.red.bold("Exiting due to missing environment variables."));
  process.exit(1); // Exit the process
}
