import express, { Request, Response } from 'express';
import * as dotenv from 'dotenv';
import cors from 'cors';
import db from './db';

// Load environment variables
dotenv.config();

const app = express();
// Use port from .env or default to 3001
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());        // Enable Cross-Origin Resource Sharing
app.use(express.json()); // Parse JSON request bodies

// --- API ENDPOINTS ---

/**
 * [ADMIN] POST /issuers
 * Registers a new trusted issuer.
 * In a real system, this would be heavily protected.
 * Body: { "issuer_did": "did:example:123", "public_key": "---BEGIN PUBLIC KEY---..." }
 */
app.post('/issuers', async (req: Request, res: Response) => {
  const { issuer_did, public_key } = req.body;

  if (!issuer_did || !public_key) {
    return res.status(400).json({ error: 'issuer_did and public_key are required' });
  }

  try {
    const query = 'INSERT INTO issuers (issuer_did, public_key) VALUES ($1, $2) RETURNING *';
    const values = [issuer_did, public_key];
    const result = await db.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Failed to register issuer', details: err.message });
  }
});

/**
 * [VERIFIER] GET /issuers/:did
 * Gets the public key for a given Issuer DID.
 * The Verifier Service will call this to verify a credential's signature.
 */
app.get('/issuers/:did(*)', async (req: Request, res: Response) => {
  try {
    const { did } = req.params;
    const query = 'SELECT public_key FROM issuers WHERE issuer_did = $1';
    const values = [did];
    
    const result = await db.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Issuer not found or not trusted' });
    }
    
    res.status(200).json(result.rows[0]);
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

/**
 * [ISSUER] POST /revoke
 * Revokes a credential by adding its JTI (serial number) to the list.
 * Body: { "jti": "urn:uuid:12345-67890" }
 */
app.post('/revoke', async (req: Request, res: Response) => {
  const { jti } = req.body;

  if (!jti) {
    return res.status(400).json({ error: 'jti is required' });
  }

  try {
    const query = 'INSERT INTO revocation_list (jti) VALUES ($1) RETURNING *';
    const values = [jti];
    const result = await db.query(query, values);
    res.status(201).json({ message: 'Credential revoked', ...result.rows[0] });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Failed to revoke credential', details: err.message });
  }
});

/**
 * [VERIFIER] GET /is_revoked/:jti
 * Checks if a credential JTI (serial number) is in the revocation list.
 * The Verifier Service will call this for every transaction.
 */
app.get('/is_revoked/:jti(*)', async (req: Request, res: Response) => {
  try {
    const { jti } = req.params;
    const query = 'SELECT 1 FROM revocation_list WHERE jti = $1';
    const values = [jti];

    const result = await db.query(query, values);

    if (result.rows.length > 0) {
      res.status(200).json({ is_revoked: true });
    } else {
      res.status(200).json({ is_revoked: false });
    }
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// --- Server Start ---
app.listen(PORT, () => {
  console.log(`Mock Trust Layer server running on http://localhost:${PORT}`);
});