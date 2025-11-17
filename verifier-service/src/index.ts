import express, { Request, Response } from 'express';
import * as dotenv from 'dotenv';
import cors from 'cors';
import { verifyVcJwt } from './verification.service';

// --- Setup ---
dotenv.config();
const app = express();
const PORT = process.env.PORT || 3003;

// --- Middleware ---
app.use(cors());
app.use(express.json());

// --- API ENDPOINTS ---

/**
 * [PUBLIC] POST /verify
 * Receives a VC-JWT, verifies it, and returns the trusted data.
 * This is the main endpoint for any relying party.
 * Body: { "vcJwt": "eyJhbGciOi..." }
 */
app.post('/verify', async (req: Request, res: Response) => {
  const { vcJwt } = req.body;

  if (!vcJwt) {
    return res.status(400).json({ 
      status: 'VERIFICATION_FAILED', 
      error: 'Missing vcJwt in request body' 
    });
  }

  // Call our verification service
  const result = await verifyVcJwt(vcJwt);

  if (!result.isValid) {
    return res.status(400).json({
      status: 'VERIFICATION_FAILED',
      error: result.error || 'Unknown verification error',
    });
  }

  // --- SUCCESS ---
  // The token is valid. We return the *actual credential* part,
  // which is what the Verifier's application really cares about.
  res.status(200).json({
    status: 'VERIFIED',
    data: result.payload.vc, // Return the "vc" object from the payload
  });
});

// --- Server Start ---
app.listen(PORT, () => {
  console.log(`Verifier Service running on http://localhost:${PORT}`);
});