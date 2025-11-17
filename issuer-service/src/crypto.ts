import * as jose from 'node-jose';

/**
 * Generates a new P-256 Elliptic Curve key pair.
 * @returns {Promise<{privateKeyJwk: object, publicKeyJwk: object}>}
 */
export const generateEcKeyPair = async () => {
  const keystore = jose.JWK.createKeyStore();
  const key = await keystore.generate('EC', 'P-256', {
    alg: 'ES256',
    use: 'sig',
  });

  // Export as public and private JWKs
  // We use .toJSON(true) for the private key
  const privateKeyJwk = key.toJSON(true);
  const publicKeyJwk = key.toJSON(false);

  return { privateKeyJwk, publicKeyJwk };
};