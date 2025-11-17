import React, { useState } from 'react';
import axios from 'axios';

// --- Configuration ---
// This is the user we are simulating
const MOCK_USER_ID = 'user123'; 
const MOCK_USER_DID = 'did:example:user-rohan-xyz'; // This DID is fine as a mock
const ISSUER_SERVICE_URL = 'http://localhost:3002';
// ---------------------

interface Props {
  onCredentialIssued: (vcJwt: string) => void;
}

export const IssuerControls: React.FC<Props> = ({ onCredentialIssued }) => {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchCredential = async (type: 'pan' | 'address') => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await axios.post(
        `${ISSUER_SERVICE_URL}/issue/${type}`,
        {
          userId: MOCK_USER_ID,
          userDid: MOCK_USER_DID,
        }
      );
      
      onCredentialIssued(response.data.vcJwt);

    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.error || 'Failed to fetch credential');
    }
    setIsLoading(false);
  };

  return (
    <div className="issuer-controls">
      <button onClick={() => fetchCredential('pan')} disabled={isLoading}>
        {isLoading ? 'Issuing...' : '1. Get PAN Token'}
      </button>
      <button onClick={() => fetchCredential('address')} disabled={isLoading}>
        {isLoading ? 'Issuing...' : '2. Get Address Token'}
      </button>
      {error && <div className="verification-result error">{error}</div>}
    </div>
  );
};