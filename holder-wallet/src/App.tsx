import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { CredentialCard } from './components/CredentialCard';
import { IssuerControls } from './components/IssuerControls';
import { VerifierDemo } from './components/VerifierDemo';
import './App.css';

// --- Configuration ---
const VERIFIER_SERVICE_URL = 'http://localhost:3003';
const WALLET_STORAGE_KEY = 'kycWallet';
// ---------------------

function App() {
  // State for the credentials (VC-JWTs) held in the wallet
  const [credentials, setCredentials] = useState<string[]>([]);
  
  // State for the verification process
  const [isLoading, setIsLoading] = useState(false);
  const [verificationResult, setVerificationResult] = useState<any | null>(null);
  const [verificationError, setVerificationError] = useState<string | null>(null);

  // Load credentials from localStorage on app start
  useEffect(() => {
    const storedCredentials = localStorage.getItem(WALLET_STORAGE_KEY);
    if (storedCredentials) {
      setCredentials(JSON.parse(storedCredentials));
    }
  }, []);

  // Save credentials to localStorage whenever they change
  useEffect(() => {
    localStorage.setItem(WALLET_STORAGE_KEY, JSON.stringify(credentials));
  }, [credentials]);

  // Called from IssuerControls when a new VC is issued
  const handleCredentialIssued = (vcJwt: string) => {
    // Add new credential, avoiding duplicates
    if (!credentials.includes(vcJwt)) {
      setCredentials((prev) => [...prev, vcJwt]);
    }
  };

  // Called from CredentialCard when user clicks "Present"
  const handleVerifyCredential = async (vcJwt: string) => {
    setIsLoading(true);
    setVerificationResult(null);
    setVerificationError(null);

    try {
      const response = await axios.post(
        `${VERIFIER_SERVICE_URL}/verify`,
        { vcJwt }
      );
      
      // On success, show the data
      setVerificationResult(response.data.data);

    } catch (err: any) {
      console.error(err);
      // On failure, show the error
      setVerificationError(err.response?.data?.error || 'Verification request failed');
    }
    setIsLoading(false);
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>Tokenized KYC Holder Wallet</h1>
        <p>This is your wallet. Get credentials from the Issuer, then present them to the Verifier.</p>
      </header>

      <div className="App-content">
        <div className="column">
          <h2>Issuer (Port 3002)</h2>
          <IssuerControls onCredentialIssued={handleCredentialIssued} />
          
          <hr style={{margin: '24px 0'}} />

          <h2>Verifier (Port 3003)</h2>
          <VerifierDemo
            verificationResult={verificationResult}
            verificationError={verificationError}
          />
        </div>

        <div className="column">
          <h2>My Wallet Credentials</h2>
          <div className="credential-list">
            {credentials.length === 0 && (
              <p>Your wallet is empty. Get a token from the Issuer.</p>
            )}
            {credentials.map((vc) => (
              <CredentialCard
                key={vc.substring(vc.length - 20)} // Use last 20 chars as key
                vcJwt={vc}
                onVerify={handleVerifyCredential}
                isLoading={isLoading}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;