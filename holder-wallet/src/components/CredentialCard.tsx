import React from 'react';

// This is an interface for the *decoded* payload of our VC-JWTs
interface DecodedVC {
  jti: string;
  vc: {
    type: string[];
    credentialSubject: any;
  };
}

// Helper function to decode the JWT payload
// This is for display only and does not verify the signature
const decodeJwt = (token: string): DecodedVC | null => {
  try {
    const payloadBase64 = token.split('.')[1];
    const decodedJson = atob(payloadBase64);
    return JSON.parse(decodedJson) as DecodedVC;
  } catch (e) {
    console.error('Failed to decode JWT', e);
    return null;
  }
};

interface Props {
  vcJwt: string;
  onVerify: (token: string) => void;
  isLoading: boolean;
}

export const CredentialCard: React.FC<Props> = ({ vcJwt, onVerify, isLoading }) => {
  const decoded = decodeJwt(vcJwt);

  if (!decoded) {
    return <div className="credential-card">Error: Invalid Credential</div>;
  }

  // Get the name of the credential (e.g., "PanVerificationCredential")
  const vcType = decoded.vc.type[1] || 'VerifiableCredential';
  // Get the main data from the credential
  const subject = decoded.vc.credentialSubject;

  return (
    <div className="credential-card">
      <h4>{vcType}</h4>
      {/* Show different data based on the type */}
      {vcType === 'PanVerificationCredential' && (
        <>
          <p>PAN: {subject.pan}</p>
          <p>Name: {subject.nameAsPerPan}</p>
        </>
      )}
      {vcType === 'AddressVerificationCredential' && (
        <>
          <p>District: {subject.address.district}</p>
          <p>State: {subject.address.state}</p>
        </>
      )}
      <p>
        <small>JTI (Serial): {decoded.jti.substring(0, 20)}...</small>
      </p>
      <button onClick={() => onVerify(vcJwt)} disabled={isLoading}>
        {isLoading ? 'Verifying...' : 'Present for Verification'}
      </button>
    </div>
  );
};