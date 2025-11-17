import React from 'react';

interface Props {
  verificationResult: any;
  verificationError: string | null;
}

export const VerifierDemo: React.FC<Props> = ({
  verificationResult,
  verificationError,
}) => {
  return (
    <div className="verifier-demo">
      <p>
        When you click "Present for Verification" on a card, this area will show
        the result from the Verifier Service (Port 3003).
      </p>

      {/* Show Error Message */}
      {verificationError && (
        <div className="verification-result error">
          <h4>Verification Failed</h4>
          <pre>{verificationError}</pre>
        </div>
      )}

      {/* Show Success Message */}
      {verificationResult && (
        <div className="verification-result success">
          <h4>Verification Success!</h4>
          <p>The Verifier received the following trusted data:</p>
          <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {JSON.stringify(verificationResult, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};