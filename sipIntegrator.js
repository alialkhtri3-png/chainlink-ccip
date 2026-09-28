const { verifyTypedData, keccak256, toHex } = require('viem');

// EIP-712 Domain Definition for SIP
const sipDomain = {
  name: 'Sovereign Identity Protocol',
  version: '1',
  chainId: 84532, // Base Sepolia Chain ID
};

// EIP-712 Types for Sovereign Identity Verifiable Credential
const sipTypes = {
  VerifiableCredential: [
    { name: 'issuer', type: 'address' },
    { name: 'subject', type: 'address' },
    { name: 'claimsHash', type: 'bytes32' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' }
  ]
};

/**
 * Verify EIP-712 VC Signature within CCIP Payload
 */
async function verifySipCcipCredential(vcData, signature, expectedIssuer) {
  try {
    const valid = await verifyTypedData({
      address: expectedIssuer,
      domain: sipDomain,
      types: sipTypes,
      primaryType: 'VerifiableCredential',
      message: vcData,
      signature: signature
    });

    return {
      isValid: valid,
      issuer: expectedIssuer,
      subject: vcData.subject,
      claimsHash: vcData.claimsHash,
      proofType: 'EIP-712 TypedData'
    };
  } catch (error) {
    return {
      isValid: false,
      error: error.message
    };
  }
}

/**
 * Extract SIP Metadata embedded within CCIP ExtraData or Data Payload
 */
function parseSipPayload(dataHex) {
  if (!dataHex || dataHex === '0x' || dataHex.length < 130) {
    return null;
  }
  
  // Checking SIP Payload Magic Prefix (e.g. 0x736970 = "sip")
  const cleanHex = dataHex.startsWith('0x') ? dataHex.slice(2) : dataHex;
  const magic = cleanHex.slice(0, 6);
  
  if (magic.toLowerCase() === '736970') {
    return {
      protocol: 'SIP-V1',
      rawSipData: '0x' + cleanHex.slice(6)
    };
  }

  return null;
}

module.exports = {
  sipDomain,
  sipTypes,
  verifySipCcipCredential,
  parseSipPayload
};
