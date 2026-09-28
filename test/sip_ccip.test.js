import { describe, it, expect } from 'vitest';
import { verifySipCcipCredential, sipDomain, sipTypes } from '../sipIntegrator';
import { privateKeyToAccount } from 'viem/accounts';

describe('SIP EIP-712 & CCIP Integration Tests', () => {
  it('Should successfully verify EIP-712 VC signed by SIP Issuer', async () => {
    const account = privateKeyToAccount('0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
    
    const vcMessage = {
      issuer: account.address,
      subject: '0x2222222222222222222222222222222222222222',
      claimsHash: '0x1111111111111111111111111111111111111111111111111111111111111111',
      nonce: 1n,
      deadline: 9999999999n
    };

    const signature = await account.signTypedData({
      domain: sipDomain,
      types: sipTypes,
      primaryType: 'VerifiableCredential',
      message: vcMessage
    });

    const result = await verifySipCcipCredential(vcMessage, signature, account.address);
    
    expect(result.isValid).toBe(true);
    expect(result.issuer).toBe(account.address);
    expect(result.proofType).toBe('EIP-712 TypedData');
  });
});
