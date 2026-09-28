import { describe, it, expect } from 'vitest';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { decodeCcipPayload } = require('./decode.js');

describe('CCIP Payload Decoder - Edge Cases & Core Auditing Tests', () => {
  it('1. Should correctly decode Standard CCIP Any2EVM Token Transfer Payload', () => {
    const payload = "0x87907a1b065e3496c2bb0b32a0dbfe1ade9dca33e15b6a07a003d9c6500a0861181e253d8f94a1b700b46c4101c8dd807e521983563c5d17a90f6673d3da04c60000000000000000000000004d61b82eab6477c7b29e4190af5c906b923ef3ad0000000000000000000000000097bc49e4c33eae61d5b3b661da92f1f9e2af21000000000000000000000000000000000000021e19e0c9bab2400000";
    const res = decodeCcipPayload(payload);
    expect(res.type).toBe('StandardTokenTransfer');
    expect(res.decoded.rawAmountWei).toBe('10000000000000000000000');
  });

  it('2. Should handle truncated uint256 padding without Byte Shift', () => {
    const payload = "0x87907a1b065e3496c2bb0b32a0dbfe1ade9dca33e15b6a07a003d9c6500a0861181e253d8f94a1b700b46c4101c8dd807e521983563c5d17a90f6673d3da04c60000000000000000000000004d61b82eab6477c7b29e4190af5c906b923ef3ad0000000000000000000000000097bc49e4c33eae61d5b3b661da92f1f9e2af21021e19e0c9bab2400000";
    const res = decodeCcipPayload(payload);
    expect(res.type).toBe('StandardTokenTransfer');
  });

  it('3. Should auto-detect EVMExtraArgsV1 header (0x97a657c9)', () => {
    const payload = "0x97a657c90000000000000000000000000000000000000000000000000000000000030d40";
    const res = decodeCcipPayload(payload);
    expect(res.type).toBe('EVMExtraArgsV1');
    expect(res.decoded.gasLimit).toBe('200000');
  });

  it('4. Should auto-detect EVMExtraArgsV2 header (0x181dcf10) and unpack bool', () => {
    const payload = "0x181dcf100000000000000000000000000000000000000000000000000000000000030d400000000000000000000000000000000000000000000000000000000000000001";
    const res = decodeCcipPayload(payload);
    expect(res.type).toBe('EVMExtraArgsV2');
    expect(res.decoded.allowOutOfOrderExecution).toBe(true);
  });

  it('5. Should support Explicit Custom ABI mode', () => {
    const payload = "0x0000000000000000000000000000000000000000000000000000000000030d40";
    const res = decodeCcipPayload(payload, "uint256");
    expect(res.type).toBe('CustomABI');
    expect(res.decoded.slot_0_uint256).toBe('200000');
  });

  it('6. Should throw Error on Invalid Hex Character', () => {
    expect(() => decodeCcipPayload("0xZZZZ1234")).toThrow("Invalid Hex string provided.");
  });

  it('7. Should throw Error on missing input', () => {
    expect(() => decodeCcipPayload("")).toThrow("Missing input payload");
  });
});
