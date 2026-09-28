pragma solidity ^0.8.0;

import {MessageV1Codec} from "../chains/evm/contracts/libraries/MessageV1Codec.sol";
import {FinalityCodec} from "../chains/evm/contracts/libraries/FinalityCodec.sol";

contract MessageIdProbeScript {
  uint64 constant SOURCE_CHAIN_SELECTOR = 1;
  uint64 constant DEST_CHAIN_SELECTOR = 2;

  function run() external pure returns (bytes32 id, bytes memory encoded) {
    MessageV1Codec.MessageV1 memory message = MessageV1Codec.MessageV1({
      sourceChainSelector: SOURCE_CHAIN_SELECTOR,
      destChainSelector: DEST_CHAIN_SELECTOR,
      messageNumber: 1,
      executionGasLimit: 400_000,
      ccipReceiveGasLimit: 200_000,
      finality: FinalityCodec._encodeBlockDepth(100),
      ccvAndExecutorHash: bytes32(0),
      onRampAddress: abi.encode(address(0x1111111111111111111111111111111111111111)),
      offRampAddress: abi.encodePacked(address(0x2222222222222222222222222222222222222222)),
      sender: abi.encode(address(0x3333333333333333333333333333333333333333)),
      receiver: abi.encodePacked(address(0x4444444444444444444444444444444444444444)),
      destBlob: "",
      tokenTransfer: new MessageV1Codec.TokenTransferV1[](0),
      data: ""
    });

    encoded = MessageV1Codec._encodeMessageV1(message);
    id = keccak256(encoded);
  }
}
