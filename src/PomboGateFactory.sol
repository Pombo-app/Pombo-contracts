// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {PomboGate} from "./PomboGate.sol";

/// @title PomboGateFactory — deploys one EIP-1167 PomboGate clone per channel
///
/// ERC-1271 gives the contract only (hash, signature) — it cannot know which
/// channel it is validating for, so every channel needs its own clone.
/// The caller becomes the gate owner and the clone address becomes the
/// channel's Streamr publisher id.
contract PomboGateFactory {
    address public immutable implementation;

    event GateCreated(address indexed gate, address indexed owner, PomboGate.Mode mode);

    constructor() {
        implementation = address(new PomboGate());
    }

    function createGate(PomboGate.Mode mode, address token, uint256 minBalance, uint256 price, uint64 duration)
        external
        returns (address gate)
    {
        gate = Clones.clone(implementation);
        PomboGate(gate).initialize(msg.sender, mode, token, minBalance, price, duration);
        emit GateCreated(gate, msg.sender, mode);
    }
}
