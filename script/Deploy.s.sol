// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {PomboGateFactory} from "../src/PomboGateFactory.sol";

/// Deploys the PomboGateFactory (which deploys the PomboGate implementation
/// in its constructor). One factory per network; gates are created per channel
/// by the clients via createGate.
///
/// Testnet (Polygon Amoy):
///   forge script script/Deploy.s.sol --rpc-url amoy \
///     --private-key $DEPLOYER_KEY --broadcast
contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        PomboGateFactory factory = new PomboGateFactory();
        vm.stopBroadcast();

        console.log("PomboGateFactory:", address(factory));
        console.log("PomboGate implementation:", factory.implementation());
    }
}
