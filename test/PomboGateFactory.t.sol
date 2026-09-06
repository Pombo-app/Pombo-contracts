// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {PomboGate} from "../src/PomboGate.sol";
import {PomboGateFactory} from "../src/PomboGateFactory.sol";
import {MockERC20, MockERC721} from "./mocks/Mocks.sol";

contract PomboGateFactoryTest is Test {
    PomboGateFactory factory;
    MockERC20 token20;
    MockERC721 token721;
    address creatorA = makeAddr("creatorA");
    address creatorB = makeAddr("creatorB");
    address alice = makeAddr("alice");

    function setUp() public {
        factory = new PomboGateFactory();
        token20 = new MockERC20();
        token721 = new MockERC721();
    }

    function createClosed(address creator) internal returns (address) {
        vm.prank(creator);
        return factory.createGate(PomboGate.Mode.NONE, address(0), 0, 0, 0, PomboGate.WireIdentity.VISIBLE, false);
    }

    function test_createGate_callerBecomesOwner() public {
        address gate = createClosed(creatorA);
        assertEq(PomboGate(gate).owner(), creatorA);
        assertTrue(PomboGate(gate).checkAccess(creatorA));
    }

    function test_createGate_emitsEvent() public {
        vm.recordLogs();
        address gate = createClosed(creatorA);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        // last log is GateCreated(gate, owner, mode)
        Vm.Log memory last = logs[logs.length - 1];
        assertEq(last.topics[0], keccak256("GateCreated(address,address,uint8)"));
        assertEq(address(uint160(uint256(last.topics[1]))), gate);
        assertEq(address(uint160(uint256(last.topics[2]))), creatorA);
    }

    function test_clonesHaveIsolatedState() public {
        PomboGate gateA = PomboGate(createClosed(creatorA));
        PomboGate gateB = PomboGate(createClosed(creatorB));

        vm.prank(creatorA);
        gateA.allow(alice);

        assertTrue(gateA.checkAccess(alice));
        assertFalse(gateB.checkAccess(alice));
        assertFalse(gateB.allowlist(alice));

        // creators cannot administer each other's gates
        vm.prank(creatorA);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gateB.allow(alice);
    }

    function test_createGate_invalidParamsBubbleUp() public {
        vm.prank(creatorA);
        vm.expectRevert(PomboGate.InvalidParams.selector);
        factory.createGate(PomboGate.Mode.TOKEN_BALANCE, address(0), 1, 0, 0, PomboGate.WireIdentity.VISIBLE, false);
    }

    function test_createGate_invalidTokenBubblesUp() public {
        vm.prank(creatorA);
        vm.expectRevert(PomboGate.InvalidToken.selector);
        factory.createGate(PomboGate.Mode.TOKEN_BALANCE, alice, 1, 0, 0, PomboGate.WireIdentity.VISIBLE, false);
    }

    function test_eachModeDeploys() public {
        vm.startPrank(creatorA);
        factory.createGate(PomboGate.Mode.NONE, address(0), 0, 0, 0, PomboGate.WireIdentity.VISIBLE, false);
        factory.createGate(
            PomboGate.Mode.TOKEN_BALANCE, address(token20), 1e18, 0, 0, PomboGate.WireIdentity.SEALED, false
        );
        factory.createGate(
            PomboGate.Mode.NFT_OWNERSHIP, address(token721), 0, 0, 0, PomboGate.WireIdentity.VISIBLE, true
        );
        factory.createGate(PomboGate.Mode.PAID, address(token20), 0, 1e6, 30 days, PomboGate.WireIdentity.SEALED, true);
        vm.stopPrank();
    }
}
