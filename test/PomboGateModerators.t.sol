// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PomboGate} from "../src/PomboGate.sol";
import {PomboGateTestBase} from "./PomboGate.t.sol";

/// Moderators (v1.1): owner-appointed, may manage membership, may not erase
/// history, may not touch the owner or each other, may not mint moderators.
contract PomboGateModeratorsTest is PomboGateTestBase {
    PomboGate gate;
    address mod;
    uint256 modPk;

    function setUp() public override {
        super.setUp();
        gate = newGate(PomboGate.Mode.NONE);
        (mod, modPk) = makeAddrAndKey("moderator");
        vm.prank(owner);
        gate.setModerator(mod, true);
    }

    function test_setModerator_onlyOwner() public {
        vm.prank(mod);
        vm.expectRevert(PomboGate.NotOwner.selector);
        gate.setModerator(alice, true);
    }

    function test_setModerator_grantsMembership() public {
        assertTrue(gate.moderators(mod));
        assertTrue(gate.everMember(mod));
        assertTrue(gate.allowlist(mod));
        assertTrue(gate.checkAccess(mod));
    }

    function test_setModerator_dismissKeepsMembership() public {
        vm.prank(owner);
        gate.setModerator(mod, false);
        assertFalse(gate.moderators(mod));
        assertTrue(gate.everMember(mod));
        assertTrue(gate.allowlist(mod));
    }

    function test_setModerator_ownerAndZeroRejected() public {
        vm.startPrank(owner);
        vm.expectRevert(PomboGate.InvalidParams.selector);
        gate.setModerator(owner, true);
        vm.expectRevert(PomboGate.ZeroAddress.selector);
        gate.setModerator(address(0), true);
        vm.stopPrank();
    }

    function test_moderatorCanAllowAndBatch() public {
        vm.prank(mod);
        gate.allow(alice);
        assertTrue(gate.checkAccess(alice));

        address[] memory users = new address[](2);
        users[0] = bob;
        users[1] = carol;
        vm.prank(mod);
        gate.allowBatch(users);
        assertTrue(gate.checkAccess(bob) && gate.checkAccess(carol));
    }

    function test_moderatorCanBanAndUnbanMembers() public {
        vm.prank(mod);
        gate.allow(alice);
        vm.prank(mod);
        gate.ban(alice, false);
        assertFalse(gate.checkAccess(alice));
        // sticky history survives a moderator ban too
        bytes32 hash = keccak256("payload");
        assertEq(gate.isValidSignature(hash, sign(alicePk, hash)), MAGIC);
        vm.prank(mod);
        gate.unban(alice);
        assertTrue(gate.checkAccess(alice));
    }

    function test_moderatorCanRevokeAllow() public {
        vm.prank(mod);
        gate.allow(alice);
        vm.prank(mod);
        gate.revokeAllow(alice);
        assertFalse(gate.checkAccess(alice));
        assertTrue(gate.everMember(alice));
    }

    function test_moderatorCannotErase() public {
        vm.prank(mod);
        gate.allow(alice);
        vm.prank(mod);
        vm.expectRevert(PomboGate.NotOwner.selector);
        gate.ban(alice, true);
        // owner still can
        vm.prank(owner);
        gate.ban(alice, true);
        assertTrue(gate.erased(alice));
    }

    function test_moderatorCannotTouchOwner() public {
        vm.startPrank(mod);
        vm.expectRevert(PomboGate.InvalidParams.selector);
        gate.ban(owner, false);
        vm.expectRevert(PomboGate.InvalidParams.selector);
        gate.revokeAllow(owner);
        vm.stopPrank();
    }

    function test_moderatorCannotTouchModerator() public {
        (address mod2,) = makeAddrAndKey("moderator2");
        vm.prank(owner);
        gate.setModerator(mod2, true);

        vm.startPrank(mod);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gate.ban(mod2, false);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gate.revokeAllow(mod2);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gate.unban(mod2);
        vm.stopPrank();

        // the owner can moderate moderators
        vm.prank(owner);
        gate.ban(mod2, false);
        assertTrue(gate.banned(mod2));
    }

    function test_strangerStillLockedOut() public {
        vm.startPrank(alice);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gate.allow(bob);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gate.ban(bob, false);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gate.unban(bob);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gate.revokeAllow(bob);
        vm.stopPrank();
    }

    function test_bannedModeratorLosesAccessButKeepsHistory() public {
        vm.prank(owner);
        gate.ban(mod, false);
        assertFalse(gate.checkAccess(mod));
        bytes32 hash = keccak256("payload");
        assertEq(gate.isValidSignature(hash, sign(modPk, hash)), MAGIC);
    }

    function test_moderatorAccess_tokenModeWithoutHolding() public {
        PomboGate tokenGate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        vm.prank(owner);
        tokenGate.setModerator(mod, true);
        // a moderator has access without holding the gate asset
        assertTrue(tokenGate.checkAccess(mod));
        assertTrue(tokenGate.everMember(mod));
    }
}
