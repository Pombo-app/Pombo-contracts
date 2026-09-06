// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PomboGate} from "../src/PomboGate.sol";
import {PomboGateTestBase} from "./PomboGate.t.sol";

/// Moderators (v3): owner-appointed, manage the allowlist and publish in
/// read-only channels; ban/unban is owner-only. They may not touch the owner
/// or each other and may not appoint moderators.
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

    function test_setModerator_grantsMembership() public view {
        assertTrue(gate.moderators(mod));
        assertTrue(gate.allowlist(mod));
        assertTrue(gate.checkAccess(mod));
    }

    function test_setModerator_dismissKeepsAllowlistMembership() public {
        vm.prank(owner);
        gate.setModerator(mod, false);
        assertFalse(gate.moderators(mod));
        assertTrue(gate.allowlist(mod));
        assertTrue(gate.checkAccess(mod));
    }

    function test_setModerator_dismissInTokenModeDropsAccess() public {
        // no allowlist outside NONE: a dismissed moderator without the asset
        // is out
        PomboGate tokenGate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        vm.startPrank(owner);
        tokenGate.setModerator(mod, true);
        assertTrue(tokenGate.checkAccess(mod));
        tokenGate.setModerator(mod, false);
        vm.stopPrank();
        assertFalse(tokenGate.checkAccess(mod));
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

    function test_moderatorCanRevokeAllow() public {
        vm.prank(mod);
        gate.allow(alice);
        vm.prank(mod);
        gate.revokeAllow(alice);
        assertFalse(gate.checkAccess(alice));
        assertFalse(gate.allowlist(alice));
    }

    function test_moderatorCannotBanOrUnban() public {
        vm.prank(mod);
        gate.allow(alice);
        vm.startPrank(mod);
        vm.expectRevert(PomboGate.NotOwner.selector);
        gate.ban(alice);
        vm.expectRevert(PomboGate.NotOwner.selector);
        gate.unban(alice);
        vm.stopPrank();
        // the owner can
        vm.prank(owner);
        gate.ban(alice);
        assertTrue(gate.banned(alice));
    }

    function test_moderatorCannotTouchOwner() public {
        vm.prank(mod);
        vm.expectRevert(PomboGate.InvalidParams.selector);
        gate.revokeAllow(owner);
    }

    function test_moderatorCannotTouchModerator() public {
        (address mod2,) = makeAddrAndKey("moderator2");
        vm.prank(owner);
        gate.setModerator(mod2, true);

        vm.prank(mod);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gate.revokeAllow(mod2);

        // the owner can moderate moderators
        vm.prank(owner);
        gate.revokeAllow(mod2);
        assertFalse(gate.allowlist(mod2));
    }

    function test_moderatorCannotSetPriceOrDuration() public {
        PomboGate paid = newGate(PomboGate.Mode.PAID);
        vm.prank(owner);
        paid.setModerator(mod, true);
        vm.startPrank(mod);
        vm.expectRevert(PomboGate.NotOwner.selector);
        paid.setPrice(1);
        vm.expectRevert(PomboGate.NotOwner.selector);
        paid.setDuration(1);
        vm.stopPrank();
    }

    function test_strangerStillLockedOut() public {
        vm.startPrank(alice);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gate.allow(bob);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gate.revokeAllow(bob);
        vm.expectRevert(PomboGate.NotOwner.selector);
        gate.ban(bob);
        vm.expectRevert(PomboGate.NotOwner.selector);
        gate.unban(bob);
        vm.stopPrank();
    }

    function test_bannedModeratorLosesAccessAndWrites() public {
        vm.prank(owner);
        gate.ban(mod);
        assertFalse(gate.checkAccess(mod));
        bytes32 hash = keccak256("payload");
        assertEq(gate.isValidSignature(hash, sign(modPk, hash)), INVALID);
    }

    function test_moderatorAccess_tokenModeWithoutHolding() public {
        PomboGate tokenGate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        vm.prank(owner);
        tokenGate.setModerator(mod, true);
        assertTrue(tokenGate.checkAccess(mod));
    }
}
