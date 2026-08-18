// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {PomboGate} from "../src/PomboGate.sol";
import {PomboGateFactory} from "../src/PomboGateFactory.sol";
import {MockERC20, MockERC20Permit, MockERC721} from "./mocks/Mocks.sol";

contract PomboGateTestBase is Test {
    bytes4 constant MAGIC = 0x1626ba7e;
    bytes4 constant INVALID = 0xffffffff;

    PomboGateFactory factory;
    MockERC20 token20;
    MockERC20Permit tokenPermit;
    MockERC721 token721;

    address owner;
    uint256 ownerPk;
    address alice;
    uint256 alicePk;
    address bob;
    uint256 bobPk;
    address carol;
    uint256 carolPk;

    uint256 constant MIN_BALANCE = 100e18;
    uint256 constant PRICE = 5e6;
    uint64 constant DURATION = 30 days;

    function setUp() public virtual {
        factory = new PomboGateFactory();
        token20 = new MockERC20();
        tokenPermit = new MockERC20Permit();
        token721 = new MockERC721();

        (owner, ownerPk) = makeAddrAndKey("owner");
        (alice, alicePk) = makeAddrAndKey("alice");
        (bob, bobPk) = makeAddrAndKey("bob");
        (carol, carolPk) = makeAddrAndKey("carol");

        // ERC-1271 checks against block.timestamp in PAID mode; start away from 0
        vm.warp(1_700_000_000);
    }

    function newGate(PomboGate.Mode mode) internal returns (PomboGate) {
        vm.prank(owner);
        if (mode == PomboGate.Mode.NONE) {
            return PomboGate(factory.createGate(mode, address(0), 0, 0, 0));
        }
        if (mode == PomboGate.Mode.TOKEN_BALANCE) {
            return PomboGate(factory.createGate(mode, address(token20), MIN_BALANCE, 0, 0));
        }
        if (mode == PomboGate.Mode.NFT_OWNERSHIP) {
            return PomboGate(factory.createGate(mode, address(token721), 0, 0, 0));
        }
        return PomboGate(factory.createGate(mode, address(tokenPermit), 0, PRICE, DURATION));
    }

    /// Bare clone that skipped the constructor — initialize is still open,
    /// exactly like a factory clone the moment before its initialize call.
    function newUninitializedClone() internal returns (PomboGate) {
        return PomboGate(Clones.clone(factory.implementation()));
    }

    /// Standard 65-byte recoverable ECDSA signature over the raw hash —
    /// exactly what the Streamr SDK hands to isValidSignature (§3.11).
    function sign(uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(r, s, v);
    }

    function fundAndPay(PomboGate gate, address user) internal {
        tokenPermit.mint(user, PRICE);
        vm.startPrank(user);
        tokenPermit.approve(address(gate), PRICE);
        gate.pay();
        vm.stopPrank();
    }
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

contract PomboGateInitTest is PomboGateTestBase {
    function test_implementationIsLocked() public {
        PomboGate impl = PomboGate(factory.implementation());
        vm.expectRevert(PomboGate.AlreadyInitialized.selector);
        impl.initialize(owner, PomboGate.Mode.NONE, address(0), 0, 0, 0);
    }

    function test_cloneCannotBeInitializedTwice() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.expectRevert(PomboGate.AlreadyInitialized.selector);
        gate.initialize(alice, PomboGate.Mode.NONE, address(0), 0, 0, 0);
    }

    function test_zeroOwnerReverts() public {
        PomboGate g = newUninitializedClone();
        vm.expectRevert(PomboGate.ZeroAddress.selector);
        g.initialize(address(0), PomboGate.Mode.NONE, address(0), 0, 0, 0);
    }

    /// expectRevert arms on the NEXT external call, so the clone must exist
    /// before the assertion — hence the pre-created gate parameter.
    function expectInvalidParams(
        PomboGate g,
        PomboGate.Mode mode_,
        address token_,
        uint256 minBalance_,
        uint256 price_,
        uint64 duration_
    ) internal {
        vm.expectRevert(PomboGate.InvalidParams.selector);
        g.initialize(owner, mode_, token_, minBalance_, price_, duration_);
    }

    function test_ownerIsEverMemberInAllModes() public {
        assertTrue(newGate(PomboGate.Mode.NONE).everMember(owner));
        assertTrue(newGate(PomboGate.Mode.TOKEN_BALANCE).everMember(owner));
        assertTrue(newGate(PomboGate.Mode.NFT_OWNERSHIP).everMember(owner));
        assertTrue(newGate(PomboGate.Mode.PAID).everMember(owner));
    }

    function test_noneMode_ownerIsAllowlisted() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        assertTrue(gate.allowlist(owner));
    }

    function test_paramsStored() public {
        PomboGate gate = newGate(PomboGate.Mode.PAID);
        assertEq(gate.owner(), owner);
        assertEq(uint8(gate.mode()), uint8(PomboGate.Mode.PAID));
        assertEq(gate.token(), address(tokenPermit));
        assertEq(gate.price(), PRICE);
        assertEq(gate.duration(), DURATION);
    }

    function test_invalidParams_none() public {
        expectInvalidParams(newUninitializedClone(), PomboGate.Mode.NONE, address(token20), 0, 0, 0);
        expectInvalidParams(newUninitializedClone(), PomboGate.Mode.NONE, address(0), 1, 0, 0);
    }

    function test_invalidParams_token() public {
        expectInvalidParams(newUninitializedClone(), PomboGate.Mode.TOKEN_BALANCE, address(0), MIN_BALANCE, 0, 0);
        expectInvalidParams(newUninitializedClone(), PomboGate.Mode.TOKEN_BALANCE, address(token20), 0, 0, 0);
        expectInvalidParams(
            newUninitializedClone(), PomboGate.Mode.TOKEN_BALANCE, address(token20), MIN_BALANCE, PRICE, 0
        );
    }

    function test_invalidParams_nft() public {
        expectInvalidParams(newUninitializedClone(), PomboGate.Mode.NFT_OWNERSHIP, address(0), 0, 0, 0);
        expectInvalidParams(newUninitializedClone(), PomboGate.Mode.NFT_OWNERSHIP, address(token721), 1, 0, 0);
    }

    function test_invalidParams_paid() public {
        expectInvalidParams(newUninitializedClone(), PomboGate.Mode.PAID, address(0), 0, PRICE, DURATION);
        expectInvalidParams(newUninitializedClone(), PomboGate.Mode.PAID, address(tokenPermit), 0, 0, DURATION);
        expectInvalidParams(newUninitializedClone(), PomboGate.Mode.PAID, address(tokenPermit), 0, PRICE, 0);
        expectInvalidParams(newUninitializedClone(), PomboGate.Mode.PAID, address(tokenPermit), 1, PRICE, DURATION);
    }
}

// ---------------------------------------------------------------------------
// isValidSignature — sticky membership
// ---------------------------------------------------------------------------

contract PomboGateSignatureTest is PomboGateTestBase {
    bytes32 constant HASH = keccak256("streamr envelope payload");

    function test_ownerSignatureIsValidFromBlockOne() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        assertEq(gate.isValidSignature(HASH, sign(ownerPk, HASH)), MAGIC);
    }

    function test_nonMemberIsInvalid() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_allowedMemberIsValid() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.prank(owner);
        gate.allow(alice);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
    }

    function test_sticky_revokeAllowKeepsHistoryValid() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.allow(alice);
        gate.revokeAllow(alice);
        vm.stopPrank();
        assertFalse(gate.checkAccess(alice));
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
    }

    function test_sticky_banKeepsHistoryValid() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.allow(alice);
        gate.ban(alice, false);
        vm.stopPrank();
        assertFalse(gate.checkAccess(alice));
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
    }

    function test_erasedInvalidatesHistory() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.allow(alice);
        gate.ban(alice, true);
        vm.stopPrank();
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_uneraseRestoresHistory() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.allow(alice);
        gate.ban(alice, true);
        gate.unerase(alice);
        vm.stopPrank();
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
    }

    function test_token_holderWithoutJoinIsValid() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
    }

    function test_token_holderBelowMinIsInvalid() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE - 1);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_token_sellWithoutJoinLosesHistory() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
        token20.burn(alice, MIN_BALANCE);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_token_sticky_joinThenSellKeepsHistory() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE);
        vm.prank(alice);
        gate.join();
        token20.burn(alice, MIN_BALANCE);
        assertFalse(gate.checkAccess(alice));
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
    }

    function test_token_bannedHolderStillValidatesHistory() public {
        // Ban cuts writes at the key layer; signatures — history — survive.
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE);
        vm.prank(owner);
        gate.ban(alice, false);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
        assertFalse(gate.checkAccess(alice));
    }

    function test_nft_holderWithoutJoinIsValid() public {
        PomboGate gate = newGate(PomboGate.Mode.NFT_OWNERSHIP);
        token721.mint(alice);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
    }

    function test_nft_sticky_joinThenSellKeepsHistory() public {
        PomboGate gate = newGate(PomboGate.Mode.NFT_OWNERSHIP);
        uint256 id = token721.mint(alice);
        vm.prank(alice);
        gate.join();
        token721.burn(id);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
    }

    function test_nft_sellWithoutJoinLosesHistory() public {
        PomboGate gate = newGate(PomboGate.Mode.NFT_OWNERSHIP);
        uint256 id = token721.mint(alice);
        token721.burn(id);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_paid_sticky_expiryKeepsHistoryValid() public {
        PomboGate gate = newGate(PomboGate.Mode.PAID);
        fundAndPay(gate, alice);
        vm.warp(block.timestamp + DURATION + 1);
        assertFalse(gate.checkAccess(alice));
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
    }

    function test_paid_neverPaidIsInvalid() public {
        PomboGate gate = newGate(PomboGate.Mode.PAID);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_malformedSignatureReturnsInvalid_noRevert() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        assertEq(gate.isValidSignature(HASH, hex""), INVALID);
        assertEq(gate.isValidSignature(HASH, hex"deadbeef"), INVALID);
        assertEq(gate.isValidSignature(HASH, new bytes(65)), INVALID);
    }

    function test_highSMalleatedSignatureIsInvalid() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, HASH);
        // secp256k1 order N; flip to the high-s twin — OZ ECDSA must reject it
        uint256 N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 sHigh = bytes32(N - uint256(s));
        uint8 vFlipped = v == 27 ? 28 : 27;
        assertEq(gate.isValidSignature(HASH, abi.encodePacked(r, sHigh, vFlipped)), INVALID);
    }

    function test_signatureOverDifferentHashIsInvalid() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        bytes memory sig = sign(ownerPk, keccak256("some other payload"));
        assertEq(gate.isValidSignature(HASH, sig), INVALID);
    }
}

// ---------------------------------------------------------------------------
// checkAccess / accessUntil — the CURRENT gate
// ---------------------------------------------------------------------------

contract PomboGateAccessTest is PomboGateTestBase {
    function test_none_allowlistDrivesAccess() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        assertFalse(gate.checkAccess(alice));
        vm.prank(owner);
        gate.allow(alice);
        assertTrue(gate.checkAccess(alice));
        vm.prank(owner);
        gate.revokeAllow(alice);
        assertFalse(gate.checkAccess(alice));
    }

    function test_none_banCutsAccess_unbanRestores() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.allow(alice);
        gate.ban(alice, false);
        vm.stopPrank();
        assertFalse(gate.checkAccess(alice));
        vm.prank(owner);
        gate.unban(alice);
        // allowlist was untouched by the ban, so access is back
        assertTrue(gate.checkAccess(alice));
    }

    function test_token_balanceBoundary() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE - 1);
        assertFalse(gate.checkAccess(alice));
        token20.mint(alice, 1);
        assertTrue(gate.checkAccess(alice));
    }

    function test_token_accessLapsesOnSell() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE);
        assertTrue(gate.checkAccess(alice));
        vm.prank(alice);
        token20.transfer(bob, 1);
        assertFalse(gate.checkAccess(alice));
    }

    function test_token_bannedHolderHasNoAccess() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE);
        vm.prank(owner);
        gate.ban(alice, false);
        assertFalse(gate.checkAccess(alice));
    }

    function test_nft_holdingDrivesAccess() public {
        PomboGate gate = newGate(PomboGate.Mode.NFT_OWNERSHIP);
        assertFalse(gate.checkAccess(alice));
        uint256 id = token721.mint(alice);
        assertTrue(gate.checkAccess(alice));
        token721.burn(id);
        assertFalse(gate.checkAccess(alice));
    }

    function test_paid_strictExpiryBoundary() public {
        PomboGate gate = newGate(PomboGate.Mode.PAID);
        fundAndPay(gate, alice);
        uint64 until = gate.paidUntil(alice);
        vm.warp(until - 1);
        assertTrue(gate.checkAccess(alice));
        // paidUntil > now is strict: at the exact second it is expired
        vm.warp(until);
        assertFalse(gate.checkAccess(alice));
    }

    function test_ownerAlwaysHasAccess_everyMode() public {
        // Owner never holds tokens, never pays — access regardless
        assertTrue(newGate(PomboGate.Mode.NONE).checkAccess(owner));
        assertTrue(newGate(PomboGate.Mode.TOKEN_BALANCE).checkAccess(owner));
        assertTrue(newGate(PomboGate.Mode.NFT_OWNERSHIP).checkAccess(owner));
        assertTrue(newGate(PomboGate.Mode.PAID).checkAccess(owner));
    }

    function test_accessUntil_paid() public {
        PomboGate gate = newGate(PomboGate.Mode.PAID);
        assertEq(gate.accessUntil(alice), 0);
        fundAndPay(gate, alice);
        assertEq(gate.accessUntil(alice), uint64(block.timestamp) + DURATION);
        vm.prank(owner);
        gate.ban(alice, false);
        assertEq(gate.accessUntil(alice), 0);
        assertEq(gate.accessUntil(owner), type(uint64).max);
    }

    function test_accessUntil_booleanModes() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        assertEq(gate.accessUntil(alice), 0);
        token20.mint(alice, MIN_BALANCE);
        assertEq(gate.accessUntil(alice), type(uint64).max);
    }
}

// ---------------------------------------------------------------------------
// Membership mutations
// ---------------------------------------------------------------------------

contract PomboGateMembershipTest is PomboGateTestBase {
    function test_allow_onlyOwnerOrModerator() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.prank(alice);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gate.allow(alice);
    }

    function test_allow_wrongModeReverts() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        vm.prank(owner);
        vm.expectRevert(PomboGate.WrongMode.selector);
        gate.allow(alice);
    }

    function test_allow_zeroAddressReverts() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.prank(owner);
        vm.expectRevert(PomboGate.ZeroAddress.selector);
        gate.allow(address(0));
    }

    function test_allowBatch() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        address[] memory users = new address[](3);
        users[0] = alice;
        users[1] = bob;
        users[2] = carol;
        vm.prank(owner);
        gate.allowBatch(users);
        assertTrue(gate.checkAccess(alice) && gate.checkAccess(bob) && gate.checkAccess(carol));
        assertTrue(gate.everMember(alice) && gate.everMember(bob) && gate.everMember(carol));
    }

    function test_join_setsEverMember() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE);
        vm.prank(alice);
        vm.expectEmit(true, false, false, false);
        emit PomboGate.MemberJoined(alice);
        gate.join();
        assertTrue(gate.everMember(alice));
    }

    function test_join_nonHolderReverts() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        vm.prank(alice);
        vm.expectRevert(PomboGate.GateNotHeld.selector);
        gate.join();
    }

    function test_join_belowMinReverts() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE - 1);
        vm.prank(alice);
        vm.expectRevert(PomboGate.GateNotHeld.selector);
        gate.join();
    }

    function test_join_nft() public {
        PomboGate gate = newGate(PomboGate.Mode.NFT_OWNERSHIP);
        token721.mint(alice);
        vm.prank(alice);
        gate.join();
        assertTrue(gate.everMember(alice));
    }

    function test_join_wrongModeReverts() public {
        PomboGate none = newGate(PomboGate.Mode.NONE);
        vm.prank(alice);
        vm.expectRevert(PomboGate.WrongMode.selector);
        none.join();

        PomboGate paid = newGate(PomboGate.Mode.PAID);
        vm.prank(alice);
        vm.expectRevert(PomboGate.WrongMode.selector);
        paid.join();
    }

    function test_join_bannedHolderReverts() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE);
        vm.prank(owner);
        gate.ban(alice, false);
        vm.prank(alice);
        vm.expectRevert(PomboGate.IsBanned.selector);
        gate.join();
    }
}

// ---------------------------------------------------------------------------
// PAID: pay / payWithPermit
// ---------------------------------------------------------------------------

contract PomboGatePayTest is PomboGateTestBase {
    PomboGate gate;

    function setUp() public override {
        super.setUp();
        gate = newGate(PomboGate.Mode.PAID);
    }

    function test_pay_transfersPriceToOwner() public {
        fundAndPay(gate, alice);
        assertEq(tokenPermit.balanceOf(owner), PRICE);
        assertEq(tokenPermit.balanceOf(alice), 0);
    }

    function test_pay_setsPaidUntilAndEverMember() public {
        fundAndPay(gate, alice);
        assertEq(gate.paidUntil(alice), uint64(block.timestamp) + DURATION);
        assertTrue(gate.everMember(alice));
        assertTrue(gate.checkAccess(alice));
    }

    function test_pay_earlyRenewalExtendsFromCurrentEnd() public {
        fundAndPay(gate, alice);
        uint64 firstEnd = gate.paidUntil(alice);
        // renew halfway through — no days lost
        vm.warp(block.timestamp + DURATION / 2);
        fundAndPay(gate, alice);
        assertEq(gate.paidUntil(alice), firstEnd + DURATION);
    }

    function test_pay_lateRenewalRestartsFromNow() public {
        fundAndPay(gate, alice);
        vm.warp(block.timestamp + DURATION + 10 days);
        fundAndPay(gate, alice);
        assertEq(gate.paidUntil(alice), uint64(block.timestamp) + DURATION);
    }

    function test_pay_withoutFundsReverts() public {
        vm.startPrank(alice);
        tokenPermit.approve(address(gate), PRICE);
        vm.expectRevert();
        gate.pay();
        vm.stopPrank();
    }

    function test_pay_withoutApprovalReverts() public {
        tokenPermit.mint(alice, PRICE);
        vm.prank(alice);
        vm.expectRevert();
        gate.pay();
    }

    function test_pay_bannedReverts() public {
        vm.prank(owner);
        gate.ban(alice, false);
        tokenPermit.mint(alice, PRICE);
        vm.startPrank(alice);
        tokenPermit.approve(address(gate), PRICE);
        vm.expectRevert(PomboGate.IsBanned.selector);
        gate.pay();
        vm.stopPrank();
    }

    function test_pay_wrongModeReverts() public {
        PomboGate none = newGate(PomboGate.Mode.NONE);
        vm.prank(alice);
        vm.expectRevert(PomboGate.WrongMode.selector);
        none.pay();
    }

    function _permitSig(uint256 pk, address permitOwner, uint256 value, uint256 deadline)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                permitOwner,
                address(gate),
                value,
                tokenPermit.nonces(permitOwner),
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", tokenPermit.DOMAIN_SEPARATOR(), structHash));
        return vm.sign(pk, digest);
    }

    function test_payWithPermit_singleTransaction() public {
        tokenPermit.mint(alice, PRICE);
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _permitSig(alicePk, alice, PRICE, deadline);
        vm.prank(alice);
        gate.payWithPermit(PRICE, deadline, v, r, s);
        assertEq(tokenPermit.balanceOf(owner), PRICE);
        assertTrue(gate.checkAccess(alice));
    }

    function test_payWithPermit_frontRunPermitDoesNotBrick() public {
        // A griefer consumes the permit first; pay must still succeed because
        // the allowance is in place — the try/catch swallows the used permit.
        tokenPermit.mint(alice, PRICE);
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _permitSig(alicePk, alice, PRICE, deadline);
        vm.prank(bob);
        tokenPermit.permit(alice, address(gate), PRICE, deadline, v, r, s);
        vm.prank(alice);
        gate.payWithPermit(PRICE, deadline, v, r, s);
        assertTrue(gate.checkAccess(alice));
    }
}

// ---------------------------------------------------------------------------
// Moderation: ban / unban / erase
// ---------------------------------------------------------------------------

contract PomboGateModerationTest is PomboGateTestBase {
    function test_ban_onlyOwnerOrModerator() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.prank(alice);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gate.ban(bob, false);
    }

    function test_ban_ownerCannotBanSelf() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.prank(owner);
        vm.expectRevert(PomboGate.InvalidParams.selector);
        gate.ban(owner, false);
    }

    function test_ban_eraseOnlyInClosedChannels() public {
        PomboGate token = newGate(PomboGate.Mode.TOKEN_BALANCE);
        vm.prank(owner);
        vm.expectRevert(PomboGate.WrongMode.selector);
        token.ban(alice, true);

        PomboGate paid = newGate(PomboGate.Mode.PAID);
        vm.prank(owner);
        vm.expectRevert(PomboGate.WrongMode.selector);
        paid.ban(alice, true);

        PomboGate nft = newGate(PomboGate.Mode.NFT_OWNERSHIP);
        vm.prank(owner);
        vm.expectRevert(PomboGate.WrongMode.selector);
        nft.ban(alice, true);
    }

    function test_ban_withErase_setsBothFlags() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.allow(alice);
        vm.expectEmit(true, false, false, true);
        emit PomboGate.Banned(alice, true);
        gate.ban(alice, true);
        vm.stopPrank();
        assertTrue(gate.banned(alice));
        assertTrue(gate.erased(alice));
    }

    function test_ban_withoutErase_leavesErasedFalse() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.prank(owner);
        gate.ban(alice, false);
        assertTrue(gate.banned(alice));
        assertFalse(gate.erased(alice));
    }

    function test_unban_unerase_strangerRejected() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(alice);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gate.unban(bob);
        // unerase stays owner-only — it resurrects erased history
        vm.expectRevert(PomboGate.NotOwner.selector);
        gate.unerase(bob);
        vm.stopPrank();
    }
}

// ---------------------------------------------------------------------------
// Ownership
// ---------------------------------------------------------------------------

contract PomboGateOwnershipTest is PomboGateTestBase {
    function test_transferOwnership() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.prank(owner);
        gate.transferOwnership(alice);
        assertEq(gate.owner(), alice);
        assertTrue(gate.everMember(alice));
        assertTrue(gate.allowlist(alice));

        // old owner lost admin powers (and was never a moderator)
        vm.prank(owner);
        vm.expectRevert(PomboGate.NotAuthorized.selector);
        gate.allow(bob);

        // new owner has them
        vm.prank(alice);
        gate.allow(bob);
        assertTrue(gate.checkAccess(bob));
    }

    function test_transferOwnership_zeroReverts() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.prank(owner);
        vm.expectRevert(PomboGate.ZeroAddress.selector);
        gate.transferOwnership(address(0));
    }

    function test_transferOwnership_onlyOwner() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.prank(alice);
        vm.expectRevert(PomboGate.NotOwner.selector);
        gate.transferOwnership(alice);
    }
}

// ---------------------------------------------------------------------------
// Fuzz
// ---------------------------------------------------------------------------

contract PomboGateFuzzTest is PomboGateTestBase {
    function testFuzz_onlySignaturesFromMembersValidate(uint256 pk, bytes32 hash) public {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        address signer = vm.addr(pk);
        bytes memory sig = sign(pk, hash);

        // unknown signer: never valid
        if (signer != owner) {
            assertEq(gate.isValidSignature(hash, sig), INVALID);
        }

        // after allow: always valid, regardless of hash
        vm.prank(owner);
        gate.allow(signer);
        assertEq(gate.isValidSignature(hash, sig), MAGIC);

        // sticky under revoke + ban
        vm.startPrank(owner);
        gate.revokeAllow(signer);
        if (signer != owner) gate.ban(signer, false);
        vm.stopPrank();
        assertEq(gate.isValidSignature(hash, sig), MAGIC);
    }

    function testFuzz_tokenGateTracksBalanceExactly(uint256 balance) public {
        balance = bound(balance, 0, type(uint128).max);
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, balance);
        assertEq(gate.checkAccess(alice), balance >= MIN_BALANCE);
        bytes32 hash = keccak256("payload");
        assertEq(gate.isValidSignature(hash, sign(alicePk, hash)), balance >= MIN_BALANCE ? MAGIC : INVALID);
    }

    function testFuzz_paidUntilNeverDecreases(uint64[4] calldata gaps) public {
        PomboGate gate = newGate(PomboGate.Mode.PAID);
        uint64 previous = 0;
        for (uint256 i = 0; i < gaps.length; i++) {
            vm.warp(block.timestamp + (gaps[i] % (2 * DURATION)));
            fundAndPay(gate, alice);
            uint64 current = gate.paidUntil(alice);
            assertGt(current, previous);
            assertGe(current, uint64(block.timestamp) + DURATION);
            previous = current;
        }
    }

    function testFuzz_garbageSignaturesNeverRevert(bytes calldata garbage) public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        bytes4 result = gate.isValidSignature(keccak256("h"), garbage);
        // Either invalid, or (vanishingly unlikely) a valid sig of a member
        assertTrue(result == INVALID || result == MAGIC);
    }
}
