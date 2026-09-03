// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {PomboGate} from "../src/PomboGate.sol";
import {PomboGateFactory} from "../src/PomboGateFactory.sol";
import {MockERC20, MockERC20Permit, MockERC721, MockBreakableToken} from "./mocks/Mocks.sol";

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
        return newGate(mode, false);
    }

    function newGate(PomboGate.Mode mode, bool readOnly) internal returns (PomboGate) {
        vm.prank(owner);
        if (mode == PomboGate.Mode.NONE) {
            return PomboGate(factory.createGate(mode, address(0), 0, 0, 0, PomboGate.WireIdentity.VISIBLE, readOnly));
        }
        if (mode == PomboGate.Mode.TOKEN_BALANCE) {
            return PomboGate(
                factory.createGate(mode, address(token20), MIN_BALANCE, 0, 0, PomboGate.WireIdentity.VISIBLE, readOnly)
            );
        }
        if (mode == PomboGate.Mode.NFT_OWNERSHIP) {
            return
                PomboGate(
                    factory.createGate(mode, address(token721), 0, 0, 0, PomboGate.WireIdentity.VISIBLE, readOnly)
                );
        }
        return PomboGate(
            factory.createGate(mode, address(tokenPermit), 0, PRICE, DURATION, PomboGate.WireIdentity.VISIBLE, readOnly)
        );
    }

    /// Gate on a token whose balanceOf can be flipped to revert after creation.
    function newBreakableGate(PomboGate.Mode mode) internal returns (PomboGate gate, MockBreakableToken breakable) {
        breakable = new MockBreakableToken();
        uint256 min = mode == PomboGate.Mode.TOKEN_BALANCE ? MIN_BALANCE : 0;
        vm.prank(owner);
        gate = PomboGate(factory.createGate(mode, address(breakable), min, 0, 0, PomboGate.WireIdentity.VISIBLE, false));
    }

    /// Bare clone that skipped the constructor — initialize is still open,
    /// exactly like a factory clone the moment before its initialize call.
    function newUninitializedClone() internal returns (PomboGate) {
        return PomboGate(Clones.clone(factory.implementation()));
    }

    /// Standard 65-byte recoverable ECDSA signature over the raw hash —
    /// exactly what the Streamr SDK hands to isValidSignature.
    function sign(uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(r, s, v);
    }

    function fundAndPay(PomboGate gate, address user) internal {
        uint256 amount = gate.price();
        tokenPermit.mint(user, amount);
        vm.startPrank(user);
        tokenPermit.approve(address(gate), amount);
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
        impl.initialize(owner, PomboGate.Mode.NONE, address(0), 0, 0, 0, PomboGate.WireIdentity.VISIBLE, false);
    }

    function test_cloneCannotBeInitializedTwice() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.expectRevert(PomboGate.AlreadyInitialized.selector);
        gate.initialize(alice, PomboGate.Mode.NONE, address(0), 0, 0, 0, PomboGate.WireIdentity.VISIBLE, false);
    }

    function test_zeroOwnerReverts() public {
        PomboGate g = newUninitializedClone();
        vm.expectRevert(PomboGate.ZeroAddress.selector);
        g.initialize(address(0), PomboGate.Mode.NONE, address(0), 0, 0, 0, PomboGate.WireIdentity.VISIBLE, false);
    }

    function test_ownerHasAccessInAllModes() public {
        assertTrue(newGate(PomboGate.Mode.NONE).checkAccess(owner));
        assertTrue(newGate(PomboGate.Mode.TOKEN_BALANCE).checkAccess(owner));
        assertTrue(newGate(PomboGate.Mode.NFT_OWNERSHIP).checkAccess(owner));
        assertTrue(newGate(PomboGate.Mode.PAID).checkAccess(owner));
    }

    function test_noneMode_ownerIsAllowlisted() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        assertTrue(gate.allowlist(owner));
        assertEq(gate.membersCount(), 1);
        assertEq(gate.membersAt(0, 10)[0], owner);
    }

    function test_paramsStored() public {
        PomboGate gate = newGate(PomboGate.Mode.PAID);
        assertEq(gate.owner(), owner);
        assertEq(uint8(gate.mode()), uint8(PomboGate.Mode.PAID));
        assertEq(gate.token(), address(tokenPermit));
        assertEq(gate.price(), PRICE);
        assertEq(gate.duration(), DURATION);
        assertEq(uint8(gate.wireIdentity()), uint8(PomboGate.WireIdentity.VISIBLE));
        assertFalse(gate.readOnly());
    }

    function test_wireIdentitySealedAndReadOnlyStored() public {
        vm.prank(owner);
        PomboGate gate = PomboGate(
            factory.createGate(PomboGate.Mode.NONE, address(0), 0, 0, 0, PomboGate.WireIdentity.SEALED, true)
        );
        assertEq(uint8(gate.wireIdentity()), uint8(PomboGate.WireIdentity.SEALED));
        assertTrue(gate.readOnly());
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
        g.initialize(owner, mode_, token_, minBalance_, price_, duration_, PomboGate.WireIdentity.VISIBLE, false);
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

    function test_tokenWithoutBalanceOfReverts() public {
        // the factory has code but no balanceOf — the call reverts
        PomboGate g = newUninitializedClone();
        vm.expectRevert(PomboGate.InvalidToken.selector);
        g.initialize(
            owner,
            PomboGate.Mode.TOKEN_BALANCE,
            address(factory),
            MIN_BALANCE,
            0,
            0,
            PomboGate.WireIdentity.VISIBLE,
            false
        );
    }

    function test_eoaAsTokenReverts() public {
        // a codeless address answers the staticcall with empty data
        PomboGate g = newUninitializedClone();
        vm.expectRevert(PomboGate.InvalidToken.selector);
        g.initialize(
            owner, PomboGate.Mode.TOKEN_BALANCE, alice, MIN_BALANCE, 0, 0, PomboGate.WireIdentity.VISIBLE, false
        );
        PomboGate g2 = newUninitializedClone();
        vm.expectRevert(PomboGate.InvalidToken.selector);
        g2.initialize(owner, PomboGate.Mode.PAID, alice, 0, PRICE, DURATION, PomboGate.WireIdentity.VISIBLE, false);
    }

    function test_compliantErc721Initializes() public {
        // ERC-721 balanceOf(address(0)) MUST revert per the standard, so the
        // interface probe must not use the zero address
        PomboGate gate = newGate(PomboGate.Mode.NFT_OWNERSHIP);
        assertEq(gate.token(), address(token721));
    }
}

// ---------------------------------------------------------------------------
// isValidSignature — single gate: write access cut the moment access lapses
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

    function test_closed_revokeAllowCutsWrites() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.allow(alice);
        gate.revokeAllow(alice);
        vm.stopPrank();
        assertFalse(gate.checkAccess(alice));
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_closed_banCutsWrites() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.allow(alice);
        gate.ban(alice);
        vm.stopPrank();
        assertFalse(gate.checkAccess(alice));
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_closed_unbanRestoresWrites() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.allow(alice);
        gate.ban(alice);
        gate.unban(alice);
        vm.stopPrank();
        // the allowlist entry survived the ban, so access and writes are back
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
    }

    function test_token_holderIsValid() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
    }

    function test_token_holderBelowMinIsInvalid() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE - 1);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_token_sellingCutsWrites() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
        vm.prank(alice);
        assertTrue(token20.transfer(bob, 1));
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_token_bannedHolderCannotWrite() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, MIN_BALANCE);
        vm.prank(owner);
        gate.ban(alice);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
        assertFalse(gate.checkAccess(alice));
    }

    function test_nft_holderIsValid() public {
        PomboGate gate = newGate(PomboGate.Mode.NFT_OWNERSHIP);
        token721.mint(alice);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
    }

    function test_nft_sellingCutsWrites() public {
        PomboGate gate = newGate(PomboGate.Mode.NFT_OWNERSHIP);
        uint256 id = token721.mint(alice);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
        token721.burn(id);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_paid_subscriberIsValid() public {
        PomboGate gate = newGate(PomboGate.Mode.PAID);
        fundAndPay(gate, alice);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
    }

    function test_paid_expiryCutsWrites() public {
        PomboGate gate = newGate(PomboGate.Mode.PAID);
        fundAndPay(gate, alice);
        vm.warp(block.timestamp + DURATION + 1);
        assertFalse(gate.checkAccess(alice));
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_paid_neverPaidIsInvalid() public {
        PomboGate gate = newGate(PomboGate.Mode.PAID);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_paid_bannedSubscriberCannotWrite() public {
        PomboGate gate = newGate(PomboGate.Mode.PAID);
        fundAndPay(gate, alice);
        vm.prank(owner);
        gate.ban(alice);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_moderatorWritesWithoutHolding() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        vm.prank(owner);
        gate.setModerator(alice, true);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
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
// Read-only channels: the flag is a DECLARATION. The contract only sees a
// hash, never the stream a signature belongs to, so filtering here would cut
// reactions, presence and key requests along with the messages. Sealed
// enforces "members do not post" through key distribution; Visible through
// readers at ingest and, later, the validating storage node.
// ---------------------------------------------------------------------------

contract PomboGateReadOnlyTest is PomboGateTestBase {
    bytes32 constant HASH = keccak256("streamr envelope payload");

    function test_flagDoesNotAffectIsValidSignature() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE, true);
        vm.startPrank(owner);
        gate.allow(alice);
        gate.setModerator(bob, true);
        vm.stopPrank();

        assertTrue(gate.readOnly());
        assertEq(gate.isValidSignature(HASH, sign(ownerPk, HASH)), MAGIC);
        assertEq(gate.isValidSignature(HASH, sign(bobPk, HASH)), MAGIC);
        // a plain member signs valid too: their reactions, presence and key
        // requests must validate — the message cut lives outside the contract
        assertTrue(gate.checkAccess(alice));
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
        // strangers stay out regardless
        assertEq(gate.isValidSignature(HASH, sign(carolPk, HASH)), INVALID);
    }

    function test_token_holderSignsValid() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE, true);
        token20.mint(alice, MIN_BALANCE);
        assertTrue(gate.checkAccess(alice));
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
    }

    function test_bannedMemberStaysCut() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE, true);
        vm.startPrank(owner);
        gate.setModerator(bob, true);
        gate.ban(bob);
        vm.stopPrank();
        assertEq(gate.isValidSignature(HASH, sign(bobPk, HASH)), INVALID);
    }

    function test_readOnlyDoesNotAffectCheckAccess() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE, true);
        vm.prank(owner);
        gate.allow(alice);
        // reading — key distribution — is untouched by the read-only flag
        assertTrue(gate.checkAccess(alice));
    }
}

// ---------------------------------------------------------------------------
// Broken gate token: fail-open at ingest, strict for key distribution
// ---------------------------------------------------------------------------

contract PomboGateBrokenTokenTest is PomboGateTestBase {
    bytes32 constant HASH = keccak256("streamr envelope payload");

    function test_token_ingestFailsOpen_checkAccessReverts() public {
        (PomboGate gate, MockBreakableToken breakable) = newBreakableGate(PomboGate.Mode.TOKEN_BALANCE);
        breakable.setBalance(alice, MIN_BALANCE);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
        assertTrue(gate.checkAccess(alice));

        breakable.setBroken(true);
        // ingest accepts the write — a broken token must not freeze the channel
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
        assertEq(gate.isValidSignature(HASH, sign(bobPk, HASH)), MAGIC);
        // but key distribution must NOT open up: checkAccess reverts and the
        // clients fail closed
        vm.expectRevert();
        gate.checkAccess(alice);
        vm.expectRevert();
        gate.checkAccess(bob);
    }

    function test_nft_ingestFailsOpen_checkAccessReverts() public {
        (PomboGate gate, MockBreakableToken breakable) = newBreakableGate(PomboGate.Mode.NFT_OWNERSHIP);
        breakable.setBroken(true);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
        vm.expectRevert();
        gate.checkAccess(alice);
    }

    function test_banStillCutsWritesWhileTokenIsBroken() public {
        (PomboGate gate, MockBreakableToken breakable) = newBreakableGate(PomboGate.Mode.TOKEN_BALANCE);
        vm.prank(owner);
        gate.ban(alice);
        breakable.setBroken(true);
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), INVALID);
    }

    function test_readOnlyGateFailsOpenWhileTokenIsBroken() public {
        MockBreakableToken breakable = new MockBreakableToken();
        vm.prank(owner);
        PomboGate gate = PomboGate(
            factory.createGate(
                PomboGate.Mode.TOKEN_BALANCE,
                address(breakable),
                MIN_BALANCE,
                0,
                0,
                PomboGate.WireIdentity.VISIBLE,
                true
            )
        );
        breakable.setBroken(true);
        // the read-only flag is a declaration, not a filter: a broken token
        // fails open at ingest for everyone, exactly like a non-RO gate
        assertEq(gate.isValidSignature(HASH, sign(alicePk, HASH)), MAGIC);
        assertEq(gate.isValidSignature(HASH, sign(ownerPk, HASH)), MAGIC);
    }

    function test_statesRevertsWhileTokenIsBroken() public {
        (PomboGate gate, MockBreakableToken breakable) = newBreakableGate(PomboGate.Mode.TOKEN_BALANCE);
        breakable.setBroken(true);
        address[] memory users = new address[](1);
        users[0] = alice;
        vm.expectRevert();
        gate.states(users);
    }

    function test_ownerUnaffectedByBrokenToken() public {
        (PomboGate gate, MockBreakableToken breakable) = newBreakableGate(PomboGate.Mode.TOKEN_BALANCE);
        breakable.setBroken(true);
        // owner short-circuits before the asset check on both paths
        assertTrue(gate.checkAccess(owner));
        assertEq(gate.isValidSignature(HASH, sign(ownerPk, HASH)), MAGIC);
    }
}

// ---------------------------------------------------------------------------
// checkAccess / accessUntil — the live gate
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
        gate.ban(alice);
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
        assertTrue(token20.transfer(bob, 1));
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

    function test_accessUntil_paid() public {
        PomboGate gate = newGate(PomboGate.Mode.PAID);
        assertEq(gate.accessUntil(alice), 0);
        fundAndPay(gate, alice);
        assertEq(gate.accessUntil(alice), uint64(block.timestamp) + DURATION);
        vm.prank(owner);
        gate.ban(alice);
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
// states — batch state read
// ---------------------------------------------------------------------------

contract PomboGateStatesTest is PomboGateTestBase {
    function test_states_closedChannel() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.allow(alice);
        gate.allow(bob);
        gate.ban(bob);
        gate.setModerator(carol, true);
        vm.stopPrank();

        address[] memory users = new address[](5);
        users[0] = owner;
        users[1] = alice;
        users[2] = bob;
        users[3] = carol;
        users[4] = makeAddr("stranger");
        PomboGate.MemberState[] memory result = gate.states(users);

        assertTrue(result[0].access);
        assertTrue(result[0].allowed);
        assertTrue(result[1].access && result[1].allowed && !result[1].banned && !result[1].moderator);
        assertTrue(!result[2].access && result[2].allowed && result[2].banned);
        assertTrue(result[3].access && result[3].moderator && result[3].allowed);
        assertTrue(!result[4].access && !result[4].allowed && !result[4].banned && !result[4].moderator);
    }

    function test_states_paidChannel() public {
        PomboGate gate = newGate(PomboGate.Mode.PAID);
        fundAndPay(gate, alice);
        address[] memory users = new address[](2);
        users[0] = alice;
        users[1] = bob;
        PomboGate.MemberState[] memory result = gate.states(users);
        assertTrue(result[0].access);
        assertEq(result[0].paidUntil, uint64(block.timestamp) + DURATION);
        assertTrue(!result[1].access);
        assertEq(result[1].paidUntil, 0);
    }

    function test_states_emptyInput() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        assertEq(gate.states(new address[](0)).length, 0);
    }
}

// ---------------------------------------------------------------------------
// Member enumeration (NONE mode)
// ---------------------------------------------------------------------------

contract PomboGateEnumerationTest is PomboGateTestBase {
    function test_countAndPagination() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.allow(alice);
        gate.allow(bob);
        gate.allow(carol);
        vm.stopPrank();

        assertEq(gate.membersCount(), 4); // owner + 3

        address[] memory all = gate.membersAt(0, 10);
        assertEq(all.length, 4);
        assertEq(all[0], owner);
        assertEq(all[1], alice);
        assertEq(all[2], bob);
        assertEq(all[3], carol);

        address[] memory page = gate.membersAt(1, 2);
        assertEq(page.length, 2);
        assertEq(page[0], alice);
        assertEq(page[1], bob);

        assertEq(gate.membersAt(4, 10).length, 0);
        assertEq(gate.membersAt(100, 10).length, 0);
    }

    function test_allowIsIdempotent() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.allow(alice);
        gate.allow(alice);
        vm.stopPrank();
        assertEq(gate.membersCount(), 2);
    }

    function test_revokeRemovesFromEnumeration() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.allow(alice);
        gate.allow(bob);
        gate.revokeAllow(alice); // swap-and-pop: bob moves into alice's slot
        vm.stopPrank();

        assertEq(gate.membersCount(), 2);
        address[] memory all = gate.membersAt(0, 10);
        assertEq(all[0], owner);
        assertEq(all[1], bob);
        assertFalse(gate.allowlist(alice));
        assertTrue(gate.allowlist(bob));
    }

    function test_revokeNonMemberIsNoop() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.prank(owner);
        gate.revokeAllow(alice);
        assertEq(gate.membersCount(), 1);
    }

    function test_banDoesNotRemoveFromEnumeration() public {
        // the loss-of-access sweep needs banned members as candidates too
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.allow(alice);
        gate.ban(alice);
        vm.stopPrank();
        assertEq(gate.membersCount(), 2);
        assertTrue(gate.allowlist(alice));
    }

    function test_wrongModeReverts() public {
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        vm.expectRevert(PomboGate.WrongMode.selector);
        gate.membersCount();
        vm.expectRevert(PomboGate.WrongMode.selector);
        gate.membersAt(0, 10);
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

    function test_allow_bannedReverts() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.ban(alice);
        vm.expectRevert(PomboGate.IsBanned.selector);
        gate.allow(alice);
        // re-admitting takes an explicit unban first
        gate.unban(alice);
        gate.allow(alice);
        vm.stopPrank();
        assertTrue(gate.checkAccess(alice));
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
    }

    function test_allowBatch_bannedEntryRevertsWholeBatch() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.ban(bob);
        address[] memory users = new address[](2);
        users[0] = alice;
        users[1] = bob;
        vm.expectRevert(PomboGate.IsBanned.selector);
        gate.allowBatch(users);
        vm.stopPrank();
    }
}

// ---------------------------------------------------------------------------
// PAID: pay / payWithPermit / setPrice / setDuration
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

    function test_pay_setsPaidUntil() public {
        fundAndPay(gate, alice);
        assertEq(gate.paidUntil(alice), uint64(block.timestamp) + DURATION);
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
        gate.ban(alice);
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

    function test_setPrice_appliesToNextPayment() public {
        vm.prank(owner);
        gate.setPrice(PRICE * 2);
        assertEq(gate.price(), PRICE * 2);
        fundAndPay(gate, alice);
        assertEq(tokenPermit.balanceOf(owner), PRICE * 2);
    }

    function test_setDuration_appliesToNextPayment() public {
        vm.prank(owner);
        gate.setDuration(7 days);
        fundAndPay(gate, alice);
        assertEq(gate.paidUntil(alice), uint64(block.timestamp) + 7 days);
    }

    function test_setPriceDuration_runningSubscriptionKeepsEnd() public {
        fundAndPay(gate, alice);
        uint64 end = gate.paidUntil(alice);
        vm.startPrank(owner);
        gate.setPrice(PRICE * 10);
        gate.setDuration(1 days);
        vm.stopPrank();
        assertEq(gate.paidUntil(alice), end);
        assertTrue(gate.checkAccess(alice));
    }

    function test_setPriceDuration_onlyOwner() public {
        vm.startPrank(alice);
        vm.expectRevert(PomboGate.NotOwner.selector);
        gate.setPrice(1);
        vm.expectRevert(PomboGate.NotOwner.selector);
        gate.setDuration(1);
        vm.stopPrank();
    }

    function test_setPriceDuration_zeroReverts() public {
        vm.startPrank(owner);
        vm.expectRevert(PomboGate.InvalidParams.selector);
        gate.setPrice(0);
        vm.expectRevert(PomboGate.InvalidParams.selector);
        gate.setDuration(0);
        vm.stopPrank();
    }

    function test_setPriceDuration_wrongModeReverts() public {
        PomboGate none = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        vm.expectRevert(PomboGate.WrongMode.selector);
        none.setPrice(1);
        vm.expectRevert(PomboGate.WrongMode.selector);
        none.setDuration(1);
        vm.stopPrank();
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
// Moderation: ban / unban (owner only)
// ---------------------------------------------------------------------------

contract PomboGateModerationTest is PomboGateTestBase {
    function test_ban_onlyOwner() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.prank(alice);
        vm.expectRevert(PomboGate.NotOwner.selector);
        gate.ban(bob);
    }

    function test_unban_onlyOwner() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.prank(alice);
        vm.expectRevert(PomboGate.NotOwner.selector);
        gate.unban(bob);
    }

    function test_ban_ownerCannotBanSelf() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.prank(owner);
        vm.expectRevert(PomboGate.InvalidParams.selector);
        gate.ban(owner);
    }

    function test_ban_emitsEvent() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit PomboGate.Banned(alice);
        gate.ban(alice);
        assertTrue(gate.banned(alice));
    }

    function test_ownerCanBanModerator() public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        vm.startPrank(owner);
        gate.setModerator(bob, true);
        gate.ban(bob);
        vm.stopPrank();
        assertTrue(gate.banned(bob));
        assertFalse(gate.checkAccess(bob));
    }
}

// ---------------------------------------------------------------------------
// Fuzz
// ---------------------------------------------------------------------------

contract PomboGateFuzzTest is PomboGateTestBase {
    function testFuzz_signatureValidityTracksAccess(uint256 pk, bytes32 hash) public {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        address signer = vm.addr(pk);
        bytes memory sig = sign(pk, hash);

        // unknown signer: never valid
        if (signer != owner) {
            assertEq(gate.isValidSignature(hash, sig), INVALID);
        }

        // after allow: valid, regardless of hash
        vm.prank(owner);
        gate.allow(signer);
        assertEq(gate.isValidSignature(hash, sig), MAGIC);

        // revoking cuts writes immediately
        vm.prank(owner);
        gate.revokeAllow(signer);
        if (signer != owner) {
            assertEq(gate.isValidSignature(hash, sig), INVALID);
        }
    }

    function testFuzz_tokenGateTracksBalanceExactly(uint256 balance) public {
        balance = bound(balance, 0, type(uint128).max);
        PomboGate gate = newGate(PomboGate.Mode.TOKEN_BALANCE);
        token20.mint(alice, balance);
        assertEq(gate.checkAccess(alice), balance >= MIN_BALANCE);
        bytes32 hash = keccak256("payload");
        // single gate: ingest and key distribution agree while the token responds
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

    function testFuzz_enumerationStaysConsistent(uint8 addCount, uint8 removeMask) public {
        PomboGate gate = newGate(PomboGate.Mode.NONE);
        addCount = uint8(bound(addCount, 0, 8));
        address[] memory users = new address[](addCount);
        vm.startPrank(owner);
        for (uint256 i = 0; i < addCount; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            users[i] = address(uint160(0x1000 + i));
            gate.allow(users[i]);
        }
        uint256 expected = 1 + addCount; // owner + added
        for (uint256 i = 0; i < addCount; i++) {
            if ((removeMask >> i) & 1 != 0) {
                gate.revokeAllow(users[i]);
                expected--;
            }
        }
        vm.stopPrank();

        assertEq(gate.membersCount(), expected);
        address[] memory all = gate.membersAt(0, 20);
        assertEq(all.length, expected);
        for (uint256 i = 0; i < addCount; i++) {
            bool kept = (removeMask >> i) & 1 == 0;
            assertEq(gate.allowlist(users[i]), kept);
            bool found = false;
            for (uint256 j = 0; j < all.length; j++) {
                if (all[j] == users[i]) found = true;
            }
            assertEq(found, kept);
        }
    }
}
