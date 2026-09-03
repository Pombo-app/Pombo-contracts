// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title PomboGate — per-channel access gate (ERC-1271), v3
///
/// One EIP-1167 clone per channel. The clone address is the Streamr publisher
/// for every member; message authorship is recovered client-side via ecrecover
/// of the envelope signature. The Streamr SDK recovers the signer BEFORE
/// calling this contract and passes (keccak256(payload), signature), so the
/// signature must be a standard 65-byte recoverable ECDSA signature over the
/// raw hash — no EIP-191 prefix, no ZK blobs, no certificate chains.
///
/// Single gate: isValidSignature answers the same question as checkAccess —
/// "does this signer have access right now?" — plus the read-only filter.
/// Selling the gate asset, letting a subscription expire, being revoked or
/// banned all cut ingest immediately on any vanilla node. Permanence of
/// already-published messages is a property of storage retention plus the
/// Pombo read policy (validate at ingest, never revalidate), not of this
/// contract.
contract PomboGate is IERC1271 {
    using SafeERC20 for IERC20;

    enum Mode {
        NONE, // Closed: owner-managed allowlist
        TOKEN_BALANCE, // Gated: hold >= minBalance of an ERC-20
        NFT_OWNERSHIP, // Gated: hold >= 1 of an ERC-721
        PAID // Subscription: pay `price` of `token` for `duration` seconds
    }

    /// Identity on the wire. VISIBLE: every message is signed by its author's
    /// account. SEALED: everyone publishes under a shared channel key and
    /// authorship travels sealed inside the envelope.
    enum WireIdentity {
        VISIBLE,
        SEALED
    }

    struct MemberState {
        bool access; // checkAccess(user) — strict, reverts on a broken token
        bool banned;
        bool moderator;
        bool allowed; // on the NONE allowlist
        uint64 paidUntil; // subscription end (PAID), 0 otherwise
    }

    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    address public owner;
    Mode public mode;
    /// ERC-20 (TOKEN_BALANCE, PAID) or ERC-721 (NFT_OWNERSHIP) address
    address public token;
    /// Minimum ERC-20 balance for TOKEN_BALANCE
    uint256 public minBalance;
    /// Subscription price in `token` units (PAID)
    uint256 public price;
    /// Subscription length in seconds (PAID)
    uint64 public duration;
    /// Immutable after initialize. The contract is the authority on the
    /// channel's identity mode; the stream-metadata flag is a cached copy.
    WireIdentity public wireIdentity;
    /// Immutable after initialize. Only the owner and moderators publish.
    bool public readOnly;

    bool private _initialized;

    /// Cuts access — and with it signature validity — in every mode.
    mapping(address => bool) public banned;
    /// Subscription end per member (PAID).
    mapping(address => uint64) public paidUntil;
    /// Owner-appointed moderators: manage the allowlist, publish in read-only
    /// channels, but never ban, never touch the owner or each other, and
    /// never appoint moderators.
    mapping(address => bool) public moderators;

    /// Current members of a NONE (Closed) channel, enumerable.
    address[] private _members;
    /// 1-based index into _members; 0 means not a member.
    mapping(address => uint256) private _memberIndex;

    event Initialized(
        address indexed owner,
        Mode mode,
        address token,
        uint256 minBalance,
        uint256 price,
        uint64 duration,
        WireIdentity wireIdentity,
        bool readOnly
    );
    event Allowed(address indexed user);
    event AllowRevoked(address indexed user);
    event Paid(address indexed user, uint64 paidUntil);
    event Banned(address indexed user);
    event Unbanned(address indexed user);
    event ModeratorSet(address indexed user, bool enabled);
    event PriceSet(uint256 price);
    event DurationSet(uint64 duration);

    error AlreadyInitialized();
    error NotOwner();
    error NotAuthorized();
    error WrongMode();
    error ZeroAddress();
    error InvalidParams();
    error InvalidToken();
    error IsBanned();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyOwnerOrModerator() {
        if (msg.sender != owner && !moderators[msg.sender]) revert NotAuthorized();
        _;
    }

    /// Moderators act on regular members only — the owner and other
    /// moderators are out of their reach. The owner can act on anyone.
    function _requireModerationTarget(address user) internal view {
        if (user == owner) revert InvalidParams();
        if (msg.sender != owner && moderators[user]) revert NotAuthorized();
    }

    /// Lock the implementation contract; only clones can be initialized.
    constructor() {
        _initialized = true;
    }

    function initialize(
        address owner_,
        Mode mode_,
        address token_,
        uint256 minBalance_,
        uint256 price_,
        uint64 duration_,
        WireIdentity wireIdentity_,
        bool readOnly_
    ) external {
        if (_initialized) revert AlreadyInitialized();
        _initialized = true;
        if (owner_ == address(0)) revert ZeroAddress();

        if (mode_ == Mode.NONE) {
            if (token_ != address(0) || minBalance_ != 0 || price_ != 0 || duration_ != 0) revert InvalidParams();
        } else if (mode_ == Mode.TOKEN_BALANCE) {
            if (token_ == address(0) || minBalance_ == 0 || price_ != 0 || duration_ != 0) revert InvalidParams();
        } else if (mode_ == Mode.NFT_OWNERSHIP) {
            if (token_ == address(0) || minBalance_ != 0 || price_ != 0 || duration_ != 0) revert InvalidParams();
        } else {
            if (token_ == address(0) || price_ == 0 || duration_ == 0 || minBalance_ != 0) revert InvalidParams();
        }
        // A wrong token address would create a channel that never works.
        // Probing address(this) — not address(0), which compliant ERC-721s
        // MUST revert on — is the one balanceOf query valid on both
        // interfaces.
        if (mode_ != Mode.NONE) {
            (bool ok, bytes memory data) = token_.staticcall(abi.encodeCall(IERC20.balanceOf, (address(this))));
            if (!ok || data.length < 32) revert InvalidToken();
        }

        owner = owner_;
        mode = mode_;
        token = token_;
        minBalance = minBalance_;
        price = price_;
        duration = duration_;
        wireIdentity = wireIdentity_;
        readOnly = readOnly_;

        if (mode_ == Mode.NONE) {
            _addMember(owner_);
        }

        emit Initialized(owner_, mode_, token_, minBalance_, price_, duration_, wireIdentity_, readOnly_);
    }

    // ---------------------------------------------------------------- ERC-1271

    /// @notice Single gate: valid iff the signer has access right now. Uses
    /// the fail-open asset check — see _holdsGateAssetSafe.
    ///
    /// readOnly is deliberately NOT consulted here: this contract only sees a
    /// hash, never the stream a signature belongs to, so a filter would cut a
    /// member's reactions, presence and key requests along with the messages.
    /// The flag is a declaration. Who enforces "members do not post":
    /// Sealed — key distribution (the content key only goes to owner and
    /// moderators); Visible — readers at ingest, and the storage node once it
    /// validates, both of which know the stream and can scope the cut to it.
    function isValidSignature(bytes32 hash, bytes memory signature) external view override returns (bytes4) {
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        if (err != ECDSA.RecoverError.NoError || signer == address(0)) return INVALID_SIGNATURE;
        return _hasAccess(signer, true) ? MAGIC_VALUE : INVALID_SIGNATURE;
    }

    // ------------------------------------------------------------------ views

    /// @notice Does this user have access right now? Drives key distribution
    /// in the clients. Strict: a broken gate token makes this revert, and the
    /// clients treat that as fail-closed.
    function checkAccess(address user) public view returns (bool) {
        return _hasAccess(user, false);
    }

    function _hasAccess(address user, bool failOpen) internal view returns (bool) {
        if (user == owner) return true;
        if (banned[user]) return false;
        if (moderators[user]) return true;
        if (mode == Mode.NONE) return _memberIndex[user] != 0;
        if (mode == Mode.PAID) return paidUntil[user] > block.timestamp;
        return failOpen ? _holdsGateAssetSafe(user) : _holdsGateAsset(user);
    }

    /// @notice UI helper: when the user's current access lapses.
    /// PAID returns the subscription end; other modes are boolean gates and
    /// return max-uint64 while access holds, 0 otherwise.
    function accessUntil(address user) external view returns (uint64) {
        if (mode == Mode.PAID) {
            if (user == owner) return type(uint64).max;
            return banned[user] ? 0 : paidUntil[user];
        }
        return checkAccess(user) ? type(uint64).max : 0;
    }

    /// @notice Batch state read — one call instead of one per field per user.
    function states(address[] calldata users) external view returns (MemberState[] memory result) {
        result = new MemberState[](users.length);
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            result[i] = MemberState({
                access: _hasAccess(user, false),
                banned: banned[user],
                moderator: moderators[user],
                allowed: _memberIndex[user] != 0,
                paidUntil: paidUntil[user]
            });
        }
    }

    /// @notice Number of allowlisted members (NONE mode only).
    function membersCount() external view returns (uint256) {
        if (mode != Mode.NONE) revert WrongMode();
        return _members.length;
    }

    /// @notice Paginated allowlist read (NONE mode only). Order is not stable
    /// across removals.
    function membersAt(uint256 offset, uint256 limit) external view returns (address[] memory page) {
        if (mode != Mode.NONE) revert WrongMode();
        uint256 len = _members.length;
        if (offset >= len) return new address[](0);
        uint256 end = offset + limit;
        if (end > len) end = len;
        page = new address[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            page[i - offset] = _members[i];
        }
    }

    /// @notice Is this user on the NONE allowlist?
    function allowlist(address user) external view returns (bool) {
        return _memberIndex[user] != 0;
    }

    /// Strict asset check: a revert in the gate token bubbles up. This is the
    /// path behind checkAccess, and it must NEVER fail open — a broken token
    /// answering true would hand epoch keys to anyone.
    function _holdsGateAsset(address user) internal view returns (bool) {
        if (mode == Mode.TOKEN_BALANCE) return IERC20(token).balanceOf(user) >= minBalance;
        return IERC721(token).balanceOf(user) > 0;
    }

    /// Ingest path only (isValidSignature): a broken gate token must not
    /// freeze the channel, so a failed balanceOf ACCEPTS the write — the
    /// worst case is unreadable ciphertext in storage, while a frozen channel
    /// is unrecoverable. ERC-20 and ERC-721 share the balanceOf selector.
    function _holdsGateAssetSafe(address user) internal view returns (bool) {
        (bool ok, bytes memory data) = token.staticcall(abi.encodeCall(IERC20.balanceOf, (user)));
        if (!ok || data.length < 32) return true;
        uint256 balance = abi.decode(data, (uint256));
        return mode == Mode.TOKEN_BALANCE ? balance >= minBalance : balance > 0;
    }

    // ------------------------------------------------------- membership: NONE

    function allow(address user) external onlyOwnerOrModerator {
        _allow(user);
    }

    function allowBatch(address[] calldata users) external onlyOwnerOrModerator {
        for (uint256 i = 0; i < users.length; i++) {
            _allow(users[i]);
        }
    }

    function _allow(address user) internal {
        if (mode != Mode.NONE) revert WrongMode();
        if (user == address(0)) revert ZeroAddress();
        if (banned[user]) revert IsBanned();
        _addMember(user);
        emit Allowed(user);
    }

    /// @notice Undo an allow without the ban stigma.
    function revokeAllow(address user) external onlyOwnerOrModerator {
        if (mode != Mode.NONE) revert WrongMode();
        _requireModerationTarget(user);
        _removeMember(user);
        emit AllowRevoked(user);
    }

    function _addMember(address user) internal {
        if (_memberIndex[user] != 0) return;
        _members.push(user);
        _memberIndex[user] = _members.length;
    }

    function _removeMember(address user) internal {
        uint256 idx = _memberIndex[user];
        if (idx == 0) return;
        uint256 last = _members.length;
        if (idx != last) {
            address moved = _members[last - 1];
            _members[idx - 1] = moved;
            _memberIndex[moved] = idx;
        }
        _members.pop();
        _memberIndex[user] = 0;
    }

    // ------------------------------------------------------- membership: PAID

    /// @notice Pay for `duration` seconds of access. Renewing before expiry
    /// extends from the current end, so renewing early loses no days.
    /// Deliberately msg.sender-only: third-party payment would link payer and
    /// beneficiary on-chain forever.
    function pay() public {
        if (mode != Mode.PAID) revert WrongMode();
        if (banned[msg.sender]) revert IsBanned();

        uint64 current = paidUntil[msg.sender];
        uint64 base = current > block.timestamp ? current : uint64(block.timestamp);
        uint64 newUntil = base + duration;
        paidUntil[msg.sender] = newUntil;

        emit Paid(msg.sender, newUntil);

        IERC20(token).safeTransferFrom(msg.sender, owner, price);
    }

    /// @notice pay() in a single transaction for EIP-2612 tokens (e.g. USDC on
    /// Polygon). A front-run permit must not brick the payment, hence try/catch.
    function payWithPermit(uint256 permitValue, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        try IERC20Permit(token).permit(msg.sender, address(this), permitValue, deadline, v, r, s) {} catch {}
        pay();
    }

    // ------------------------------------------------------------- moderation

    /// @notice Cut access — and with it ingest — in any mode. Owner only.
    function ban(address user) external onlyOwner {
        if (user == owner) revert InvalidParams();
        banned[user] = true;
        emit Banned(user);
    }

    function unban(address user) external onlyOwner {
        banned[user] = false;
        emit Unbanned(user);
    }

    /// @notice Appoint or dismiss a moderator (owner only). In NONE mode
    /// appointing also allowlists them, so dismissal leaves membership intact;
    /// in the other modes a dismissed moderator keeps access only through the
    /// gate itself.
    function setModerator(address user, bool enabled) external onlyOwner {
        if (user == address(0)) revert ZeroAddress();
        if (user == owner) revert InvalidParams();
        moderators[user] = enabled;
        if (enabled && mode == Mode.NONE) {
            _addMember(user);
        }
        emit ModeratorSet(user, enabled);
    }

    // ------------------------------------------------------------- parameters

    /// @notice Change the subscription price (PAID only). Affects future
    /// payments; running subscriptions keep their end date.
    function setPrice(uint256 price_) external onlyOwner {
        if (mode != Mode.PAID) revert WrongMode();
        if (price_ == 0) revert InvalidParams();
        price = price_;
        emit PriceSet(price_);
    }

    /// @notice Change the subscription length (PAID only). Affects future
    /// payments; running subscriptions keep their end date.
    function setDuration(uint64 duration_) external onlyOwner {
        if (mode != Mode.PAID) revert WrongMode();
        if (duration_ == 0) revert InvalidParams();
        duration = duration_;
        emit DurationSet(duration_);
    }
}
