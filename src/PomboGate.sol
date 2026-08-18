// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title PomboGate — per-channel access gate with sticky membership (ERC-1271)
///
/// One EIP-1167 clone per channel. The clone address is the Streamr publisher
/// for every member; message authorship is recovered client-side via ecrecover
/// of the envelope signature. The Streamr SDK recovers the signer BEFORE
/// calling this contract and passes (keccak256(payload), signature), so the
/// signature must be a standard 65-byte recoverable ECDSA signature over the
/// raw hash — no EIP-191 prefix, no ZK blobs, no certificate chains.
///
/// Signature validity implements STICKY MEMBERSHIP (high-water mark): leaving,
/// selling the gate asset or letting a subscription expire NEVER invalidates
/// messages already published. Write-cut for ex-members happens at the epoch
/// key layer (checkAccess before answering KEY_REQUEST + kid freshness rule),
/// not by invalidating signatures. The only thing that makes history disappear
/// is `erased` — an explicit owner option in the ban flow of Closed (NONE)
/// channels.
contract PomboGate is IERC1271 {
    using SafeERC20 for IERC20;

    enum Mode {
        NONE, // Closed: owner-managed allowlist
        TOKEN_BALANCE, // Gated: hold >= minBalance of an ERC-20
        NFT_OWNERSHIP, // Gated: hold >= 1 of an ERC-721
        PAID // Subscription: pay `price` of `token` for `duration` seconds
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

    bool private _initialized;

    /// High-water mark: once true, stays true. Grants signature validity forever.
    mapping(address => bool) public everMember;
    /// Cuts future access (checkAccess) but preserves history (isValidSignature).
    mapping(address => bool) public banned;
    /// The ONLY flag that invalidates published history. Owner-set, NONE mode only.
    mapping(address => bool) public erased;
    /// Current members of a NONE (Closed) channel.
    mapping(address => bool) public allowlist;
    /// Subscription end per member (PAID).
    mapping(address => uint64) public paidUntil;
    /// Owner-appointed moderators: manage membership (allow/revoke/ban/unban)
    /// but never erase history, never touch the owner or other moderators,
    /// and never appoint moderators.
    mapping(address => bool) public moderators;

    event Initialized(
        address indexed owner, Mode mode, address token, uint256 minBalance, uint256 price, uint64 duration
    );
    event Allowed(address indexed user);
    event AllowRevoked(address indexed user);
    event MemberJoined(address indexed user);
    event Paid(address indexed user, uint64 paidUntil);
    event Banned(address indexed user, bool erasedHistory);
    event Unbanned(address indexed user);
    event Unerased(address indexed user);
    event ModeratorSet(address indexed user, bool enabled);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error AlreadyInitialized();
    error NotOwner();
    error NotAuthorized();
    error WrongMode();
    error ZeroAddress();
    error InvalidParams();
    error IsBanned();
    error IsErased();
    error GateNotHeld();

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
        uint64 duration_
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

        owner = owner_;
        mode = mode_;
        token = token_;
        minBalance = minBalance_;
        price = price_;
        duration = duration_;

        // The owner publishes through the clone too (KEY_ANNOUNCE etc.),
        // so their signatures must validate from block one.
        everMember[owner_] = true;
        if (mode_ == Mode.NONE) {
            allowlist[owner_] = true;
        }

        emit Initialized(owner_, mode_, token_, minBalance_, price_, duration_);
    }

    // ---------------------------------------------------------------- ERC-1271

    /// @notice Sticky membership: everMember (or currently holding the gate
    /// asset in TOKEN/NFT modes, since join() is optional there) and not erased.
    /// `banned` deliberately does NOT invalidate signatures — banning cuts
    /// future writes at the key layer while preserving the thread.
    function isValidSignature(bytes32 hash, bytes memory signature) external view override returns (bytes4) {
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        if (err != ECDSA.RecoverError.NoError || signer == address(0)) return INVALID_SIGNATURE;
        if (erased[signer]) return INVALID_SIGNATURE;
        if (everMember[signer]) return MAGIC_VALUE;
        // join() is optional in TOKEN/NFT modes: a current holder who never
        // joined is a valid author. If they sell without ever joining, their
        // history stops validating — permanence is opt-in via join().
        if (_holdsGateAsset(signer)) return MAGIC_VALUE;
        return INVALID_SIGNATURE;
    }

    // ------------------------------------------------------------------ views

    /// @notice The CURRENT gate — drives key distribution and UI, not history.
    function checkAccess(address user) public view returns (bool) {
        if (user == owner) return true;
        if (banned[user]) return false;
        if (moderators[user]) return true;
        if (mode == Mode.NONE) return allowlist[user];
        if (mode == Mode.PAID) return paidUntil[user] > block.timestamp;
        return _holdsGateAsset(user);
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

    function _holdsGateAsset(address user) internal view returns (bool) {
        if (mode == Mode.TOKEN_BALANCE) return IERC20(token).balanceOf(user) >= minBalance;
        if (mode == Mode.NFT_OWNERSHIP) return IERC721(token).balanceOf(user) > 0;
        return false;
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
        allowlist[user] = true;
        everMember[user] = true;
        emit Allowed(user);
    }

    /// @notice Undo an allow without the ban stigma. everMember stays — allow()
    /// is a public, owner-signed commitment that this address was a member.
    function revokeAllow(address user) external onlyOwnerOrModerator {
        if (mode != Mode.NONE) revert WrongMode();
        _requireModerationTarget(user);
        allowlist[user] = false;
        emit AllowRevoked(user);
    }

    // -------------------------------------------------- membership: TOKEN/NFT

    /// @notice Optional single-tx opt-in to permanence for holder gates.
    /// Without it, a holder who sells without ever joining loses their history.
    function join() external {
        if (mode != Mode.TOKEN_BALANCE && mode != Mode.NFT_OWNERSHIP) revert WrongMode();
        if (banned[msg.sender]) revert IsBanned();
        if (erased[msg.sender]) revert IsErased();
        if (!_holdsGateAsset(msg.sender)) revert GateNotHeld();
        everMember[msg.sender] = true;
        emit MemberJoined(msg.sender);
    }

    // ------------------------------------------------------- membership: PAID

    /// @notice Pay for `duration` seconds of access. Renewing before expiry
    /// extends from the current end, so renewing early loses no days.
    /// Deliberately msg.sender-only: third-party payment would link payer and
    /// beneficiary on-chain forever.
    function pay() public {
        if (mode != Mode.PAID) revert WrongMode();
        if (banned[msg.sender]) revert IsBanned();
        if (erased[msg.sender]) revert IsErased();

        uint64 current = paidUntil[msg.sender];
        uint64 base = current > block.timestamp ? current : uint64(block.timestamp);
        uint64 newUntil = base + duration;
        paidUntil[msg.sender] = newUntil;
        everMember[msg.sender] = true;

        emit Paid(msg.sender, newUntil);
        emit MemberJoined(msg.sender);

        IERC20(token).safeTransferFrom(msg.sender, owner, price);
    }

    /// @notice pay() in a single transaction for EIP-2612 tokens (e.g. USDC on
    /// Polygon). A front-run permit must not brick the payment, hence try/catch.
    function payWithPermit(uint256 permitValue, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        try IERC20Permit(token).permit(msg.sender, address(this), permitValue, deadline, v, r, s) {} catch {}
        pay();
    }

    // ------------------------------------------------------------- moderation

    /// @notice Cut future access, preserve history. `eraseHistory` is the one
    /// exception — available only in NONE (Closed) channels, where removing a
    /// member IS the ban and the OWNER may explicitly choose to erase their
    /// messages from the network. Moderators ban, only the owner erases.
    function ban(address user, bool eraseHistory) external onlyOwnerOrModerator {
        _requireModerationTarget(user);
        banned[user] = true;
        if (eraseHistory) {
            if (msg.sender != owner) revert NotOwner();
            if (mode != Mode.NONE) revert WrongMode();
            erased[user] = true;
        }
        emit Banned(user, eraseHistory);
    }

    function unban(address user) external onlyOwnerOrModerator {
        _requireModerationTarget(user);
        banned[user] = false;
        emit Unbanned(user);
    }

    /// @notice Undo an erase — the member's history validates again.
    function unerase(address user) external onlyOwner {
        erased[user] = false;
        emit Unerased(user);
    }

    /// @notice Appoint or dismiss a moderator (owner only). Appointing also
    /// makes them a member — a moderator who cannot enter the channel is
    /// useless — and dismissal leaves membership intact.
    function setModerator(address user, bool enabled) external onlyOwner {
        if (user == address(0)) revert ZeroAddress();
        if (user == owner) revert InvalidParams();
        moderators[user] = enabled;
        if (enabled) {
            everMember[user] = true;
            if (mode == Mode.NONE) {
                allowlist[user] = true;
            }
        }
        emit ModeratorSet(user, enabled);
    }

    // -------------------------------------------------------------- ownership

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        address previous = owner;
        owner = newOwner;
        everMember[newOwner] = true;
        if (mode == Mode.NONE) {
            allowlist[newOwner] = true;
        }
        emit OwnershipTransferred(previous, newOwner);
    }
}
