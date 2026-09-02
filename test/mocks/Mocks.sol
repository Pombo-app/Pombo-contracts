// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("Mock Token", "MOCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external {
        _burn(from, amount);
    }
}

contract MockERC20Permit is ERC20Permit {
    constructor() ERC20("Mock Permit Token", "MOCKP") ERC20Permit("Mock Permit Token") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// Minimal balanceOf-only token whose balanceOf can be switched to revert —
/// models a paused token or a proxy upgraded to nothing, after the gate
/// already validated the interface at initialize.
contract MockBreakableToken {
    mapping(address => uint256) private _balances;
    bool public broken;

    function setBalance(address user, uint256 balance) external {
        _balances[user] = balance;
    }

    function setBroken(bool broken_) external {
        broken = broken_;
    }

    function balanceOf(address user) external view returns (uint256) {
        require(!broken, "token broken");
        return _balances[user];
    }
}

contract MockERC721 is ERC721 {
    uint256 private _nextId = 1;

    constructor() ERC721("Mock NFT", "MNFT") {}

    function mint(address to) external returns (uint256 id) {
        id = _nextId++;
        _mint(to, id);
    }

    function burn(uint256 id) external {
        _burn(id);
    }
}
