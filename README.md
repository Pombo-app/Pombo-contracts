# Pombo Contracts

On-chain access gates for [Pombo](https://pombo.cc) channels.

A **PomboGate** is a minimal per-channel membership contract. Each gated
channel deploys one EIP-1167 clone through the factory; the clone address
becomes the channel's publisher identity on the Streamr network, and the
contract answers two questions:

- **`isValidSignature(hash, signature)`** ([ERC-1271]) — is this message from
  someone who was ever a member? Membership is *sticky*: leaving, selling the
  gate asset or letting a subscription expire never invalidates messages
  already published. Only an explicit owner `erase` removes an author's
  history.
- **`checkAccess(user)`** — does this user have access *right now*? This
  drives encryption-key distribution and UI state in the clients, never the
  validity of past messages.

[ERC-1271]: https://eips.ethereum.org/EIPS/eip-1271

## Modes

| Mode | Access rule |
|---|---|
| `NONE` | Owner-managed allowlist (closed channel) |
| `TOKEN_BALANCE` | Hold at least `minBalance` of an ERC-20 |
| `NFT_OWNERSHIP` | Hold at least one token of an ERC-721 |
| `PAID` | Active subscription: `price` of an ERC-20 per `duration`, EIP-2612 permit supported |

In holder modes, `join()` is an optional one-transaction opt-in to permanent
membership — without it, selling the asset also drops the holder's message
history. Owners may appoint **moderators** (`setModerator`), who manage
membership but cannot erase history, touch the owner or other moderators, or
appoint moderators.

## Deployments

Polygon PoS (chain 137):

| Contract | Address |
|---|---|
| `PomboGateFactory` | `0x14595B5F192fA56714D1F8821BD1651dC5bFd1aB` |
| `PomboGate` implementation | `0xE14fE177F0AC116513b9EB9dB753b9e7b9022817` |

> These contracts have **not yet been audited**.

## Development

Built with [Foundry](https://getfoundry.sh).

```sh
forge build
forge test
```

Deploy:

```sh
forge script script/Deploy.s.sol --rpc-url polygon --private-key $DEPLOYER_KEY --broadcast
```

## License

[MIT](LICENSE)
