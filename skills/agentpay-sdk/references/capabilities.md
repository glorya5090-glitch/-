# Capabilities

## Use These Commands

- One-click bootstrap: `curl -fsSL https://wlfi.sh | bash`
- One-click skills only: `curl -fsSL https://wlfi.sh | bash -s -- --skills-only`
- One-click update: rerun `curl -fsSL https://wlfi.sh | bash`
- Source install or update: `pnpm install && npm run build && npm run install:cli-launcher && npm run install:rust-binaries`
- Show config: `agentpay config show --json`
- Reuse wallet: `agentpay wallet --json`
- Set up wallet: `agentpay admin setup`
- Reuse existing wallet during setup recovery: `agentpay admin setup --reuse-existing-wallet`
- Restore wallet from encrypted backup: `agentpay admin setup --restore-wallet-from <PATH>`
- Export encrypted wallet backup: `agentpay admin wallet-backup export --output <PATH>`
- Verify encrypted wallet backup: `agentpay admin wallet-backup verify <PATH>`
- Open policy TUI: `agentpay admin tui`
- Check native balance: `agentpay rpc balance --address <ADDRESS> --rpc-url <RPC_URL> --json`
- Check ERC-20 balance: `agentpay rpc balance --address <ADDRESS> --token <TOKEN> --rpc-url <RPC_URL> --json`
- Generate funding QR payload: `node scripts/prepare-funding-request.mjs --address <ADDRESS> --chain-id <CHAIN_ID> --network-name <NAME> --json`
- Set default token policy: `agentpay admin token set-chain <tokenKey> <chainKey> --per-tx <amount> --daily <amount> --weekly <amount>`
- Add manual approval policy: `agentpay admin add-manual-approval-policy --network <id> --min-amount-wei <wei> --max-amount-wei <wei> ...`
- List manual approval requests: `agentpay admin list-manual-approval-requests`
- Approve manual approval request: `agentpay admin approve-manual-approval-request`
- Resume approved broadcast-backed manual approval request: `agentpay admin resume-manual-approval-request --approval-request-id <UUID>`
- Reject manual approval request: `agentpay admin reject-manual-approval-request`
- Native transfer: `agentpay transfer-native --network <name> --to <address> --amount <amount>`
- ERC-20 transfer: `agentpay transfer --network <name> --token <address> --to <address> --amount <amount>`
- Approve allowance: `agentpay approve --network <name> --token <address> --spender <address> --amount <amount>`
- Policy-checked raw tx request: `agentpay broadcast --network <name> --to <address> --value-wei <wei> ...`
- Explicit sign and send: `agentpay tx broadcast --network <name> --rpc-url <url> --from <address> --to <address> --value-wei <wei> ...`

## Hard Rules

- Never ask the user to paste `VAULT_PASSWORD` into chat.
- Never ask the user to paste a wallet backup password into chat.
- Do not ask the user for a vault password before policy or admin mutations.
- For setup and agent-auth admin flows, use a local secure prompt.
- For policy changes, default to `agentpay admin tui`.
- `agentpay admin setup` should be run locally so the CLI can prompt securely if needed.
- `agentpay wallet --json` is the wallet reuse check.
- If the wallet exists and the user wants to preserve it while re-running setup, use `agentpay admin setup --reuse-existing-wallet`.
- If the machine is new or the local wallet is gone and the user has a backup, use `agentpay admin setup --restore-wallet-from <PATH>`.
- If the user does not specify network or asset for a payment, default to `USD1` on `bsc`.
- If a request enters manual approval, say it is pending user approval instead of saying it failed.
- For manual approval, prefer the local admin CLI approval commands.
- For `transfer --broadcast`, `transfer-native --broadcast`, `approve --broadcast`, and `bitrefill buy --broadcast`, tell the user to keep the original command running after they approve locally.
- If the original broadcast command is already gone after approval, use `agentpay admin resume-manual-approval-request --approval-request-id <UUID>`.
- `transfer-native`, `transfer`, and `approve` use `--amount`, not `--amount-wei`.
- `broadcast` and `tx broadcast` use wei-denominated fields such as `--value-wei`.
- `transfer-native`, `transfer`, `approve`, and `bitrefill buy` can also broadcast immediately with `--broadcast`.
- For Bitrefill quote and preview output, `amount` is the raw onchain base-unit integer, not a human-decimal amount. Example: ETH base units are wei, and `amount: 1000000` with `decimals: 6` means `1 USDC`.
- Destination overrides still belong to `agentpay admin tui`.
- If the user only asks what the skill can do, answer directly from the skill instead of probing the machine.

## Secure Paths

- Setup: `agentpay admin setup`
- Setup recovery with the same vault: `agentpay admin setup --reuse-existing-wallet`
- Policy editing: `agentpay admin tui`
- Manual approval: `agentpay admin list-manual-approval-requests`

## Built-In Defaults

- built-in chain: `bsc` -> chain id `56` -> default RPC `https://bsc.drpc.org`
- built-in token: `bnb` -> native BSC asset
- built-in token: `usd1` -> mapped on `eth` and `bsc`
- default payment asset when unspecified: `usd1` on `bsc` -> `0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d`

## Do Not Say

- Do not claim the wallet address can always be reconstructed from config alone.
- Do not claim the SDK knows how to buy app-specific assets without another app skill.
- Do not claim destination overrides were applied unless the TUI path was actually used.
- Do not keep trying to send when native gas is missing.
