# Chain-Hopping and DEX

## 1. Overview

Chain-hopping is the practice of moving value across multiple
blockchains to break the on-chain link between the source and
the destination. Because each blockchain has its own ledger,
an observer who follows one chain loses track of the value
when it crosses to another chain. The bridge, exchange, or
swap service that performs the conversion sees both sides,
but the two public ledgers do not.

Decentralized exchanges (DEXs) are a common tool for
chain-hopping. They allow a user to swap one asset for
another without a custodial intermediary, using on-chain
liquidity pools or order books. The swap is recorded on the
destination chain, but the link to the source chain is only
visible to the DEX's smart contract and to anyone who can
correlate the two sides.

This file covers:

- The technical design of cross-chain bridges and DEXs.
- The traces they leave on both chains.
- The operational security that matters for chain-hopping.
- The attacks against chain-hopping infrastructure.
- The legal and ethical boundaries.

This is the fifth file in the **Anonymous Crypto Operations
and AML** subcategory.

## 2. Threat Model

The threat model for chain-hopping is different from the
threat model for a single chain. The adversary is:

| Threat | Effect on chain-hopping |
|--------|--------------------------|
| On-chain link between source and destination | Mitigated if the bridge or DEX does not keep logs |
| Bridge or DEX logging | NOT mitigated - the service sees both sides |
| Bridge or DEX compromise | NOT mitigated - the service can be hacked |
| Bridge or DEX legal process | NOT mitigated - the service's records can be subpoenaed |
| Chain-analysis correlation across chains | Partially mitigated - vendors are getting better at cross-chain analysis |
| Timing correlation | Partially mitigated - delays help, but the swap is observable |
| Amount correlation | Partially mitigated - amounts can be split or randomized |
| Network-level analysis | NOT mitigated - the service sees your IP unless you use Tor |
| Liquidity and slippage | NOT mitigated - a large swap moves the price |
| Smart contract bugs | NOT mitigated - a buggy bridge can lose your funds |

**What chain-hopping does NOT protect against:**

- A bridge or DEX that keeps logs and later discloses them.
- A chain-analysis vendor that has cross-chain heuristics.
- Timing correlation if you swap and spend immediately.
- Your own operational-security mistakes: reusing an address,
  broadcasting from your home IP, using a KYC-linked wallet.
- A smart contract exploit that drains the bridge.
- A DEX that is sanctioned or fronted by law enforcement.

## 3. How It Works (technical)

**Cross-chain bridges.**

A bridge is a service that locks value on one chain and
issues equivalent value on another chain. The two main
designs are:

- **Lock-and-mint.** The user locks coins in a contract on
  Chain A. The bridge mints equivalent coins on Chain B.
  To go back, the user burns the coins on Chain B and the
  contract on Chain A unlocks the original coins.
- **Liquidity pools.** The bridge holds liquidity on both
  chains. The user deposits on Chain A and the bridge
  releases from its pool on Chain B. The bridge rebalances
  its pools over time.

The bridge sees the deposit address on Chain A and the
withdrawal address on Chain B. If it keeps logs, the link
is recoverable. If it does not keep logs, the link is only
visible on the two public chains as two separate events.

**Decentralized exchanges (DEXs).**

A DEX is a smart contract or a set of contracts that allow
users to swap one asset for another without a custodial
intermediary. The two main designs are:

- **Automated Market Makers (AMMs).** A liquidity pool
  with two or more assets. The price is determined by a
  formula (e.g. constant product `x * y = k`). The user
  swaps against the pool.
- **Order books.** A traditional order book implemented
  on-chain. The user matches against another user's order.

The DEX sees the swap on-chain. If the DEX is on the same
chain as the source asset, the link between the source and
the destination is visible to anyone who analyzes the
chain. If the DEX is on a different chain (e.g. a
cross-chain DEX), the link is only visible to the DEX's
contracts.

**Chain-hopping patterns.**

The most common chain-hopping patterns are:

- **Bridge then DEX.** Move coins across a bridge, then
  swap on a DEX on the destination chain.
- **DEX then bridge.** Swap on a DEX, then bridge the
  proceeds to another chain.
- **Multiple hops.** Repeat the pattern across several
  chains.
- **Privacy coin hop.** Move coins into Monero, then out
  to a different chain. The Monero hop breaks the link
  more effectively than a bridge, because Monero's
  ledger is private.
- **Centralized exchange hop.** Move coins to a
  centralized exchange, trade, and withdraw to a
  different chain. The exchange sees both sides and
  keeps KYC records.

**Traces left.**

- **On the source chain.** The deposit to the bridge or
  the swap on the DEX. The source address, the amount,
  and the timestamp are public.
- **On the destination chain.** The withdrawal from the
  bridge or the swap on the DEX. The destination
  address, the amount, and the timestamp are public.
- **Off-chain.** The bridge's or DEX's logs, the user's
  IP, the user's wallet software, and any other
  metadata.
- **Cross-chain analysis.** Vendors are developing
  heuristics that correlate the two sides using timing,
  amounts, and known bridge and DEX addresses.

## 4. Installation and Setup

This section describes setup for an **authorized engagement or
approved research project**.

**Step 1. Check the legal status.**

Before using any bridge or DEX, check:

- Is the bridge or DEX sanctioned in your jurisdiction or
  in the jurisdiction of the counterparty?
- Is using a DEX itself a regulated activity in your
  jurisdiction?
- Does the engagement's rules of engagement explicitly
  cover the use of a bridge or a DEX?

If the answer to any of these is unclear, do not proceed.

**Step 2. Choose the bridge or DEX.**

- **Reputation.** Prefer bridges and DEXs with a long
  track record and public audits.
- **Liquidity.** Check that the pool has enough liquidity
  for your amount without excessive slippage.
- **Logs.** Prefer services that do not require an account
  and do not advertise logging.
- **Sanctions.** Check the OFAC SDN list and any other
  relevant sanctions lists.
- **Chain.** Prefer chains that are not KYC-gated.

**Step 3. Prepare the source wallet.**

- Use a wallet that does not leak your identity.
- Generate a fresh source address for the swap.
- Do not use an address that is linked to a KYC exchange.

**Step 4. Prepare the destination wallet.**

- Use a wallet that does not leak your identity.
- Generate a fresh destination address for the swap.
- Do not reuse the destination address.

**Step 5. Prepare the network.**

- Use Tor for all interactions with the bridge or DEX.
- Do not broadcast from a home IP, a corporate network, or
  a public Wi-Fi that logs.

**Step 6. Execute the swap.**

Follow the procedure in section 6.

## 5. Hardening and Configuration

Chain-hopping is an operational-security procedure, not a
software configuration. The hardening is in the habits.

**Source hygiene:**

- Do not use an address that is linked to a KYC exchange.
- Do not use the same address for multiple swaps.
- Do not use an address that has been used for personal
  transactions.

**Destination hygiene:**

- Use a fresh destination address for each swap.
- Do not withdraw to an address that is linked to your
  identity.
- Do not consolidate the outputs immediately.

**Service hygiene:**

- Prefer bridges and DEXs that do not require an account.
- Prefer services that do not advertise logging.
- Do not use a bridge or DEX that is sanctioned.
- Do not use a bridge or DEX that has been hacked
  recently without understanding the risk.

**Timing hygiene:**

- Do not swap and spend immediately.
- Add a random delay between the swap and the next
  transaction.
- Do not swap at predictable times.

**Amount hygiene:**

- Split large amounts into multiple smaller swaps.
- Avoid round amounts.
- Do not swap the exact amount you need for a purchase.

**Network hygiene:**

- Use Tor for all interactions.
- Do not use the same network for the source and the
  destination.
- Do not use a VPN that is linked to your identity.

**Operational hygiene:**

- Keep an offline log of the swap (amount, bridge or
  DEX, date, source address, destination address) for
  your own records.
- Do not reuse the same bridge or DEX for multiple
  unrelated swaps.
- Do not discuss the swap on a channel that is linked
  to your identity.

## 6. Operational Usage

**Bridge then DEX:**

1. Choose a bridge that connects the source chain to
   the destination chain.
2. Deposit the source asset to the bridge's contract on
   the source chain.
3. Wait for the bridge to confirm the deposit and issue
   the wrapped asset on the destination chain.
4. Swap the wrapped asset for the desired asset on a
   DEX on the destination chain.
5. Withdraw the desired asset to a fresh destination
   address.
6. Wait for confirmations.
7. Do not spend immediately.

**DEX then bridge:**

1. Swap the source asset for a bridge-compatible asset
   on a DEX on the source chain.
2. Deposit the bridge-compatible asset to the bridge's
   contract.
3. Wait for the bridge to confirm and issue the asset
   on the destination chain.
4. Withdraw to a fresh destination address.
5. Wait for confirmations.
6. Do not spend immediately.

**Multiple hops:**

1. Repeat the bridge-then-DEX or DEX-then-bridge
   pattern across multiple chains.
2. Use a fresh address at each step.
3. Do not reuse the same bridge or DEX across steps
   if you can avoid it.
4. Add delays between steps.

**Privacy coin hop:**

1. Swap the source asset for Monero on a DEX or a
   bridge that supports Monero.
2. Wait for confirmations.
3. Move the Monero through your own wallet.
4. Swap the Monero for the desired asset on a
   different chain.
5. Withdraw to a fresh destination address.
6. Wait for confirmations.
7. Do not spend immediately.

## 7. Common Mistakes

- **Using a bridge or DEX that keeps logs.** The service
  sees both sides.
- **Using a sanctioned bridge or DEX.** Using a
  sanctioned service is a criminal offense in most
  jurisdictions.
- **Using the same address for multiple swaps.** The
  address links the swaps.
- **Swapping and spending immediately.** Timing
  correlation is a real risk.
- **Reusing the destination address.** The address
  links the outputs.
- **Consolidating the outputs immediately.** The
  consolidation links them.
- **Using a bridge or DEX that has been hacked
  recently.** The funds may be lost.
- **Not using Tor.** The service sees your IP.
- **Not keeping an offline log.** You will not
  remember the details later.
- **Assuming the swap makes the coins legally clean.**
  It does not. Exchanges may flag coins that have
  passed through a bridge or DEX.

## 8. Attacks Against It

Chain-hopping infrastructure is attacked by:

- **Bridge exploits.** Bridges are high-value targets.
  Several major bridges have been hacked, with losses
  in the hundreds of millions of dollars. Examples
  include Wormhole, Ronin, and Nomad.
- **DEX exploits.** DEXs are also targets. Common
  exploits include reentrancy, price manipulation,
  and flash loans.
- **Smart contract bugs.** A bug in the bridge or DEX
  contract can result in loss of funds.
- **Front-running.** A malicious actor can see your
  swap in the mempool and trade ahead of you to
  profit from the price impact.
- **Sandwich attacks.** A form of front-running
  specific to AMMs.
- **Chain-analysis correlation.** Vendors are
  developing heuristics that link the source and the
  destination across chains.
- **Legal process.** The bridge or DEX's records can
  be subpoenaed.
- **Sanctions screening.** Using a sanctioned bridge
  or DEX is a crime, and the resulting coins may be
  flagged.
- **Exchange flagging.** Some exchanges flag coins
  that have passed through a bridge or DEX.
- **Network-level analysis.** The service sees your
  IP unless you use Tor.

## 9. Detection (Blue Team)

Chain-analysis firms and law enforcement use a combination
of techniques against chain-hopping:

- **Cross-chain correlation.** Heuristics that link the
  source and destination using timing, amounts, and
  known bridge and DEX addresses.
- **Bridge and DEX labeling.** Known bridge and DEX
  addresses are labeled in chain-analysis databases.
- **Sanctions screening.** Sanctioned bridge and DEX
  addresses are flagged.
- **Exchange reporting.** Exchanges report
  transactions with known bridges and DEXs as
  suspicious in some cases.
- **Network-level analysis.** Correlating the user's
  traffic with IP addresses.
- **Endpoint forensics.** Seized devices reveal the
  wallet and the transaction history.
- **Off-chain intelligence.** Human intelligence,
  informants, and documents.
- **Bridge and DEX logs.** If the service keeps logs
  and they are recovered, the link is direct.

For a defender or researcher, the practical output is a
cluster of addresses on multiple chains and, if the
service's logs are recovered, a full link between the
source and the destination.

## 10. Case Studies

**Case 1 - Wormhole bridge exploit.** In February 2022,
the Wormhole bridge was exploited for approximately
$320 million. The attacker minted wrapped ETH without
depositing collateral. The bridge was patched and the
funds were partially recovered, but the case illustrates
the risk of bridge exploits.

**Case 2 - Ronin bridge exploit.** In March 2022, the
Ronin bridge (used by Axie Infinity) was exploited for
approximately $625 million. The attacker compromised
private keys used to validate bridge transactions. The
FBI attributed the attack to the Lazarus Group. The
case illustrates the risk of centralized validation in
bridges.

**Case 3 - Nomad bridge exploit.** In August 2022, the
Nomad bridge was exploited for approximately $190
million. A bug in the contract allowed anyone to
withdraw funds by copying a valid transaction. The
case illustrates the risk of smart contract bugs.

**Case 4 - Cross-chain chain analysis.** A chain-analysis
vendor published a report showing that it could link
source and destination addresses across a major bridge
using timing and amount correlation. The report is a
useful reference for understanding the limits of
chain-hopping.

**Case 5 - Authorized engagement.** A red team used a
bridge and a DEX to move funds for a client
engagement. The team used fresh addresses on both
chains, Tor for all interactions, and a random delay
between the swap and the next transaction. At the end
of the engagement, the wallets were destroyed and the
log was handed to the client. The engagement report
documented the chain-hopping path and the teardown.

## 11. Legal and Ethical Notes

Chain-hopping sits at the intersection of several legal
regimes:

- **Sanctions.** Several bridges and DEXs have been
  sanctioned by OFAC. Using a sanctioned service is a
  criminal offense in most jurisdictions.
- **Money transmission.** In some jurisdictions,
  operating a bridge or DEX without a license is
  money transmission and is a criminal offense. Using
  one may also be regulated.
- **AML.** Regulated exchanges report transactions
  with known bridges and DEXs as suspicious in some
  cases. The FATF travel rule requires virtual asset
  service providers to share sender and receiver
  information for transfers above a threshold.
- **Securities law.** Some tokens traded on DEXs may
  be considered securities in some jurisdictions.
  Trading them may be regulated.
- **Tax.** In most jurisdictions, swaps are taxable
  events, and the tax authority expects records.
- **Authorization.** For an engagement, the client's
  rules of engagement must explicitly cover the use
  of a bridge or a DEX. Do not assume that "the
  client asked for a red team" includes permission
  to use a bridge or a DEX.
- **Ethical boundary.** Chain-hopping is used by
  criminal actors. Using it for authorized work is
  not itself unethical, but it can create the
  appearance of association. Be transparent with
  the client and document the choice.

**Do not use chain-hopping for:**

- Money laundering.
- Sanctions evasion.
- Financing illegal activity.
- Any activity outside an authorized engagement or
  approved research project.
- Anything that would expose the client to legal
  risk they did not agree to.

## 12. Production Notes

- **Cost.** Bridge fees are typically 0.1-1% plus
  gas. DEX fees are typically 0.05-0.3% plus gas.
  Gas costs vary with network congestion.
- **Speed.** Bridge confirmations can take minutes to
  hours. DEX swaps are usually fast on the
  destination chain.
- **Counterparty risk.** The bridge or DEX is a
  smart contract. Its security depends on the
  quality of the code and the audits.
- **Record-keeping.** Keep an offline log of every
  swap (amount, bridge or DEX, date, source
  address, destination address) for your own
  records.
- **Teardown.** At the end of an engagement,
  destroy the wallets, destroy the log, and
  document the destruction.
- **Migration.** If a bridge or DEX is suspected
  of being compromised or sanctioned, switch to a
  different service.

## 13. References

- OFAC sanctions list (for sanctioned bridges and
  DEXs).
- FATF guidance on virtual assets and money
  transmission.
- Chainalysis, Elliptic, and TRM reports on
  cross-chain analysis.
- Academic papers on cross-chain bridges and DEX
  security.
- Post-mortem reports for Wormhole, Ronin, and
  Nomad exploits.
- Documentation for major bridges and DEXs.
- The client's rules of engagement document (for
  authorized engagements).
