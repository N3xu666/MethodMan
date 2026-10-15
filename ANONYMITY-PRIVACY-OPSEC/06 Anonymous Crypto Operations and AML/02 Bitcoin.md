# Bitcoin

## 1. Overview

Bitcoin (BTC) is the first and largest cryptocurrency. Its design
prioritizes transparency and verifiability over privacy: every
transaction is public, permanent, and linked to the addresses that
participated in it. The full transaction graph is visible to anyone
who runs a node or queries a block explorer.

This is the opposite of Monero's design. Where Monero tries to make
every transaction unlinkable, Bitcoin makes every transaction
linkable by default. Privacy on Bitcoin is not a property of the
protocol; it is a property of how carefully the user manages
addresses, UTXOs, and off-chain metadata.

Despite this, Bitcoin is widely used, and a large fraction of
criminal and gray-area activity still uses it, because it is liquid
and accepted almost everywhere. Understanding Bitcoin's privacy
model is therefore essential for anyone working on the defensive or
offensive side of blockchain analysis.

This file covers the Bitcoin ledger, the UTXO model, the privacy
techniques that partially mitigate Bitcoin's transparency
(CoinJoin, PayJoin, Lightning, Taproot), and the operational
hygiene that matters.

This is the second file in the **Anonymous Crypto Operations and
AML** subcategory, after Monero.

## 2. Threat Model

Bitcoin is designed against double-spending and forgery, not
against surveillance. The threat model for a privacy-conscious
Bitcoin user is:

| Threat | Effect on Bitcoin |
|--------|-------------------|
| Public ledger analysis | NOT mitigated - every transaction is public |
| Address reuse | NOT mitigated - reusing an address links all its transactions |
| Change address identification | Partially mitigated by good wallet hygiene, but heuristics are strong |
| Common-input-ownership heuristic | NOT mitigated - inputs spent together are assumed to belong to one entity |
| Exchange KYC | NOT mitigated - the exchange records the purchase and the withdrawal address |
| Network-level traffic analysis | Partially mitigated by Tor, Dandelion (not in Bitcoin Core), and broadcast privacy |
| Off-chain correlation | NOT mitigated - timing, amounts, and IP are all leak vectors |
| Chain analysis vendors | NOT mitigated - Chainalysis, Elliptic, TRM all cover Bitcoin extensively |
| Legal process | NOT mitigated - Bitcoin is not a legal shield |

**What Bitcoin does NOT protect against:**

- Reusing an address. This is the single most damaging mistake.
- Combining UTXOs from different contexts in one transaction.
- Buying BTC on a KYC exchange and sending it to a personal wallet.
- Broadcasting from an IP that is linked to your identity.
- Using a wallet that leaks your addresses to a third-party server.
- Leaking amounts and timing through off-chain channels.
- A chain-analysis vendor that already has your cluster labeled.

## 3. How It Works (technical)

**The UTXO model.**

Bitcoin does not have accounts; it has unspent transaction outputs
(UTXOs). A UTXO is a chunk of bitcoin locked to a specific script
(usually a public key hash). To spend it, the owner provides a
signature that satisfies the script. A transaction consumes one or
more UTXOs (inputs) and creates one or more new UTXOs (outputs).

This model is the source of Bitcoin's privacy properties and
problems:

- Every UTXO has a history. Spending it links the new output to the
  old one.
- If multiple UTXOs are spent in the same transaction, an observer
  can reasonably assume they belong to the same entity
  (common-input-ownership heuristic).
- If a transaction has one input and two outputs, one of the
  outputs is usually the payment and the other is the change. The
  change output is often identifiable by its script type, its
  amount, or its position.

**Addresses.**

A Bitcoin address is a human-readable encoding of a script. Modern
addresses are either P2PKH (starts with `1`), P2SH (starts with
`3`), or Bech32 (starts with `bc1`). Reusing an address links all
transactions that touch it.

**The mempool and propagation.**

Transactions are broadcast to the network and held in the mempool
until a miner includes them in a block. The propagation path is
observable: a node that is the first to see a transaction is a
strong candidate for the originator. This is why broadcast privacy
matters.

**Chain analysis heuristics.**

Chain-analysis vendors use several heuristics to cluster addresses:

- **Common-input-ownership.** Inputs spent together are assumed to
  belong to one entity.
- **Change detection.** The output that is not the payment is
  usually the change. Vendors use script type, amount, position,
  and roundness to identify it.
- **Address reuse.** An address that appears in multiple
  transactions links them.
- **Peeling chains.** A series of transactions where a small
  amount is peeled off each time and the rest is sent back as
  change.
- **Consolidation.** A transaction with many inputs is usually a
  consolidation of one entity's UTXOs.
- **Temporal analysis.** Transactions that happen close in time
  are often linked.
- **Amount analysis.** Round amounts and distinctive amounts are
  fingerprints.

**Privacy techniques.**

Several techniques partially mitigate Bitcoin's transparency:

- **CoinJoin.** Multiple parties collaborate on a single
  transaction with multiple inputs and outputs, so an observer
  cannot tell which output belongs to which input. This breaks
  the common-input-ownership heuristic for the participants.
- **PayJoin (P2EP).** The receiver contributes an input to the
  transaction, so the transaction does not look like a normal
  one-input payment. This breaks the common-input-ownership
  heuristic and the change-detection heuristic.
- **Lightning Network.** Off-chain payments that are not
  broadcast to the main chain. On-chain footprint is limited to
  the channel open and close.
- **Taproot.** A 2021 upgrade that makes complex scripts
  indistinguishable from simple payments, and improves
  multisig privacy.
- **Silent Payments.** A 2023 proposal (BIP 352) for
  reusable payment codes that do not reuse addresses.

None of these is a complete solution. CoinJoin in particular has
been targeted by regulators and by chain-analysis vendors, and
some CoinJoin coordinators have been shut down or sanctioned.

## 4. Installation and Setup

This section describes setup for an **authorized engagement or
approved research project**.

**Step 1. Choose a wallet.**

The wallet determines your privacy more than the protocol does.
Key criteria:

- **Runs a full node or connects to your own node.** A wallet
  that queries a third-party server leaks your addresses.
- **Supports coin control.** You must be able to choose which
  UTXOs to spend.
- **Supports PSBT.** Partially Signed Bitcoin Transactions are
  the standard for hardware-wallet workflows.
- **Supports the privacy techniques you need.** CoinJoin,
  PayJoin, Lightning, Taproot.

Recommended: Bitcoin Core (full node, coin control, PSBT) for
desktop; Sparrow or Specter for hardware-wallet workflows.
Mobile wallets are acceptable only for small amounts and only if
they connect to your own node.

**Step 2. Run a full node.**

A full node validates the chain and serves your wallet. It does
not leak your addresses to a third party. Run it on a dedicated
machine or a home server. Use Tor for the node's outbound
connections.

**Step 3. Generate the wallet.**

- Generate the seed offline if possible.
- Write the seed on paper or metal. Do not store it digitally.
- Use a strong passphrase as an additional factor.
- Test the restore procedure before you need it.

**Step 4. Fund the wallet.**

This is the step where most operational-security mistakes happen.
See section 5.

## 5. Hardening and Configuration

Bitcoin privacy is entirely a function of how you manage UTXOs,
addresses, and metadata. The protocol does not help you.

**Address hygiene:**

- Never reuse an address. Generate a fresh one for every
  incoming payment.
- Do not publish a static address. Use a payment code or a
  fresh address per interaction.
- Do not use the same wallet for personal funds and engagement
  funds.

**UTXO hygiene:**

- Use coin control. Label every UTXO with its source and
  context.
- Never combine UTXOs from different contexts in one
  transaction. This is the most common way to link two
  identities.
- Never combine a KYC-acquired UTXO with a non-KYC one. The
  KYC UTXO contaminates the whole transaction.
- Consider a separate wallet per context (personal, work,
  engagement).

**Transaction hygiene:**

- Use PayJoin when possible. It breaks the common-input
  heuristic for the receiver.
- Use CoinJoin carefully. Some coordinators are sanctioned or
  under legal pressure. Understand the legal status in your
  jurisdiction.
- Avoid round amounts. Pay exact amounts or add a small
  random amount.
- Do not transact at predictable times.
- Use a fresh change address. Modern wallets do this by
  default; verify it.

**Network hygiene:**

- Broadcast through Tor. Bitcoin Core supports `-proxy` and
  `-torcontrol`.
- Do not broadcast from a home IP, a corporate network, or a
  public Wi-Fi that logs.
- Consider broadcasting through a different node than the one
  that holds your wallet.

**Device hygiene:**

- Full-disk encryption on the wallet device.
- Hardware wallet for significant amounts.
- No browser, no email, no social media on the wallet device.
- No screenshots of the seed, the addresses, or the wallet.

**Funding hygiene:**

- Do not buy BTC on a KYC exchange and send it directly to
  your wallet. The exchange records the purchase and the
  withdrawal address.
- Prefer peer-to-peer methods (see the Physical and Prepaid
  file in this subcategory) for use cases that require
  anonymity from the exchange.
- Do not fund a wallet from a source that is itself linked to
  your identity.

## 6. Operational Usage

Day-to-day use of Bitcoin for an authorized engagement:

- **Receive.** Generate a fresh address for every incoming
  payment. Verify the amount in your own node, not in a block
  explorer.
- **Spend.** Use coin control to select which UTXOs to spend.
  Use a fresh change address. Verify the transaction before
  broadcast.
- **Confirm.** Wait for at least 3 confirmations for medium-value
  transactions and 6 for high-value ones.
- **Back up.** Back up the wallet descriptor and the seed after
  every significant change. Store the backup offline.
- **Audit.** If the engagement requires an audit trail, document
  every UTXO and every transaction in your offline log.

**Engagement-specific considerations:**

- If the client requires the funds to be returned at the end of
  the engagement, plan the return path in advance and document
  it. Do not commingle engagement funds with personal funds.
- If the engagement uses Bitcoin for a payment to a third party
  (e.g. a bounty), document the payment and the recipient in
  the engagement report.
- If the engagement is time-boxed, schedule the wallet teardown
  and the seed destruction before the engagement starts.

## 7. Common Mistakes

- **Reusing an address.** The single most damaging mistake.
  It links every transaction that touches the address.
- **Combining UTXOs from different contexts.** This links the
  contexts permanently.
- **Buying BTC on a KYC exchange and sending it directly to
  your wallet.** The exchange records the purchase and the
  withdrawal.
- **Using a wallet that queries a third-party server.** The
  server sees your addresses and your IP.
- **Broadcasting from a home IP.** The first node to see your
  transaction is a strong candidate for the originator.
- **Storing the seed digitally.** The seed is the wallet.
- **Using round amounts and predictable timing.**
- **Assuming CoinJoin is enough.** CoinJoin breaks some
  heuristics but not all, and the resulting UTXOs may be
  flagged by chain-analysis vendors.
- **Not waiting for enough confirmations.**
- **Reusing a wallet after a suspected compromise.**

## 8. Attacks Against It

Bitcoin is attacked at the protocol level, the network level, and
the endpoint level:

- **Chain analysis.** Vendors cluster addresses using the
  heuristics described in section 3. Their databases are large
  and their labels are shared with law enforcement.
- **Network-level deanonymization.** An adversary who controls
  many nodes can correlate transactions with IP addresses.
  Broadcasting through Tor mitigates this but does not eliminate
  it.
- **Endpoint compromise.** Malware can steal the seed, replace
  the recipient address in the clipboard, or redirect the
  transaction.
- **Exchange subpoena.** The exchange's KYC records link a
  purchase to a real identity.
- **Payment-processor correlation.** If you buy BTC with a card
  or a bank transfer, the processor's records link the purchase
  to your identity.
- **Off-chain correlation.** An observer who sees both the
  on-chain transaction and a real-world event can link the two.
- **Wallet fingerprinting.** Different wallets produce slightly
  different transactions.
- **Clipboard hijacking.** Malware replaces the recipient
  address in the clipboard. Always verify the address in the
  wallet.
- **CoinJoin deanonymization.** Some CoinJoin implementations
  have been shown to leak information. The Wasabi and Samourai
  coordinators have been targeted by law enforcement.
- **Sanctions screening.** Some addresses are on sanctions
  lists. Transacting with them is a criminal offense in most
  jurisdictions.

## 9. Detection (Blue Team)

Chain-analysis firms and law enforcement use a combination of
techniques against Bitcoin:

- **Heuristic clustering.** Common-input-ownership, change
  detection, peeling chains, consolidation, address reuse.
- **Known-entity labeling.** Exchanges, mixers, darknet
  markets, and sanctioned addresses are labeled.
- **Temporal analysis.** Correlation of transaction times with
  known events.
- **Amount analysis.** Round amounts and distinctive amounts
  are fingerprints.
- **Network-level analysis.** Running many nodes, observing
  transaction propagation, correlating with IP addresses.
- **Exchange records.** The most reliable source: a subpoena
  to an exchange reveals who bought BTC and when.
- **Endpoint forensics.** Seized devices reveal the wallet,
  the seed, and the transaction history.
- **Off-chain intelligence.** Human intelligence, informants,
  and documents.
- **CoinJoin analysis.** Vendors have developed heuristics to
  identify CoinJoin transactions and, in some cases, to
  de-anonymize their participants.

For a defender or researcher, the practical output is a
cluster of addresses linked to a real-world entity, and a
report that documents the methodology and the confidence
level.

## 10. Case Studies

**Case 1 - Address reuse.** A user published a static Bitcoin
address on a website and used it for every incoming payment.
A chain-analysis vendor linked all the payments to the same
entity and, through off-chain intelligence, to the user's real
identity. The on-chain transactions were public from the start.

**Case 2 - UTXO contamination.** A user bought BTC on a KYC
exchange and later combined that UTXO with a non-KYC UTXO in
the same transaction. The chain-analysis vendor labeled the
whole transaction as KYC-associated, contaminating the non-KYC
funds.

**Case 3 - CoinJoin and sanctions.** A user participated in a
CoinJoin with an address that was later sanctioned. The user's
resulting UTXOs were flagged by exchanges, and the user had to
provide documentation of the source of funds to access them.
This case illustrates that CoinJoin does not make the
resulting UTXOs legally clean.

**Case 4 - Authorized engagement.** A red team used Bitcoin to
pay a third-party bounty during a client engagement. The team
bought the BTC through a peer-to-peer method, ran their own
node, used a dedicated wallet for the engagement, and used
PayJoin for the payment. At the end of the engagement, the
wallet was destroyed and the seed was shredded in the presence
of the client's representative. The engagement report
documented the payment path and the teardown.

## 11. Legal and Ethical Notes

Bitcoin is legal in most jurisdictions, but the legal
landscape is complex:

- **KYC and AML.** Regulated exchanges are required to
  identify their customers and to report suspicious
  transactions. The FATF travel rule requires virtual asset
  service providers to share sender and receiver information
  for transfers above a threshold.
- **Sanctions.** Some Bitcoin addresses are on sanctions
  lists. Transacting with a sanctioned address is a criminal
  offense in most jurisdictions.
- **Tax.** In most jurisdictions, Bitcoin transactions are
  taxable events, and the tax authority expects records.
  Keeping an offline log is both an operational-security
  measure and a legal one.
- **CoinJoin legality.** The legal status of CoinJoin varies
  by jurisdiction. Some coordinators have been sanctioned or
  shut down. Understand the status before participating.
- **Authorization.** For an engagement, the client's rules of
  engagement must explicitly cover the use of cryptocurrency.
  Do not assume that "the client asked for a red team"
  includes permission to use Bitcoin.
- **Ethical boundary.** Bitcoin is used by criminal actors.
  Using it for authorized work is not itself unethical, but
  it can create the appearance of association. Be
  transparent with the client and document the choice.

**Do not use Bitcoin for:**

- Money laundering.
- Sanctions evasion.
- Financing illegal activity.
- Any activity outside an authorized engagement or approved
  research project.
- Anything that would expose the client to legal risk they
  did not agree to.

## 12. Production Notes

- **Cost.** Bitcoin transaction fees vary with network
  congestion. Budget for fees on every transaction.
- **Confirmation time.** Roughly 10 minutes per block. Wait
  for at least 3 confirmations for medium-value transactions
  and 6 for high-value ones.
- **Node operation.** Running a full node requires disk space
  (currently hundreds of GB and growing) and bandwidth. Plan
  for it.
- **Wallet backup.** Back up the wallet descriptor and the
  seed after every significant change. Test the restore
  procedure before you need it.
- **Migration.** If you suspect a wallet is linked to your
  identity, abandon it and create a new one. Do not reuse
  the seed.
- **Teardown.** At the end of an engagement, destroy the
  wallet, destroy the seed, and document the destruction.
- **Record-keeping.** Keep an offline log of every transaction
  for the client's report and for your own legal protection.

## 13. References

- Bitcoin Core documentation and BIP repository.
- Bitcoin Wiki on privacy and coin control.
- Academic papers on Bitcoin deanonymization (common-input
  ownership, change detection, network-level analysis).
- Chainalysis, Elliptic, and TRM reports on Bitcoin.
- FATF guidance on virtual assets and the travel rule.
- Documentation for CoinJoin (Wasabi, Samourai, JoinMarket),
  PayJoin (BIP 78), Taproot (BIP 341), and Silent Payments
  (BIP 352).
- The client's rules of engagement document (for authorized
  engagements).
