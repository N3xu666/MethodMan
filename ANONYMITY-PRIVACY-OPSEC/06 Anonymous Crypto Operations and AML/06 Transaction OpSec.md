# Transaction OpSec

## 1. Overview

Transaction OpSec is the set of habits and decisions that
determine what an observer can learn from your on-chain
activity, beyond what the protocol itself reveals. It covers
address hygiene, timing, amounts, fees, metadata, and the
off-chain context that surrounds every transaction.

Most real-world de-anonymization does not happen because a
cryptocurrency's cryptography is broken. It happens because
the user made an operational mistake: reused an address,
transacted in round amounts, broadcast from a home IP, posted
about the transaction on social media, or funded a wallet
from an account linked to their identity.

This file is about those mistakes and how to avoid them. It
applies to every cryptocurrency: Bitcoin, Monero, Ethereum,
and any other chain. The protocol-specific details are in the
individual files (Monero, Bitcoin, Mixers, etc.); this file
is about the habits that apply to all of them.

This is the sixth file in the **Anonymous Crypto Operations
and AML** subcategory.

## 2. Threat Model

Transaction OpSec is not a single technique; it is a set of
habits that reduce the information an observer can collect.
The adversary is:

| Threat | Effect of good transaction OpSec |
|--------|----------------------------------|
| Address reuse | Mitigated - use a fresh address per transaction |
| Amount fingerprinting | Mitigated - avoid round amounts |
| Timing fingerprinting | Mitigated - randomize timing |
| Fee fingerprinting | Partially mitigated - use standard fee rates |
| Network-level analysis | Mitigated by Tor, I2P, or a trusted VPN |
| Wallet fingerprinting | Partially mitigated - choose a wallet with a large anonymity set |
| Off-chain correlation | Mitigated by separating identities across contexts |
| UTXO contamination | Mitigated by coin control |
| Exchange KYC | NOT mitigated - the exchange's records are outside your control |
| Legal process | NOT mitigated - transaction OpSec is not a legal shield |
| Endpoint compromise | NOT mitigated - malware can steal keys regardless of your habits |

**What transaction OpSec does NOT protect against:**

- A KYC exchange that records the purchase and the withdrawal
  address.
- A chain-analysis vendor that already has your cluster
  labeled.
- A counterparty who is an informant or an undercover officer.
- A compromised device or a compromised wallet.
- A legal order that compels a service to disclose your
  records.
- Your own mistakes: reusing a pseudonym, posting about a
  transaction, or transacting from a network that is linked
  to your identity.

## 3. How It Works (technical)

Transaction OpSec is a set of principles. Each principle
reduces a class of information leakage.

**Principle 1: Address uniqueness.**

Every incoming payment should go to a fresh address. Address
reuse is the single most damaging mistake in Bitcoin and
similar transparent chains: it links every transaction that
touches the address. In Monero, stealth addresses make this
automatic, but the principle still applies to the wallet
level: do not reuse the same wallet for unrelated contexts.

**Principle 2: UTXO separation.**

In UTXO-based chains (Bitcoin, Litecoin, and similar), each
unspent output has a history. Spending two UTXOs from
different contexts in the same transaction links those
contexts permanently. Use coin control to keep contexts
separate.

**Principle 3: Amount hygiene.**

Round amounts are fingerprints. If you always send 1.0 BTC or
0.5 ETH, an observer can link your transactions by amount.
Pay exact amounts, or add a small random amount to break the
pattern.

**Principle 4: Timing hygiene.**

Transaction timing is observable. If you always transact at
the same time of day or on the same day of the week, an
observer can link your transactions by timing. Randomize the
timing of your transactions. Add delays between the receipt
of funds and the spend.

**Principle 5: Fee hygiene.**

Fee selection is a fingerprint. Wallets that use a specific
fee algorithm produce transactions that are statistically
distinguishable from other wallets. Use a wallet with a
large anonymity set, or manually set the fee to a common
value.

**Principle 6: Network hygiene.**

The network sees your IP when you broadcast a transaction.
Use Tor, I2P, or a trusted VPN to hide it. Do not broadcast
from a network that is linked to your identity: home IP,
corporate network, public Wi-Fi with a captive portal.

**Principle 7: Wallet hygiene.**

Different wallets produce different transaction patterns.
Wallets that leak addresses to third-party servers, that
reuse addresses, or that do not support coin control are
privacy risks. Choose a wallet that gives you control and
does not leak.

**Principle 8: Off-chain separation.**

The on-chain transaction is only one part of the picture.
Your email, your phone number, your social media accounts,
and your forum handles are all part of your identity. Keep
them separate from your on-chain activity. Do not use the
same email for a KYC exchange and a peer-to-peer trade. Do
not post about a transaction on a channel that is linked
to your identity.

**Principle 9: Context separation.**

Use a different wallet, a different address, and a different
identity for every context. Personal funds, work funds, and
engagement funds should never share a wallet. If one context
is compromised, the others should be unaffected.

**Principle 10: Minimize on-chain footprint.**

Every on-chain transaction is a permanent record. Minimize
the number of transactions you make. Consolidate only when
necessary. Use off-chain solutions (Lightning, sidechains,
or centralized services) when the privacy trade-off is
acceptable.

## 4. Installation and Setup

This section describes setup for an **authorized engagement or
approved research project**.

**Step 1. Define your contexts.**

List every context in which you will use cryptocurrency:

- Personal savings.
- Work expenses.
- Engagement funds.
- Research funds.
- Donations.

Each context gets its own wallet.

**Step 2. Define your identities.**

For each context, define:

- A dedicated email address.
- A dedicated communication channel.
- A dedicated payment method.
- A dedicated device or VM if possible.

Do not share identities across contexts.

**Step 3. Choose your wallets.**

For each context, choose a wallet that:

- Runs a full node or connects to your own node.
- Supports coin control.
- Does not leak addresses to third-party servers.
- Supports the privacy features you need (Tor, CoinJoin,
  PayJoin).

**Step 4. Set up your network.**

For each context, define:

- How you broadcast transactions (Tor, I2P, or a trusted
  VPN).
- How you access your wallet (a dedicated device or VM).
- How you store your seeds (offline, physically secure).

**Step 5. Set up your record-keeping.**

Keep an offline log of:

- Every address you generate.
- Every transaction you make (amount, date, counterparty
  if known).
- Every payment method you use.
- Every identity you use.

This log is for your own records, for the engagement report,
and for tax purposes.

## 5. Hardening and Configuration

Transaction OpSec is a habit, not a software configuration.
The hardening is in the discipline.

**Daily habits:**

- Generate a fresh address for every incoming payment.
- Use coin control to select which UTXOs to spend.
- Avoid round amounts.
- Randomize the timing of transactions.
- Use a standard fee rate.
- Broadcast through Tor or I2P.
- Keep your contexts separate.

**Weekly habits:**

- Review your transaction log.
- Check for address reuse.
- Check for UTXO contamination.
- Check for unexpected transactions.
- Update your wallet software.

**Monthly habits:**

- Rotate your receiving addresses.
- Review your identities for cross-context leaks.
- Review your network setup.
- Test your backup and restore procedure.
- Review the legal and regulatory landscape.

**Engagement-specific habits:**

- Document every transaction in the engagement log.
- Do not commingle engagement funds with personal funds.
- Do not reuse wallets or identities across engagements.
- Destroy wallets and seeds at the end of the engagement.
- Document the destruction for the client.

## 6. Operational Usage

**Receiving funds:**

1. Generate a fresh address.
2. Give the address to the sender.
3. Verify the amount in your own wallet, not in a block
   explorer.
4. Wait for the required number of confirmations.
5. Label the UTXO in your wallet with its source and
   context.

**Sending funds:**

1. Determine the amount and the recipient.
2. Use coin control to select the UTXOs to spend. Do not
   spend UTXOs from different contexts in the same
   transaction.
3. Choose a fresh change address (most wallets do this by
   default; verify it).
4. Set the fee to a standard rate.
5. Verify the recipient address in the wallet, not in the
   clipboard.
6. Broadcast through Tor or I2P.
7. Verify the transaction in your own node, not in a block
   explorer.
8. Wait for the required number of confirmations.

**Consolidating UTXOs:**

1. Consolidate only when necessary.
2. Consolidate within a single context.
3. Do not consolidate across contexts.
4. Use a fresh change address.
5. Broadcast through Tor or I2P.

**Cross-chain operations:**

1. Follow the procedures in the relevant files (Mixers,
   Chain-Hopping).
2. Keep the source and destination contexts separate.
3. Add delays between steps.
4. Do not reuse addresses across chains.

## 7. Common Mistakes

- **Reusing an address.** The single most damaging
  mistake.
- **Spending UTXOs from different contexts in the same
  transaction.** This links the contexts permanently.
- **Using round amounts.** Round amounts are fingerprints.
- **Transacting at predictable times.** Timing is
  observable.
- **Using a non-standard fee rate.** Fee selection is a
  fingerprint.
- **Broadcasting from a home IP or a corporate network.**
  The network sees your IP.
- **Using the same email for multiple contexts.** Email
  addresses link identities.
- **Posting about a transaction on social media.** Off-chain
  correlation is the most common real-world
  de-anonymization vector.
- **Reusing a wallet after a suspected compromise.**
- **Not keeping an offline log.** You will not remember the
  details later.
- **Assuming that transaction OpSec makes you anonymous.**
  It reduces information leakage; it does not eliminate it.

## 8. Attacks Against It

Transaction OpSec is attacked by:

- **Chain-analysis clustering.** Vendors use heuristics
  (common-input-ownership, change detection, address
  reuse, peeling chains, consolidation) to cluster
  addresses.
- **Network-level analysis.** An adversary who controls
  many nodes can correlate transactions with IP
  addresses. Tor mitigates but does not eliminate this.
- **Off-chain correlation.** An observer who sees both the
  on-chain transaction and a real-world event can link
  the two.
- **Endpoint compromise.** Malware on the wallet device can
  steal the seed, replace the recipient address in the
  clipboard, or redirect the transaction.
- **Social engineering.** An attacker who knows your
  identity can trick you into revealing information about
  your transactions.
- **Legal process.** A subpoena to a service you used can
  reveal your records.
- **Wallet fingerprinting.** Different wallets produce
  slightly different transactions.
- **Timing correlation.** An observer correlates the timing
  of your transactions with known events.
- **Amount correlation.** An observer correlates the
  amounts of your transactions with known prices or
  invoices.
- **Data leaks.** A service you used may be breached, and
  your records may be exposed.

## 9. Detection (Blue Team)

Chain-analysis firms and law enforcement use a combination
of techniques to defeat transaction OpSec:

- **Heuristic clustering.** Common-input-ownership, change
  detection, peeling chains, consolidation, address reuse.
- **Known-entity labeling.** Exchanges, mixers, darknet
  markets, and sanctioned addresses are labeled.
- **Temporal analysis.** Correlation of transaction times
  with known events.
- **Amount analysis.** Round amounts and distinctive
  amounts are fingerprints.
- **Network-level analysis.** Running many nodes and
  correlating transactions with IP addresses.
- **Exchange records.** A subpoena to an exchange reveals
  who bought and when.
- **Endpoint forensics.** Seized devices reveal the wallet,
  the seed, and the transaction history.
- **Off-chain intelligence.** Human intelligence,
  informants, and documents.
- **Social media analysis.** Posts that correlate with
  on-chain activity.
- **Data-broker records.** Commercial data brokers sell
  identity data that can be correlated with on-chain
  activity.

For a defender or researcher, the practical output is a
cluster of addresses linked to a real-world entity, and a
report that documents the methodology and the confidence
level.

## 10. Case Studies

**Case 1 - Address reuse.** A user published a static
Bitcoin address on a website and used it for every incoming
payment. A chain-analysis vendor linked all the payments to
the same entity and, through off-chain intelligence, to the
user's real identity.

**Case 2 - UTXO contamination.** A user bought BTC on a KYC
exchange and later combined that UTXO with a non-KYC UTXO
in the same transaction. The chain-analysis vendor labeled
the whole transaction as KYC-associated, contaminating the
non-KYC funds.

**Case 3 - Social media correlation.** A user posted a
screenshot of a transaction confirmation on social media.
The screenshot included the transaction ID. A researcher
correlated the transaction ID with the user's other
on-chain activity and, through the user's public profile,
with their real identity.

**Case 4 - Network-level analysis.** A user broadcast a
transaction from their home IP. A chain-analysis vendor
that runs many nodes observed the transaction propagation
and correlated the first node to see it with the user's
IP. The vendor's records linked the transaction to the
user's real identity.

**Case 5 - Authorized engagement.** A red team followed
transaction OpSec best practices throughout a client
engagement: fresh addresses, coin control, separated
contexts, Tor broadcast, and an offline log. At the end of
the engagement, the wallets were destroyed and the log was
handed to the client. The engagement report documented
the transaction OpSec practices and the teardown.

## 11. Legal and Ethical Notes

Transaction OpSec is legal in most jurisdictions, but the
legal landscape is complex:

- **AML.** Regulated exchanges are required to report
  suspicious transactions. Some patterns (structuring,
  rapid movement of funds, use of mixers) trigger
  reporting.
- **Sanctions.** Some addresses are on sanctions lists.
  Transacting with a sanctioned address is a criminal
  offense in most jurisdictions.
- **Tax.** In most jurisdictions, cryptocurrency
  transactions are taxable events, and the tax authority
  expects records.
- **Money transmission.** In some jurisdictions,
  receiving and sending cryptocurrency on behalf of
  others may be considered money transmission and may
  require a license.
- **Authorization.** For an engagement, the client's
  rules of engagement must explicitly cover the use of
  cryptocurrency and the transaction OpSec practices.
  Do not assume that "the client asked for a red team"
  includes permission to use cryptocurrency.
- **Ethical boundary.** Transaction OpSec is used by
  criminal actors. Using it for authorized work is not
  itself unethical, but it can create the appearance of
  association. Be transparent with the client and
  document the choice.

**Do not use transaction OpSec for:**

- Money laundering.
- Sanctions evasion.
- Financing illegal activity.
- Any activity outside an authorized engagement or
  approved research project.
- Anything that would expose the client to legal risk
  they did not agree to.

## 12. Production Notes

- **Cost.** Transaction OpSec has no direct cost, but it
  may increase transaction fees (e.g. using a standard
  fee rate instead of a low one).
- **Speed.** Randomizing timing and adding delays slows
  down transactions. Budget for this in the engagement
  timeline.
- **Complexity.** Managing separate contexts, wallets,
  and identities is complex. Plan for it and document
  it.
- **Record-keeping.** Keep an offline log of every
  transaction for the client's report and for your own
  legal protection.
- **Teardown.** At the end of an engagement, destroy
  the wallets, destroy the log, and document the
  destruction.
- **Migration.** If a context is suspected of being
  compromised, abandon it and create a new one.

## 13. References

- Bitcoin Wiki on privacy and coin control.
- Monero Project documentation on wallet hygiene.
- Academic papers on Bitcoin and Monero
  de-anonymization (heuristics, network-level
  analysis, off-chain correlation).
- Chainalysis, Elliptic, and TRM reports on
  transaction analysis.
- FATF guidance on virtual assets.
- Privacy-focused wallet documentation (Wasabi,
  Samourai, Sparrow, Feather).
- The client's rules of engagement document (for
  authorized engagements).
