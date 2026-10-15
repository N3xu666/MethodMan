# Monero

## 1. Overview

Monero (XMR) is a privacy-focused cryptocurrency built around the goal
of making every transaction unlinkable and untraceable by default. It
is the dominant privacy coin and the reference implementation for the
techniques that most other privacy coins copy.

Three properties distinguish Monero from Bitcoin:

- **Sender ambiguity.** Ring signatures mix the real spender with
  decoy outputs, so an observer cannot tell which output was actually
  spent.
- **Receiver ambiguity.** Stealth addresses (one-time public keys)
  ensure that every payment to a wallet goes to a fresh address that
  only the recipient can link to the wallet.
- **Amount confidentiality.** RingCT (Ring Confidential Transactions)
  hides the amount being transferred.

Monero is used by privacy advocates, journalists, and ordinary users
who want financial privacy. It is also used by criminal actors, which
is why it is a priority target for blockchain-analysis firms and law
enforcement. This file covers the technical design, the operational
hygiene that matters, and the limits of what Monero actually protects
against.

This is the first file in the **Anonymous Crypto Operations and AML**
subcategory.

## 2. Threat Model

Monero is designed against a passive observer who sees the whole
blockchain and against a network-level adversary who can see your
traffic. It is not designed against every threat.

| Threat | Effect of Monero |
|--------|------------------|
| Blockchain analysis of sender | Mitigated by ring signatures, but weakened by decoy selection bias |
| Blockchain analysis of receiver | Mitigated by stealth addresses |
| Blockchain analysis of amount | Mitigated by RingCT |
| Network-level traffic analysis | Partially mitigated by Dandelion++ and Tor/I2P support |
| Exchange KYC | NOT mitigated - the exchange knows who bought the XMR |
| Wallet compromise | NOT mitigated - malware can steal keys regardless of the chain |
| Metadata leakage from your own device | NOT mitigated - clipboard, screenshots, browser history |
| Off-chain correlation (timing, amounts) | Partially mitigated - amounts are hidden on-chain, but timing still leaks |
| Legal process against you | NOT mitigated - Monero is not a legal shield |

**What Monero does NOT protect against:**

- Buying XMR on a KYC exchange and then moving it to your own wallet.
  The exchange records the purchase and can be subpoenaed.
- Reusing a wallet across contexts (personal, work, engagement).
- Leaking your identity through your own operational security:
  posting from the same device, using the same email, reusing
  usernames.
- A compromised operating system or a wallet binary that is not
  verified.
- A determined state-level adversary with physical access to your
  device.
- Off-chain correlation between an on-chain transaction and a real
  event (e.g. an order placed on a market).

## 3. How It Works (technical)

**Ring signatures.**

A Monero transaction spends a real output plus N-1 decoy outputs
(called "ring members"). The signature proves that the spender knows
the private key for one of the outputs, without revealing which one.
The current default ring size is 16 (as of the 2022 hard fork).

The decoys are chosen from the blockchain using a probability
distribution that is meant to match real spending behavior. Early
versions of Monero used a naive distribution, which allowed
researchers to guess the real output with high probability. The
current distribution (the "gamma" distribution, introduced in
2020) is better but still not perfect.

**Stealth addresses.**

Every payment goes to a one-time public key derived from the
recipient's public view key and the sender's private transaction
key. The recipient can scan the chain with their private view key
to find payments, and spend them with their private spend key. An
observer cannot link two payments to the same wallet.

**RingCT.**

RingCT hides the amount of every transaction. Before RingCT
(introduced in 2017), amounts were visible. After RingCT, only the
sender and receiver know the amount. The network verifies that the
inputs and outputs balance using cryptographic commitments.

**Dandelion++.**

Dandelion++ is a network-layer protocol that changes how
transactions propagate. In the "stem" phase, a transaction is
passed along a random path of nodes before being broadcast in the
"fluff" phase. This makes it harder for a network observer to
determine which node originated the transaction.

**Tor and I2P support.**

Monero nodes and wallets can route traffic through Tor or I2P.
This hides the IP address of the node from other nodes and from
the network. It does not hide the transaction from the blockchain.

**View keys.**

A Monero wallet has a private view key and a private spend key. The
view key can be shared (e.g. with an auditor) to allow the holder
to see incoming transactions without being able to spend them. This
is useful for transparency in some contexts, but it also means that
sharing the view key compromises privacy for all incoming
transactions.

**The limits.**

- Ring signatures protect the sender, but only if the decoys are
  indistinguishable from the real output. Decoy selection is an
  active research area.
- RingCT hides amounts, but the transaction graph is still public:
  an observer sees that some output was spent, just not which one.
- Dandelion++ raises the cost of network analysis but does not
  eliminate it.
- Tor/I2P hide your IP but not your on-chain behavior.

## 4. Installation and Setup

This section describes setup for an **authorized engagement or
approved research project**. It assumes you have a documented need
for private transactions.

**Step 1. Choose a wallet.**

The reference wallet is the Monero GUI (desktop) or Monero CLI
(`monero-wallet-cli`). Both are maintained by the Monero Project.
Third-party wallets exist (Feather, Cake Wallet, Monerujo) and are
acceptable if you verify the binary and understand the trade-offs.

For an engagement, prefer the CLI wallet: it has fewer moving
parts, fewer network requests, and no browser component.

**Step 2. Verify the binary.**

- Download from the official Monero website or the official
  GitHub releases page.
- Verify the GPG signature against the maintainer's public key.
- Verify the SHA-256 hash against the published hash.
- On Linux, prefer the distribution package if it is recent
  enough. On Windows, verify the binary hash after download.

Do not install a wallet from a third-party site, a package
mirror you do not trust, or a browser extension.

**Step 3. Create the wallet.**

- Generate the wallet offline if possible. The Monero GUI and CLI
  both support offline generation.
- Write the 25-word mnemonic seed on paper. Do not store it in a
  password manager, a cloud note, or a screenshot.
- Set a strong password for the wallet file. The password protects
  the file on disk, not the seed.
- Store the seed in a physically secure location, separate from
  the device that holds the wallet.

**Step 4. Synchronize the node.**

You have two options:

- **Run your own node.** Full node, synchronized over Tor or I2P.
  This is the privacy-preserving option: your wallet does not
  leak your address to a third-party node.
- **Use a remote node.** Faster and less resource-intensive, but
  the remote node sees your IP and your wallet's queries. For an
  engagement, use a remote node only over Tor, and only a node
  you trust.

For serious use, run your own node on a machine that is separate
from your daily workstation.

**Step 5. Fund the wallet.**

This is the step where most operational-security mistakes happen.
See section 5.

## 5. Hardening and Configuration

Monero protects the on-chain transaction. It does not protect the
endpoints. Most real-world de-anonymization happens at the
endpoints, not on the chain.

**Wallet hygiene:**

- One wallet per context. Do not use the same wallet for personal
  funds and engagement funds.
- One address per incoming payment. Stealth addresses make this
  automatic, but do not publish a single address for multiple
  unrelated payments.
- Do not share the view key unless the use case requires it and
  the consequences are understood.
- Do not reuse the wallet seed across devices. If a device is
  compromised, the seed is compromised.

**Device hygiene:**

- Use a dedicated device for the wallet if possible. A cheap
  laptop or a dedicated VM is enough.
- Full-disk encryption on the device.
- No browser, no email, no social media on the wallet device.
- No clipboard sharing between the wallet device and the daily
  workstation.
- No screenshots of the wallet, the seed, or the address.

**Network hygiene:**

- Run the wallet behind Tor or I2P.
- If using a remote node, use one over Tor, and verify the node's
  TLS certificate.
- Do not broadcast transactions from a network that is
  identifiable (home IP, corporate network, public Wi-Fi with
  captive portal).

**Funding hygiene:**

- Do not buy XMR directly on a KYC exchange and send it to your
  wallet. The exchange records the purchase and the withdrawal
  address.
- If you must use an exchange, use it as one hop in a longer
  chain, and understand that the exchange's records are the
  weakest link.
- Prefer peer-to-peer methods (see the Physical and Prepaid file
  in this subcategory) for use cases that require anonymity from
  the exchange.
- Do not fund a wallet from a source that is itself linked to
  your identity (a personal Bitcoin wallet, a payroll deposit, a
  refund to your bank account).

**Operational hygiene:**

- Do not transact in round amounts. Round amounts are a
  fingerprint.
- Do not transact at predictable times (e.g. every Monday at
  09:00).
- Do not reuse a wallet after an incident. If a wallet is
  suspected of being linked to your identity, abandon it.
- Keep an offline log of transactions for your own records (not
  for the chain).

## 6. Operational Usage

Day-to-day use of Monero for an authorized engagement:

- **Receive.** Give the sender your address. The wallet scans
  the chain for incoming payments. Verify the amount in the
  wallet, not in a block explorer.
- **Spend.** The wallet selects inputs, chooses decoys, and
  builds the transaction. The default ring size is 16. Do not
  lower it.
- **Confirm.** Wait for at least 10 confirmations before
  treating a payment as final. Monero blocks are mined roughly
  every 2 minutes.
- **Back up.** Back up the wallet file and the seed after every
  significant transaction. Store the backup offline.
- **Audit.** If the engagement requires an audit trail, use a
  view key (not the spend key) and document what was shared.

**Engagement-specific considerations:**

- If the client requires the funds to be returned at the end of
  the engagement, plan the return path in advance and document
  it. Do not commingle engagement funds with personal funds.
- If the engagement uses Monero for a payment to a third party
  (e.g. a bounty), document the payment and the recipient in the
  engagement report. The client's legal team may need it.
- If the engagement is time-boxed, schedule the wallet teardown
  and the seed destruction before the engagement starts.

## 7. Common Mistakes

- **Buying XMR on a KYC exchange and sending it directly to
  your wallet.** The exchange records the purchase and the
  withdrawal. This is the single most common de-anonymization
  vector.
- **Reusing a wallet across contexts.** Personal, work, and
  engagement funds in the same wallet link all three.
- **Storing the seed in a password manager or a cloud note.**
  The seed is the wallet. Anyone with the seed has the funds.
- **Using a remote node without Tor.** The node sees your IP
  and your wallet's queries.
- **Using a wallet binary from an untrusted source.** Malware
  can steal keys, redirect payments, or replace addresses.
- **Sharing the view key casually.** The view key reveals all
  incoming transactions.
- **Transacting in round amounts or at predictable times.**
  These are fingerprints.
- **Not waiting for enough confirmations.** A transaction can
  be reorganized out of the chain.
- **Reusing a wallet after a suspected compromise.**
- **Assuming Monero is legal everywhere.** Some exchanges and
  some jurisdictions restrict or ban privacy coins.

## 8. Attacks Against It

Monero is attacked at both the protocol level and the endpoint
level:

- **Decoy selection analysis.** Academic research has shown that
  some decoys are statistically more likely to be real than
  others, allowing probabilistic guessing. The Monero Project
  has responded with changes to the decoy selection algorithm,
  but the attack is not fully closed.
- **Network-level deanonymization.** An adversary who controls
  a large fraction of nodes can correlate transactions with
  IP addresses. Dandelion++ and Tor/I2P raise the cost but do
  not eliminate it.
- **Endpoint compromise.** Malware on the wallet device can
  steal the seed, replace the recipient address in the clipboard,
  or redirect the transaction. This is the most common real-world
  attack.
- **Exchange subpoena.** The exchange's KYC records link a
  purchase to a real identity.
- **Payment-processor correlation.** If you buy XMR with a card
  or a bank transfer, the processor's records link the purchase
  to your identity.
- **Off-chain correlation.** An observer who sees both the
  on-chain transaction and a real-world event (e.g. a market
  order) can link the two.
- **Wallet fingerprinting.** Different wallets produce slightly
  different transactions. An observer can sometimes identify the
  wallet software, and from there narrow down the user.
- **View-key leakage.** If a view key is shared or stolen, the
  attacker sees all incoming transactions.
- **Clipboard hijacking.** Malware replaces the recipient
  address in the clipboard. Always verify the address in the
  wallet, not in the clipboard.

## 9. Detection (Blue Team)

Blockchain-analysis firms (Chainalysis, Elliptic, TRM) and law
enforcement use a combination of techniques against Monero:

- **Decoy selection heuristics.** Statistical analysis of which
  output in a ring is most likely to be real.
- **Timing analysis.** Correlation of transaction broadcast
  times with known events.
- **Amount analysis.** Even with RingCT, some amount information
  leaks through fee selection and change outputs.
- **Network-level analysis.** Running many nodes, observing
  transaction propagation, and correlating with IP addresses.
- **Exchange records.** The most reliable source: a subpoena to
  an exchange reveals who bought XMR and when.
- **Endpoint forensics.** Seized devices reveal the wallet, the
  seed, and the transaction history.
- **Off-chain intelligence.** Human intelligence, informants,
  and documents.
- **Blockchain-analysis vendor reports.** Vendors publish
  reports naming Monero addresses and clusters linked to
  criminal activity.

For a defender or researcher, the practical output is a
cluster of addresses linked to a real-world entity, and a
report that documents the methodology and the confidence
level.

## 10. Case Studies

**Case 1 - Exchange KYC.** A user bought XMR on a regulated
exchange and sent it to a personal wallet. The exchange's KYC
records linked the purchase to the user's identity. When law
enforcement later subpoenaed the exchange, the user's entire
Monero history was reconstructable from the exchange's records,
even though the on-chain transactions were private.

**Case 2 - Decoy selection research.** Academic researchers
published a paper showing that a non-trivial fraction of Monero
ring signatures could be de-anonymized with statistical
analysis. The Monero Project responded with changes to the
decoy selection algorithm, but the paper remains a useful
reference for understanding the limits of ring signatures.

**Case 3 - Endpoint compromise.** A user's wallet device was
infected with malware that replaced the recipient address in
the clipboard. The user sent funds to the attacker's address
without noticing. The on-chain transaction was private, but the
funds were gone. This case illustrates that Monero protects the
chain, not the endpoint.

**Case 4 - Authorized engagement.** A red team used Monero to
pay a third-party bounty during a client engagement. The team
bought the XMR through a peer-to-peer method, ran their own
node over Tor, and used a dedicated wallet for the engagement.
At the end of the engagement, the wallet was destroyed and the
seed was shredded in the presence of the client's representative.
The engagement report documented the payment path and the
teardown.

## 11. Legal and Ethical Notes

Monero is legal in most jurisdictions, but the legal landscape
is changing:

- **Exchange restrictions.** Some regulated exchanges delist
  privacy coins. In some jurisdictions, exchanges are required
  to identify the source of funds for privacy-coin transactions.
- **Travel rule.** The FATF travel rule requires virtual asset
  service providers to share sender and receiver information
  for transfers above a threshold. This applies to exchanges,
  not to self-hosted wallets, but the rules are evolving.
- **Sanctions.** Some Monero addresses are on sanctions lists.
  Transacting with a sanctioned address is a criminal offense
  in most jurisdictions.
- **Tax.** In most jurisdictions, Monero transactions are
  taxable events, and the tax authority expects records.
  Keeping an offline log is both an operational-security
  measure and a legal one.
- **Authorization.** For an engagement, the client's rules of
  engagement must explicitly cover the use of cryptocurrency.
  Do not assume that "the client asked for a red team" includes
  permission to use Monero.
- **Ethical boundary.** Monero is used by criminal actors.
  Using it for authorized work is not itself unethical, but it
  can create the appearance of association. Be transparent
  with the client and document the choice.

**Do not use Monero for:**

- Money laundering.
- Sanctions evasion.
- Financing illegal activity.
- Any activity outside an authorized engagement or approved
  research project.
- Anything that would expose the client to legal risk they
  did not agree to.

## 12. Production Notes

- **Cost.** Monero transaction fees are low but not zero.
  Budget for fees on every transaction.
- **Confirmation time.** Roughly 2 minutes per block. Wait for
  at least 10 confirmations for high-value transactions.
- **Node operation.** Running a full node requires disk space
  (currently tens of GB and growing) and bandwidth. Plan for
  it.
- **Wallet backup.** Back up the wallet file and the seed
  after every significant transaction. Test the restore
  procedure before you need it.
- **Migration.** If you suspect a wallet is linked to your
  identity, abandon it and create a new one. Do not reuse the
  seed.
- **Teardown.** At the end of an engagement, destroy the
  wallet, destroy the seed, and document the destruction.
- **Record-keeping.** Keep an offline log of every transaction
  for the client's report and for your own legal protection.

## 13. References

- Monero Project documentation (getmonero.org).
- Monero Research Lab papers on ring signatures, decoy
  selection, and RingCT.
- Academic papers on Monero de-anonymization (decoy selection
  bias, network-level analysis).
- Chainalysis, Elliptic, and TRM reports on Monero and privacy
  coins.
- FATF guidance on virtual assets and the travel rule.
- The client's rules of engagement document (for authorized
  engagements).
