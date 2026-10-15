# Mixers and Tumblers

## 1. Overview

A cryptocurrency mixer (also called a tumbler) is a service or
protocol that breaks the on-chain link between the source of
funds and the destination. The user sends coins to the mixer,
and the mixer sends different coins to the destination, so a
naive observer cannot follow the money.

The category includes:

- **Custodial mixers.** A service that takes custody of the
  coins and returns different coins. The user trusts the
  operator. Most of these have been shut down or sanctioned.
- **CoinJoin.** A collaborative transaction where multiple
  parties contribute inputs and receive outputs. No custody,
  no operator trust, but a coordinator is usually involved.
- **Chaumian mixes.** A protocol using blind signatures to
  break the link without custody. Used in some privacy-focused
  wallets.
- **Cross-chain swaps.** A swap on one chain for coins on
  another chain, which breaks the on-chain link because the
  two chains are separate. Covered in the Chain-Hopping and
  DEX file.
- **Privacy coins.** Monero and similar coins have mixing built
  into the protocol. Covered in the Monero file.

This file focuses on custodial mixers and CoinJoin. It covers
the technical design, the legal landscape after the 2022-2024
enforcement actions, and the operational security that matters.

This is the fourth file in the **Anonymous Crypto Operations
and AML** subcategory.

## 2. Threat Model

The threat model for mixers is different from the threat model
for the underlying cryptocurrency. The adversary is not only a
blockchain analyst; it is also:

| Threat | Effect on mixers |
|--------|------------------|
| On-chain link between source and destination | Mitigated if the mixer works as advertised |
| Chain-analysis clustering | Partially mitigated - the mixer breaks the link but the resulting coins may be flagged |
| Custodial mixer operator | NOT mitigated - the operator can steal, log, or inform |
| Coordinator logging (CoinJoin) | NOT mitigated - the coordinator sees the inputs and outputs |
| Legal process against the mixer | NOT mitigated - the mixer's records can be subpoenaed |
| Sanctions screening | NOT mitigated - some mixers are sanctioned, and using them is a crime |
| Exchange flagging | NOT mitigated - some exchanges flag coins that pass through mixers |
| Timing correlation | Partially mitigated - delays help, but the mixer's behavior is observable |
| Amount correlation | Partially mitigated - equal-amount outputs help, but fees and change leak |
| Network-level analysis | NOT mitigated - the mixer sees your IP unless you use Tor |

**What mixers do NOT protect against:**

- A custodial mixer that is an exit scam, a honeypot, or a
  law-enforcement front.
- A coordinator that logs the inputs and outputs and later
  shares them.
- The legal consequences of using a sanctioned mixer.
- Exchange policies that flag coins that have passed through
  a mixer.
- Your own operational-security mistakes: reusing an address,
  broadcasting from your home IP, mixing only a small amount.
- Timing correlation if you mix and spend immediately.

## 3. How It Works (technical)

**Custodial mixers.**

- The user sends coins to the mixer's deposit address.
- The mixer pools the coins with other users' coins.
- The mixer sends different coins to the user's withdrawal
  address, minus a fee.
- The mixer can implement delays, amount splitting, and
  multiple withdrawal addresses to complicate analysis.
- The mixer knows the deposit address, the withdrawal address,
  and the amount. If the mixer keeps logs, the link is
  recoverable.
- Most custodial mixers have been shut down, sanctioned, or
  exit-scammed. Helix, Bitcoin Fog, and BestMixer are examples
  of mixers that were taken down and whose operators were
  prosecuted.

**CoinJoin.**

- Multiple users collaborate on a single transaction with
  multiple inputs and multiple outputs.
- Each user contributes one or more inputs and receives one or
  more outputs of the same amount.
- The transaction is constructed by a coordinator (in
  Chaumian CoinJoin) or by the participants (in
  JoinMarket-style coordination).
- The coordinator sees the inputs and outputs but cannot link
  them without additional information.
- The resulting coins are "mixed" - an observer cannot tell
  which output belongs to which input.
- CoinJoin does not change the amount of the coins; it
  changes their on-chain history.

**Chaumian mixes.**

- The user blinds a coin, sends it to the mixer, and receives
  a blind signature.
- The user unblinds the signature and uses it to claim a
  different coin from the mixer.
- The mixer cannot link the blinded coin to the unblinded
  claim.
- This is the design used in some privacy-focused wallets and
  in the original Chaumian ecash proposals.
- The mixer still sees the deposit and the withdrawal, but
  cannot link them.

**Privacy coins.**

- Monero and similar coins have mixing built into the
  protocol (ring signatures, stealth addresses, RingCT).
- There is no separate mixer service; the privacy is a
  property of every transaction.
- See the Monero file in this subcategory.

**Cross-chain swaps.**

- A swap on one chain for coins on another chain.
- The two chains are separate, so the on-chain link is
  broken.
- The swap service (a DEX or a bridge) sees both sides and
  can link them if it keeps logs.
- See the Chain-Hopping and DEX file in this subcategory.

## 4. Installation and Setup

This section describes setup for an **authorized engagement or
approved research project**. It assumes you have a documented
need for mixing.

**Step 1. Check the legal status.**

Before using any mixer, check:

- Is the mixer sanctioned in your jurisdiction or in the
  jurisdiction of the counterparty?
- Is using a mixer itself a regulated activity (money
  transmission) in your jurisdiction?
- Does the engagement's rules of engagement explicitly cover
  the use of a mixer?

If the answer to any of these is unclear, do not proceed.

**Step 2. Choose the method.**

- **CoinJoin** is the least custodial and the most widely
  used. It has no operator who takes custody, but it has a
  coordinator who sees the inputs and outputs.
- **Chaumian mixes** are less common but have a stronger
  privacy model in theory.
- **Custodial mixers** are the most custodial and the most
  risky. Most have been shut down or sanctioned. Avoid them
  unless the engagement explicitly requires one and the
  client has accepted the legal risk.

**Step 3. Prepare the input coins.**

- Use coins that are not already linked to your identity.
- Do not mix coins that came directly from a KYC exchange.
  The exchange records the withdrawal, and the mixer does
  not erase that record.
- Split the amount into multiple smaller amounts if the
  mixer supports it.

**Step 4. Prepare the output wallet.**

- Use a wallet that does not leak your identity.
- Generate a fresh output address for each withdrawal.
- Do not reuse the output address across mixers or across
  transactions.

**Step 5. Execute the mix.**

Follow the method-specific procedure in section 6.

## 5. Hardening and Configuration

Mixers are operational-security procedures, not software
configurations. The hardening is in the habits.

**Input hygiene:**

- Do not mix coins that are already linked to your identity.
- Do not mix coins that came directly from a KYC exchange.
- Split the amount if the mixer supports it.
- Do not mix and spend immediately. Wait for a delay.

**Output hygiene:**

- Use a fresh output address for each withdrawal.
- Do not withdraw to an address that is linked to your
  identity.
- Do not consolidate the outputs immediately. Wait before
  consolidating.
- Do not reuse the output address.

**Coordinator hygiene (CoinJoin):**

- Use a coordinator you trust or one with a strong privacy
  policy.
- Understand that the coordinator sees the inputs and
  outputs.
- Consider running your own coordinator if the engagement
  requires it and the client has approved the operational
  cost.

**Network hygiene:**

- Use Tor for all mixer interactions.
- Do not broadcast from a home IP, a corporate network, or
  a public Wi-Fi that logs.
- Do not use the same network for the input and the output.

**Legal hygiene:**

- Check the sanctions status of the mixer before using it.
- Check the legal status of mixing in your jurisdiction.
- Keep an offline log of the mix (amount, mixer, date,
  input address, output address) for your own records.
- Do not mix on behalf of a client without written
  authorization.

## 6. Operational Usage

**CoinJoin:**

1. Choose a wallet that supports CoinJoin (Wasabi,
   Samourai, JoinMarket, or a similar wallet).
2. Fund the wallet with the coins you want to mix.
3. Register the coins with the coordinator.
4. Wait for a round. The coordinator constructs the
   transaction.
5. Sign the transaction. The coins are mixed.
6. Wait for confirmations.
7. Do not spend the mixed coins immediately. Wait for a
   delay.
8. Do not consolidate the mixed coins with unmixed coins.

**Chaumian mixes:**

1. Choose a wallet or service that supports Chaumian
   mixing.
2. Blind the coins.
3. Send the blinded coins to the mixer.
4. Receive the blind signature.
5. Unblind the signature.
6. Claim the new coins from the mixer.
7. Wait for confirmations.
8. Do not spend the new coins immediately.

**Custodial mixers:**

1. Choose a mixer with a long reputation and a strong
   privacy policy.
2. Send the coins to the deposit address.
3. Specify the withdrawal address and the delay.
4. Receive the coins at the withdrawal address.
5. Verify the amount in your own wallet.
6. Wait for confirmations.
7. Do not spend the coins immediately.

## 7. Common Mistakes

- **Mixing coins that are already linked to your
  identity.** The mixer does not erase the exchange's
  record of the withdrawal.
- **Mixing coins that came directly from a KYC exchange.**
  The exchange's records link the withdrawal to your
  identity.
- **Using a custodial mixer.** Most have been shut down or
  sanctioned, and the operator can steal or inform.
- **Mixing and spending immediately.** Timing correlation
  is a real risk.
- **Reusing the output address.** The address links the
  outputs.
- **Consolidating mixed and unmixed coins.** The
  consolidation links them.
- **Using a mixer that is sanctioned.** Using a sanctioned
  mixer is a criminal offense in most jurisdictions.
- **Not using Tor.** The mixer sees your IP.
- **Not keeping an offline log.** You will not remember
  the details later.
- **Assuming a mixer makes the coins legally clean.** It
  does not. Exchanges may flag mixed coins.

## 8. Attacks Against It

Mixers are attacked by:

- **Chain-analysis clustering.** Vendors have developed
  heuristics to identify CoinJoin transactions and, in some
  cases, to de-anonymize their participants.
- **Coordinator logging.** A coordinator that logs the
  inputs and outputs can link them later.
- **Custodial mixer exit scam.** The operator takes the
  coins and disappears.
- **Custodial mixer honeypot.** The operator is a
  law-enforcement front.
- **Legal process against the mixer.** The mixer's records
  are subpoenaed.
- **Sanctions screening.** Using a sanctioned mixer is a
  crime, and the resulting coins may be flagged.
- **Exchange flagging.** Some exchanges flag coins that
  have passed through a mixer.
- **Timing correlation.** An observer correlates the
  deposit and the withdrawal through timing.
- **Amount correlation.** An observer correlates the
  deposit and the withdrawal through amounts, especially if
  the amounts are distinctive.
- **Network-level analysis.** The mixer sees your IP unless
  you use Tor.
- **Wallet fingerprinting.** Different wallets produce
  slightly different transactions.

## 9. Detection (Blue Team)

Chain-analysis firms and law enforcement use a combination of
techniques against mixers:

- **CoinJoin detection.** Heuristics that identify CoinJoin
  transactions by their structure (multiple inputs, equal
  outputs, specific script types).
- **CoinJoin de-anonymization.** Heuristics that link
  inputs and outputs within a CoinJoin, sometimes using
  timing or amount information.
- **Mixer labeling.** Known mixer addresses are labeled in
  chain-analysis databases.
- **Sanctions screening.** Sanctioned mixer addresses are
  flagged, and transactions with them are reported.
- **Exchange reporting.** Exchanges report withdrawals to
  known mixers as suspicious.
- **Network-level analysis.** Correlating mixer traffic
  with IP addresses.
- **Endpoint forensics.** Seized devices reveal the wallet
  and the transaction history.
- **Off-chain intelligence.** Human intelligence,
  informants, and documents.
- **Custodial mixer seizure.** Law enforcement seizes the
  mixer's servers and recovers its logs.

For a defender or researcher, the practical output is a
cluster of addresses linked to a mixer and, if the mixer's
logs are recovered, a full link between deposits and
withdrawals.

## 10. Case Studies

**Case 1 - Helix.** The Helix mixer was shut down by US law
enforcement in 2020. Its operator, Larry Harmon, was
prosecuted and sentenced to three years in prison. The
investigation relied on the mixer's logs, which had been
recovered from the operator's servers.

**Case 2 - Bitcoin Fog.** The Bitcoin Fog mixer was shut
down in 2021. Its operator, Roman Sterlingov, was convicted
in 2024. The investigation relied on blockchain analysis and
on the mixer's records.

**Case 3 - BestMixer.** The BestMixer mixer was shut down
by Dutch and Europol authorities in 2019. The investigation
relied on the mixer's logs.

**Case 4 - CoinJoin and sanctions.** A user participated in
a CoinJoin with an address that was later sanctioned. The
user's resulting UTXOs were flagged by exchanges, and the
user had to provide documentation of the source of funds to
access them.

**Case 5 - Authorized engagement.** A red team used
CoinJoin to mix the funds for a client engagement. The team
used a dedicated wallet, a dedicated coordinator, and Tor.
At the end of the engagement, the wallet was destroyed and
the log was handed to the client. The engagement report
documented the mixing path and the teardown.

## 11. Legal and Ethical Notes

Mixers sit at the intersection of several legal regimes:

- **Sanctions.** Several mixers have been sanctioned by the
  US Treasury's Office of Foreign Assets Control (OFAC).
  Using a sanctioned mixer is a criminal offense in most
  jurisdictions, even for a legitimate purpose.
- **Money transmission.** In some jurisdictions,
  operating a mixer without a license is money
  transmission and is a criminal offense. Using a mixer
  may also be regulated.
- **AML.** Regulated exchanges report transactions with
  known mixers as suspicious. The FATF travel rule
  requires virtual asset service providers to share
  sender and receiver information for transfers above a
  threshold.
- **Tax.** In most jurisdictions, mixing does not change
  the tax treatment of the coins. The tax authority
  expects records.
- **Authorization.** For an engagement, the client's rules
  of engagement must explicitly cover the use of a mixer.
  Do not assume that "the client asked for a red team"
  includes permission to mix coins.
- **Ethical boundary.** Mixers are used by criminal actors.
  Using them for authorized work is not itself unethical,
  but it can create the appearance of association. Be
  transparent with the client and document the choice.

**Do not use mixers for:**

- Money laundering.
- Sanctions evasion.
- Financing illegal activity.
- Any activity outside an authorized engagement or
  approved research project.
- Anything that would expose the client to legal risk
  they did not agree to.

## 12. Production Notes

- **Cost.** CoinJoin fees are typically 0.1-1% plus
  mining fees. Custodial mixer fees are typically 1-5%.
- **Speed.** CoinJoin rounds happen every few hours.
  Chaumian mixes depend on the mixer. Custodial mixers
  are usually fast.
- **Counterparty risk.** Custodial mixers have the
  highest counterparty risk. CoinJoin has the lowest.
- **Record-keeping.** Keep an offline log of every mix
  (amount, mixer, date, input address, output address)
  for your own records.
- **Teardown.** At the end of an engagement, destroy the
  wallet, destroy the log, and document the destruction.
- **Migration.** If a mixer is suspected of being
  compromised or sanctioned, switch to a different
  method.

## 13. References

- OFAC sanctions list (for sanctioned mixers).
- FATF guidance on virtual assets and money
  transmission.
- Chainalysis, Elliptic, and TRM reports on mixers.
- Academic papers on CoinJoin and Chaumian mixing.
- Documentation for Wasabi, Samourai, and JoinMarket.
- Court documents and press releases on Helix,
  Bitcoin Fog, and BestMixer.
- The client's rules of engagement document (for
  authorized engagements).
