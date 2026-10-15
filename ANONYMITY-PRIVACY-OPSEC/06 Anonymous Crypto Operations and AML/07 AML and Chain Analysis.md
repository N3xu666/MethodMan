# AML and Chain Analysis

## 1. Overview

Anti-money-laundering (AML) is the set of laws, regulations,
and procedures that financial institutions use to detect and
prevent the movement of illicit funds. In the cryptocurrency
context, AML is implemented through a combination of
regulated exchanges, blockchain-analysis vendors, and law
enforcement.

Chain analysis is the technical discipline behind AML for
cryptocurrencies. It is the practice of clustering addresses,
labeling entities, and following the flow of funds across the
public ledger. The three dominant vendors are Chainalysis,
Elliptic, and TRM Labs. Their products are used by
exchanges, banks, and law enforcement in most jurisdictions.

This file covers:

- What chain analysis is and how it works.
- The heuristics that vendors use to cluster addresses.
- The AML rules that apply to cryptocurrency.
- How to operate within the legal framework.
- The limits of chain analysis and AML.

This is the seventh file in the **Anonymous Crypto Operations
and AML** subcategory. It is the defensive counterpart to the
earlier files: it describes what the adversary can do.

## 2. Threat Model

The threat model for AML and chain analysis is the inverse of
the threat model for the earlier files in this subcategory.
Here, the adversary is the analyst, the vendor, the exchange,
and the law-enforcement officer.

| Threat | Effect on the user |
|--------|---------------------|
| Address clustering | Links addresses to a single entity |
| Entity labeling | Associates addresses with exchanges, mixers, and known actors |
| Transaction graph analysis | Follows the flow of funds across the ledger |
| Risk scoring | Assigns a risk level to an address or transaction |
| Exchange AML | Blocks or reports suspicious transactions |
| Law-enforcement investigation | Uses vendor data and legal process to identify the user |
| Cross-chain analysis | Extends the analysis across multiple blockchains |
| Off-chain data correlation | Combines on-chain data with KYC, social media, and data-broker records |

**What chain analysis does NOT protect against (for the analyst):**

- A user who follows strict operational security.
- A user who uses privacy coins with strong cryptographic
  protections.
- A user who never links their on-chain activity to their
  real identity.
- A user who uses off-chain channels that the analyst
  cannot access.
- A user in a jurisdiction where the analyst cannot enforce
  a subpoena.

**What chain analysis CAN do (for the analyst):**

- Link addresses that were used together.
- Identify the exchange or service that an address belongs to.
- Follow the flow of funds through the ledger.
- Flag transactions that pass through known mixers or
  sanctioned addresses.
- Correlate on-chain data with off-chain data (KYC, social
  media, data-broker records).
- Support a legal case with a documented methodology.

## 3. How It Works (technical)

**Address clustering.**

Chain-analysis vendors group addresses into clusters based on
heuristics. The main heuristics are:

- **Common-input-ownership.** Inputs spent together in the
  same transaction are assumed to belong to the same
  entity. This is the strongest heuristic in Bitcoin and
  similar UTXO chains.
- **Change detection.** The output that is not the payment
  is usually the change. Vendors use script type, amount,
  position, and roundness to identify it.
- **Address reuse.** An address that appears in multiple
  transactions links them.
- **Peeling chains.** A series of transactions where a
  small amount is peeled off each time and the rest is
  sent back as change.
- **Consolidation.** A transaction with many inputs is
  usually a consolidation of one entity's UTXOs.
- **Temporal analysis.** Transactions that happen close in
  time are often linked.
- **Amount analysis.** Round amounts and distinctive
  amounts are fingerprints.
- **Deposit patterns.** Deposits to an exchange are often
  clustered by their behavior (many small deposits, then a
  large withdrawal, etc.).

**Entity labeling.**

Vendors maintain a database of labels for known entities:

- **Exchanges.** Deposits and withdrawals are labeled with
  the exchange name.
- **Mixers.** Known mixers are labeled.
- **Darknet markets.** Known market addresses are labeled.
- **Ransomware.** Known ransomware payment addresses are
  labeled.
- **Sanctioned entities.** OFAC-sanctioned addresses are
  labeled.
- **Mining pools.** Known mining pool addresses are
  labeled.
- **Gambling services.** Known gambling addresses are
  labeled.

Labels come from public sources (e.g. exchange deposit
addresses published on their websites), from law
enforcement, from commercial data, and from the vendors'
own research.

**Transaction graph analysis.**

Vendors build a graph of every transaction and every address.
They can follow the flow of funds from any starting point,
using the clustering and labeling to interpret the graph.
The output is a timeline of movements with labels and risk
scores.

**Risk scoring.**

Each address and transaction is assigned a risk score based
on its history. The score is used by exchanges and banks to
decide whether to accept, block, or report a transaction.
The scoring methodology is proprietary; different vendors
may assign different scores to the same address.

**Cross-chain analysis.**

Vendors are extending their analysis across chains. They
correlate deposits and withdrawals to bridges and DEXs,
and they follow the flow of funds across multiple ledgers.
The field is evolving; cross-chain analysis is less mature
than single-chain analysis but improving rapidly.

**Off-chain data correlation.**

Vendors combine on-chain data with off-chain data:

- **KYC data.** From exchanges and banks.
- **Public records.** Company registrations, court filings.
- **Social media.** Public posts that correlate with
  on-chain activity.
- **Data brokers.** Commercial data on identity,
  location, and behavior.
- **Law-enforcement databases.** Criminal records,
  investigations, and informants.

**The AML rules.**

The main AML rules for cryptocurrency are:

- **FATF Recommendation 15.** Countries should regulate
  virtual asset service providers (VASPs) and require
  them to identify customers and report suspicious
  transactions.
- **The travel rule.** VASPs must share sender and
  receiver information for transfers above a threshold
  (typically USD/EUR 1000).
- **OFAC sanctions.** Transactions with sanctioned
  addresses are prohibited.
- **Local AML laws.** Each jurisdiction implements the
  FATF recommendations in its own way. The details
  (thresholds, reporting requirements, penalties)
  vary.

## 4. Installation and Setup

This section describes how to operate within the AML
framework for an **authorized engagement or approved
research project**. It assumes you are the analyst, the
researcher, or the operator who needs to understand the
AML environment.

**Step 1. Understand the regulatory environment.**

For each jurisdiction you operate in, identify:

- The AML law and its implementing regulations.
- The threshold for reporting (if any).
- The definition of a VASP.
- The sanctions regime (OFAC, EU, UK, UN, local).
- The tax treatment of cryptocurrency.

**Step 2. Understand the vendor landscape.**

The three dominant vendors are:

- **Chainalysis.** Used by US law enforcement, many
  exchanges, and many banks.
- **Elliptic.** Used by many banks and exchanges,
  especially in Europe.
- **TRM Labs.** Used by many exchanges and law
  enforcement agencies.

Other vendors exist (CipherTrace, Merkle Science, and
others). The methodology is similar; the labels and the
risk scores differ.

**Step 3. Understand your own exposure.**

If you use cryptocurrency for an authorized engagement,
your activity may be visible to a vendor. Consider:

- Which exchanges you use and what they report.
- Which addresses are labeled as belonging to you.
- Which transactions may be flagged as high-risk.
- How you would respond to an inquiry from an
  exchange or a regulator.

**Step 4. Document your compliance posture.**

For an engagement, document:

- The legal basis for the cryptocurrency use.
- The AML and sanctions checks you performed.
- The records you keep.
- The process for responding to a legal inquiry.

## 5. Hardening and Configuration

For the analyst, the hardening is in the methodology. For
the user, the hardening is in the compliance posture.

**For the analyst:**

- **Validate your labels.** A label that is wrong can
  lead to a false accusation. Use multiple sources.
- **Document your heuristics.** The methodology must be
  reproducible and defensible in court.
- **Understand the confidence level.** Not every cluster
  is certain. Use a confidence score.
- **Do not over-claim.** A cluster is not a person. A
  heuristic is not proof.
- **Consider false positives.** The common-input
  heuristic is strong but not infallible. CoinJoin and
  PayJoin break it.
- **Respect privacy laws.** GDPR, CCPA, and similar
  laws apply to the personal data you process.
- **Respect the law.** Chain analysis is a tool; it does
  not authorize illegal surveillance.

**For the user:**

- **Know your counterparties.** If you transact with a
  sanctioned address, your coins may be flagged.
- **Keep records.** For tax and for legal defense.
- **Do not use sanctioned services.** The legal risk is
  not worth the privacy benefit.
- **Understand exchange policies.** Some exchanges flag
  coins that have passed through mixers or bridges.
- **Be transparent with the client.** In an engagement,
  document every transaction and every AML check.

## 6. Operational Usage

**For the analyst:**

1. Start with a known address (from a case, a report, or
   a complaint).
2. Run clustering to identify the entity's other
   addresses.
3. Label the entity using the vendor database.
4. Follow the flow of funds forward and backward.
5. Identify the points where funds enter and leave the
   cluster (exchanges, mixers, bridges).
6. Assign a risk score to each address and transaction.
7. Document the analysis with the methodology and the
   confidence level.
8. If the analysis is for a legal case, ensure that the
   methodology is defensible and the chain of custody
   is documented.

**For the user:**

1. Before transacting, check the counterparty address
   against the sanctions list.
2. If the counterparty is an exchange, understand its
   AML policy.
3. Keep a record of every transaction.
4. If a transaction is flagged, respond to the exchange
   with documentation.
5. If an inquiry comes from law enforcement, consult a
   lawyer before responding.

## 7. Common Mistakes

**For the analyst:**

- **Over-claiming.** A cluster is not a person.
- **Using a single heuristic.** Clustering should
  combine multiple heuristics.
- **Ignoring false positives.** CoinJoin and PayJoin
  break the common-input heuristic.
- **Using stale labels.** Addresses change hands;
  labels can become wrong.
- **Not documenting the methodology.** A legal case
  requires a defensible methodology.
- **Not respecting privacy laws.** GDPR and similar
  laws apply.
- **Assuming cross-chain analysis is mature.** It is
  improving but less mature than single-chain
  analysis.

**For the user:**

- **Using a sanctioned service.** The legal risk is
  not worth it.
- **Assuming that a mixer makes coins clean.** It does
  not; exchanges may still flag them.
- **Not keeping records.** Tax and legal defense
  require records.
- **Not understanding exchange policies.** Some
  exchanges flag coins that have passed through
  mixers or bridges.
- **Not responding to a legal inquiry.** Ignoring a
  subpoena is a separate offense.
- **Not consulting a lawyer.** AML and sanctions law
  is complex; a lawyer is essential.

## 8. Attacks Against It

Chain analysis and AML systems are attacked by:

- **Privacy coins.** Monero and similar coins break
  the clustering heuristics by design.
- **CoinJoin.** Breaks the common-input heuristic.
- **PayJoin.** Breaks the common-input heuristic and
  the change-detection heuristic.
- **Lightning Network.** Off-chain transactions are
  not visible on the main chain.
- **Cross-chain swaps.** Break the link between
  source and destination.
- **Mixers.** Break the link between deposit and
  withdrawal.
- **False-flag transactions.** An attacker can send
  coins to an address to contaminate it.
- **Dust attacks.** An attacker can send small
  amounts to many addresses to track their spending.
- **Label poisoning.** An attacker can attempt to
  corrupt a vendor's label database.
- **Legal challenges.** Privacy advocates have
  challenged the legality of some chain-analysis
  practices.
- **Jurisdictional limits.** A vendor's data may not
  be usable in a jurisdiction that has stronger
  privacy protections.

## 9. Detection (Blue Team)

Blue teams (exchanges, banks, and law enforcement) use
chain analysis to detect and investigate suspicious
activity:

- **Transaction monitoring.** Real-time screening of
  every deposit and withdrawal against the vendor's
  database.
- **Risk scoring.** Assigning a risk score to each
  address and transaction.
- **Sanctions screening.** Checking every transaction
  against the OFAC SDN list and other sanctions
  lists.
- **Pattern detection.** Identifying known patterns
  (structuring, rapid movement, use of mixers,
  deposit-to-mixer-to-exchange, etc.).
- **Investigation.** Following the flow of funds
  from a known criminal address to identify
  accomplices and cash-out points.
- **Reporting.** Filing suspicious activity reports
  (SARs) with the relevant authority.
- **Cooperation with law enforcement.** Providing
  data in response to a legal order.

For the analyst, the output is a documented
investigation with a reproducible methodology and a
defensible conclusion.

## 10. Case Studies

**Case 1 - Silk Road.** The Silk Road darknet market was
shut down in 2013. The investigation relied on
chain analysis to link the market's Bitcoin addresses
to its operator, Ross Ulbricht. The case was one of
the first major uses of chain analysis in law
enforcement.

**Case 2 - Welcome to Video.** The Welcome to Video
child-exploitation site was shut down in 2018. The
investigation used chain analysis to link Bitcoin
payments to the site's operators and users. The case
led to arrests in multiple countries.

**Case 3 - Colonial Pipeline.** The Colonial Pipeline
ransomware attack in 2021 led to a ransom payment in
Bitcoin. The FBI recovered most of the ransom by
following the funds on-chain and obtaining the
private key. The case illustrates that chain analysis
can lead to recovery even after payment.

**Case 4 - Bitcoin Fog.** The Bitcoin Fog mixer was
shut down in 2021. The investigation relied on chain
analysis and on the mixer's logs. The operator,
Roman Sterlingov, was convicted in 2024.

**Case 5 - Chain-analysis vendor report.** A major
vendor published a report linking a ransomware
group's payments to a specific exchange and a
specific cluster of addresses. The report was used
by law enforcement in multiple jurisdictions.

**Case 6 - Authorized engagement.** A red team used
cryptocurrency for a client engagement. The team
documented every transaction, checked every
counterparty against the sanctions list, and kept
an offline log. At the end of the engagement, the
log was handed to the client's legal team. No
transactions were flagged.

## 11. Legal and Ethical Notes

AML and chain analysis sit at the intersection of
several legal regimes:

- **AML laws.** Each jurisdiction implements the FATF
  recommendations in its own way. The details
  (thresholds, reporting requirements, penalties)
  vary.
- **Sanctions.** OFAC, EU, UK, UN, and other
  sanctions regimes prohibit transactions with
  sanctioned entities. Violations are criminal
  offenses.
- **Privacy laws.** GDPR, CCPA, and similar laws
  apply to the personal data that chain-analysis
  vendors process.
- **Data protection.** Some jurisdictions restrict
  the transfer of personal data across borders.
- **Legal process.** Chain-analysis vendors respond
  to subpoenas and court orders. The scope of what
  they can disclose varies by jurisdiction.
- **Authorization.** For an engagement, the client's
  rules of engagement must explicitly cover the use
  of cryptocurrency and the AML compliance posture.
- **Ethical boundary.** Chain analysis is a tool.
  Using it for authorized investigations is not
  itself unethical, but it can be misused for
  surveillance, harassment, or political
  persecution. Use it within the law and with
  respect for privacy.

**Do not use chain analysis for:**

- Unauthorized surveillance.
- Harassment or doxxing.
- Political persecution.
- Discrimination based on protected
  characteristics.
- Any activity outside an authorized investigation
  or approved research project.

## 12. Production Notes

- **Cost.** Vendor subscriptions are expensive
  (thousands to hundreds of thousands of dollars per
  year). Budget for it if you are building an AML
  program.
- **Coverage.** Vendors cover the major chains
  (Bitcoin, Ethereum, and the largest stablecoins)
  well; coverage of smaller chains and privacy
  coins is less complete.
- **Accuracy.** Label accuracy varies. Validate
  labels before acting on them.
- **Latency.** Real-time screening is standard for
  exchanges; batch analysis is common for
  investigations.
- **Integration.** Vendors integrate with exchange
  and bank systems via APIs.
- **Record-keeping.** Keep records of every
  screening decision for regulatory audit.
- **Legal review.** Have a lawyer review your AML
  program and your vendor contracts.

## 13. References

- FATF Recommendation 15 and the travel rule.
- OFAC SDN list and other sanctions lists.
- Chainalysis, Elliptic, and TRM Labs public
  reports.
- Academic papers on chain analysis and AML.
- Court documents and press releases on Silk
  Road, Welcome to Video, Colonial Pipeline,
  and Bitcoin Fog.
- GDPR, CCPA, and similar privacy laws.
- The client's rules of engagement document (for
  authorized engagements).
