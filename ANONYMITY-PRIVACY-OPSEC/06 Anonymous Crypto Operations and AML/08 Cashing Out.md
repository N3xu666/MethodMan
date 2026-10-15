# Cashing Out

## 1. Overview

Cashing out is the process of converting cryptocurrency back
into fiat currency or into goods and services that can be
used in the traditional economy. It is the final step in
most cryptocurrency workflows, and it is where the largest
number of operational-security mistakes happen.

The reason is simple: fiat is regulated. Banks, exchanges,
payment processors, and merchants are subject to KYC, AML,
and reporting requirements. Every conversion from crypto to
fiat creates a record that links the cryptocurrency to an
identity, a bank account, or a physical location.

This file covers:

- The main cashing-out methods and their trade-offs.
- The operational security that matters for each.
- The AML and tax implications.
- The common mistakes and how to avoid them.
- The legal and ethical boundaries.

This is the eighth and final file in the **Anonymous Crypto
Operations and AML** subcategory. It is the practical
counterpart to the earlier files: those describe how to
acquire and move cryptocurrency privately; this one
describes how to convert it back without creating a single
identity-linked event.

## 2. Threat Model

Cashing out reverses the privacy properties of the earlier
steps. Even if the cryptocurrency was acquired and moved
privately, the cashing-out step can link it to your
identity. The adversary is:

| Threat | Effect on cashing out |
|--------|------------------------|
| KYC exchange | Records your identity and the source of funds |
| Bank reporting | Reports large or suspicious deposits |
| Merchant records | Links the purchase to your identity |
| Payment processor | Records the transaction and the parties |
| Tax authority | Expects records of every conversion |
| Chain-analysis vendor | Links the on-chain transaction to the exchange |
| Physical surveillance | Observes ATM withdrawals and in-person trades |
| Counterparty risk | The buyer or seller can steal, cheat, or inform |
| Legal process | A subpoena to an exchange reveals your records |

**What good cashing-out OpSec does NOT protect against:**

- A KYC exchange that records your identity and the source
  of funds.
- A bank that reports a large or unusual deposit.
- A merchant that records the purchase.
- A tax authority that audits you.
- A chain-analysis vendor that has already linked your
  cluster to your identity.
- A legal order that compels a service to disclose your
  records.
- Your own mistakes: depositing directly into a personal
  account, using a KYC exchange for a large amount, or
  cashing out in a way that matches a known pattern.

## 3. How It Works (technical)

**Cashing-out methods.**

- **Centralized exchange (CEX).** Sell crypto for fiat on a
  regulated exchange (Coinbase, Kraken, Binance, etc.). The
  exchange performs KYC, records the transaction, and
  deposits the fiat to your bank account. The most
  convenient method, and the one with the most records.
- **Peer-to-peer (P2P) trade.** Sell crypto directly to
  another person for cash or a bank transfer. The trade is
  off-exchange, but the counterparty may be an informant or
  an undercover officer, and the bank transfer creates a
  record.
- **Crypto ATM.** Sell crypto at an ATM that dispenses
  cash. The ATM records the transaction, has a camera, and
  may require ID for large amounts.
- **Merchant payment.** Spend crypto directly at a merchant
  that accepts it. The merchant records the purchase, and
  the on-chain transaction is public.
- **Gift cards and prepaid cards.** Convert crypto to gift
  cards or prepaid cards, then use them for purchases. The
  issuer records the activation and the redemption.
- **Over-the-counter (OTC) desk.** Sell a large amount to a
  broker who handles the trade and the fiat transfer. The
  broker performs KYC and reports the transaction.
- **Physical exchange.** Meet a buyer in person and exchange
  crypto for cash. The most private method, and the one
  with the highest physical risk.

**The trade-offs.**

| Method | Privacy | Convenience | Legal risk |
|--------|---------|-------------|------------|
| CEX | Low | High | Low (if compliant) |
| P2P | Medium | Medium | Medium |
| Crypto ATM | Medium | High | Medium |
| Merchant payment | Low | High | Low |
| Gift cards | Medium | Medium | Medium |
| OTC desk | Low | High | Low (if compliant) |
| Physical exchange | High | Low | Medium-High |

**The records.**

Every method creates records:

- **CEX.** KYC record, transaction record, bank deposit
  record, and (in most jurisdictions) a report to the tax
  authority.
- **P2P.** Counterparty's records, bank transfer record (if
  used), and any communication records.
- **Crypto ATM.** ATM operator's records, camera footage,
  and (if required) ID scan.
- **Merchant payment.** Merchant's records and the on-chain
  transaction.
- **Gift cards.** Issuer's activation and redemption
  records.
- **OTC desk.** KYC record, transaction record, and bank
  transfer record.
- **Physical exchange.** No formal records, but physical
  risk and the possibility of surveillance.

## 4. Installation and Setup

This section describes setup for an **authorized engagement or
approved research project**.

**Step 1. Define your goal.**

Ask yourself:

- How much do you need to cash out?
- How quickly?
- Into what form (bank account, cash, goods)?
- What is the legal and tax treatment in your jurisdiction?
- What is the engagement's rules of engagement on cashing
  out?

**Step 2. Choose the method.**

Match the method to the goal:

- **Small amounts, high convenience.** CEX or crypto ATM.
- **Large amounts, high convenience.** OTC desk or CEX.
- **Moderate amounts, medium privacy.** P2P or gift cards.
- **High privacy, low convenience.** Physical exchange.

**Step 3. Prepare the receiving account.**

- If using a bank account, consider whether the deposit
  will trigger a report.
- If using a merchant, consider whether the purchase will
  be recorded.
- If using cash, consider how you will store it.

**Step 4. Prepare the records.**

- Keep an offline log of every cashing-out transaction
  (amount, method, date, counterparty if known).
- For tax purposes, keep records of the acquisition cost
  and the sale price.
- For an engagement, keep records for the client's report.

**Step 5. Execute the cash-out.**

Follow the method-specific procedure in section 6.

## 5. Hardening and Configuration

Cashing out is an operational-security procedure, not a
software configuration. The hardening is in the habits.

**Amount hygiene:**

- Avoid cashing out a round amount.
- Split large amounts into multiple smaller cash-outs over
  time.
- Do not cash out the exact amount you need for a specific
  purchase if that amount is distinctive.

**Timing hygiene:**

- Do not cash out immediately after receiving the funds.
- Add random delays between the on-chain transaction and
  the cash-out.
- Do not cash out at predictable times (e.g. every Monday).

**Method hygiene:**

- Use a different method for different contexts.
- Do not reuse the same exchange account, the same P2P
  counterparty, or the same ATM for multiple cash-outs if
  you can avoid it.
- Do not use a method that is known to report aggressively
  unless you have a legitimate reason.

**Account hygiene:**

- Use a bank account that is not linked to your primary
  identity if the use case requires it. (Note: this may
  itself be a crime in some jurisdictions - check the
  law.)
- Do not deposit directly into an account that is linked
  to your personal life if the use case requires
  separation.
- Do not mix cashing-out funds with personal funds.

**Record hygiene:**

- Keep an offline log of every cash-out.
- Do not store the log on a device that is linked to your
  identity.
- For an engagement, hand the log to the client at the end.

**Legal hygiene:**

- Understand the tax treatment of your cash-outs in your
  jurisdiction.
- Understand the AML reporting thresholds.
- Do not structure transactions to avoid reporting
  thresholds - structuring is itself a crime.
- Consult a lawyer if you are unsure.

## 6. Operational Usage

**Centralized exchange:**

1. Choose an exchange that supports your jurisdiction and
   your cryptocurrency.
2. Complete KYC.
3. Deposit the cryptocurrency to your exchange account.
4. Sell for fiat.
5. Withdraw the fiat to your bank account.
6. Record the transaction for tax purposes.

**Peer-to-peer trade:**

1. Choose a P2P platform or a counterparty you trust.
2. Agree on the amount, the rate, and the payment method.
3. Send the cryptocurrency to the counterparty's address.
4. Receive the fiat in the agreed form (cash or bank
   transfer).
5. Verify the fiat before releasing the cryptocurrency if
   using escrow.
6. Record the transaction.

**Crypto ATM:**

1. Choose an ATM that supports the cryptocurrency and the
   amount.
2. Provide the wallet address and (if required) ID.
3. Send the cryptocurrency to the ATM's address.
4. Receive the cash.
5. Verify the amount.
6. Leave the area. Do not go directly home.

**Merchant payment:**

1. Choose a merchant that accepts the cryptocurrency.
2. Complete the purchase.
3. Pay with the cryptocurrency.
4. Keep the receipt.
5. Record the transaction.

**Gift cards and prepaid cards:**

1. Choose a seller that accepts cryptocurrency for gift
   cards or prepaid cards.
2. Send the cryptocurrency.
3. Receive the card code or the physical card.
4. Use the card for purchases.
5. Record the transaction.

**OTC desk:**

1. Choose a reputable OTC desk.
2. Complete KYC.
3. Agree on the amount, the rate, and the settlement
   method.
4. Send the cryptocurrency.
5. Receive the fiat in your bank account.
6. Record the transaction.

**Physical exchange:**

1. Choose a counterparty you trust.
2. Agree on the amount, the rate, and the meeting place.
3. Meet in a public place.
4. Exchange the cryptocurrency and the cash in the same
   meeting.
5. Verify the amount.
6. Leave separately.

## 7. Common Mistakes

- **Cashing out immediately after receiving the funds.**
  Timing correlation is a real risk.
- **Cashing out a round amount.** Round amounts are
  fingerprints.
- **Depositing directly into an account that is linked
  to your identity for a use case that requires
  separation.**
- **Structuring transactions to avoid reporting
  thresholds.** Structuring is itself a crime.
- **Not keeping records.** Tax and legal defense require
  records.
- **Using a KYC exchange for a large amount without
  understanding the reporting requirements.**
- **Using a P2P counterparty who is an informant or an
  undercover officer.**
- **Using an ATM with a camera and an ID scanner for a
  large amount.**
- **Not consulting a lawyer or a tax advisor.**
- **Assuming that the cashing-out method makes the funds
  legally clean.** It does not; the source of funds
  matters.

## 8. Attacks Against It

Cashing out is attacked by:

- **Exchange AML.** The exchange blocks or reports
  suspicious transactions.
- **Bank reporting.** The bank reports large or unusual
  deposits.
- **Chain-analysis vendor.** The vendor links the
  on-chain transaction to the exchange deposit.
- **Counterparty fraud.** The P2P counterparty takes the
  cryptocurrency and does not pay.
- **Undercover law enforcement.** The P2P counterparty
  is an undercover officer.
- **Robbery.** A physical exchange can be a setup for a
  robbery.
- **ATM camera and ID scanner.** The machine records the
  transaction and the user.
- **Prepaid card issuer records.** The issuer records the
  activation and the redemption.
- **Gift card issuer records.** The issuer records the
  activation and the redemption.
- **Tax audit.** The tax authority audits your records.
- **Legal process.** A subpoena to an exchange reveals
  your records.

## 9. Detection (Blue Team)

Exchanges, banks, and law enforcement detect suspicious
cashing-out activity through:

- **Transaction monitoring.** Real-time screening of
  every deposit and withdrawal against the vendor's
  database.
- **Risk scoring.** Assigning a risk score to each
  address and transaction.
- **Sanctions screening.** Checking every transaction
  against the OFAC SDN list and other sanctions lists.
- **Pattern detection.** Identifying known patterns
  (structuring, rapid movement, use of mixers,
  deposit-to-mixer-to-exchange, etc.).
- **Bank reporting.** Reports of large or unusual
  deposits.
- **Tax reporting.** Reports from exchanges and
  payment processors.
- **Investigation.** Following the flow of funds from
  a known criminal address to the cash-out point.
- **Cooperation with law enforcement.** Providing
  data in response to a legal order.

For the analyst, the output is a documented
investigation with a reproducible methodology and a
defensible conclusion.

## 10. Case Studies

**Case 1 - CEX deposit.** A user sold cryptocurrency on
a major exchange and withdrew the fiat to a personal
bank account. The exchange reported the transaction to
the tax authority. When the user was later audited,
the exchange's records were used to reconstruct the
user's entire cryptocurrency history.

**Case 2 - P2P trade.** A user sold cryptocurrency to a
P2P counterparty who was an undercover officer. The
user was arrested after the transaction. The case
illustrates that P2P trades are vulnerable to stings.

**Case 3 - ATM.** A user sold cryptocurrency at an ATM
that required ID for amounts above a threshold. The
ATM operator's records linked the sale to the user's
identity. When law enforcement later subpoenaed the
operator, the user's entire sale history was
reconstructable.

**Case 4 - Merchant payment.** A user paid for a
high-value item with cryptocurrency at a merchant. The
merchant recorded the purchase. When the merchant was
later audited, the user's purchase history was
disclosed.

**Case 5 - Physical exchange.** A user met a buyer in
a coffee shop to sell cryptocurrency for cash. The
buyer was an undercover officer. The user was
arrested after the transaction.

**Case 6 - Authorized engagement.** A red team cashed
out the proceeds of a client engagement through a
regulated OTC desk. The team completed KYC, documented
the transaction, and provided the records to the
client's legal team. The cash-out was fully compliant
and no transactions were flagged.

## 11. Legal and Ethical Notes

Cashing out sits at the intersection of several legal
regimes:

- **AML.** Regulated exchanges and OTC desks are
  required to identify customers and report suspicious
  transactions. The FATF travel rule requires virtual
  asset service providers to share sender and receiver
  information for transfers above a threshold.
- **Sanctions.** OFAC, EU, UK, UN, and other sanctions
  regimes prohibit transactions with sanctioned
  entities.
- **Tax.** In most jurisdictions, cryptocurrency sales
  are taxable events, and the tax authority expects
  records. Structuring transactions to avoid reporting
  is itself a crime.
- **Money transmission.** In some jurisdictions,
  receiving and sending cryptocurrency on behalf of
  others may be considered money transmission and may
  require a license.
- **Banking law.** Some jurisdictions restrict the use
  of personal bank accounts for business transactions.
- **Authorization.** For an engagement, the client's
  rules of engagement must explicitly cover the
  cashing-out method and the records to be kept. Do
  not assume that "the client asked for a red team"
  includes permission to cash out cryptocurrency.
- **Ethical boundary.** Cashing out is a normal
  activity for legitimate users. Using it for
  authorized work is not itself unethical, but it can
  create the appearance of association. Be transparent
  with the client and document the choice.

**Do not use cashing-out methods for:**

- Money laundering.
- Structuring to avoid reporting thresholds.
- Sanctions evasion.
- Financing illegal activity.
- Any activity outside an authorized engagement or
  approved research project.
- Anything that would expose the client to legal
  risk they did not agree to.

## 12. Production Notes

- **Cost.** CEX fees are typically 0.1-0.5%. P2P
  spreads are typically 1-5%. ATM fees are typically
  5-15%. OTC desk fees are typically 0.1-1% plus
  spread. Physical exchange spreads are typically
  1-10%.
- **Speed.** CEX is fast (minutes to hours). P2P
  depends on the counterparty. ATM is instant. OTC
  desk is fast for small amounts, slower for large.
- **Counterparty risk.** Physical exchange has the
  highest counterparty risk. CEX has the lowest.
- **Record-keeping.** Keep an offline log of every
  cash-out for the client's report and for your own
  legal protection.
- **Teardown.** At the end of an engagement, destroy
  any physical instruments (cards, receipts) and
  document the destruction.
- **Migration.** If a method is suspected of being
  compromised, switch to a different method.

## 13. References

- FATF Recommendation 15 and the travel rule.
- OFAC SDN list and other sanctions lists.
- Local tax authority guidance on cryptocurrency.
- Chainalysis, Elliptic, and TRM reports on
  cash-out patterns.
- Academic papers on cryptocurrency AML and
  cash-out analysis.
- Documentation for major exchanges and OTC desks.
- The client's rules of engagement document (for
  authorized engagements).
