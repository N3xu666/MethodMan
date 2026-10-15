# Physical and Prepaid

## 1. Overview

Physical and prepaid methods are the cash-to-crypto and
cash-to-cash on-ramps that do not require a bank account, a
credit card, or a KYC identity check. They are the traditional
way to acquire cryptocurrency without linking the purchase to
your legal identity.

The category includes:

- **Cash by mail.** Sending physical cash to a seller who
  sends cryptocurrency to your address.
- **In-person cash trades.** Meeting a seller, handing over
  cash, receiving cryptocurrency in person.
- **Prepaid cards.** Cards purchased with cash and used to
  buy cryptocurrency online.
- **Crypto ATMs.** Machines that accept cash and send
  cryptocurrency to a wallet, or accept cryptocurrency and
  dispense cash.
- **Gift cards.** Some sellers accept gift cards (Amazon,
  Apple, etc.) in exchange for cryptocurrency.
- **Cash-to-cash.** Physical exchange of one currency for
  another, or of cash for a prepaid instrument.

Each method has different operational-security properties.
This file covers the trade-offs, the practical procedures, and
the common mistakes.

This is the third file in the **Anonymous Crypto Operations
and AML** subcategory, after Monero and Bitcoin.

## 2. Threat Model

The threat model for physical and prepaid methods is different
from the threat model for on-chain privacy. The adversary is
not a blockchain analyst; it is:

| Threat | Effect on physical/prepaid |
|--------|----------------------------|
| KYC at a regulated exchange | Avoided - these methods are off-exchange |
| Bank record of the purchase | Avoided - cash does not appear in a bank statement |
| Credit-card record | Avoided - prepaid cards are not linked to a bank account |
| AML transaction reporting | Partially avoided - thresholds and rules vary by jurisdiction |
| Physical surveillance | NOT mitigated - a meeting can be observed |
| Counterparty risk | NOT mitigated - the seller can steal, cheat, or inform |
| Mail interception | NOT mitigated - cash by mail can be stolen or traced |
| ATM camera | NOT mitigated - ATMs have cameras and sometimes ID scanners |
| Prepaid card issuer records | NOT mitigated - the issuer knows where the card was bought and used |
| Gift card issuer records | NOT mitigated - the issuer knows the card was activated and redeemed |
| Undercover law enforcement | NOT mitigated - an in-person trade can be a sting |

**What physical and prepaid methods do NOT protect against:**

- A counterparty who is an informant or an undercover officer.
- Physical surveillance of the meeting or the ATM.
- Mail interception if the package is not properly disguised.
- A prepaid card issuer that cooperates with law enforcement.
- A gift card issuer that flags unusual redemption patterns.
- Your own operational-security mistakes: reusing a meeting
  location, a phone number, or a vehicle.

## 3. How It Works (technical)

**Cash by mail.**

- The buyer and seller agree on an amount and a rate over an
  encrypted channel.
- The buyer sends physical cash (usually in a padded envelope
  or a small package) to an address provided by the seller.
- The seller confirms receipt and sends cryptocurrency to the
  buyer's address.
- The escrow is either the seller's reputation (on a forum) or
  a third-party escrow service.
- Risks: mail theft, seller non-delivery, seller informing,
  postal inspection.

**In-person cash trades.**

- The buyer and seller agree on a time and a public place.
- The buyer brings cash, the seller brings a device with a
  wallet.
- The seller sends cryptocurrency to the buyer's address, or
  the buyer sends cash after confirmation.
- Risks: robbery, surveillance, sting, counterparty
  non-delivery.

**Prepaid cards.**

- The buyer purchases a prepaid card with cash at a retail
  store.
- The buyer uses the card to buy cryptocurrency online from
  a seller that accepts prepaid cards.
- The card issuer records the activation and the redemption.
- Risks: card issuer records, seller fraud, card
  deactivation.

**Crypto ATMs.**

- The buyer inserts cash and provides a wallet address.
- The machine sends cryptocurrency to the address.
- Some machines require ID verification for amounts above a
  threshold; others do not.
- Risks: camera, ID scanner, machine operator records,
  location tracking.

**Gift cards.**

- The buyer purchases a gift card with cash.
- The buyer sends the gift card code to a seller who accepts
  it in exchange for cryptocurrency.
- The gift card issuer records the activation and the
  redemption.
- Risks: issuer records, seller fraud, card deactivation.

**Cash-to-cash.**

- The buyer exchanges one physical currency for another, or
  cash for a prepaid instrument.
- The exchange rate is usually worse than the market rate.
- Risks: counterparty risk, physical risk, no recourse.

## 4. Installation and Setup

This section describes setup for an **authorized engagement or
approved research project**.

**Step 1. Choose the method.**

Match the method to the threat model:

- If the threat is a bank record, any cash method works.
- If the threat is a KYC exchange, any off-exchange method
  works.
- If the threat is a counterparty who might inform, prefer
  methods with no human counterparty (ATMs, prepaid cards).
- If the threat is physical surveillance, avoid in-person
  meetings and ATMs with cameras.

**Step 2. Prepare the receiving wallet.**

- Use a wallet that does not leak your identity (see the
  Monero and Bitcoin files in this subcategory).
- Generate the receiving address before the purchase.
- Do not reuse the address across purchases.
- Test the wallet with a small amount first.

**Step 3. Prepare the cash.**

- Withdraw cash in a way that does not create a single large
  withdrawal event (e.g. multiple smaller withdrawals over
  time).
- Do not use a bank that is known to report large cash
  withdrawals.
- If the amount is large, consider splitting it across
  multiple methods and multiple days.

**Step 4. Prepare the communication channel.**

- Use an encrypted messaging app (see the Secure
  Communications subcategory) for negotiating with sellers.
- Use a dedicated phone number or account for the purchase.
- Do not use your personal phone number or your personal
  email.

**Step 5. Execute the purchase.**

Follow the method-specific procedure in section 6.

## 5. Hardening and Configuration

Physical and prepaid methods are operational-security
procedures, not software configurations. The hardening is in
the habits.

**Counterparty hygiene:**

- Prefer sellers with a long reputation on a well-known
  forum.
- Use escrow if available. Understand the escrow's terms.
- Do not use a seller who insists on a non-escrow, non-refundable
  arrangement for a first transaction.
- Do not reveal your real identity to the seller.
- Do not use a phone number or email that is linked to your
  identity.

**Physical hygiene:**

- For in-person trades, choose a public place with multiple
  exits and no obvious cameras.
- Do not use the same location twice.
- Do not use the same vehicle twice if you can avoid it.
- Do not carry more cash than the transaction requires.
- Do not carry identification that links you to the cash.

**Communication hygiene:**

- Use an encrypted messaging app with disappearing messages.
- Do not send photos of yourself, your documents, or your
  location.
- Do not use the same account for multiple purchases.
- Do not reuse the same wording in messages to different
  sellers.

**Financial hygiene:**

- Do not deposit the cryptocurrency into a wallet that is
  linked to your identity.
- Do not convert the cryptocurrency to fiat through a
  regulated exchange without understanding the KYC
  implications.
- Keep an offline log of the purchase (amount, rate, seller
  handle, method) for your own records.

## 6. Operational Usage

**Cash by mail:**

1. Negotiate the amount, the rate, and the address over an
   encrypted channel.
2. Package the cash in a way that does not look like cash
   (e.g. between pages of a book, inside a padded envelope).
3. Send with tracking if the seller requires it; without
   tracking if you want to avoid a record.
4. Confirm with the seller after delivery.
5. Receive the cryptocurrency to your pre-generated address.
6. Verify the amount in your own wallet.

**In-person cash trades:**

1. Negotiate the time and place over an encrypted channel.
2. Arrive early and observe the location before the meeting.
3. Meet in a public place. Do not go to a private location.
4. Confirm the amount and the rate before handing over cash.
5. Send or receive the cryptocurrency in the same meeting.
   Do not split the transaction across meetings.
6. Leave separately. Do not walk to your vehicle with the
   counterparty.

**Prepaid cards:**

1. Buy the card with cash at a retail store.
2. Activate the card if required.
3. Use the card to buy cryptocurrency from a seller that
   accepts prepaid cards.
4. Do not reuse the same card for multiple purchases.
5. Destroy the card after the purchase.

**Crypto ATMs:**

1. Choose an ATM that does not require ID for the amount you
   need.
2. Bring cash and a wallet address.
3. Use the machine. Do not interact with anyone who
   approaches you.
4. Verify the transaction in your wallet.
5. Leave the area. Do not go directly home.

**Gift cards:**

1. Buy the gift card with cash at a retail store.
2. Do not activate it online with your personal account.
3. Send the code to the seller over an encrypted channel.
4. Receive the cryptocurrency to your pre-generated address.
5. Verify the amount in your own wallet.

**Cash-to-cash:**

1. Negotiate the rate over an encrypted channel.
2. Meet in a public place.
3. Exchange the cash and the other instrument in the same
   meeting.
4. Verify the instrument before leaving.

## 7. Common Mistakes

- **Using a bank withdrawal that creates a single large
  event.** Multiple smaller withdrawals over time are less
  noticeable.
- **Using your personal phone number or email with the
  seller.** This links the purchase to your identity.
- **Reusing the same meeting location or vehicle.** This
  links multiple purchases.
- **Sending cash without tracking for a large amount.** If
  the package is lost or stolen, there is no recourse.
- **Using a prepaid card that is linked to your identity.**
  Some cards require activation with a phone number or an
  email.
- **Using an ATM with a camera and an ID scanner for a
  large amount.** The machine records the transaction and
  the location.
- **Buying a gift card online with your personal account.**
  The issuer records the purchase.
- **Not testing the wallet before the purchase.** A typo in
  the address loses the funds.
- **Reusing the receiving address across purchases.** The
  address links the purchases.
- **Not keeping an offline log.** You will not remember the
  details later.

## 8. Attacks Against It

Physical and prepaid methods are attacked by:

- **Counterparty fraud.** The seller takes the cash and does
  not send the cryptocurrency, or sends less than agreed.
- **Robbery.** An in-person trade can be a setup for a
  robbery.
- **Undercover law enforcement.** An in-person trade can be
  a sting.
- **Mail theft.** Cash by mail can be stolen in transit.
- **Postal inspection.** In some jurisdictions, postal
  inspectors can open packages.
- **ATM camera and ID scanner.** The machine records the
  transaction, the location, and sometimes the user's
  identity.
- **Prepaid card issuer records.** The issuer knows where
  the card was bought and where it was used.
- **Gift card issuer records.** The issuer knows where the
  card was activated and redeemed.
- **Surveillance of the meeting location.** Cameras,
  undercover officers, or informants.
- **Communication interception.** If the encrypted channel
  is compromised or the seller is an informant, the
  negotiation is visible.

## 9. Detection (Blue Team)

Law enforcement and researchers identify physical and prepaid
activity through:

- **Informants and undercover officers.** The most reliable
  source for in-person trades.
- **Surveillance.** Cameras at ATMs, meeting locations, and
  retail stores.
- **Mail interception.** Postal inspectors and controlled
  deliveries.
- **Prepaid card issuer records.** Activation and redemption
  data.
- **Gift card issuer records.** Activation and redemption
  data.
- **ATM operator records.** Transaction logs and camera
  footage.
- **Bank records.** Large cash withdrawals and deposits.
- **Communication metadata.** If the encrypted channel is
  compromised or the seller is an informant.
- **Blockchain analysis.** The receiving address can be
  clustered with other addresses, and the purchase can be
  correlated with the on-chain transaction.

For a defender or researcher, the practical output is a
documented purchase path and, if the seller is an informant,
a full transcript of the negotiation.

## 10. Case Studies

**Case 1 - Cash by mail.** A user bought cryptocurrency by
mailing cash to a seller on a forum. The package was
intercepted by postal inspectors, who photographed the
contents and forwarded the package to the destination
address. The seller was already under investigation, and the
user's address was linked to the seller's records.

**Case 2 - In-person trade.** A user met a seller in a
coffee shop to buy cryptocurrency with cash. The seller was
an undercover officer. The user was arrested after the
transaction. The case illustrates that in-person trades are
vulnerable to stings.

**Case 3 - ATM.** A user bought cryptocurrency at an ATM
that required ID for amounts above a threshold. The user
provided a driver's license. The ATM operator's records
linked the purchase to the user's identity. When law
enforcement later subpoenaed the operator, the user's
entire purchase history was reconstructable.

**Case 4 - Authorized engagement.** A red team bought
cryptocurrency for a client engagement using cash by mail
through a well-reputed seller on a forum. The team used a
dedicated address, a dedicated communication channel, and
a dedicated wallet. At the end of the engagement, the wallet
was destroyed and the log was handed to the client. The
engagement report documented the purchase path and the
teardown.

## 11. Legal and Ethical Notes

Physical and prepaid methods are legal in most
jurisdictions, but the legal landscape is complex:

- **Money transmission laws.** In some jurisdictions,
  buying and selling cryptocurrency for cash without a
  license is considered money transmission and is a
  criminal offense.
- **AML reporting.** Some jurisdictions require reporting
  of cash transactions above a threshold. Structuring
  transactions to avoid the threshold is itself a crime.
- **Counterfeit detection.** Prepaid cards and gift cards
  can be counterfeit. Buying or using a counterfeit card is
  a crime.
- **Sanctions.** Some jurisdictions restrict transactions
  with sanctioned entities. Buying cryptocurrency from a
  sanctioned seller is a criminal offense.
- **Tax.** In most jurisdictions, cryptocurrency purchases
  and sales are taxable events, and the tax authority
  expects records.
- **Authorization.** For an engagement, the client's rules
  of engagement must explicitly cover the use of
  cryptocurrency and the purchase method. Do not assume
  that "the client asked for a red team" includes
  permission to buy cryptocurrency with cash.
- **Ethical boundary.** Physical and prepaid methods are
  used by criminal actors. Using them for authorized work
  is not itself unethical, but it can create the appearance
  of association. Be transparent with the client and
  document the choice.

**Do not use physical or prepaid methods for:**

- Money laundering.
- Structuring to avoid reporting thresholds.
- Sanctions evasion.
- Financing illegal activity.
- Any activity outside an authorized engagement or
  approved research project.
- Anything that would expose the client to legal risk
  they did not agree to.

## 12. Production Notes

- **Cost.** Physical and prepaid methods usually have a
  worse rate than regulated exchanges (typically 3-10%
  above market). Budget for the spread.
- **Speed.** Cash by mail takes days. In-person trades can
  be same-day. ATMs are instant. Prepaid cards depend on
  the seller.
- **Counterparty risk.** The seller is the weakest link.
  Prefer escrow, reputation, and small first transactions.
- **Record-keeping.** Keep an offline log of every purchase
  (amount, rate, seller handle, method, date) for your own
  records.
- **Teardown.** At the end of an engagement, destroy any
  physical instruments (cards, receipts) and document the
  destruction.
- **Migration.** If a method is suspected of being
  compromised, switch to a different method and a
  different seller.

## 13. References

- FATF guidance on virtual assets and money transmission.
- Local regulations on cash transactions and reporting
  thresholds.
- Forum reputation systems for peer-to-peer cryptocurrency
  sellers.
- Academic papers on the operational security of physical
  cryptocurrency purchases.
- Vendor threat-intel reports on cryptocurrency-related
  fraud and stings.
- The client's rules of engagement document (for authorized
  engagements).
