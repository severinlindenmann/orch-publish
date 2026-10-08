# Changelog

## 0.2.0

- Apps page: a Needs you card on top (links to show, shares to publish, failed deploys), one card per app with its
  address, Copy address, Restart, Stop or Start and Delete (one confirm; the typed-slug box is gone), an app view with
  details and its log, and shares grouped by ticket with Copy link or Revoke and Live, Waiting for you and Ended filters.
- A staged index.html in a folder named like a ticket key is labelled index.html, not as a ticket link.

## 0.1.2

- The logs of an app deleted since the last fetch read as empty instead of a failed fetch.
- A live end-to-end test (ORCH_APPS_LIVE=1) drives every button's code against the real server.

## 0.1.1

- Ticket card: only live shares and apps, Revoke or Manage in each row, "until" instead of "ends".
- Apps tab: address and Start or Stop in each row; Copy address on the app card.
- Shares tab: Live and Ended filters, Revoke in each row, Copy link for public shares.
- The ends-soon decision skips shares published for a day or less and shows a readable date.

## 0.1.0

- First version: ticket card, Today tile, publish and expiry decisions, Apps page with Apps, Shares and Server tabs,
  actions Show link once, Revoke, Start, Stop, Restart, Delete, and the done-ticket expiry.
