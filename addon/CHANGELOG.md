# Changelog

## 0.1.3

- A ticket moving to done gives its open-ended shares their 7-day end again: on_event used an outbox argument core does not take and crashed.

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
