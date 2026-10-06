# Pocketful --- Live Demo

Pocketful is a digital wallet and payments application built for the
WeAreDevelopers Dark Factory Hackathon.

This repository contains the deployment version of Pocketful used to
provide the live application demo.

> **Deployment adaptation:** `Pocketful-Demo` is a deployment adaptation of
> the official Pocketful submission. Persistent external storage is used only
> for the hosted demonstration environment. The authoritative hackathon
> implementation and factory-generated history are preserved in
> `Pocketful-Final`.

## Live Demo

https://pocketful-demo.vercel.app/

## Official Hackathon Submission

The authoritative hackathon repository is:

https://github.com/gdjonret/Pocketful-Final

The official repository contains:

-   All four Pocketful implementation stages
-   `FACTORY.md`
-   Generic Planner, Implementer, and Reviewer mandates
-   Complete BAND collaboration evidence in `room.json`
-   Preserved agent-generated Git history
-   Stage verification and execution documentation

## About Pocketful

Pocketful provides wallet and payment workflows through a browser-based
interface and API.

Across the four challenge stages, the application evolves to support
features including:

-   Account creation and authentication
-   Wallet balances
-   Payments between users
-   Payment requests
-   Split payments
-   Payment authorizations and captures
-   Historical and temporal balance views
-   Refunds
-   Batch corrections
-   State export and import

## Autonomous Factory

The official Pocketful implementation was produced using a three-seat
autonomous software engineering factory:

**Planner → Implementer → Reviewer**

The Planner coordinates work and acceptance, the Implementer builds and
verifies scoped changes, and the Reviewer independently evaluates the
implementation before acceptance.

The complete factory definition and collaboration evidence are preserved
in the official submission repository.

## Deployment Repository

This repository exists specifically to support the hosted demonstration.

Deployment-specific configuration or adaptations in this repository
should not be interpreted as part of the original autonomous factory
execution.

For judging, implementation history, factory architecture, mandates,
collaboration evidence, and stage outputs, refer to:

https://github.com/gdjonret/Pocketful-Final

## Team

-   Gloria Djonret
-   Eric Muhirwa Kalisa

## Hackathon

WeAreDevelopers Dark Factory Hackathon --- BAND

## Demo Persistence on Vercel

The hosted demo can persist its complete Pocketful state in Upstash Redis. This
keeps accounts, password hashes, login tokens, balances, payments, requests,
authorizations, refunds, corrections, and temporal ledger data available when
Vercel replaces or restarts an application instance.

Configure these environment variables in the Vercel project:

- `KV_REST_API_URL`
- `KV_REST_API_TOKEN`
- `POCKETFUL_DEMO_ADMIN_SECRET` — a long random secret used only to protect the
  challenge state-management helpers on the public demo.

`UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` are also accepted as
compatibility fallbacks for direct Upstash configurations.

When Redis credentials are absent, Pocketful retains its original in-memory
behavior for local development and challenge-compatible testing.

### Public demo security

When persistence is configured, `/_test/reset`, `/_test/export`, and
`/_test/import` are hidden from unauthenticated public callers. An authorized
administrative call must include the `X-Pocketful-Demo-Admin` header matching
`POCKETFUL_DEMO_ADMIN_SECRET`.

The deployment is a hackathon demonstration and must not be used for real
financial or sensitive personal data.
