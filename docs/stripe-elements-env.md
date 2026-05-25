# Stripe Elements checkout — environment variables

The on-site checkout page (`public/checkout-elements.html`) needs your Stripe keys in a **`.env`** file at the **project root** (next to `server.js`). The server loads it automatically via `dotenv`.

## Step-by-step: create `.env`

1. In the project root, create a new file named **`.env`** (leading dot, no extension).

2. Copy the contents of **`.env.example`** into `.env`, then replace the placeholder values with your real keys from the [Stripe Dashboard → API keys](https://dashboard.stripe.com/apikeys).

3. Use keys from the **same mode** (Test vs Live) for every variable. Test keys start with `sk_test_` and `pk_test_`; live keys start with `sk_live_` and `pk_live_`.

### Required for Elements checkout

| Variable | What it is | Where it is used |
|----------|--------------|-------------------|
| **`STRIPE_SECRET_KEY`** | Secret key (`sk_test_...` or `sk_live_...`) | **Server only.** Used to create `PaymentIntent`s. Never put this in frontend code or commit it to git. |
| **`STRIPE_PUBLISHABLE_KEY`** | Publishable key (`pk_test_...` or `pk_live_...`) | Returned by `GET /api/stripe-config` to the browser for Stripe.js. Safe to expose in the client. |

Example (test mode — replace with your own keys):

```env
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
```

### Required to compute the order total

The server totals the cart using **Stripe Price IDs** (`price_...`) from your Dashboard. Each product in the shop must map to a price you set in `.env`:

| Variable | Products that use it |
|----------|----------------------|
| `STRIPE_PRICE_MATCHING` | “Rising” / matching set (and default for Abundant if `STRIPE_PRICE_ABUNDANT` is empty) |
| `STRIPE_PRICE_ABUNDANT` | Optional override for Abundant |
| `STRIPE_PRICE_LOVE_LETTER` | Self Love |
| `STRIPE_PRICE_DATE_NIGHT` | His & Hers |
| `STRIPE_PRICE_MEMORY` | Memory Journal |

### Optional

| Variable | Purpose |
|----------|---------|
| `PUBLIC_BASE_URL` | Base URL for **hosted Checkout** success/cancel links (e.g. `https://yourdomain.com`). Defaults to `http://localhost:PORT`. The Elements page uses the browser origin for `return_url`; this variable does not change that. |
| `PORT` | HTTP port (default `3000`). |

## After editing `.env`

Restart the Node server so it reloads environment variables.

## Apple Pay / Google Pay

- Serve the site over **HTTPS** in production.
- In the Stripe Dashboard, complete **Apple Pay** domain verification for your production domain if you want Apple Pay on the web.
- The checkout page sets Express Checkout to **`applePay: 'always'`** and **`googlePay: 'always'`** so wallet buttons are offered whenever Stripe can show them (including **Chrome on macOS**, where Apple Pay is only available with this setting). Stripe still requires a **registered Apple Pay domain** for real transactions outside localhost.
- **Safari** (macOS / iOS) is the most reliable place to see Apple Pay during development on **http://localhost**.

## Security notes

- **`.env`** should stay **gitignored** (this repo already ignores it). Only commit **`.env.example`** (no real secrets).
- The **secret** key must only exist on the server in `STRIPE_SECRET_KEY`.
