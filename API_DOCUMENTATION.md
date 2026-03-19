# Earth Exchange API Documentation

**Base URL:** `https://api.erth.network`

Earth Exchange is a decentralized exchange (AMM DEX) on Secret Network. All trading pairs use ERTH as the base currency.

---

## Endpoints

### GET https://api.erth.network/tickers

CoinGecko-compliant DEX ticker endpoint. Returns 24-hour pricing, volume, and liquidity data for all trading pairs.

**Response:**

```json
[
  {
    "ticker_id": "<erth_contract>_<token_b_contract>",
    "base_currency": "<erth_contract_address>",
    "target_currency": "<token_b_contract_address>",
    "pool_id": "<token_b_contract_address>",
    "last_price": "0.5",
    "base_volume": "1000",
    "target_volume": "500",
    "liquidity_in_usd": "50000"
  }
]
```

| Field | Type | Description |
|-------|------|-------------|
| `ticker_id` | string | Pair identifier: `{base_contract}_{target_contract}` |
| `base_currency` | string | ERTH token contract address |
| `target_currency` | string | Target token contract address |
| `pool_id` | string | Unique pool identifier (target token contract address) |
| `last_price` | decimal string | Price of 1 ERTH in target token terms |
| `base_volume` | decimal string | 24-hour trading volume in ERTH |
| `target_volume` | decimal string | 24-hour trading volume in target token |
| `liquidity_in_usd` | decimal string | Total pool liquidity in USD |

**Trading Pairs:**

| Pair | Base | Target |
|------|------|--------|
| ERTH/ANML | ERTH | ANML |
| ERTH/SSCRT | ERTH | sSCRT (wrapped SCRT) |
| ERTH/XMR | ERTH | sXMR (wrapped Monero) |

**Notes:**
- This is an AMM DEX; there is no order book.
- Volume is derived from on-chain daily volume buckets.
- Liquidity in USD is calculated from pool reserves and latest price data.

---

### GET https://api.erth.network/supply/erth

Returns the current ERTH total supply as a plain number.

**Response:** `text/plain`

```
1000000.123456
```

---

### GET https://api.erth.network/supply/anml

Returns the current ANML total supply as a plain number.

**Response:** `text/plain`

```
5000000.654321
```

---

### GET https://api.erth.network/analytics

Returns full analytics history and latest snapshot including ERTH/ANML prices, market caps, TVL, and per-pool data.

**Response:**

```json
{
  "latest": {
    "timestamp": 1710806400000,
    "erthPrice": 0.0042,
    "erthTotalSupply": 1000000,
    "erthMarketCap": 4200,
    "tvl": 25000,
    "anmlPrice": 0.0001,
    "anmlTotalSupply": 5000000,
    "anmlMarketCap": 500,
    "scrtPrice": 0.35,
    "pools": [
      {
        "token": "SSCRT",
        "erthPrice": 0.0042,
        "tvl": 15000,
        "arbDepth": 0,
        "tokenPrice": 0.35
      }
    ]
  },
  "history": [ ]
}
```

---

### GET https://api.erth.network/erth-price

Returns the current ERTH price in USD.

**Response:**

```json
{
  "price": 0.0042,
  "timestamp": 1710806400000,
  "marketCap": 4200
}
```

---

### GET https://api.erth.network/anml-price

Returns the current ANML price in USD.

**Response:**

```json
{
  "price": 0.0001,
  "timestamp": 1710806400000,
  "marketCap": 500
}
```

---

## General Information

- All endpoints are publicly accessible with no authentication required.
- Responses are JSON unless otherwise noted (supply endpoints return `text/plain`).
- Price and supply data is sourced live from on-chain contract queries on Secret Network.
- Analytics snapshots are updated hourly.
