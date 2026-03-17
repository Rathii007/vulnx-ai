# VulnScanner Frontend

This app is a Next.js dashboard for the FastAPI vulnerability scanner backend.

## Features

- Start a new scan from a target URL.
- Watch real-time scan progress over SSE.
- Browse scan history.
- View detailed findings and severity levels.
- Download completed scan reports as PDF.

## Setup

1. Install dependencies:

```bash
npm install
```

2. Create environment variables:

```bash
# .env.local
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
NEXT_PUBLIC_SCANNER_API_KEY=change-me-in-production
```

3. Start the frontend:

```bash
npm run dev
```

The app runs at http://localhost:3000.

## Validate

```bash
npm run lint
npm run build
```
