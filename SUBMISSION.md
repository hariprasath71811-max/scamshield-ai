# Devpost submission pack

Copy the relevant sections into the YUnet AIgnite Buildathon 2026 submission form.

---

## General info

**Project name (≤ 60 characters):**

`ScamShield AI`

**Elevator pitch (≤ 200 characters):**

> Paste any suspicious link, review or message. ScamShield AI returns a 0–100 threat index, the evidence behind it and safe next steps in under a second — with no data stored.

**Built with (up to 25 tags):**

Java · HTML5 · CSS3 · Vanilla JavaScript · Java HttpServer · REST API · HTML5 Canvas · Glassmorphism · Explainable AI · Heuristic Risk Scoring · Cybersecurity · Phishing Detection · Consumer Safety · Privacy-first Design · Zero Dependencies

---

## Project story

### Inspiration

Scams no longer look like scams. They look like a limited-time marketplace deal, a
delivery update, a five-star review, or a checkout page with the right logo. The
pressure is designed to make a shopper act before they think.

We wanted to build the pause button.

ScamShield AI was inspired by a simple B2C problem: everyday consumers are asked to
make split-second trust decisions with no safety net. They do not need a SOC dashboard
or a cybersecurity course. They need a clear answer to three questions:

1. Does this look dangerous?
2. Why?
3. What should I do right now?

### What it does

The user pastes one suspicious item — a product listing, review, checkout URL, SMS,
WhatsApp message or email — and selects the content type. ScamShield AI returns:

- A 0–100 threat index.
- A plain-language `SAFE`, `WARNING` or `DANGER` verdict.
- A weighted risk breakdown across signal families.
- Every detected signal with its severity and point contribution.
- Clear consumer-safety recommendations and three immediate next actions.
- A shareable, copyable risk report with a report ID and timestamp.

Four synthetic presets let judges test the entire experience in one click:
**Suspicious 90% Off Deal**, **Phishing SMS Link**, **Clean Official Store** and
**Fake Review Farm**.

### How we built it

**Backend — pure Java, zero dependencies.**
`src/Main.java` uses Java's native `com.sun.net.httpserver.HttpServer`. It serves the
static UI, exposes `POST /api/analyze`, parses JSON with a small in-file parser and
runs an explainable heuristic ensemble. Link/domain checks inspect scheme, host shape,
punycode, IP literals, shorteners, risky TLDs, sensitive paths, redirects and brand
mismatches. Language checks detect urgency, threats, credential requests, payment
rails, fake-review patterns, secrecy and off-platform contact. Compound rules raise
the score when individually weak signals form one coherent attack.

The API is intentionally transparent: each signal has a title, description, severity,
category and point value. Scores are capped at 100. No external AI API, database,
API key or build tool is required.

**Frontend — one self-contained HTML file.**
The UI uses inline CSS and vanilla JavaScript with a dark glassmorphism design, a
pointer-reactive Canvas particle network, an animated circular threat meter, pulsing
status badges, animated risk bars, staggered evidence cards, hover-tilt interactions,
clipboard paste, one-click presets and a copyable report. It is responsive, keyboard
accessible and respects `prefers-reduced-motion`.

**Delivery — ready to run and deploy.**
A one-command Windows/Linux launcher, Dockerfile, GitHub Actions compile check,
security headers, static-path confinement, request-size limits and a health endpoint
make the project easy for judges to run and easy to ship.

### Challenges we ran into

- **Making risk scores feel trustworthy.** A single keyword is not evidence. We
  weighted signals, deduplicated them and added compound rules so a lone "limited
  time" does not accuse a legitimate shop, while urgency + OTP + a hostile domain
  produces a decisive verdict.
- **Keeping the demo dependency-free.** No Maven, no npm, no external AI API. That
  meant writing our own JSON parser, static server and structured scoring model in
  one Java file — while still exposing a clean API contract.
- **Designing for clarity under pressure.** The report had to be useful in a glance:
  score first, action second, evidence third. We built the information hierarchy
  around that sequence.
- **A high-impact interface without a frontend build.** All animation, layout and
  state management live in one HTML file, with a Canvas particle field that stays
  smooth and degrades gracefully for reduced-motion users.

### Accomplishments we are proud of

- A complete end-to-end product — not a mockup — with a real API and real scoring.
- Explainable evidence behind every verdict, including point contributions.
- One-click demos covering high-risk, safe and cautionary outcomes.
- A self-contained, responsive UI that looks and feels like a shipped consumer product.
- A privacy-first architecture: no content storage, no third-party calls, no accounts.
- Deployment artifacts included: Dockerfile, CI workflow, run scripts and API docs.

### What we learned

- Consumer trust is a UX problem as much as a security problem. The best warning is
  one a frightened person can understand and act on immediately.
- Explainability makes risk actionable. "100/100" alone creates anxiety; "brand name
  used on an unverified domain, credential harvesting language, dangerous destination"
  creates understanding.
- Heuristics need humility. ScamShield is a verification aid, not a guarantee, and the
  product says so openly.

### What is next for ScamShield AI

- Optional live domain intelligence: WHOIS age, TLS certificate history and threat feeds.
- Screenshot and QR-code scanning for messaging apps.
- A browser extension and share-sheet mobile flow so verification happens where the
  scam arrives.
- A multilingual signal pack for Bengali, Hindi and other regional languages.
- Community reporting and a privacy-preserving signal feedback loop.
- A lightweight phishing-awareness dashboard for families and small businesses.

---

## Try it out links

- **Live demo:** `https://<your-deployment-url>`
- **GitHub repository:** `https://github.com/<your-username>/scamshield-ai`
- **Video demo:** `https://youtu.be/<your-video-id>`

---

## Additional info (judges)

**Product name & brief:**

ScamShield AI is an explainable consumer fraud and phishing sentinel. Users paste a
suspicious link, review or message; the Java backend scores it from 0–100 using
weighted signals and domain checks, then returns evidence, a risk breakdown and
actionable safety steps. It runs with zero external dependencies and stores no content.

**How to run:**

```bash
cd scamshield-ai
javac --release 11 -d out src/Main.java
java --add-modules jdk.httpserver -cp out Main
```

Open `http://localhost:8080/` and click any preset.

**Demo walkthrough:**

1. Click **Suspicious 90% Off Deal** → score 100, `DANGER`.
2. Review the weighted composition and evidence cards.
3. Click **Copy report** to produce a shareable consumer report.
4. Return to the analyzer and click **Clean Official Store** → score 0, `SAFE`.
5. Try **Fake Review Farm** → score 52, `WARNING`.

**Demo video:** `https://youtu.be/<your-video-id>`
