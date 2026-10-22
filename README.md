# NFC attendance clock (MVP, 2026-10-22)

Tap a plain NFC sticker with a phone → a web page opens → attendance is logged with time, name
and the sticker's location. No app for the worker, no hardware, no accounts.

## Layout
- `index.html` — landing + "create a dashboard" (POST /signup → secret admin link `d/?k=…`)
- `d/` — manager dashboard: today's table (time / name / location), workers (personal install
  links, WhatsApp share), stickers (one URL per location, Web NFC write on Android), CSV export
- `s/?k=<install_key>` — personal install link: binds THIS phone to the worker (token in localStorage)
- `t/?c=<code>` — the URL written on the sticker: logs an arrival (GPS stamped), "end of day" button
- `supabase/functions/clock/index.ts` — the whole API, one Edge Function, schema `clock`
- `supabase/migrations/001_clock_schema.sql` — applied to the shared CompanyCard/MeetingBrand project

## Deploy
Site: GitHub Pages from the repository root (static, no build).
API: `SUPABASE_ACCESS_TOKEN=… npx -y supabase@2 functions deploy clock --project-ref ohobtgbyrlczfdztzvqi --no-verify-jwt`

## Anti-spoofing (plain NTAG213/215 stickers)
The sticker URL is static, so the defences are: (1) the phone must be bound through a personal
install link, (2) every tap carries a GPS stamp compared with the sticker's position (`far` flag),
(3) same sticker within 2 minutes = one arrival. Signed-URL tags (NTAG 424 DNA) are the later tier.
