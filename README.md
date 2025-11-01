# QR Car Generator (Admin + Public)

Admin UI to create QR codes for cars. Public page shows owner name and car number, with a button to dial a proxy/virtual number. DL/RC links are protected by a password.

## Features
- Admin login (simple password)
- Create car entries (owner name, car no, mobile, proxy number, DL link, RC link, docs password)
- Auto-generate QR that links to the public page
- Public page:
  - "Dial owner" uses the proxy number
  - DL/RC unlocked with password and short-lived links
- Print-friendly sticker view

## Quick start
1) Install Node.js 18+
2) Copy `.env.example` to `.env` and edit values
3) `npm install`
4) `npm start`
5) Open `http://localhost:3000`
   - Login with `ADMIN_PASSWORD` from `.env`
   - Create a car entry and get the QR

## Public base URL
- Set `PUBLIC_BASE_URL` in `.env` to what you want encoded into the QR, e.g.
  - Local: `http://localhost:3000`
  - Tunneling: `https://abc123.ngrok.io`
- The QR will point to `${PUBLIC_BASE_URL}/c/<id>`

## Masked calling
- This demo just uses `tel:<virtual_number>` for the "Dial owner" button.
- For production masking (proxy numbers, two-leg calls), integrate a telephony provider (Exotel, MyOperator, Airtel IQ, etc) in `/api/call/:id`.

## Security notes
- Passwords for DL/RC are stored as bcrypt hashes.
- DL/RC links are redirected via short-lived, one-time tokens.
- Add your own storage for documents and signed URLs if needed.

## Print
- Open the print view from the success page to print a sticker with QR + meta.
