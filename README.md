# DAPV Decentralized Auction Web App (Flask)

Role-based web app for decentralized auction workflow:
- Login-first entry page
- Signup with full profile fields + role (`bidder` / `auctioneer`)
- Profile dashboard with past activity
- Bidder flow: see all auctions, participate, generate keys, choose bid value, submit with auctioneer-shared secret key
- Auctioneer flow: create auction, set bidder limit + minimum auctioneers + Shamir threshold `k`, join multi-auctioneer auctions, start only when minimum auctioneers are present, share secret keys for bidders

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app app.py init-db
flask --app app.py run
```

Open http://127.0.0.1:5000
