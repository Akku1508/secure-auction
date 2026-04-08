# DAPV Decentralized Auction Web App (Flask)

A complete starter website for a privacy-preserving decentralized-auction workflow with:
- User signup/login/logout
- Auction creation and browsing
- Commit bid flow (hash commitment)
- Reveal bid flow (commitment verification)
- Winner announcement
- SQLite database via Flask-SQLAlchemy

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app app.py init-db
flask --app app.py run
```

Open http://127.0.0.1:5000

## Notes

This is an application-layer simulation of the cryptographic protocol and decentralized workflow. It provides a production-style web UX skeleton that you can extend with:
- your ring signature implementation,
- Pedersen commitment over EC points,
- OT/threshold logic,
- Ethereum/Web3 smart contract integration.
