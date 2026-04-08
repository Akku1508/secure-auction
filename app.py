import hashlib
import secrets
from datetime import datetime

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-change-me'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auction.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    wallet_address = db.Column(db.String(80), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    auctions = db.relationship('Auction', backref='creator', lazy=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Auction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    min_bid = db.Column(db.Integer, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(32), default='BIDDING_OPEN')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bids = db.relationship('Bid', backref='auction', lazy=True, cascade='all,delete-orphan')


class Bid(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    auction_id = db.Column(db.Integer, db.ForeignKey('auction.id'), nullable=False)
    bidder_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    committed_amount_hash = db.Column(db.String(128), nullable=False)
    commitment_nonce = db.Column(db.String(64), nullable=False)
    revealed_amount = db.Column(db.Integer, nullable=True)
    is_revealed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


def hash_commitment(amount: int, nonce: str) -> str:
    return hashlib.sha256(f'{amount}:{nonce}'.encode()).hexdigest()


@app.route('/')
def home():
    active_auctions = Auction.query.order_by(Auction.created_at.desc()).all()
    return render_template('index.html', auctions=active_auctions)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists.', 'error')
            return redirect(url_for('register'))

        wallet_address = '0x' + secrets.token_hex(20)
        user = User(username=username, email=email, wallet_address=wallet_address)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Login successful.', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid credentials.', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


@app.route('/dashboard')
@login_required
def dashboard():
    my_auctions = Auction.query.filter_by(creator_id=current_user.id).order_by(Auction.created_at.desc()).all()
    my_bids = Bid.query.filter_by(bidder_id=current_user.id).order_by(Bid.created_at.desc()).all()
    return render_template('dashboard.html', my_auctions=my_auctions, my_bids=my_bids)


@app.route('/auction/create', methods=['GET', 'POST'])
@login_required
def create_auction():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        min_bid = int(request.form.get('min_bid', '0'))
        end_time_str = request.form.get('end_time', '')

        try:
            end_time = datetime.fromisoformat(end_time_str)
        except ValueError:
            flash('Invalid end time format.', 'error')
            return redirect(url_for('create_auction'))

        if end_time <= datetime.utcnow():
            flash('End time must be in the future.', 'error')
            return redirect(url_for('create_auction'))

        auction = Auction(
            title=title,
            description=description,
            min_bid=min_bid,
            end_time=end_time,
            creator_id=current_user.id,
        )
        db.session.add(auction)
        db.session.commit()
        flash('Auction created successfully.', 'success')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    return render_template('create_auction.html')


@app.route('/auction/<int:auction_id>', methods=['GET', 'POST'])
@login_required
def auction_detail(auction_id: int):
    auction = db.session.get(Auction, auction_id)
    if not auction:
        flash('Auction not found.', 'error')
        return redirect(url_for('dashboard'))

    now = datetime.utcnow()
    if now > auction.end_time and auction.status == 'BIDDING_OPEN':
        auction.status = 'BIDDING_CLOSED'
        db.session.commit()

    if request.method == 'POST' and auction.status == 'BIDDING_OPEN':
        amount = int(request.form.get('amount', '0'))
        if amount < auction.min_bid:
            flash('Bid is below minimum bid.', 'error')
            return redirect(url_for('auction_detail', auction_id=auction.id))

        nonce = secrets.token_hex(16)
        commitment_hash = hash_commitment(amount, nonce)

        bid = Bid(
            auction_id=auction.id,
            bidder_id=current_user.id,
            committed_amount_hash=commitment_hash,
            commitment_nonce=nonce,
        )
        db.session.add(bid)
        db.session.commit()
        flash('Bid committed successfully (hidden until reveal). Save your bid amount locally.', 'success')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    all_bids = Bid.query.filter_by(auction_id=auction.id).order_by(Bid.created_at.desc()).all()
    participants = len({b.bidder_id for b in all_bids})
    return render_template('auction_detail.html', auction=auction, bids=all_bids, participants=participants)


@app.route('/auction/<int:auction_id>/reveal', methods=['POST'])
@login_required
def reveal_bid(auction_id: int):
    auction = db.session.get(Auction, auction_id)
    if not auction:
        flash('Auction not found.', 'error')
        return redirect(url_for('dashboard'))

    amount = int(request.form.get('amount', '0'))
    nonce = request.form.get('nonce', '').strip()

    bid = Bid.query.filter_by(auction_id=auction.id, bidder_id=current_user.id).order_by(Bid.created_at.desc()).first()
    if not bid:
        flash('No bid found for reveal.', 'error')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    if bid.committed_amount_hash != hash_commitment(amount, nonce):
        flash('Reveal failed: commitment mismatch.', 'error')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    bid.revealed_amount = amount
    bid.is_revealed = True
    db.session.commit()
    flash('Bid reveal successful.', 'success')
    return redirect(url_for('auction_detail', auction_id=auction.id))


@app.route('/auction/<int:auction_id>/winner')
@login_required
def winner(auction_id: int):
    auction = db.session.get(Auction, auction_id)
    if not auction:
        flash('Auction not found.', 'error')
        return redirect(url_for('dashboard'))

    revealed_bids = Bid.query.filter_by(auction_id=auction.id, is_revealed=True).all()
    if not revealed_bids:
        flash('No revealed bids yet.', 'error')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    winning_bid = max(revealed_bids, key=lambda b: b.revealed_amount)
    winner_user = db.session.get(User, winning_bid.bidder_id)

    return render_template(
        'winner.html',
        auction=auction,
        winning_bid=winning_bid,
        winner_user=winner_user,
        total_revealed=len(revealed_bids),
    )


@app.cli.command('init-db')
def init_db_command():
    db.create_all()
    print('Initialized the database.')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
