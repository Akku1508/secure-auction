import hashlib
import json
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


class Role:
    BIDDER = 'bidder'
    AUCTIONEER = 'auctioneer'


class AuctionStatus:
    DRAFT = 'DRAFT'
    OPEN = 'OPEN'
    CLOSED = 'CLOSED'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    wallet_address = db.Column(db.String(80), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    auctions_created = db.relationship('Auction', backref='creator', lazy=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Auction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    bid_values_json = db.Column(db.Text, nullable=False, default='[]')
    max_bidders = db.Column(db.Integer, nullable=False, default=10)
    min_auctioneers_required = db.Column(db.Integer, nullable=False, default=2)
    shamir_k = db.Column(db.Integer, nullable=False, default=2)
    status = db.Column(db.String(32), nullable=False, default=AuctionStatus.DRAFT)
    secret_keys_shared = db.Column(db.Boolean, default=False)
    shared_secret_pool_json = db.Column(db.Text, nullable=False, default='[]')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    closed_at = db.Column(db.DateTime, nullable=True)

    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def bid_values(self):
        try:
            return json.loads(self.bid_values_json)
        except json.JSONDecodeError:
            return []

    def shared_secret_pool(self):
        try:
            return json.loads(self.shared_secret_pool_json)
        except json.JSONDecodeError:
            return []


class AuctioneerParticipation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    auction_id = db.Column(db.Integer, db.ForeignKey('auction.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)


class BidParticipation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    auction_id = db.Column(db.Integer, db.ForeignKey('auction.id'), nullable=False)
    bidder_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    public_key = db.Column(db.String(128), nullable=True)
    private_key = db.Column(db.String(128), nullable=True)
    key_generated = db.Column(db.Boolean, default=False)


class Bid(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    auction_id = db.Column(db.Integer, db.ForeignKey('auction.id'), nullable=False)
    bidder_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    selected_bid_value = db.Column(db.Integer, nullable=False)
    commitment_hash = db.Column(db.String(128), nullable=False)
    commitment_nonce = db.Column(db.String(64), nullable=False)
    secret_key_selected = db.Column(db.String(128), nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


def hash_commitment(value: int, nonce: str) -> str:
    return hashlib.sha256(f'{value}:{nonce}'.encode()).hexdigest()


def activity_feed_for_user(user_id: int):
    activities = []

    auctions = Auction.query.filter_by(creator_id=user_id).all()
    for a in auctions:
        activities.append({
            'time': a.created_at,
            'text': f'Created auction "{a.title}" (status: {a.status})'
        })

    bidder_joins = BidParticipation.query.filter_by(bidder_id=user_id).all()
    for j in bidder_joins:
        auction = db.session.get(Auction, j.auction_id)
        if auction:
            activities.append({
                'time': j.joined_at,
                'text': f'Joined as bidder in auction "{auction.title}"'
            })

    bids = Bid.query.filter_by(bidder_id=user_id).all()
    for b in bids:
        auction = db.session.get(Auction, b.auction_id)
        if auction:
            activities.append({
                'time': b.submitted_at,
                'text': f'Submitted bid in "{auction.title}" with value option {b.selected_bid_value}'
            })

    auctioneer_joins = AuctioneerParticipation.query.filter_by(user_id=user_id).all()
    for j in auctioneer_joins:
        auction = db.session.get(Auction, j.auction_id)
        if auction:
            activities.append({
                'time': j.joined_at,
                'text': f'Joined as auctioneer in "{auction.title}"'
            })

    activities.sort(key=lambda x: x['time'], reverse=True)
    return activities


@app.route('/')
def root():
    return redirect(url_for('dashboard' if current_user.is_authenticated else 'login'))


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

        flash('Invalid username/password.', 'error')
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', '').strip().lower()

        if role not in (Role.BIDDER, Role.AUCTIONEER):
            flash('Please select a valid role.', 'error')
            return redirect(url_for('signup'))

        if not all([full_name, username, email, phone, password]):
            flash('All fields are required.', 'error')
            return redirect(url_for('signup'))

        exists = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if exists:
            flash('Username or email already registered.', 'error')
            return redirect(url_for('signup'))

        user = User(
            full_name=full_name,
            username=username,
            email=email,
            phone=phone,
            role=role,
            wallet_address='0x' + secrets.token_hex(20),
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Signup successful. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    activities = activity_feed_for_user(current_user.id)
    return render_template('dashboard.html', activities=activities)


@app.route('/bidder/auctions')
@login_required
def bidder_auctions():
    if current_user.role != Role.BIDDER:
        flash('Only bidders can access this page.', 'error')
        return redirect(url_for('dashboard'))

    auctions = Auction.query.order_by(Auction.created_at.desc()).all()
    return render_template('bidder_auctions.html', auctions=auctions)


@app.route('/auctioneer/auctions')
@login_required
def auctioneer_auctions():
    if current_user.role != Role.AUCTIONEER:
        flash('Only auctioneers can access this page.', 'error')
        return redirect(url_for('dashboard'))

    auctions = Auction.query.order_by(Auction.created_at.desc()).all()
    return render_template('auctioneer_auctions.html', auctions=auctions)


@app.route('/auctioneer/create', methods=['GET', 'POST'])
@login_required
def create_auction():
    if current_user.role != Role.AUCTIONEER:
        flash('Only auctioneers can create auctions.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        bid_values = request.form.get('bid_values', '').strip()  # comma separated
        max_bidders = int(request.form.get('max_bidders', '10'))
        min_auctioneers_required = int(request.form.get('min_auctioneers_required', '2'))
        shamir_k = int(request.form.get('shamir_k', '2'))

        try:
            bid_values_list = [int(x.strip()) for x in bid_values.split(',') if x.strip()]
        except ValueError:
            flash('Bid values must be comma-separated integers.', 'error')
            return redirect(url_for('create_auction'))

        if not bid_values_list:
            flash('Provide at least one bid value.', 'error')
            return redirect(url_for('create_auction'))

        if shamir_k > min_auctioneers_required:
            flash('Shamir threshold k cannot be greater than required auctioneers.', 'error')
            return redirect(url_for('create_auction'))

        auction = Auction(
            title=title,
            description=description,
            bid_values_json=json.dumps(bid_values_list),
            max_bidders=max_bidders,
            min_auctioneers_required=min_auctioneers_required,
            shamir_k=shamir_k,
            creator_id=current_user.id,
            status=AuctionStatus.DRAFT,
        )
        db.session.add(auction)
        db.session.flush()

        db.session.add(AuctioneerParticipation(auction_id=auction.id, user_id=current_user.id))
        db.session.commit()
        flash('Auction created in DRAFT. Add auctioneers and then start.', 'success')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    return render_template('create_auction.html')


@app.route('/auction/<int:auction_id>')
@login_required
def auction_detail(auction_id: int):
    auction = db.session.get(Auction, auction_id)
    if not auction:
        flash('Auction not found.', 'error')
        return redirect(url_for('dashboard'))

    auctioneers = AuctioneerParticipation.query.filter_by(auction_id=auction.id).all()
    bidders = BidParticipation.query.filter_by(auction_id=auction.id).all()
    bids = Bid.query.filter_by(auction_id=auction.id).order_by(Bid.submitted_at.desc()).all()

    is_joined_bidder = BidParticipation.query.filter_by(auction_id=auction.id, bidder_id=current_user.id).first() is not None
    is_joined_auctioneer = AuctioneerParticipation.query.filter_by(auction_id=auction.id, user_id=current_user.id).first() is not None

    return render_template(
        'auction_detail.html',
        auction=auction,
        auctioneers=auctioneers,
        bidders=bidders,
        bids=bids,
        bid_values=auction.bid_values(),
        shared_keys=auction.shared_secret_pool(),
        is_joined_bidder=is_joined_bidder,
        is_joined_auctioneer=is_joined_auctioneer,
    )


@app.route('/auction/<int:auction_id>/join-auctioneer', methods=['POST'])
@login_required
def join_as_auctioneer(auction_id: int):
    if current_user.role != Role.AUCTIONEER:
        flash('Only auctioneers can join as auctioneer.', 'error')
        return redirect(url_for('dashboard'))

    auction = db.session.get(Auction, auction_id)
    if not auction:
        flash('Auction not found.', 'error')
        return redirect(url_for('dashboard'))

    exists = AuctioneerParticipation.query.filter_by(auction_id=auction.id, user_id=current_user.id).first()
    if not exists:
        db.session.add(AuctioneerParticipation(auction_id=auction.id, user_id=current_user.id))
        db.session.commit()
        flash('Joined as auctioneer successfully.', 'success')
    else:
        flash('Already joined as auctioneer.', 'error')

    return redirect(url_for('auction_detail', auction_id=auction.id))


@app.route('/auction/<int:auction_id>/start', methods=['POST'])
@login_required
def start_auction(auction_id: int):
    auction = db.session.get(Auction, auction_id)
    if not auction:
        flash('Auction not found.', 'error')
        return redirect(url_for('dashboard'))

    is_auctioneer = AuctioneerParticipation.query.filter_by(auction_id=auction.id, user_id=current_user.id).first()
    if not is_auctioneer:
        flash('Only joined auctioneers can start this auction.', 'error')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    auctioneer_count = AuctioneerParticipation.query.filter_by(auction_id=auction.id).count()
    if auctioneer_count < auction.min_auctioneers_required:
        flash(
            f'Auction cannot start until minimum auctioneers are present ({auctioneer_count}/{auction.min_auctioneers_required}).',
            'error',
        )
        return redirect(url_for('auction_detail', auction_id=auction.id))

    auction.status = AuctionStatus.OPEN
    auction.started_at = datetime.utcnow()
    db.session.commit()
    flash('Auction started successfully.', 'success')
    return redirect(url_for('auction_detail', auction_id=auction.id))


@app.route('/auction/<int:auction_id>/close', methods=['POST'])
@login_required
def close_auction(auction_id: int):
    auction = db.session.get(Auction, auction_id)
    if not auction:
        flash('Auction not found.', 'error')
        return redirect(url_for('dashboard'))

    is_auctioneer = AuctioneerParticipation.query.filter_by(auction_id=auction.id, user_id=current_user.id).first()
    if not is_auctioneer:
        flash('Only joined auctioneers can close this auction.', 'error')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    auction.status = AuctionStatus.CLOSED
    auction.closed_at = datetime.utcnow()
    db.session.commit()
    flash('Auction closed.', 'success')
    return redirect(url_for('auction_detail', auction_id=auction.id))


@app.route('/auction/<int:auction_id>/share-secret-keys', methods=['POST'])
@login_required
def share_secret_keys(auction_id: int):
    auction = db.session.get(Auction, auction_id)
    if not auction:
        flash('Auction not found.', 'error')
        return redirect(url_for('dashboard'))

    is_auctioneer = AuctioneerParticipation.query.filter_by(auction_id=auction.id, user_id=current_user.id).first()
    if not is_auctioneer:
        flash('Only joined auctioneers can share secret keys.', 'error')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    # Simulate auctioneer secret key share pool for bidders.
    key_pool = [f'SK-{auction.id}-{i}-{secrets.token_hex(4)}' for i in range(max(3, auction.max_bidders))]
    auction.shared_secret_pool_json = json.dumps(key_pool)
    auction.secret_keys_shared = True
    db.session.commit()
    flash('Secret key pool shared by auctioneers. Bidders can now select one key.', 'success')
    return redirect(url_for('auction_detail', auction_id=auction.id))


@app.route('/auction/<int:auction_id>/join-bidder', methods=['POST'])
@login_required
def join_as_bidder(auction_id: int):
    if current_user.role != Role.BIDDER:
        flash('Only bidders can join as bidder.', 'error')
        return redirect(url_for('dashboard'))

    auction = db.session.get(Auction, auction_id)
    if not auction:
        flash('Auction not found.', 'error')
        return redirect(url_for('dashboard'))

    joined = BidParticipation.query.filter_by(auction_id=auction.id, bidder_id=current_user.id).first()
    if joined:
        flash('Already joined as bidder.', 'error')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    bidder_count = BidParticipation.query.filter_by(auction_id=auction.id).count()
    if bidder_count >= auction.max_bidders:
        flash('Bidder limit reached for this auction.', 'error')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    db.session.add(BidParticipation(auction_id=auction.id, bidder_id=current_user.id))
    db.session.commit()
    flash('Joined as bidder.', 'success')
    return redirect(url_for('auction_detail', auction_id=auction.id))


@app.route('/auction/<int:auction_id>/generate-keys', methods=['POST'])
@login_required
def generate_keys(auction_id: int):
    if current_user.role != Role.BIDDER:
        flash('Only bidders can generate keys.', 'error')
        return redirect(url_for('dashboard'))

    participation = BidParticipation.query.filter_by(auction_id=auction_id, bidder_id=current_user.id).first()
    if not participation:
        flash('Join as bidder before generating keys.', 'error')
        return redirect(url_for('auction_detail', auction_id=auction_id))

    participation.public_key = 'PUB-' + secrets.token_hex(16)
    participation.private_key = 'PRIV-' + secrets.token_hex(16)
    participation.key_generated = True
    db.session.commit()
    flash('Bidder keys generated successfully.', 'success')
    return redirect(url_for('auction_detail', auction_id=auction_id))


@app.route('/auction/<int:auction_id>/submit-bid', methods=['POST'])
@login_required
def submit_bid(auction_id: int):
    if current_user.role != Role.BIDDER:
        flash('Only bidders can submit bids.', 'error')
        return redirect(url_for('dashboard'))

    auction = db.session.get(Auction, auction_id)
    if not auction:
        flash('Auction not found.', 'error')
        return redirect(url_for('dashboard'))

    if auction.status != AuctionStatus.OPEN:
        flash('Auction is not OPEN for bidding.', 'error')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    participation = BidParticipation.query.filter_by(auction_id=auction.id, bidder_id=current_user.id).first()
    if not participation or not participation.key_generated:
        flash('Join and generate keys before submitting bid.', 'error')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    bid_value = int(request.form.get('bid_value', '0'))
    secret_key_selected = request.form.get('secret_key_selected', '').strip()

    if bid_value not in auction.bid_values():
        flash('Please select a valid bid value from options.', 'error')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    if not auction.secret_keys_shared:
        flash('Auctioneer has not shared secret keys yet.', 'error')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    if secret_key_selected not in auction.shared_secret_pool():
        flash('Please select a valid secret key from shared list.', 'error')
        return redirect(url_for('auction_detail', auction_id=auction.id))

    nonce = secrets.token_hex(16)
    commitment = hash_commitment(bid_value, nonce)

    bid = Bid(
        auction_id=auction.id,
        bidder_id=current_user.id,
        selected_bid_value=bid_value,
        commitment_hash=commitment,
        commitment_nonce=nonce,
        secret_key_selected=secret_key_selected,
    )
    db.session.add(bid)
    db.session.commit()

    flash('Bid submitted with commitment + selected secret key.', 'success')
    return redirect(url_for('auction_detail', auction_id=auction.id))


@app.cli.command('init-db')
def init_db_command():
    db.create_all()
    print('Initialized the database.')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
