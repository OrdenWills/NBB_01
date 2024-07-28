from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_caching import Cache
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

from forms import RegisterForm, LoginForm  # Your forms.py 
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
import os

import cloudinary
import cloudinary.uploader
from datetime import datetime
# import dotenv

# dotenv.load_dotenv('keys.env')

app = Flask(__name__)

# app and database config
app.config['SECRET_KEY'] = os.getenv('APP_SECRET')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')# SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')


jwt = JWTManager(app)
db = SQLAlchemy(app)
CORS(app)

# Socketio
socketio = SocketIO(app, cors_allowed_origins="*")

# Caching
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

login_manager = LoginManager()
login_manager.init_app(app)

# Configure Cloudinary
cloudinary.config(
    cloud_name='dphmp7gih',
    api_key=os.environ.get('CLOUDINARY_API_KEY'),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET'),
)

# ... (your existing `load_user` function) ...
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONFIGURE TABLE
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    is_vendor = db.Column(db.Boolean, default=False)
    vendor_info = relationship("VendorInfo", uselist=False, back_populates="user")



class VendorInfo(db.Model):
    __tablename__ = "vendor_info"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True)
    business_name = db.Column(db.String(255))
    # Other vendor-specific fields
    user = relationship("User", back_populates="vendor_info")

class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user = relationship("User", backref="products")
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    images = db.Column(db.JSON, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    subcategory = db.Column(db.String(50))
    # ... (You might add more product fields here) ...
    def to_dict(self):
        return {
            'id': self.id,
            'vendor_id': self.vendor_id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'images': self.images,
            'category': self.category
        }

class Chat(db.Model):
    __tablename__ = "chats"
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user1 = relationship("User", foreign_keys=[user1_id], backref="chats_as_user1")
    user2 = relationship("User", foreign_keys=[user2_id], backref="chats_as_user2")
    # ... (You might add more chat fields here) ...

class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey("chats.id"), nullable=False)
    chat = relationship("Chat", backref="messages")
    sender_id = db.Column(db.Integer, nullable=False) # User ID or Vendor ID
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False) 

    def to_dict(self):
        return {
            "id": self.id,
            "chat_id": self.chat_id,
            "sender_id": self.sender_id,
            "text": self.text,
            "timestamp": self.timestamp.isoformat()  # Format timestamp as ISO 8601 string
        }

# Create all the tables if they don't exist 
with app.app_context():
    db.create_all()


@app.route('/')
def home():
    products = Product.query.all()
    return jsonify([product.to_dict() for product in products])

# Registration, login, logout) ...
@app.route('/api/register', methods=["POST"])
def register():
    data = request.get_json()
    # extract the data
    email = data.get('email')
    password = data.get('password')
    username = data.get('username')

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "User with this email already exists"}), 409  # Conflict


    hash_and_salted_password = generate_password_hash(
        password,
        method='pbkdf2:sha256',
        salt_length=8
    )
    new_user = User(
        email=email,
        username=username,
        password=hash_and_salted_password,
    )
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    return jsonify({"message": "Login successful!"}), 200


@app.route('/api/login', methods=["POST"])
def login():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"error": "Invalid email or password. Please try again."}), 401 
    else:
        access_token = create_access_token(identity=user.id)
        return jsonify({
            "message": "Login successful!",
            "access_token": access_token,
            "user_id": user.id,
            "is_vendor": user.is_vendor
        }), 200


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

# Then, in protected routes:
@app.route('/api/some-protected-route', methods=['GET'])
@jwt_required()
def some_protected_route():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify({"user_id": user.id})

# Products API Endpoints

@app.route('/api/add-products', methods=['POST'])
@login_required
def add_product():
    
    try:
        # Ensure the user is a vendor (you may need to adjust this based on your user model)
        if not current_user.is_vendor:
            current_user.is_vendor = True
            # return jsonify({"error": "Only vendors can add products"}), 403

        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        category = request.form.get('category')
        subcategory = request.form.get('subcategory')
        
        # Handle image uploads
        image_urls = []
        if 'images' in request.files:
            images = request.files.getlist('images')
            for image in images:
                result = cloudinary.uploader.upload(image) # Cloudinary upload 
                image_urls.append(result['secure_url'])

        new_product = Product(
            vendor_id=current_user.id,
            name=name,
            description=description,
            price=float(price),
            images=image_urls,
            category=category,
            subcategory=subcategory
        )
        

        db.session.add(new_product)
        db.session.commit()

        return jsonify({"message": "Product added successfully", "product_id": new_product.id}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/become-full-time-vendor', methods=['POST'])
@login_required
def become_full_time_vendor():
    data = request.json
    business_name = data.get('business_name')

    if not business_name:
        return jsonify({"error": "Business name is required"}), 400

    if not current_user.vendor_info:
        vendor_info = VendorInfo(user_id=current_user.id, business_name=business_name)
        db.session.add(vendor_info)
    else:
        current_user.vendor_info.business_name = business_name

    current_user.is_vendor = True
    db.session.commit()

    return jsonify({"message": "Successfully registered as a full-time vendor"}), 200

@app.route('/api/products')
def get_products():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    products = Product.query.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        'products': [product.to_dict() for product in products.items],
        'total': products.total,
        'pages': products.pages,
        'current_page': products.page
    })

@cache.cached(timeout=300)  # Cache for 5 minutes
@app.route('/api/products/<int:product_id>')
def get_product(product_id):
    product = Product.query.get(product_id)
    if product:
        return jsonify(product.to_dict())
    else:
        return jsonify({"error": "Product not found"}), 404

# Vendor handling (locations and details)

@app.route('/api/vendors/locations') 
def get_vendor_locations():
    vendors = Vendor.query.all() 

    vendor_locations = [
        {
            'id': vendor.id,
            'latitude': vendor.latitude,
            'longitude': vendor.longitude,
            'category': vendor.category,
            'name': vendor.name
        }
        for vendor in vendors
    ]
    return jsonify(vendor_locations)

@app.route('/api/vendors/<int:vendor_id>')
def get_vendor(vendor_id):
    vendor = Vendor.query.get(vendor_id)
    if vendor:
        return jsonify({
            'id': vendor.id,
            'name': vendor.name,
            'email': vendor.email,
            'phone': vendor.phone,
            'location': vendor.location,
            'latitude': vendor.latitude,
            'longitude': vendor.longitude
        })
    else:
        return jsonify({"error": "Vendor not found"}), 404

# ... (Your existing code for admin-only routes) ...

# Chat API Endpoints


@app.route('/api/chats', methods=['POST'])
@login_required
def create_chat():
    data = request.json
    if not data or 'other_user_id' not in data:
        return jsonify({"error": "Missing required fields"}), 400

    other_user_id = data['other_user_id']

    # Check if the other user exists
    other_user = User.query.get(other_user_id)
    if not other_user:
        return jsonify({"error": "User not found"}), 404

    # Check if a chat already exists between the current user and the other user
    existing_chat = Chat.query.filter(
        ((Chat.user1_id == current_user.id) & (Chat.user2_id == other_user_id)) |
        ((Chat.user1_id == other_user_id) & (Chat.user2_id == current_user.id))
    ).first()

    if existing_chat:
        return jsonify({"chat_id": existing_chat.id, "message": "Chat already exists"}), 200

    new_chat = Chat(user1_id=current_user.id, user2_id=other_user_id)
    db.session.add(new_chat)
    db.session.commit()
    return jsonify({"chat_id": new_chat.id}), 201

@app.route('/api/chats/<int:chat_id>/messages', methods=['GET'])
@login_required
def get_messages(chat_id):
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        chat = Chat.query.get(chat_id)
        if not chat:
            return jsonify({"error": "Chat not found"}), 404

        if current_user.id != chat.user1_id and current_user.id != chat.user2_id:
            return jsonify({"error": "Unauthorized access"}), 403

        messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.timestamp.desc()).paginate(page=page, per_page=per_page)
        
        return jsonify({
            'messages': [message.to_dict() for message in messages.items],
            'total': messages.total,
            'pages': messages.pages,
            'current_page': messages.page
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Socket.IO events
@socketio.on('join')
def on_join(data):
    room = data['chatId']
    join_room(room)
    emit('status', {'msg': f"User has joined the chat."}, room=room)

@socketio.on('leave')
def on_leave(data):
    room = data['chatId']
    leave_room(room)
    emit('status', {'msg': f"User has left the chat."}, room=room)

@socketio.on('sendMessage')
def handle_message(data):
    try:
        chat_id = data['chatId']
        sender_id = data['userId']
        text = data['text']

        # Validate the chat and sender
        chat = Chat.query.get(chat_id)
        if not chat:
            raise ValueError("Chat not found")

        if sender_id != chat.user_id and sender_id != chat.vendor_id:
            raise ValueError("Invalid sender")

        new_message = Message(chat_id=chat_id, sender_id=sender_id, text=text)
        db.session.add(new_message)
        db.session.commit()

        emit('message', new_message.to_dict(), room=chat_id)
    except Exception as e:
        db.session.rollback()
        emit('error', {'message': str(e)}, room=request.sid)


if __name__ == "__main__":
    socketio.run(app, debug=True)