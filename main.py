from flask import Flask, render_template, request, jsonify, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_caching import Cache
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

from sqlalchemy import func
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
    is_full_time_vendor = db.Column(db.Boolean, default=False)
    products = relationship("Product", back_populates="user", cascade="all, delete-orphan")
    vendor_info = relationship("VendorInfo", uselist=False, back_populates="user", cascade="all, delete-orphan")

class VendorInfo(db.Model):
    __tablename__ = "vendor_info"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True)
    business_name = db.Column(db.String(255))
    user = relationship("User", back_populates="vendor_info")

class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="products")
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    images = db.Column(db.JSON, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    subcategory = db.Column(db.String(50))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'images': self.images,
            'category': self.category,
            'seller_type': 'Vendor' if self.user.is_full_time_vendor else 'Individual',
            'business_name': self.user.vendor_info.business_name if self.user.is_full_time_vendor else None
        }

class Chat(db.Model):
    __tablename__ = "chats"
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user1 = relationship("User", foreign_keys=[user1_id], backref="chats_as_user1")
    user2 = relationship("User", foreign_keys=[user2_id], backref="chats_as_user2")

class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey("chats.id"), nullable=False)
    chat = relationship("Chat", backref="messages")
    sender_id = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False) 

    def to_dict(self):
        return {
            "id": self.id,
            "chat_id": self.chat_id,
            "sender_id": self.sender_id,
            "text": self.text,
            "timestamp": self.timestamp.isoformat()
        }

with app.app_context():
    db.create_all()


@app.route('/')
@cache.cached(timeout=300)
def home():
    products = Product.query.all()
    return jsonify({"status": "success", "data": [product.to_dict() for product in products]})

@app.route('/api/register', methods=["POST"])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    username = data.get('username')

    if not email or not password or not username:
        return jsonify({"status": "error", "message": "Missing required fields"}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"status": "error", "message": "User with this email already exists"}), 409

    hash_and_salted_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
    new_user = User(email=email, username=username, password=hash_and_salted_password)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        access_token = create_access_token(identity=new_user.id)
        return jsonify({
            "status": "success",
            "message": "Registration successful!",
            "access_token": access_token,
            "user_id": new_user.id,
            }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/login', methods=["POST"])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"status": "error", "message": "Missing email or password"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"status": "error", "message": "Invalid email or password"}), 401

    login_user(user)
    access_token = create_access_token(identity=user.id)
    return jsonify({
        "status": "success",
        "message": "Login successful!",
        "access_token": access_token,
        "user_id": user.id,
        "is_full_time_vendor": user.is_full_time_vendor
    }), 200

@app.route('/api/logout')
@login_required
def logout():
    logout_user()
    return jsonify({"status": "success", "message": "Logged out successfully"}), 200

@app.route('/api/add-products', methods=['POST'])
@jwt_required()
def add_product():
    try:
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        category = request.form.get('category')
        subcategory = request.form.get('subcategory')
        
        if not name or not description or not price or not category:
            return jsonify({"status": "error", "message": "Missing required fields"}), 400

        image_urls = []
        if 'images' in request.files:
            images = request.files.getlist('images')
            for image in images:
                result = cloudinary.uploader.upload(image)
                image_urls.append(result['secure_url'])

        new_product = Product(
            user_id=get_jwt_identity(),
            name=name,
            description=description,
            price=float(price),
            images=image_urls,
            category=category,
            subcategory=subcategory
        )

        db.session.add(new_product)
        db.session.commit()

        return jsonify({"status": "success", "message": "Product added successfully", "product_id": new_product.id}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/products/trending')
@cache.cached(timeout=300)
def get_trending_products():
    products = Product.query.order_by(func.random()).limit(10).all()
    return jsonify({"status": "success", "data": [product.to_dict() for product in products]})

@app.route('/api/products/promoted')
@cache.cached(timeout=300)
def get_promoted_products():
    products = Product.query.order_by(func.random()).limit(10).all()
    return jsonify({"status": "success", "data": [product.to_dict() for product in products]})

@app.route('/api/products')
def get_products():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    products = Product.query.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        "status": "success",
        "data": {
            'products': [product.to_dict() for product in products.items],
            'total': products.total,
            'pages': products.pages,
            'current_page': products.page
        }
    })

@app.route('/api/products/<int:product_id>')
@cache.cached(timeout=300)
def get_product(product_id):
    product = Product.query.get(product_id)
    if product:
        return jsonify({"status": "success", "data": product.to_dict()})
    else:
        return jsonify({"status": "error", "message": "Product not found"}), 404

@app.route('/api/become-full-time-vendor', methods=['POST'])
@jwt_required()
def become_full_time_vendor():
    data = request.json
    business_name = data.get('business_name')

    if not business_name:
        return jsonify({"status": "error", "message": "Business name is required"}), 400

    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    if not user.vendor_info:
        vendor_info = VendorInfo(user_id=user.id, business_name=business_name)
        db.session.add(vendor_info)
    else:
        user.vendor_info.business_name = business_name

    user.is_full_time_vendor = True
    
    try:
        db.session.commit()
        return jsonify({"status": "success", "message": "Successfully registered as a full-time vendor"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/vendors/locations')
def get_vendor_locations():
    users_with_products = db.session.query(User).join(Product).filter(Product.user_id == User.id).distinct().all()

    vendor_locations = []
    for user in users_with_products:
        products_info = []
        for product in user.products:
            products_info.append({
                'id': product.id,
                'name': product.name,
                'category': product.category,
                'price': float(product.price),
                'image': product.images[0] if product.images else None
            })

        vendor_info = {
            'id': user.id,
            'latitude': user.latitude,
            'longitude': user.longitude,
            'name': user.vendor_info.business_name if user.is_full_time_vendor else "Individual",
            'is_full_time_vendor': user.is_full_time_vendor,
            'products': products_info
        }
        vendor_locations.append(vendor_info)

    return jsonify({"status": "success", "data": vendor_locations})

@app.route('/api/vendors/<int:user_id>')
def get_vendor(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({
            "status": "success",
            "data": {
                'id': user.id,
                'username': user.username,
                'is_full_time_vendor': user.is_full_time_vendor,
                'business_name': user.vendor_info.business_name if user.is_full_time_vendor else None
            }
        })
    else:
        return jsonify({"error": "User not found"}), 404

# Chat API Endpoints


@app.route('/api/chats', methods=['POST'])
@jwt_required()
def create_chat():
    data = request.json
    if not data or 'other_user_id' not in data:
        return jsonify({"status": "error", "message": "Missing required fields"}), 400

    other_user_id = data['other_user_id']
    current_user_id = get_jwt_identity()

    other_user = User.query.get(other_user_id)
    if not other_user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    existing_chat = Chat.query.filter(
        ((Chat.user1_id == current_user_id) & (Chat.user2_id == other_user_id)) |
        ((Chat.user1_id == other_user_id) & (Chat.user2_id == current_user_id))
    ).first()

    if existing_chat:
        return jsonify({"status": "success", "chat_id": existing_chat.id, "message": "Chat already exists"}), 200

    new_chat = Chat(user1_id=current_user_id, user2_id=other_user_id)
    try:
        db.session.add(new_chat)
        db.session.commit()
        return jsonify({"status": "success", "chat_id": new_chat.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/get-chats', methods=['GET'])
@jwt_required()
def get_user_chats():
    current_user_id = get_jwt_identity()
    user_chats = Chat.query.filter(
        (Chat.user1_id == current_user_id) | (Chat.user2_id == current_user_id)
    ).all()
    
    chat_list = []
    for chat in user_chats:
        other_user = chat.user2 if chat.user1_id == current_user_id else chat.user1
        last_message = Message.query.filter_by(chat_id=chat.id).order_by(Message.timestamp.desc()).first()
        
        chat_info = {
            'chat_id': chat.id,
            'other_user_id': other_user.id,
            'other_user_name': other_user.username,
            'last_message': last_message.text if last_message else '',
            'last_message_time': last_message.timestamp.isoformat() if last_message else None
        }
        chat_list.append(chat_info)
    
    return jsonify({"status": "success", "data": chat_list})

@app.route('/api/chats/<int:chat_id>/messages', methods=['GET'])
@jwt_required()
def get_messages(chat_id):
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        current_user_id = get_jwt_identity()
        chat = Chat.query.get(chat_id)
        if not chat:
            return jsonify({"status": "error", "message": "Chat not found"}), 404

        if current_user_id != chat.user1_id and current_user_id != chat.user2_id:
            return jsonify({"status": "error", "message": "Unauthorized access"}), 403

        messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.timestamp.desc()).paginate(page=page, per_page=per_page)
        
        return jsonify({
            "status": "success",
            "data": {
                'messages': [message.to_dict() for message in messages.items],
                'total': messages.total,
                'pages': messages.pages,
                'current_page': messages.page
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

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

        chat = Chat.query.get(chat_id)
        if not chat:
            raise ValueError("Chat not found")

        if sender_id != chat.user1_id and sender_id != chat.user2_id:
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