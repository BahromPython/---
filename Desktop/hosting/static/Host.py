from flask import Flask, request, jsonify, send_from_directory
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from flask_cors import CORS
import sqlite3
from passlib.hash import pbkdf2_sha256
from datetime import datetime, timezone
import logging
import os
import uuid

app = Flask(__name__)

# Настройка CORS: разрешаем запросы с localhost:8000, Render и origin: null (для тестирования через file://)
CORS(app, resources={r"/*": {"origins": ["http://localhost:8000", "https://instagram-clone.onrender.com", "http://127.0.0.1:5000", "null"]}})

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600
jwt = JWTManager(app)

# Configure upload directory
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure logging
logging.basicConfig(level=logging.DEBUG)

@jwt.invalid_token_loader
def invalid_token_callback(error):
    app.logger.error(f"JWT Invalid Token Error: {str(error)}")
    return jsonify({'msg': str(error)}), 422

@jwt.unauthorized_loader
def unauthorized_callback(error):
    app.logger.error(f"JWT Unauthorized Error: {str(error)}")
    return jsonify({'msg': str(error)}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    app.logger.error("JWT Expired Token Error: Token has expired")
    return jsonify({'msg': 'Token has expired'}), 422

def init_db():
    try:
        conn = sqlite3.connect('instagram.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            avatar_path TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            image_path TEXT NOT NULL,
            caption TEXT,
            created_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            post_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (post_id) REFERENCES posts (id),
            UNIQUE(user_id, post_id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            post_id INTEGER,
            comment TEXT NOT NULL,
            created_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (post_id) REFERENCES posts (id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS followers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            follower_id INTEGER,
            following_id INTEGER,
            FOREIGN KEY (follower_id) REFERENCES users (id),
            FOREIGN KEY (following_id) REFERENCES users (id),
            UNIQUE(follower_id, following_id)
        )''')
        conn.commit()
    except sqlite3.Error as e:
        app.logger.error(f"Database error: {e}")
    finally:
        conn.close()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'msg': 'Username and password are required'}), 400

    hashed_password = pbkdf2_sha256.hash(password)
    try:
        conn = sqlite3.connect('instagram.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, avatar_path) VALUES (?, ?, ?)', (username, hashed_password, '/static/avatar.png'))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User registered successfully'}), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'msg': 'Username already exists'}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = sqlite3.connect('instagram.db')
    c = conn.cursor()
    c.execute('SELECT id, password, avatar_path FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()

    if user and pbkdf2_sha256.verify(password, user[1]):
        user_id = str(user[0])
        access_token = create_access_token(identity=user_id)
        app.logger.info(f"Generated token for user {username}: {access_token}")
        return jsonify({'access_token': access_token, 'username': username, 'avatar_path': user[2]}), 200
    return jsonify({'msg': 'Invalid credentials'}), 401

@app.route('/upload-avatar', methods=['POST'])
@jwt_required()
def upload_avatar():
    try:
        user_id = get_jwt_identity()
        if 'avatar' not in request.files:
            return jsonify({'msg': 'Avatar file is required'}), 400

        avatar = request.files['avatar']
        if avatar.filename == '':
            return jsonify({'msg': 'No avatar selected'}), 400

        if not avatar.mimetype.startswith('image/'):
            return jsonify({'msg': 'File must be an image'}), 400

        filename = f"avatar_{user_id}_{uuid.uuid4()}.jpg"
        avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        avatar.save(avatar_path)
        app.logger.info(f"Avatar saved to: {avatar_path}")

        relative_avatar_path = f"/uploads/{filename}"
        conn = sqlite3.connect('instagram.db')
        c = conn.cursor()
        c.execute('UPDATE users SET avatar_path = ? WHERE id = ?', (relative_avatar_path, user_id))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Avatar uploaded successfully', 'avatar_path': relative_avatar_path}), 200
    except Exception as e:
        app.logger.error(f"Error in upload_avatar: {str(e)}")
        return jsonify({'msg': f'Failed to upload avatar: {str(e)}'}), 422

@app.route('/posts', methods=['POST'])
@jwt_required()
def create_post():
    try:
        user_id = get_jwt_identity()
        if 'media' not in request.files:
            return jsonify({'msg': 'Media file is required'}), 400

        media = request.files['media']
        caption = request.form.get('caption', '')

        if media.filename == '':
            return jsonify({'msg': 'No media selected'}), 400

        if not (media.mimetype.startswith('image/') or media.mimetype.startswith('video/')):
            return jsonify({'msg': 'File must be an image or video'}), 400

        filename = f"{uuid.uuid4()}_{media.filename}"
        media_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        media.save(media_path)
        app.logger.info(f"Media saved to: {media_path}")

        relative_media_path = f"/uploads/{filename}"
        created_at = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect('instagram.db')
        c = conn.cursor()
        c.execute('INSERT INTO posts (user_id, image_path, caption, created_at) VALUES (?, ?, ?, ?)',
                  (user_id, relative_media_path, caption, created_at))
        conn.commit()
        app.logger.info(f"Post created: user_id={user_id}, media_path={relative_media_path}, caption={caption}, created_at={created_at}")
        c.execute('SELECT * FROM posts WHERE user_id = ? AND image_path = ?', (user_id, relative_media_path))
        post = c.fetchone()
        app.logger.info(f"Post in database after insert: {post}")
        conn.close()
        return jsonify({'message': 'Post created successfully'}), 201
    except Exception as e:
        app.logger.error(f"Error in create_post: {str(e)}")
        return jsonify({'msg': f'Failed to create post: {str(e)}'}), 422

@app.route('/posts', methods=['GET'])
@jwt_required()
def get_posts():
    try:
        user_id = get_jwt_identity()
        conn = sqlite3.connect('instagram.db')
        c = conn.cursor()
        c.execute('''
            SELECT p.id, p.image_path, p.caption, p.created_at, u.username, u.avatar_path,
                   (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) as like_count,
                   (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) as comment_count,
                   EXISTS(SELECT 1 FROM likes l WHERE l.post_id = p.id AND l.user_id = ?) as liked_by_user,
                   EXISTS(SELECT 1 FROM followers f WHERE f.follower_id = ? AND f.following_id = p.user_id) as is_following
            FROM posts p JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
        ''', (user_id, user_id))
        posts = [
            {
                'id': row[0],
                'image_path': row[1],
                'caption': row[2],
                'created_at': row[3],
                'username': row[4],
                'avatar_path': row[5],
                'like_count': row[6],
                'comment_count': row[7],
                'liked_by_user': bool(row[8]),
                'is_following': bool(row[9])
            } for row in c.fetchall()
        ]
        app.logger.info(f"Posts retrieved: {posts}")
        conn.close()
        return jsonify(posts), 200
    except Exception as e:
        app.logger.error(f"Error in get_posts: {str(e)}")
        return jsonify({'msg': f'Failed to fetch posts: {str(e)}'}), 422

@app.route('/posts/<int:post_id>/like', methods=['POST'])
@jwt_required()
def like_post(post_id):
    user_id = get_jwt_identity()
    conn = sqlite3.connect('instagram.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO likes (user_id, post_id) VALUES (?, ?)', (user_id, post_id))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Post liked'}), 200
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'msg': 'Already liked or post does not exist'}), 400

@app.route('/posts/<int:post_id>/comment', methods=['POST'])
@jwt_required()
def comment_post(post_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    comment = data.get('comment')

    if not comment:
        return jsonify({'msg': 'Comment is required'}), 400

    created_at = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect('instagram.db')
    c = conn.cursor()
    c.execute('INSERT INTO comments (user_id, post_id, comment, created_at) VALUES (?, ?, ?, ?)',
              (user_id, post_id, comment, created_at))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Comment added'}), 201

@app.route('/posts/<int:post_id>/comments', methods=['GET'])
@jwt_required()
def get_comments(post_id):
    conn = sqlite3.connect('instagram.db')
    c = conn.cursor()
    c.execute('''
        SELECT c.comment, c.created_at, u.username, u.avatar_path
        FROM comments c JOIN users u ON c.user_id = u.id
        WHERE c.post_id = ?
        ORDER BY c.created_at DESC
    ''', (post_id,))
    comments = [
        {
            'comment': row[0],
            'created_at': row[1],
            'username': row[2],
            'avatar_path': row[3]
        } for row in c.fetchall()
    ]
    conn.close()
    return jsonify(comments), 200

@app.route('/follow/<string:username>', methods=['POST'])
@jwt_required()
def follow_user(username):
    follower_id = get_jwt_identity()
    conn = sqlite3.connect('instagram.db')
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({'msg': 'User not found'}), 404
    following_id = user[0]
    if int(follower_id) == following_id:
        conn.close()
        return jsonify({'msg': 'Cannot follow yourself'}), 400
    try:
        c.execute('INSERT INTO followers (follower_id, following_id) VALUES (?, ?)', (follower_id, following_id))
        conn.commit()
        conn.close()
        return jsonify({'message': f'You are now following {username}'}), 200
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'msg': 'Already following this user'}), 400

@app.route('/unfollow/<string:username>', methods=['POST'])
@jwt_required()
def unfollow_user(username):
    follower_id = get_jwt_identity()
    conn = sqlite3.connect('instagram.db')
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({'msg': 'User not found'}), 404
    following_id = user[0]
    c.execute('DELETE FROM followers WHERE follower_id = ? AND following_id = ?', (follower_id, following_id))
    if c.rowcount == 0:
        conn.close()
        return jsonify({'msg': 'You are not following this user'}), 400
    conn.commit()
    conn.close()
    return jsonify({'message': f'You have unfollowed {username}'}), 200

@app.route('/followers', methods=['GET'])
@jwt_required()
def get_followers():
    user_id = get_jwt_identity()
    conn = sqlite3.connect('instagram.db')
    c = conn.cursor()
    c.execute('''
        SELECT u.username, u.avatar_path
        FROM followers f JOIN users u ON f.follower_id = u.id
        WHERE f.following_id = ?
    ''', (user_id,))
    followers = [{'username': row[0], 'avatar_path': row[1]} for row in c.fetchall()]
    conn.close()
    return jsonify(followers), 200

@app.route('/following', methods=['GET'])
@jwt_required()
def get_following():
    user_id = get_jwt_identity()
    conn = sqlite3.connect('instagram.db')
    c = conn.cursor()
    c.execute('''
        SELECT u.username, u.avatar_path
        FROM followers f JOIN users u ON f.following_id = u.id
        WHERE f.follower_id = ?
    ''', (user_id,))
    following = [{'username': row[0], 'avatar_path': row[1]} for row in c.fetchall()]
    conn.close()
    return jsonify(following), 200

@app.route('/verify-token', methods=['GET'])
@jwt_required()
def verify_token():
    try:
        user_id = get_jwt_identity()
        return jsonify({'message': f'Token is valid for user ID {user_id}'}), 200
    except Exception as e:
        app.logger.error(f"Error in verify_token: {str(e)}")
        return jsonify({'msg': f'Failed to verify token: {str(e)}'}), 422

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

@app.route('/')
def serve_index():
    return app.send_static_file('index.html')

if __name__ == '__main__':
    init_db()
    port = int(os.getenv('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port, load_dotenv=False)