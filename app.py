# Task 1: Setting up the Flask application
from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = '123123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt_key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=2)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024

db = SQLAlchemy(app)
jwt = JWTManager(app)


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.username


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Task 2: Error Handling
# 400:Bad request
@app.errorhandler(400)
def unauthorized(e):
    return jsonify(error=str(e)), 400


# 401:Unauthorized
@app.errorhandler(401)
def unauthorized(e):
    return jsonify(error=str(e)), 401


# 403:Forbidden
@app.errorhandler(403)
def forbidden(e):
    return jsonify(error=str(e)), 403


# 404:Not found
@app.errorhandler(404)
def page_not_found(e):
    return jsonify(error=str(e)), 404


# 500:Internal server error
@app.errorhandler(500)
def internal_server_error(e):
    return jsonify(error=str(e)), 500


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/protected_route', methods=['GET'])
@jwt_required()  # Add jwt_required decorator to protect the route
def protected_route():
    current_user = get_jwt_identity()
    return f'Hello, {current_user}! This is a protected route.'


@app.route('/login', methods=['POST'])
def login():
    data = request.form
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity=user)
        return jsonify(access_token=access_token), 200
    else:
        return 'Invalid username or password', 401


# Task 3: Authentication
@app.route('/admin')
def admin():
    token = request.args.get('token')
    if not token:
        return jsonify({'error': 'Token is missing'}), 401
    try:
        # Decode token and get user identity
        current_user = decode_token(token)
    except Exception as e:
        return jsonify({'error': 'Invalid token'}), 401
    # Your admin-related logic goes here
    return render_template('admin.html', user=current_user)


# Task 4: File Handling
UPLOAD_FOLDER = 'Upload_folder'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_files(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['GET'])
def upload():
    return render_template('upload.html')


@app.route('/file_upload', methods=['POST'])
def file_upload():
    if 'file' not in request.files:
        return redirect(request.url)

    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)

        # Create upload folder if it doesn't exist
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])

        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('upload'))

    return render_template('upload.html', error='File not allowed')


# Task 5: Public Route
public_items = [
    {"id": 1, "name": "Public Information 1", "description": "This is a public Information 1."},
    {"id": 2, "name": "Public Information 2", "description": "This is a public Information 2."},
]


# Public route that returns a list of public items
@app.route('/public', methods=['GET'])
def public_route():
    return jsonify(public_items)


# Task 6: Services
data_ = []


# C:Create & R:Ream
@app.route('/services', methods=['GET', 'POST'])
def services_route():
    if request.method == 'POST':
        item = request.form.get('item')
        if item:
            data_.append(item)
    return render_template('services.html', data=data_)


# U:Update
@app.route('/update/<int:index>', methods=['GET', 'POST'])
def update_route(index):
    if request.method == 'POST':
        item = request.form.get('item')
        if item:
            data_[index] = item
            return redirect(url_for('services_route'))
    return render_template('update.html', item=data_[index])


# D:Delete
@app.route('/delete/<int:index>')
def delete_route(index):
    data_.pop(index)
    return redirect(url_for('services_route'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
