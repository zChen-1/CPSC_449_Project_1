# Task 1: Setting up the Flask application
from flask import Flask, jsonify, request, render_template
from flask_mysqldb import MySQL
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

app.config['MYSQL_USER'] = 'admin'
app.config['MYSQL_PASSWORD'] = 'admin'
app.config['MYSQL_DB'] = 'account.db'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_PORT'] = 3306

mySql = MySQL(app)

# Task 2: Error Handling
@app.route('/', methods=['GET'])
def index_route():
    return render_template('index.html')

@app.route('/admin', methods=['GET'])
def admin_route():
    return jsonify({'message': 'This is a protected admin route'})

# 400:Bad request
@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400

# 401:Unauthorized
@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401

# 403:Forbidden
@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403

# 404:Not found
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

# 500:Internal server error
@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# Task 3: Authentication
app.config['JWT_SECRET_KEY'] = 'jwtSecretKey'
jwt = JWTManager(app)

users = [
    {"id": 1, "username": "user1", "password": "password1"},
    {"id": 2, "username": "user2", "password": "password2"},
]

@app.route('/Authentication', methods=['GET'])
def to_authenticate():
    return render_template('Authentication.html')

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({'msg': 'Missing JSON in request'}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username or not password:
        return jsonify({'msg': 'Missing username or password'}), 400

    user = next((user for user in users if user['username'] == username and user['password'] == password), None)
    if user is None:
        return jsonify({'msg': 'Bad username or password'}), 401

    access_token = create_access_token(identity=user['id'])
    return jsonify({'access_token': access_token}), 200


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    return jsonify({'id': current_user_id, 'msg': 'This is a protected endpoint'}), 200


# Task 5: Public Route
public_items = [
    {"id": 1, "name": "Item 1", "description": "This is a public item."},
    {"id": 2, "name": "Item 2", "description": "This is another public item."},
]

@app.route('/public', methods=['GET'])
def public_route():
    return jsonify({'message': 'This is a public route'})

@app.route('/public-items', methods=['GET'])
def get_public_items():
    return jsonify({"items": public_items}), 200

# Task 6: Services
# Create
@app.route('/items', methods=['POST'])
def create_item():
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')

    if not name or not description:
        return jsonify({'error': 'Name and description are required'}), 400

    cursor = mySql.connection.cursor()
    cursor.execute('INSERT INTO items (name, description) VALUES (%s, %s)', (name, description))
    mySql.connection.commit()
    cursor.close()

    return jsonify({'message': 'Item created successfully'}), 201

# Read
@app.route('/items', methods=['GET'])
def get_items():
    cursor = mySql.connection.cursor()
    cursor.execute('SELECT * FROM items')
    items = cursor.fetchall()
    cursor.close()

    return jsonify({'items': items}), 200

# Read
@app.route('/items/<int:item_id>', methods=['GET'])
def get_item(item_id):
    cursor = mySql.connection.cursor()
    cursor.execute('SELECT * FROM items WHERE id = %s', (item_id,))
    item = cursor.fetchone()
    cursor.close()

    if item is None:
        return jsonify({'error': 'Item not found'}), 404

    return jsonify({'item': item}), 200

# Update
@app.route('/items/<int:item_id>', methods=['PUT'])
def update_item(item_id):
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')

    if not name or not description:
        return jsonify({'error': 'Name and description are required'}), 400

    cursor = mySql.connection.cursor()
    cursor.execute('UPDATE items SET name = %s, description = %s WHERE id = %s', (name, description, item_id))
    mySql.connection.commit()
    cursor.close()

    return jsonify({'message': 'Item updated successfully'}), 200

# Delete
@app.route('/items/<int:item_id>', methods=['DELETE'])
def delete_item(item_id):
    cursor = mySql.connection.cursor()
    cursor.execute('DELETE FROM items WHERE id = %s', (item_id,))
    mySql.connection.commit()
    cursor.close()

    return jsonify({'message': 'Item deleted successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)
