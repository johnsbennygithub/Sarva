from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
import csv
import io
import os

app = Flask(__name__, static_url_path='/static', static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Change this to a secure secret key in production

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Get the absolute path to the directory containing this file
basedir = os.path.abspath(os.path.dirname(__file__))
# Create the database path - use /data in production, local path in development
DATABASE_PATH = os.path.join('/data', 'inventory.db') if os.environ.get('RENDER') else os.path.join(basedir, 'inventory.db')

# Database initialization
def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create items table with user_id if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            item_type TEXT NOT NULL,
            need_to_buy BOOLEAN DEFAULT FALSE,
            date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create recent_items table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS recent_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_name TEXT NOT NULL,
            item_type TEXT NOT NULL,
            use_count INTEGER DEFAULT 1,
            last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, item_name, item_type),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# Database helper functions
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def update_recent_items(user_id, item_name, item_type):
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO recent_items (user_id, item_name, item_type, use_count, last_used)
            VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id, item_name, item_type) DO UPDATE SET
            use_count = use_count + 1,
            last_used = CURRENT_TIMESTAMP
        ''', (user_id, item_name, item_type))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error updating recent items: {e}")

# Mock user database - In a real application, you would use a proper database
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

# Mock user for demonstration - In production, use a proper database
users = {
    'admin': User(1, 'admin')
}

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if user:
        return User(user['id'], user['username'])
    return None

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([username, password, confirm_password]):
            flash('All fields are required!', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))
        
        conn = get_db_connection()
        
        # Check if username exists
        if conn.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone():
            conn.close()
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))
        
        # Create new user
        try:
            password_hash = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                        (username, password_hash))
            conn.commit()
            conn.close()
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            conn.close()
            flash('Error creating account. Please try again.', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not all([username, password]):
            flash('Please enter both username and password', 'error')
            return redirect(url_for('login'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            user_obj = User(user['id'], user['username'])
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/get-items')
@login_required
def get_items():
    search_term = request.args.get('term', '').lower()
    conn = get_db_connection()
    
    # Get suggestions from both items and recent_items tables
    items = conn.execute('''
        SELECT DISTINCT i.item_name, i.item_type,
               COALESCE(r.use_count, 0) as use_count,
               COALESCE(r.last_used, '1900-01-01') as last_used
        FROM items i
        LEFT JOIN recent_items r ON i.item_name = r.item_name AND r.user_id = i.user_id
        WHERE i.user_id = ? AND LOWER(i.item_name) LIKE ?
        ORDER BY r.use_count DESC NULLS LAST, r.last_used DESC NULLS LAST, i.item_name
    ''', (current_user.id, f'%{search_term}%')).fetchall()
    
    suggestions = [{'item_name': item['item_name'], 'item_type': item['item_type']} for item in items]
    return jsonify(suggestions)

@app.route('/add-item', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        item_name = request.form.get('item_name')
        quantity = request.form.get('quantity')
        item_type = request.form.get('item_type')
        
        if not all([item_name, quantity, item_type]):
            flash('Please fill in all fields', 'error')
            return redirect(url_for('add_item'))
        
        try:
            conn = get_db_connection()
            conn.execute('INSERT INTO items (user_id, item_name, quantity, item_type) VALUES (?, ?, ?, ?)',
                        (current_user.id, item_name, quantity, item_type))
            conn.commit()
            
            # Update recent items tracking
            update_recent_items(current_user.id, item_name, item_type)
            
            flash('Item added successfully!', 'success')
            return redirect(url_for('add_item'))
        except Exception as e:
            flash('Error adding item. Please try again.', 'error')
            return redirect(url_for('add_item'))
        finally:
            conn.close()
    
    # Get 5 most recently added items
    conn = get_db_connection()
    recent_items = conn.execute('''
        SELECT item_name, quantity, item_type, strftime('%Y-%m-%d %H:%M', date_added) as formatted_date
        FROM items
        WHERE user_id = ?
        ORDER BY date_added DESC
        LIMIT 5
    ''', (current_user.id,)).fetchall()
    
    conn.close()
    return render_template('add_item.html', recent_items=recent_items)

@app.route('/view-items')
@login_required
def view_items():
    conn = get_db_connection()
    items = conn.execute('''
        SELECT id, item_name, quantity, item_type, date_added 
        FROM items 
        WHERE user_id = ?
        ORDER BY date_added DESC
    ''', (current_user.id,)).fetchall()
    conn.close()
    return render_template('view_items.html', items=items)

@app.route('/delete-item/<int:id>')
@login_required
def delete_item(id):
    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM items WHERE id = ? AND user_id = ?', (id, current_user.id))
        conn.commit()
        conn.close()
        flash('Item deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting item: {str(e)}', 'error')
    return redirect(url_for('view_items'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/edit-item/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_item(id):
    conn = get_db_connection()
    
    if request.method == 'POST':
        try:
            # Handle both JSON and form data
            if request.is_json:
                data = request.get_json()
            else:
                data = request.form
            
            item_name = data.get('item_name')
            quantity = data.get('quantity')
            item_type = data.get('item_type')
            
            if not all([item_name, quantity, item_type]):
                return jsonify({'success': False, 'message': 'All fields are required!'})
            
            conn.execute('''
                UPDATE items 
                SET item_name = ?, quantity = ?, item_type = ?
                WHERE id = ? AND user_id = ?
            ''', (item_name, quantity, item_type, id, current_user.id))
            conn.commit()
            
            # Get updated item details
            item = conn.execute('SELECT * FROM items WHERE id = ? AND user_id = ?', (id, current_user.id)).fetchone()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Item updated successfully!',
                'item': {
                    'id': id,
                    'item_name': item_name,
                    'quantity': quantity,
                    'item_type': item_type
                }
            })
        except Exception as e:
            conn.close()
            return jsonify({'success': False, 'message': f'Error updating item: {str(e)}'})
    
    # GET request - return item details
    try:
        item = conn.execute('SELECT * FROM items WHERE id = ? AND user_id = ?', (id, current_user.id)).fetchone()
        conn.close()
        
        if item is None:
            return jsonify({'success': False, 'message': 'Item not found'})
        
        return jsonify({
            'success': True,
            'item': {
                'id': item['id'],
                'item_name': item['item_name'],
                'quantity': item['quantity'],
                'item_type': item['item_type']
            }
        })
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': f'Error fetching item: {str(e)}'})

@app.route('/shopping-list')
@login_required
def shopping_list():
    conn = get_db_connection()
    items = conn.execute('''
        SELECT id, item_name, quantity, item_type, need_to_buy 
        FROM items 
        WHERE user_id = ?
        ORDER BY need_to_buy DESC, item_name
    ''', (current_user.id,)).fetchall()
    conn.close()
    return render_template('shopping_list.html', items=items)

@app.route('/toggle-need-to-buy/<int:id>', methods=['POST'])
@login_required
def toggle_need_to_buy(id):
    try:
        conn = get_db_connection()
        # Get current status and toggle it
        current_status = conn.execute('SELECT need_to_buy FROM items WHERE id = ? AND user_id = ?', (id, current_user.id)).fetchone()
        new_status = not bool(current_status[0])
        
        conn.execute('UPDATE items SET need_to_buy = ? WHERE id = ? AND user_id = ?', (new_status, id, current_user.id))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'new_status': new_status})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/download-shopping-list')
@login_required
def download_shopping_list():
    conn = get_db_connection()
    items = conn.execute('''
        SELECT item_name, quantity, item_type
        FROM items 
        WHERE user_id = ? AND need_to_buy = TRUE
        ORDER BY item_name
    ''', (current_user.id,)).fetchall()
    conn.close()
    
    # Create a string buffer to write CSV data
    si = io.StringIO()
    cw = csv.writer(si)
    
    # Write header
    cw.writerow(['Item Name', 'Quantity', 'Type'])
    
    # Write data
    for item in items:
        cw.writerow([item['item_name'], item['quantity'], item['item_type']])
    
    output = si.getvalue()
    si.close()
    
    return send_file(
        io.BytesIO(output.encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='shopping_list.csv'
    )

@app.route('/test-static')
def test_static():
    static_file_path = os.path.join(app.static_folder, 'images/sarva-logo.png')
    if os.path.exists(static_file_path):
        return f"Image exists at {static_file_path}"
    else:
        return f"Image not found. Looking for file at: {static_file_path}"

@app.route('/database-info')
@login_required
def database_info():
    conn = get_db_connection()
    
    # Get all tables
    tables = conn.execute("""
        SELECT name 
        FROM sqlite_master 
        WHERE type='table'
    """).fetchall()
    
    database_data = {}
    
    # Get data from each table
    for table in tables:
        table_name = table[0]
        # Get column information
        columns = conn.execute(f"PRAGMA table_info('{table_name}')").fetchall()
        column_names = [column[1] for column in columns]
        
        # Get row count
        row_count = conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
        
        # Get sample data (first 5 rows)
        rows = conn.execute(f"SELECT * FROM {table_name} LIMIT 5").fetchall()
        
        database_data[table_name] = {
            'columns': column_names,
            'row_count': row_count,
            'sample_data': rows
        }
    
    conn.close()
    return render_template('database_info.html', database_data=database_data)

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug_mode) 