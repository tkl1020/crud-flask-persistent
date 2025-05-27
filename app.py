from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, session
import sqlite3
import os
import tempfile
import shutil
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
import uuid
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

sessions = {}

# --- PERSISTENT USER SYSTEM ---
def init_user_db():
    conn = sqlite3.connect('users.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS user_files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        db_name TEXT NOT NULL,
                        db_path TEXT NOT NULL)''')
    conn.commit()
    conn.close()

init_user_db()

# --- LOGIN REQUIRED DECORATOR ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- REGISTER ROUTE ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not password or not confirm_password:
            flash('Please fill in all fields')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters long')
            return render_template('register.html')

        hashed_pw = generate_password_hash(password)

        try:
            conn = sqlite3.connect('users.db')
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            conn.close()
            flash('Account created successfully!')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.')
            return render_template('register.html')

    return render_template('register.html')

# --- LOGIN ROUTE ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')

        conn = sqlite3.connect('users.db')
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = username
            flash(f'Welcome back, {username}!')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')

# --- LOGOUT ROUTE ---
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

# --- SAVED DATABASES FEATURE ---
@app.route('/save_db/<session_id>', methods=['POST'])
@login_required
def save_db(session_id):
    if session_id not in sessions:
        flash('Session expired')
        return redirect(url_for('index'))

    user = session['user_id']
    db_name = sessions[session_id]['db_name']
    db_path = sessions[session_id]['db_path']

    conn = sqlite3.connect('users.db')
    conn.execute("INSERT INTO user_files (username, db_name, db_path) VALUES (?, ?, ?)", (user, db_name, db_path))
    conn.commit()
    conn.close()

    flash(f'Database "{db_name}" saved to your account.')
    return redirect(url_for('index'))

@app.route('/load_saved_db/<int:file_id>')
@login_required
def load_saved_db(file_id):
    user = session['user_id']
    conn = sqlite3.connect('users.db')
    row = conn.execute("SELECT db_name, db_path FROM user_files WHERE id = ? AND username = ?", (file_id, user)).fetchone()
    conn.close()

    if not row:
        flash('Database not found or not yours.')
        return redirect(url_for('index'))

    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        'db_name': row[0],
        'db_path': row[1]
    }
    return redirect(url_for('select_table', session_id=session_id))

@app.context_processor
def inject_user_files():
    if 'user_id' in session:
        user = session['user_id']
        conn = sqlite3.connect('users.db')
        files = conn.execute("SELECT id, db_name FROM user_files WHERE username = ?", (user,)).fetchall()
        conn.close()
        return {'user_files': files}
    return {}
# --- REMAINING ROUTES UNCHANGED ---
# KEEP EVERYTHING BELOW THIS LINE THE SAME
# ... [original app continues unchanged from here] ...

def get_db_connection(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def get_table_info(db_path, table_name):
    conn = get_db_connection(db_path)
    cursor = conn.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()
    conn.close()
    return columns

def get_tables(db_path):
    conn = get_db_connection(db_path)
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    conn.close()
    return [table['name'] for table in tables]

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    if file and file.filename.lower().endswith(('.db', '.sqlite', '.sqlite3')):
        session_id = str(uuid.uuid4())
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{session_id}_{filename}")
        file.save(filepath)
        
        # Store session info
        sessions[session_id] = {
            'db_path': filepath,
            'db_name': filename
        }
        
        return redirect(url_for('select_table', session_id=session_id))
    
    flash('Please upload a valid database file (.db, .sqlite, .sqlite3)')
    return redirect(url_for('index'))

@app.route('/create_new', methods=['POST'])
@login_required
def create_new_db():
    db_name = request.form.get('db_name', '').strip()
    if not db_name:
        flash('Please enter a database name')
        return redirect(url_for('index'))
    
    session_id = str(uuid.uuid4())
    filename = secure_filename(f"{db_name}.db")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{session_id}_{filename}")
    
    # Create empty database
    conn = sqlite3.connect(filepath)
    conn.close()
    
    sessions[session_id] = {
        'db_path': filepath,
        'db_name': filename
    }
    
    return redirect(url_for('create_table', session_id=session_id))

@app.route('/select_table/<session_id>')
@login_required
def select_table(session_id):
    if session_id not in sessions:
        flash('Session expired')
        return redirect(url_for('index'))
    
    db_path = sessions[session_id]['db_path']
    try:
        tables = get_tables(db_path)
        return render_template('select_table.html', tables=tables, session_id=session_id)
    except Exception as e:
        flash(f'Error reading database: {str(e)}')
        return redirect(url_for('index'))

@app.route('/create_table/<session_id>')
@login_required
def create_table(session_id):
    if session_id not in sessions:
        flash('Session expired')
        return redirect(url_for('index'))
    
    return render_template('create_table.html', session_id=session_id)

@app.route('/create_table/<session_id>', methods=['POST'])
@login_required
def create_table_post(session_id):
    if session_id not in sessions:
        flash('Session expired')
        return redirect(url_for('index'))
    
    table_name = request.form.get('table_name', '').strip()
    columns = request.form.getlist('column_name[]')
    types = request.form.getlist('column_type[]')
    
    if not table_name or not columns:
        flash('Please provide table name and at least one column')
        return redirect(url_for('create_table', session_id=session_id))
    
    db_path = sessions[session_id]['db_path']
    
    try:
        # Build CREATE TABLE statement
        column_defs = []
        for col, col_type in zip(columns, types):
            if col.strip():
                column_defs.append(f"{col.strip()} {col_type}")
        
        if not column_defs:
            flash('Please provide at least one column name')
            return redirect(url_for('create_table', session_id=session_id))
        
        create_sql = f"CREATE TABLE {table_name} ({', '.join(column_defs)})"
        
        conn = get_db_connection(db_path)
        conn.execute(create_sql)
        conn.commit()
        conn.close()
        
        sessions[session_id]['current_table'] = table_name
        return redirect(url_for('crud_interface', session_id=session_id, table=table_name))
        
    except Exception as e:
        flash(f'Error creating table: {str(e)}')
        return redirect(url_for('create_table', session_id=session_id))

@app.route('/crud/<session_id>/<table>')
@login_required
def crud_interface(session_id, table):
    if session_id not in sessions:
        flash('Session expired')
        return redirect(url_for('index'))
    
    db_path = sessions[session_id]['db_path']
    sessions[session_id]['current_table'] = table
    
    try:
        # Get table structure
        columns = get_table_info(db_path, table)
        
        # Get all records
        conn = get_db_connection(db_path)
        records = conn.execute(f'SELECT rowid as row_id, * FROM {table}').fetchall()
        conn.close()
        
        return render_template('crud.html', 
                             table=table, 
                             columns=columns, 
                             records=records, 
                             session_id=session_id)
    except Exception as e:
        flash(f'Error accessing table {table}: {str(e)}')
        return redirect(url_for('select_table', session_id=session_id))

@app.route('/add_record/<session_id>/<table>', methods=['POST'])
@login_required
def add_record(session_id, table):
    if session_id not in sessions:
        return jsonify({'error': 'Session expired'}), 400
    
    db_path = sessions[session_id]['db_path']
    
    try:
        columns = get_table_info(db_path, table)
        column_names = [col['name'] for col in columns]
        
        values = []
        for col_name in column_names:
            values.append(request.form.get(col_name, ''))
        
        placeholders = ', '.join(['?' for _ in values])
        column_list = ', '.join(column_names)
        
        conn = get_db_connection(db_path)
        conn.execute(f'INSERT INTO {table} ({column_list}) VALUES ({placeholders})', values)
        conn.commit()
        conn.close()
        
        flash('Record added successfully')
        return redirect(url_for('crud_interface', session_id=session_id, table=table))
        
    except Exception as e:
        flash(f'Error adding record: {str(e)}')
        return redirect(url_for('crud_interface', session_id=session_id, table=table))

@app.route('/edit_record/<session_id>/<table>/<int:rowid>')
@login_required
def edit_record(session_id, table, rowid):
    if session_id not in sessions:
        flash('Session expired')
        return redirect(url_for('index'))
    
    db_path = sessions[session_id]['db_path']
    
    try:
        # Get table structure
        columns = get_table_info(db_path, table)
        
        # Get the specific record
        conn = get_db_connection(db_path)
        record = conn.execute(f'SELECT rowid as row_id, * FROM {table} WHERE rowid = ?', (rowid,)).fetchone()
        conn.close()
        
        if not record:
            flash('Record not found')
            return redirect(url_for('crud_interface', session_id=session_id, table=table))
        
        return render_template('edit_record.html', 
                             table=table, 
                             columns=columns, 
                             record=record, 
                             session_id=session_id,
                             rowid=rowid)
    except Exception as e:
        flash(f'Error accessing record: {str(e)}')
        return redirect(url_for('crud_interface', session_id=session_id, table=table))

@app.route('/update_record/<session_id>/<table>/<int:rowid>', methods=['POST'])
@login_required
def update_record(session_id, table, rowid):
    if session_id not in sessions:
        flash('Session expired')
        return redirect(url_for('index'))
    
    db_path = sessions[session_id]['db_path']
    
    try:
        columns = get_table_info(db_path, table)
        column_names = [col['name'] for col in columns]
        
        # Build the UPDATE statement
        set_clauses = []
        values = []
        for col_name in column_names:
            set_clauses.append(f"{col_name} = ?")
            values.append(request.form.get(col_name, ''))
        
        values.append(rowid)  # Add rowid for WHERE clause
        
        update_sql = f"UPDATE {table} SET {', '.join(set_clauses)} WHERE rowid = ?"
        
        conn = get_db_connection(db_path)
        conn.execute(update_sql, values)
        conn.commit()
        conn.close()
        
        flash('Record updated successfully')
        return redirect(url_for('crud_interface', session_id=session_id, table=table))
        
    except Exception as e:
        flash(f'Error updating record: {str(e)}')
        return redirect(url_for('edit_record', session_id=session_id, table=table, rowid=rowid))

@app.route('/delete_record/<session_id>/<table>/<int:rowid>')
@login_required
def delete_record(session_id, table, rowid):
    if session_id not in sessions:
        flash('Session expired')
        return redirect(url_for('index'))
    
    db_path = sessions[session_id]['db_path']
    
    try:
        conn = get_db_connection(db_path)
        conn.execute(f'DELETE FROM {table} WHERE rowid = ?', (rowid,))
        conn.commit()
        conn.close()
        
        flash('Record deleted successfully')
    except Exception as e:
        flash(f'Error deleting record: {str(e)}')
    
    return redirect(url_for('crud_interface', session_id=session_id, table=table))

@app.route('/download/<session_id>')
@login_required
def download_db(session_id):
    if session_id not in sessions:
        flash('Session expired')
        return redirect(url_for('index'))
    
    db_path = sessions[session_id]['db_path']
    db_name = sessions[session_id]['db_name']
    
    try:
        # Convert to absolute path
        abs_db_path = os.path.abspath(db_path)
        
        print(f"DEBUG: Absolute path: {abs_db_path}")
        print(f"DEBUG: File exists: {os.path.exists(abs_db_path)}")
        
        if not os.path.exists(abs_db_path):
            flash(f'Database file not found')
            return redirect(url_for('index'))
        
        # Try reading the file directly for dev server compatibility
        with open(abs_db_path, 'rb') as f:
            file_data = f.read()
        
        from flask import Response
        return Response(
            file_data,
            mimetype='application/octet-stream',
            headers={
                'Content-Disposition': f'attachment; filename={db_name}',
                'Content-Length': str(len(file_data))
            }
        )
        
    except Exception as e:
        print(f"DEBUG: Download error: {str(e)}")
        flash(f'Error downloading database: {str(e)}')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

# To run: python app.py
# Create a 'templates' folder and add the HTML template files there