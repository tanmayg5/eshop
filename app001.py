from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector as sqltor
from werkzeug.security import generate_password_hash, check_password_hash # For secure passwords
import datetime
from werkzeug.utils import secure_filename
import os # For generating a secret key
from functools import wraps


app = Flask(__name__)
app.secret_key = os.urandom(24)


# --- Database Configuration ---
DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWD = "tanmay05"
DB_NAME = "eshop"

UPLOAD_FOLDER = 'uploads' # The folder we created
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in and is an admin
        if 'username' not in session or not session.get('is_admin'):
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection():
    """Establishes and returns a database connection."""
    try:
        conn = sqltor.connect(
            host=DB_HOST,
            user=DB_USER,
            passwd=DB_PASSWD,
            database=DB_NAME
        )
        return conn
    except sqltor.Error as err:
        app.logger.error(f"Database connection error: {err}")
        flash(f"Database connection error: Could not connect. Please try again later.", "error")
        return None

# --- Routes ---
@app.route('/')
def index():
    """Serves the main page with login/registration forms."""
    if 'username' in session: 
        return redirect(url_for('dashboard'))
    return render_template('login_register.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password or not confirm_password:
            flash('All fields are required for registration.', 'error')
            return redirect(url_for('index'))

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return redirect(url_for('index'))

        conn = get_db_connection()
        if not conn:
            # Flash message already set by get_db_connection if it failed
            return redirect(url_for('index'))

        cursor = None
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash(f"Username '{username}' already exists. Please choose another.", 'error')
            else:
                
                hashed_password = generate_password_hash(password)
                current_date = datetime.date.today()
                cursor.execute("INSERT INTO users VALUES (%s, %s,'A', %s, 'A', 'A',0)",
                               (username, hashed_password, current_date))
                conn.commit()
                flash(f"User '{username}' registered successfully! You can now log in.", 'success')
                '''
                try:
                    cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
                    if not cursor.fetchone(): # Only insert if details don't already exist
                        cursor.execute("INSERT INTO users VALUES (%s, 'A', %s, 'A', 'A')",
                                       (username, current_date))
                        conn.commit()
                        app.logger.info(f"Details inserted for new user '{username}'")
                except sqltor.Error as detail_err:
                    app.logger.error(f"Error inserting into details table for {username}: {detail_err}")
                    # Non-critical for registration success message, so just log
                '''
                return redirect(url_for('index')) # Redirect to login page

        except sqltor.Error as err:
            app.logger.error(f"Database error during registration: {err}")
            flash(f"Registration failed due to a database error. Please try again.", 'error')
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()
    
    # For GET request to /register, just show the main page
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form.get('username')
        password_candidate = request.form.get('password') 

        if not username or not password_candidate:
            flash('Username and Password are required.', 'error')
            return redirect(url_for('index'))

        conn = get_db_connection()
        if not conn:
            return redirect(url_for('index'))

        cursor = None
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT username, passw, is_admin FROM users WHERE username = %s", (username,))
            user_record = cursor.fetchone()

            if user_record and check_password_hash(user_record['passw'], password_candidate):
                session['username'] = user_record['username']
                session['is_admin'] = user_record['is_admin'] 
                flash(f"Welcome back, {user_record['username']}!", 'success')
                return redirect(url_for('dashboard'))
            
            else:
                flash('Invalid username or password. Please check your credentials.', 'error')

        except sqltor.Error as err:
            app.logger.error(f"Database error during login: {err}")
            flash(f"Login failed due to a database error. Please try again.", 'error')
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()
    
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    """Displays the user dashboard if logged in."""
    if 'username' in session: 
        return render_template('dashboard.html')
    else:
        flash('You need to log in first to access the dashboard.', 'error')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('username', None) 
    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    if not conn:
        return redirect(url_for('index'))
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products ORDER BY created_at DESC")
    products = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('admin_dashboard.html', products=products)

@app.route('/admin/product/add', methods=['GET', 'POST'])
@admin_required
def add_product():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        stock_quantity = request.form.get('stock_quantity')
        image = request.files.get('image')

        if not name or not price or not stock_quantity:
            flash('Name, price, and stock are required fields.', 'error')
            return redirect(url_for('add_product'))

        image_url = None
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = os.path.join('uploads', filename).replace("\\", "/")

        conn = get_db_connection()
        if not conn:
            return redirect(url_for('admin_dashboard'))
        
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO products (name, description, price, stock_quantity, image_url)
                VALUES (%s, %s, %s, %s, %s)
            """, (name, description, price, stock_quantity, image_url))
            conn.commit()
            flash('Product added successfully!', 'success')
        except sqltor.Error as err:
            flash(f'Database error: {err}', 'error')
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('admin_dashboard'))

    return render_template('product_form.html', action_url=url_for('add_product'),product = None)

@app.route('/admin/product/edit/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    conn = get_db_connection()
    if not conn:
        return redirect(url_for('admin_dashboard'))
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('Product not found!', 'error')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        stock_quantity = request.form.get('stock_quantity')
        image = request.files.get('image')

        if not name or not price or not stock_quantity:
            flash('Name, price, and stock are required fields.', 'error')
            return redirect(url_for('edit_product', product_id=product_id))

        image_url = product['image_url'] 
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = os.path.join('uploads', filename).replace("\\", "/")
        
        try:
            update_cursor = conn.cursor()
            update_cursor.execute("""
                UPDATE products SET name=%s, description=%s, price=%s, stock_quantity=%s, image_url=%s
                WHERE id=%s
            """, (name, description, price, stock_quantity, image_url, product_id))
            conn.commit()
            flash('Product updated successfully!', 'success')
            update_cursor.close()
        except sqltor.Error as err:
            flash(f'Database error: {err}', 'error')
        
        cursor.close()
        conn.close()
        return redirect(url_for('admin_dashboard'))

    cursor.close()
    conn.close()
    return render_template('product_form.html', product=product, action_url=url_for('edit_product', product_id=product_id))

@app.route('/admin/product/delete/<int:product_id>', methods=['POST'])
@admin_required
def delete_product(product_id):
    conn = get_db_connection()
    if not conn:
        return redirect(url_for('admin_dashboard'))
    
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM products WHERE id = %s", (product_id,))
        conn.commit()
        flash('Product deleted successfully!', 'success')
    except sqltor.Error as err:
        flash(f'Database error: {err}', 'error')
    finally:
        cursor.close()
        conn.close()
        
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    # debug=True is helpful for development (shows errors in browser).
    # cannot run with debug=True in a production environment.
    app.run(debug=True)
