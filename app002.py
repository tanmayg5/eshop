# your_web_project_folder/app.py

from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector as sqltor
from werkzeug.security import generate_password_hash, check_password_hash # For secure passwords
from functools import wraps
import datetime
import os

# --- App & Database Configuration ---
app = Flask(__name__)
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWD = "tanmay05" # IMPORTANT: Replace with your actual password
DB_NAME = "eshop"


# --- Helper Functions ---
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
        flash("Database connection error. Please try again later.", "error")
        return None

def allowed_file(filename):
    """Checks if a file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Decorators ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or not session.get('is_admin'):
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


# --- Main & User Routes ---
@app.route('/')
def index():
    """Serves the main page with login/registration forms."""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login_register.html')

@app.route('/register', methods=['POST'])
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
            return redirect(url_for('index'))

        cursor = None
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                flash(f"Username '{username}' already exists. Please choose another.", 'error')
            else:
                # --- THIS IS THE CRITICAL SECURITY FIX ---
                # Securely HASH the password before storing it.
                hashed_password = generate_password_hash(password)

                # The new schema's column is 'password_hash'.
                cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                               (username, hashed_password))
                conn.commit()
                flash(f"User '{username}' registered successfully! You can now log in.", 'success')
                
                # NOTE: The logic for inserting into the old 'details' table has been removed
                # as that table no longer exists in the new schema.

                return redirect(url_for('index'))

        except sqltor.Error as err:
            app.logger.error(f"Database error during registration: {err}")
            flash("Registration failed due to a database error.", 'error')
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    return redirect(url_for('index'))


@app.route('/login', methods=['POST'])
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
            # Fetch all necessary user info, including the hashed password and admin status
            cursor.execute("SELECT id, username, password_hash, is_admin FROM users WHERE username = %s", (username,))
            user_record = cursor.fetchone()

            # --- THIS IS THE CRITICAL SECURITY FIX ---
            # Use check_password_hash to securely compare the submitted password with the stored hash.
            if user_record and check_password_hash(user_record['password_hash'], password_candidate):
                # Password is correct! Store user info in the session.
                session['user_id'] = user_record['id']
                session['username'] = user_record['username']
                session['is_admin'] = user_record['is_admin']
                
                flash(f"Login successful! Welcome back, {user_record['username']}!", 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password. Please check your credentials.', 'error')

        except sqltor.Error as err:
            app.logger.error(f"Database error during login: {err}")
            flash("Login failed due to a database error.", 'error')
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html')
    else:
        flash('You need to log in first to access the dashboard.', 'error')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear() # Clears all session data
    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('index'))


# --- Admin Routes (Your existing code for product and order management) ---

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    search_term = request.args.get('search', '')
    conn = get_db_connection()
    if not conn:
        return redirect(url_for('index'))
    cursor = conn.cursor(dictionary=True)
    if search_term:
        query_search_term = f"%{search_term}%"
        sql_query = "SELECT * FROM products WHERE name LIKE %s OR description LIKE %s ORDER BY created_at DESC"
        cursor.execute(sql_query, (query_search_term, query_search_term))
    else:
        sql_query = "SELECT * FROM products ORDER BY created_at DESC"
        cursor.execute(sql_query)
    products = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('admin_dashboard.html', products=products, search_term=search_term)

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
            return render_template('product_form.html', action_url=url_for('add_product'), product=None)

        image_url = None
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(save_path)
            image_url = os.path.join('uploads', filename).replace("\\", "/")

        conn = get_db_connection()
        if not conn: return redirect(url_for('admin_dashboard'))
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO products (name, description, price, stock_quantity, image_url) VALUES (%s, %s, %s, %s, %s)",
                           (name, description, price, stock_quantity, image_url))
            conn.commit()
            flash('Product added successfully!', 'success')
        except sqltor.Error as err:
            flash(f'Database error: {err}', 'error')
        finally:
            cursor.close()
            conn.close()
        return redirect(url_for('admin_dashboard'))
    return render_template('product_form.html', action_url=url_for('add_product'), product=None)

@app.route('/admin/product/edit/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    conn = get_db_connection()
    if not conn: return redirect(url_for('admin_dashboard'))
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

        image_url = product['image_url']
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = os.path.join('uploads', filename).replace("\\", "/")
        
        update_cursor = conn.cursor()
        try:
            update_cursor.execute("UPDATE products SET name=%s, description=%s, price=%s, stock_quantity=%s, image_url=%s WHERE id=%s",
                                  (name, description, price, stock_quantity, image_url, product_id))
            conn.commit()
            flash('Product updated successfully!', 'success')
        except sqltor.Error as err:
            flash(f'Database error: {err}', 'error')
        finally:
            update_cursor.close()
        
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
    if not conn: return redirect(url_for('admin_dashboard'))
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


@app.route('/admin/orders')
@admin_required
def admin_order_list():
    """Displays a list of all orders."""
    conn = get_db_connection()
    if not conn:
        return redirect(url_for('admin_dashboard')) # Or an error page
    
    cursor = conn.cursor(dictionary=True)
    try:
        # --- THIS QUERY IS NOW CORRECTED ---
        # It now joins on o.username = u.username instead of o.user_id = u.id
        cursor.execute("""
            SELECT o.id, u.username, o.total_price, o.status, o.order_date 
            FROM orders o
            JOIN users u ON o.username = u.username
            ORDER BY o.order_date DESC
        """)
        orders = cursor.fetchall()
    except sqltor.Error as err:
        flash(f'Database error: {err}', 'error')
        orders = []
    finally:
        cursor.close()
        conn.close()
        
    return render_template('admin_order_list.html', orders=orders)

@app.route('/admin/order/<int:order_id>')
@admin_required
def admin_order_detail(order_id):
    """Displays the details of a single order."""
    conn = get_db_connection()
    if not conn:
        return redirect(url_for('admin_order_list'))

    order = None
    items = []
    cursor = conn.cursor(dictionary=True)
    try:
        # --- THIS QUERY IS ALSO CORRECTED ---
        # It now joins on o.username = u.username
        cursor.execute("""
            SELECT o.id, o.username, o.total_price, o.status, o.order_date
            FROM orders o
            JOIN users u ON o.username = u.username
            WHERE o.id = %s
        """, (order_id,))
        order = cursor.fetchone()

        if order:
            # Get all items for this order, joining with products to get name and image
            cursor.execute("""
                SELECT oi.quantity, oi.price_at_purchase, p.name AS product_name, p.image_url, p.id as product_id
                FROM order_items oi
                LEFT JOIN products p ON oi.product_id = p.id
                WHERE oi.order_id = %s
            """, (order_id,))
            items = cursor.fetchall()
        else:
            flash('Order not found!', 'error')
            return redirect(url_for('admin_order_list'))

    except sqltor.Error as err:
        flash(f'Database error: {err}', 'error')
    finally:
        cursor.close()
        conn.close()

    return render_template('admin_order_detail.html', order=order, items=items)

@app.route('/admin/order/update_status/<int:order_id>', methods=['POST'])
@admin_required
def update_order_status(order_id):
    """Handles the form submission to update an order's status."""
    new_status = request.form.get('status')
    
    # Basic validation
    allowed_statuses = ['Processing', 'Shipped', 'Delivered', 'Cancelled']
    if not new_status or new_status not in allowed_statuses:
        flash('Invalid status selected.', 'error')
        return redirect(url_for('admin_order_detail', order_id=order_id))

    conn = get_db_connection()
    if not conn:
        return redirect(url_for('admin_order_detail', order_id=order_id))

    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE orders SET status = %s WHERE id = %s", (new_status, order_id))
        conn.commit()
        flash(f"Order #{order_id} status updated to '{new_status}'.", 'success')
    except sqltor.Error as err:
        flash(f'Database error: {err}', 'error')
    finally:
        cursor.close()
        conn.close()
        
    return redirect(url_for('admin_order_detail', order_id=order_id))


if __name__ == '__main__':
    app.run(debug=True)
