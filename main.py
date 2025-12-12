"""
📦 متجر التطبيقات الرقمي - نسخة نظيفة
مع: نظام دفع Bitcoin، رفع ملفات، تقييمات، وServeo
"""

from flask import Flask, render_template_string, request, jsonify, send_file
import sqlite3
import json
import os
import secrets
import hashlib
import uuid
import threading
import time
import requests
from datetime import datetime, timedelta
import qrcode
from io import BytesIO
import subprocess
import socket
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ===== إعدادات الإنتاج =====
BITCOIN_WALLET = "186DuB3DnvXvZQqxKvQgVYrs5LW9NXtLdr"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = hashlib.sha256("Admin@Secure123!".encode()).hexdigest()

# ===== Serveo Tunnel =====
SERVEO_URL = None
SERVEO_PROCESS = None

def start_serveo_tunnel(port=5000):
    """تشغيل Serveo tunnel"""
    global SERVEO_URL, SERVEO_PROCESS
    
    print("🔄 بدء تشغيل Serveo...")
    
    try:
        # تشغيل Serveo عبر SSH
        serveo_process = subprocess.Popen(
            ['ssh', '-o', 'StrictHostKeyChecking=no', '-R', '80:localhost:{}'.format(port), 'serveo.net'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        SERVEO_PROCESS = serveo_process
        
        # قراءة الإخراج
        def read_output():
            global SERVEO_URL
            for line in serveo_process.stdout:
                if 'Forwarding' in line and 'serveo.net' in line:
                    parts = line.strip().split()
                    for part in parts:
                        if 'serveo.net' in part:
                            SERVEO_URL = "https://" + part
                            print(f"✅ Serveo URL: {SERVEO_URL}")
                            # حفظ في ملف
                            with open('serveo_url.txt', 'w') as f:
                                f.write(SERVEO_URL)
                            break
        
        threading.Thread(target=read_output, daemon=True).start()
        time.sleep(5)
        
        return SERVEO_URL
        
    except Exception as e:
        print(f"❌ خطأ في Serveo: {e}")
        return None

# ===== قاعدة البيانات =====
def init_db():
    """تهيئة قاعدة البيانات"""
    conn = sqlite3.connect('appstore.db', check_same_thread=False)
    c = conn.cursor()
    
    # جدول التطبيقات
    c.execute('''CREATE TABLE IF NOT EXISTS apps
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  description TEXT NOT NULL,
                  price REAL NOT NULL,
                  features TEXT,
                  installation_steps TEXT,
                  file_name TEXT,
                  file_size TEXT,
                  icon TEXT,
                  color TEXT,
                  rating REAL DEFAULT 0,
                  total_ratings INTEGER DEFAULT 0,
                  downloads INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  is_active INTEGER DEFAULT 1)''')
    
    # جدول الطلبات
    c.execute('''CREATE TABLE IF NOT EXISTS orders
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  order_id TEXT UNIQUE NOT NULL,
                  app_id INTEGER NOT NULL,
                  amount REAL NOT NULL,
                  btc_amount REAL NOT NULL,
                  transaction_hash TEXT,
                  status TEXT DEFAULT 'pending',
                  download_code TEXT UNIQUE,
                  download_count INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  paid_at TIMESTAMP,
                  expires_at TIMESTAMP,
                  FOREIGN KEY (app_id) REFERENCES apps(id))''')
    
    # جدول التقييمات
    c.execute('''CREATE TABLE IF NOT EXISTS reviews
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  app_id INTEGER NOT NULL,
                  rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
                  comment TEXT,
                  user_name TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (app_id) REFERENCES apps(id))''')
    
    # جدول المستخدمين
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  role TEXT DEFAULT 'admin',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # إضافة المدير
    password_hash = hashlib.sha256("Admin@Secure123!".encode()).hexdigest()
    c.execute("INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, 'admin')", 
              (ADMIN_USERNAME, password_hash))
    
    conn.commit()
    conn.close()
    print("✅ قاعدة البيانات جاهزة!")

# تهيئة قاعدة البيانات
init_db()

# ===== دوال مساعدة =====
def get_db():
    conn = sqlite3.connect('appstore.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    """التحقق من نوع الملف"""
    ALLOWED_EXTENSIONS = {'zip', 'rar', 'exe', 'msi', 'apk', 'dmg', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file):
    """حفظ الملف المرفوع"""
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join('uploads', filename)
        os.makedirs('uploads', exist_ok=True)
        file.save(filepath)
        
        # حساب حجم الملف
        size = os.path.getsize(filepath)
        if size < 1024 * 1024:  # أقل من 1MB
            file_size = f"{size/1024:.1f} KB"
        else:
            file_size = f"{size/(1024*1024):.1f} MB"
        
        return filename, file_size
    return None, None

def get_bitcoin_price():
    """الحصول على سعر Bitcoin"""
    try:
        response = requests.get('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd', timeout=5)
        data = response.json()
        return data['bitcoin']['usd']
    except:
        return 45000  # سعر افتراضي

def generate_download_code():
    """إنشاء كود تحميل فريد"""
    return secrets.token_urlsafe(12)

def create_qr_code(text):
    """إنشاء QR Code"""
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img_bytes = BytesIO()
    img.save(img_bytes, 'PNG')
    img_bytes.seek(0)
    return img_bytes

# ===== مسارات API =====
@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/apps')
def get_apps():
    """الحصول على جميع التطبيقات"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM apps WHERE is_active = 1 ORDER BY created_at DESC")
    apps = c.fetchall()
    
    app_list = []
    for app in apps:
        # الحصول على التقييمات
        c.execute("SELECT AVG(rating) as avg_rating, COUNT(*) as total FROM reviews WHERE app_id = ?", (app['id'],))
        rating_data = c.fetchone()
        
        app_list.append({
            'id': app['id'],
            'name': app['name'],
            'description': app['description'],
            'price': app['price'],
            'features': json.loads(app['features']) if app['features'] else [],
            'installation_steps': app['installation_steps'],
            'file_name': app['file_name'],
            'file_size': app['file_size'],
            'icon': app['icon'] or 'fas fa-mobile-alt',
            'color': app['color'] or '#4361ee',
            'rating': rating_data['avg_rating'] or 0,
            'total_ratings': rating_data['total'] or 0,
            'downloads': app['downloads'] or 0
        })
    
    conn.close()
    return jsonify(app_list)

@app.route('/api/apps/<int:app_id>/reviews')
def get_app_reviews(app_id):
    """الحصول على تقييمات تطبيق"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM reviews WHERE app_id = ? ORDER BY created_at DESC", (app_id,))
    reviews = c.fetchall()
    
    review_list = []
    for review in reviews:
        review_list.append({
            'id': review['id'],
            'rating': review['rating'],
            'comment': review['comment'],
            'user_name': review['user_name'] or 'مستخدم',
            'created_at': review['created_at']
        })
    
    conn.close()
    return jsonify(review_list)

@app.route('/api/reviews', methods=['POST'])
def add_review():
    """إضافة تقييم جديد"""
    data = request.json
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''INSERT INTO reviews (app_id, rating, comment, user_name) 
                 VALUES (?, ?, ?, ?)''',
              (data['app_id'], data['rating'], data['comment'], data.get('user_name', 'مستخدم')))
    
    # تحديث متوسط التقييم
    c.execute("SELECT AVG(rating) as avg_rating FROM reviews WHERE app_id = ?", (data['app_id'],))
    avg_rating = c.fetchone()['avg_rating']
    
    c.execute("UPDATE apps SET rating = ?, total_ratings = total_ratings + 1 WHERE id = ?",
              (avg_rating, data['app_id']))
    
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/orders', methods=['POST'])
def create_order():
    """إنشاء طلب جديد"""
    data = request.json
    conn = get_db()
    c = conn.cursor()
    
    # الحصول على سعر Bitcoin
    btc_price = get_bitcoin_price()
    btc_amount = data['amount'] / btc_price
    
    # إنشاء كود الطلب
    order_id = str(uuid.uuid4())[:12].upper()
    
    c.execute('''INSERT INTO orders (order_id, app_id, amount, btc_amount, expires_at)
                 VALUES (?, ?, ?, ?, ?)''',
              (order_id, data['appId'], data['amount'], btc_amount,
               datetime.now() + timedelta(hours=24)))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'orderId': order_id,
        'bitcoinWallet': BITCOIN_WALLET,
        'btcAmount': btc_amount
    })

@app.route('/api/orders/confirm', methods=['POST'])
def confirm_payment():
    """تأكيد الدفع"""
    data = request.json
    conn = get_db()
    c = conn.cursor()
    
    # التحقق من الطلب
    c.execute('''SELECT * FROM orders 
                 WHERE order_id = ? AND status = 'pending' 
                 AND expires_at > ?''',
              (data['orderId'], datetime.now()))
    order = c.fetchone()
    
    if not order:
        conn.close()
        return jsonify({'success': False, 'error': 'الطلب غير صالح'})
    
    # إنشاء كود التحميل
    download_code = generate_download_code()
    
    # تحديث الطلب
    c.execute('''UPDATE orders 
                 SET status = 'paid', 
                     transaction_hash = ?,
                     download_code = ?,
                     paid_at = CURRENT_TIMESTAMP
                 WHERE order_id = ?''',
              (data['transactionHash'], download_code, data['orderId']))
    
    # زيادة عدد التحميلات
    c.execute("UPDATE apps SET downloads = downloads + 1 WHERE id = ?", (order['app_id'],))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'download_code': download_code,
        'message': 'تم الدفع بنجاح!'
    })

@app.route('/api/download/<download_code>')
def download_file(download_code):
    """تحميل الملف"""
    conn = get_db()
    c = conn.cursor()
    
    # التحقق من كود التحميل
    c.execute('''SELECT o.*, a.file_name FROM orders o
                 JOIN apps a ON o.app_id = a.id
                 WHERE o.download_code = ? AND o.status = 'paid'
                 AND o.paid_at > datetime('now', '-30 days')''',
              (download_code,))
    
    order = c.fetchone()
    
    if not order:
        conn.close()
        return jsonify({'error': 'كود التحميل غير صالح'}), 404
    
    # زيادة عداد التحميل
    c.execute("UPDATE orders SET download_count = download_count + 1 WHERE order_id = ?",
              (order['order_id'],))
    
    conn.commit()
    conn.close()
    
    # إرسال الملف
    file_path = os.path.join('uploads', order['file_name'])
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return jsonify({'error': 'الملف غير موجود'}), 404

@app.route('/api/bitcoin-price')
def bitcoin_price():
    """سعر Bitcoin"""
    return jsonify({'price': get_bitcoin_price()})

@app.route('/api/qr-code/<wallet>')
def get_qr_code(wallet):
    """الحصول على QR Code"""
    qr_img = create_qr_code(f"bitcoin:{wallet}")
    return send_file(qr_img, mimetype='image/png')

@app.route('/api/network-info')
def network_info():
    """معلومات الشبكة"""
    return jsonify({
        'local_ip': socket.gethostbyname(socket.gethostname()),
        'serveo_url': SERVEO_URL,
        'port': 5000
    })

# ===== مسارات المدير =====
def verify_admin_token():
    """التحقق من صلاحية المدير"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    return token == ADMIN_PASSWORD_HASH

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """تسجيل دخول المدير"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if username == ADMIN_USERNAME:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash == ADMIN_PASSWORD_HASH:
            return jsonify({
                'success': True,
                'token': ADMIN_PASSWORD_HASH
            })
    
    return jsonify({'success': False, 'error': 'بيانات دخول خاطئة'}), 401

@app.route('/api/admin/apps', methods=['POST'])
def add_app():
    """إضافة تطبيق جديد"""
    if not verify_admin_token():
        return jsonify({'error': 'غير مصرح'}), 401
    
    data = request.form.to_dict()
    file = request.files.get('file')
    
    # حفظ الملف
    if file:
        filename, file_size = save_uploaded_file(file)
        if not filename:
            return jsonify({'error': 'نوع الملف غير مدعوم'}), 400
    else:
        return jsonify({'error': 'يجب رفع ملف'}), 400
    
    # حفظ في قاعدة البيانات
    conn = get_db()
    c = conn.cursor()
    
    features = data.get('features', '').split('\n')
    features = [f.strip() for f in features if f.strip()]
    
    c.execute('''INSERT INTO apps (name, description, price, features, installation_steps,
                 file_name, file_size, icon, color) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (data['name'], data['description'], float(data['price']), 
               json.dumps(features), data.get('installation_steps', ''),
               filename, file_size, data.get('icon', 'fas fa-mobile-alt'),
               data.get('color', '#4361ee')))
    
    conn.commit()
    app_id = c.lastrowid
    conn.close()
    
    return jsonify({'success': True, 'id': app_id})

@app.route('/api/admin/apps')
def get_admin_apps():
    """الحصول على التطبيقات للمدير"""
    if not verify_admin_token():
        return jsonify({'error': 'غير مصرح'}), 401
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM apps ORDER BY created_at DESC")
    apps = c.fetchall()
    
    app_list = []
    for app in apps:
        app_list.append({
            'id': app['id'],
            'name': app['name'],
            'price': app['price'],
            'downloads': app['downloads'],
            'created_at': app['created_at'],
            'is_active': bool(app['is_active'])
        })
    
    conn.close()
    return jsonify(app_list)

@app.route('/api/admin/apps/<int:app_id>', methods=['DELETE'])
def delete_app(app_id):
    """حذف تطبيق"""
    if not verify_admin_token():
        return jsonify({'error': 'غير مصرح'}), 401
    
    conn = get_db()
    c = conn.cursor()
    
    # حذف التطبيق
    c.execute("DELETE FROM apps WHERE id = ?", (app_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/admin/orders')
def get_orders():
    """الحصول على الطلبات"""
    if not verify_admin_token():
        return jsonify({'error': 'غير مصرح'}), 401
    
    conn = get_db()
    c = conn.cursor()
    c.execute('''SELECT o.*, a.name as app_name FROM orders o
                 JOIN apps a ON o.app_id = a.id
                 ORDER BY o.created_at DESC LIMIT 100''')
    orders = c.fetchall()
    
    order_list = []
    for order in orders:
        order_list.append({
            'order_id': order['order_id'],
            'app_name': order['app_name'],
            'amount': order['amount'],
            'status': order['status'],
            'created_at': order['created_at'],
            'paid_at': order['paid_at']
        })
    
    conn.close()
    return jsonify(order_list)

# ===== HTML Template =====
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>متجر التطبيقات الرقمي</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --secondary: #7c3aed;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --dark: #1e293b;
            --light: #f8fafc;
            --gray: #64748b;
            --border: #e2e8f0;
            --shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
            --radius: 12px;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Cairo', sans-serif;
        }

        body {
            background: #f1f5f9;
            color: var(--dark);
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        /* الهيدر */
        header {
            background: white;
            box-shadow: var(--shadow);
            position: sticky;
            top: 0;
            z-index: 1000;
            padding: 1rem 0;
        }

        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .logo i {
            font-size: 2rem;
            color: var(--primary);
        }

        .logo h1 {
            font-size: 1.5rem;
            font-weight: 700;
        }

        nav ul {
            display: flex;
            list-style: none;
            gap: 1.5rem;
        }

        nav a {
            text-decoration: none;
            color: var(--dark);
            font-weight: 600;
            padding: 0.5rem 1rem;
            border-radius: var(--radius);
            transition: all 0.3s;
        }

        nav a:hover, nav a.active {
            background: var(--primary);
            color: white;
        }

        .btn {
            padding: 0.75rem 1.5rem;
            border-radius: var(--radius);
            border: none;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .btn-primary {
            background: var(--primary);
            color: white;
        }

        .btn-primary:hover {
            background: var(--primary-dark);
            transform: translateY(-2px);
        }

        .btn-success {
            background: var(--success);
            color: white;
        }

        .btn-danger {
            background: var(--danger);
            color: white;
        }

        /* بطاقة التطبيق */
        .app-card {
            background: white;
            border-radius: var(--radius);
            overflow: hidden;
            box-shadow: var(--shadow);
            transition: transform 0.3s;
        }

        .app-card:hover {
            transform: translateY(-5px);
        }

        .app-image {
            height: 180px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 3rem;
        }

        .app-info {
            padding: 1.5rem;
        }

        .app-title {
            font-size: 1.25rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }

        .app-description {
            color: var(--gray);
            margin-bottom: 1rem;
        }

        .app-price {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--primary);
            margin-bottom: 1rem;
        }

        .app-features {
            list-style: none;
            margin-bottom: 1.5rem;
        }

        .app-features li {
            padding: 0.25rem 0;
            color: var(--gray);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        /* التقييمات */
        .rating-stars {
            color: #fbbf24;
            margin-bottom: 0.5rem;
        }

        .reviews-container {
            margin-top: 2rem;
        }

        .review-card {
            background: white;
            padding: 1rem;
            border-radius: var(--radius);
            margin-bottom: 1rem;
            border: 1px solid var(--border);
        }

        /* صفحة الدفع */
        .payment-container {
            background: white;
            border-radius: var(--radius);
            padding: 2rem;
            box-shadow: var(--shadow);
            max-width: 800px;
            margin: 2rem auto;
        }

        .wallet-address {
            background: var(--light);
            padding: 1rem;
            border-radius: var(--radius);
            font-family: monospace;
            word-break: break-all;
            margin: 1rem 0;
            border: 2px solid var(--border);
        }

        .qr-code {
            max-width: 200px;
            margin: 1rem auto;
        }

        .qr-code img {
            width: 100%;
            border-radius: var(--radius);
        }

        /* لوحة التحكم */
        .admin-panel {
            background: white;
            border-radius: var(--radius);
            padding: 2rem;
            margin: 2rem 0;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
        }

        .form-control {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid var(--border);
            border-radius: var(--radius);
            font-size: 1rem;
        }

        textarea.form-control {
            min-height: 120px;
            resize: vertical;
        }

        .file-upload {
            border: 2px dashed var(--border);
            padding: 2rem;
            text-align: center;
            border-radius: var(--radius);
            cursor: pointer;
        }

        .file-upload:hover {
            border-color: var(--primary);
        }

        /* تنبيهات */
        .alert {
            padding: 1rem;
            border-radius: var(--radius);
            margin: 1rem 0;
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .alert-success {
            background: #d1fae5;
            color: #065f46;
            border: 1px solid #a7f3d0;
        }

        .alert-danger {
            background: #fee2e2;
            color: #991b1b;
            border: 1px solid #fecaca;
        }

        /* الفوتر */
        footer {
            background: var(--dark);
            color: white;
            padding: 3rem 0 1.5rem;
            margin-top: 4rem;
        }

        .footer-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }

        .footer-section h4 {
            font-size: 1.25rem;
            margin-bottom: 1rem;
        }

        .footer-section p {
            color: #cbd5e1;
        }

        .footer-bottom {
            text-align: center;
            padding-top: 1.5rem;
            border-top: 1px solid #334155;
            color: #94a3b8;
        }
    </style>
</head>
<body>
    <!-- JavaScript code would go here -->
</body>
</html>
'''

# ===== تشغيل التطبيق =====
if __name__ == '__main__':
    # تشغيل Serveo
    threading.Thread(target=start_serveo_tunnel, daemon=True).start()
    
    print("=" * 60)
    print("🚀 متجر التطبيقات الرقمي")
    print("=" * 60)
    print(f"👨‍💼 اسم المستخدم: {ADMIN_USERNAME}")
    print(f"🔐 كلمة المرور: Admin@Secure123!")
    print("=" * 60)
    print(f"💳 محفظة Bitcoin: {BITCOIN_WALLET}")
    print("=" * 60)
    
    # تشغيل التطبيق
    app.run(host='0.0.0.0', port=5000, debug=True)
