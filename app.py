import base64, datetime, hashlib, hmac, json, os, secrets, shutil, sqlite3, string
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.decrepit.ciphers import modes as decrepit_modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / 'storage'
FILES_DIR = STORAGE_DIR / 'files'
KEYS_DIR = STORAGE_DIR / 'keys'
DB_PATH = STORAGE_DIR / 'site.db'

STORAGE_DIR.mkdir(parents=True, exist_ok=True)
FILES_DIR.mkdir(parents=True, exist_ok=True)
KEYS_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-change-in-production'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(str(DB_PATH))
    db.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, filename TEXT NOT NULL, stored_name TEXT NOT NULL, uploaded_at TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, name TEXT NOT NULL, key_type TEXT NOT NULL, stored_name TEXT NOT NULL, created_at TEXT NOT NULL)')
    db.commit()
    db.close()


init_db()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def is_admin_user():
    if 'username' not in session:
        return False
    row = get_db().execute('SELECT is_admin FROM users WHERE username = ?', (session['username'],)).fetchone()
    return bool(row and row['is_admin'])


@app.context_processor
def inject_admin():
    return dict(is_admin=is_admin_user())


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        if not is_admin_user():
            flash('Admin access required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


def any_user():
    row = get_db().execute('SELECT COUNT(*) FROM users').fetchone()
    return row[0] > 0


def user_file_dir(username):
    d = FILES_DIR / username
    d.mkdir(parents=True, exist_ok=True)
    return d


def user_key_dir(username):
    d = KEYS_DIR / username
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_file(d, name, data):
    target = d / secure_filename(name)
    i = 1
    stem = target.stem
    suffix = target.suffix
    while target.exists():
        target = d / secure_filename(f"{stem}_{i}{suffix}")
        i += 1
    target.write_bytes(data)
    return str(target.relative_to(FILES_DIR)), target.name


def save_key(d, name, data):
    target = d / secure_filename(name)
    i = 1
    stem = target.stem
    suffix = target.suffix
    while target.exists():
        target = d / secure_filename(f"{stem}_{i}{suffix}")
        i += 1
    target.write_bytes(data)
    return str(target.relative_to(KEYS_DIR)), target.name


def generate_password(length=16, upper=True, lower=True, digits=True, special=True):
    alphabet = ''
    if upper:
        alphabet += string.ascii_uppercase
    if lower:
        alphabet += string.ascii_lowercase
    if digits:
        alphabet += string.digits
    if special:
        alphabet += string.punctuation
    if not alphabet:
        alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def build_iv(iv_text, length):
    if not iv_text:
        return os.urandom(length)
    n = int(iv_text)
    if n < 0 or n >= 2 ** 32:
        raise ValueError('IV must be a 32-bit value')
    prefix = n.to_bytes(4, 'big')
    return prefix + os.urandom(length - 4)


def derive_or_use_key(key_data, key_size):
    if len(key_data) == key_size:
        return key_data, None
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_size, salt=salt, iterations=100000)
    return kdf.derive(key_data), salt


def make_key_for_decrypt(key_data, key_size, salt=None):
    if salt is not None:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_size, salt=salt, iterations=100000)
        return kdf.derive(key_data)
    if len(key_data) != key_size:
        raise ValueError('Key length does not match')
    return key_data


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = get_db().execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html', allow_register=not any_user())


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if any_user():
        if 'username' not in session:
            flash('Please log in first')
            return redirect(url_for('login'))
        if not is_admin_user():
            flash('Admin access required')
            return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Username and password required')
            return redirect(url_for('register'))
        if get_db().execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone():
            flash('Username already exists')
            return redirect(url_for('register'))
        admin = not any_user() or 'is_admin' in request.form
        get_db().execute('INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)',
                         (username, generate_password_hash(password), 1 if admin else 0, now()))
        get_db().commit()
        if not any_user() or 'username' not in session:
            session['username'] = username
        flash('User created')
        return redirect(url_for('users'))
    return render_template('register.html')


@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/users')
@login_required
@admin_required
def users():
    rows = get_db().execute('SELECT username, is_admin, created_at FROM users ORDER BY username').fetchall()
    return render_template('users.html', users=rows)


@app.route('/users/delete/<username>', methods=['POST'])
@login_required
@admin_required
def delete_user(username):
    if username == session['username']:
        flash('You cannot delete your own account')
        return redirect(url_for('users'))
    db = get_db()
    db.execute('DELETE FROM files WHERE username = ?', (username,))
    db.execute('DELETE FROM keys WHERE username = ?', (username,))
    db.execute('DELETE FROM users WHERE username = ?', (username,))
    db.commit()
    fd = FILES_DIR / username
    kd = KEYS_DIR / username
    if fd.exists():
        shutil.rmtree(fd)
    if kd.exists():
        shutil.rmtree(kd)
    flash('User deleted')
    return redirect(url_for('users'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old = request.form.get('old_password', '')
        new = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')
        user = get_db().execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
        if not check_password_hash(user['password_hash'], old):
            flash('Old password incorrect')
        elif not new or new != confirm:
            flash('New passwords do not match')
        else:
            get_db().execute('UPDATE users SET password_hash = ? WHERE username = ?',
                             (generate_password_hash(new), session['username']))
            get_db().commit()
            flash('Password updated')
            return redirect(url_for('dashboard'))
    return render_template('change_password.html')


@app.route('/files')
@login_required
def files():
    rows = get_db().execute('SELECT * FROM files WHERE username = ? ORDER BY uploaded_at DESC', (session['username'],)).fetchall()
    return render_template('files.html', files=rows)


@app.route('/files/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('files'))
    f = request.files['file']
    if f.filename == '':
        flash('No file selected')
        return redirect(url_for('files'))
    d = user_file_dir(session['username'])
    rel, name = save_file(d, f.filename, f.read())
    get_db().execute('INSERT INTO files (username, filename, stored_name, uploaded_at) VALUES (?, ?, ?, ?)',
                     (session['username'], name, rel, now()))
    get_db().commit()
    flash('File uploaded')
    return redirect(url_for('files'))


@app.route('/files/download/<int:file_id>')
@login_required
def download_file(file_id):
    row = get_db().execute('SELECT * FROM files WHERE id = ? AND username = ?', (file_id, session['username'],)).fetchone()
    if not row:
        abort(404)
    p = FILES_DIR / row['stored_name']
    if not p.exists():
        abort(404)
    return send_file(str(p), as_attachment=True, download_name=row['filename'])


@app.route('/files/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    row = get_db().execute('SELECT * FROM files WHERE id = ? AND username = ?', (file_id, session['username'],)).fetchone()
    if not row:
        abort(404)
    p = FILES_DIR / row['stored_name']
    if p.exists():
        p.unlink()
    get_db().execute('DELETE FROM files WHERE id = ?', (file_id,))
    get_db().commit()
    flash('File deleted')
    return redirect(url_for('files'))


@app.route('/keys')
@login_required
def keys():
    rows = get_db().execute('SELECT * FROM keys WHERE username = ? ORDER BY created_at DESC', (session['username'],)).fetchall()
    return render_template('keys.html', keys=rows)


@app.route('/keys/generate', methods=['POST'])
@login_required
def generate_key():
    name = request.form.get('name', '').strip()
    key_type = request.form.get('key_type', '')
    if not name:
        flash('Key name required')
        return redirect(url_for('keys'))
    d = user_key_dir(session['username'])
    if key_type == 'aes-128':
        data = os.urandom(16)
        rel, fname = save_key(d, f"{name}.key", data)
        get_db().execute('INSERT INTO keys (username, name, key_type, stored_name, created_at) VALUES (?, ?, ?, ?, ?)',
                         (session['username'], name, 'AES-128', rel, now()))
        get_db().commit()
        key_id = get_db().execute('SELECT last_insert_rowid()').fetchone()[0]
        flash('AES-128 key generated')
        return redirect(url_for('view_key', key_id=key_id))
    if key_type == 'aes-192':
        data = os.urandom(24)
        rel, fname = save_key(d, f"{name}.key", data)
        get_db().execute('INSERT INTO keys (username, name, key_type, stored_name, created_at) VALUES (?, ?, ?, ?, ?)',
                         (session['username'], name, 'AES-192', rel, now()))
        get_db().commit()
        key_id = get_db().execute('SELECT last_insert_rowid()').fetchone()[0]
        flash('AES-192 key generated')
        return redirect(url_for('view_key', key_id=key_id))
    if key_type == 'aes-256':
        data = os.urandom(32)
        rel, fname = save_key(d, f"{name}.key", data)
        get_db().execute('INSERT INTO keys (username, name, key_type, stored_name, created_at) VALUES (?, ?, ?, ?, ?)',
                         (session['username'], name, 'AES-256', rel, now()))
        get_db().commit()
        key_id = get_db().execute('SELECT last_insert_rowid()').fetchone()[0]
        flash('AES-256 key generated')
        return redirect(url_for('view_key', key_id=key_id))
    if key_type == '3des':
        data = os.urandom(24)
        rel, fname = save_key(d, f"{name}.key", data)
        get_db().execute('INSERT INTO keys (username, name, key_type, stored_name, created_at) VALUES (?, ?, ?, ?, ?)',
                         (session['username'], name, '3DES', rel, now()))
        get_db().commit()
        key_id = get_db().execute('SELECT last_insert_rowid()').fetchone()[0]
        flash('3DES key generated')
        return redirect(url_for('view_key', key_id=key_id))
    if key_type == 'rsa':
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        priv_pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        pub_pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        rel_priv, _ = save_key(d, f"{name}_private.pem", priv_pem)
        rel_pub, _ = save_key(d, f"{name}_public.pem", pub_pem)
        get_db().execute('INSERT INTO keys (username, name, key_type, stored_name, created_at) VALUES (?, ?, ?, ?, ?)',
                         (session['username'], f"{name} (private)", 'RSA-Private', rel_priv, now()))
        key_id = get_db().execute('SELECT last_insert_rowid()').fetchone()[0]
        get_db().execute('INSERT INTO keys (username, name, key_type, stored_name, created_at) VALUES (?, ?, ?, ?, ?)',
                         (session['username'], f"{name} (public)", 'RSA-Public', rel_pub, now()))
        get_db().commit()
        flash('RSA key pair generated')
        return redirect(url_for('view_key', key_id=key_id))
    if key_type == 'ecdh':
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        priv_pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        pub_pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        rel_priv, _ = save_key(d, f"{name}_private.pem", priv_pem)
        rel_pub, _ = save_key(d, f"{name}_public.pem", pub_pem)
        get_db().execute('INSERT INTO keys (username, name, key_type, stored_name, created_at) VALUES (?, ?, ?, ?, ?)',
                         (session['username'], f"{name} (private)", 'ECDH-Private', rel_priv, now()))
        key_id = get_db().execute('SELECT last_insert_rowid()').fetchone()[0]
        get_db().execute('INSERT INTO keys (username, name, key_type, stored_name, created_at) VALUES (?, ?, ?, ?, ?)',
                         (session['username'], f"{name} (public)", 'ECDH-Public', rel_pub, now()))
        get_db().commit()
        flash('ECDH key pair generated')
        return redirect(url_for('view_key', key_id=key_id))
    flash('Unknown key type')
    return redirect(url_for('keys'))


@app.route('/keys/download/<int:key_id>')
@login_required
def download_key(key_id):
    row = get_db().execute('SELECT * FROM keys WHERE id = ? AND username = ?', (key_id, session['username'],)).fetchone()
    if not row:
        abort(404)
    p = KEYS_DIR / row['stored_name']
    if not p.exists():
        abort(404)
    return send_file(str(p), as_attachment=True, download_name=Path(row['stored_name']).name)


@app.route('/keys/delete/<int:key_id>', methods=['POST'])
@login_required
def delete_key(key_id):
    row = get_db().execute('SELECT * FROM keys WHERE id = ? AND username = ?', (key_id, session['username'],)).fetchone()
    if not row:
        abort(404)
    p = KEYS_DIR / row['stored_name']
    if p.exists():
        p.unlink()
    get_db().execute('DELETE FROM keys WHERE id = ?', (key_id,))
    get_db().commit()
    flash('Key deleted')
    return redirect(url_for('keys'))


@app.route('/keys/view/<int:key_id>')
@login_required
def view_key(key_id):
    row = get_db().execute('SELECT * FROM keys WHERE id = ? AND username = ?', (key_id, session['username'],)).fetchone()
    if not row:
        abort(404)
    p = KEYS_DIR / row['stored_name']
    if not p.exists():
        abort(404)
    data = p.read_bytes()
    if row['key_type'].endswith('Private') or row['key_type'].endswith('Public'):
        content = data.decode()
    else:
        content = base64.b64encode(data).decode()
    return render_template('view_key.html', key=row, content=content)


@app.route('/encrypt/symmetric', methods=['GET', 'POST'])
@login_required
def encrypt_symmetric():
    if request.method == 'GET':
        user_keys = get_db().execute('SELECT * FROM keys WHERE username = ? AND key_type IN (?, ?, ?, ?)',
                                     (session['username'], 'AES-128', 'AES-192', 'AES-256', '3DES')).fetchall()
        return render_template('encrypt_sym.html', keys=user_keys)
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('encrypt_symmetric'))
    f = request.files['file']
    if f.filename == '':
        flash('No file selected')
        return redirect(url_for('encrypt_symmetric'))
    algorithm = request.form.get('algorithm', '')
    key_size = int(request.form.get('key_size', '0'))
    mode = request.form.get('mode', '')
    iv_text = request.form.get('iv', '').strip()
    key_source = request.form.get('key_source', '')
    key_data = b''
    if key_source == 'file':
        if 'key_file' not in request.files or request.files['key_file'].filename == '':
            flash('Key file required')
            return redirect(url_for('encrypt_symmetric'))
        key_data = request.files['key_file'].read()
    else:
        key_text = request.form.get('key_text', '')
        if not key_text:
            flash('Key text required')
            return redirect(url_for('encrypt_symmetric'))
        key_data = key_text.encode()
    plaintext = f.read()
    try:
        if algorithm == 'AES':
            if key_size not in (16, 24, 32):
                flash('Invalid AES key size')
                return redirect(url_for('encrypt_symmetric'))
            if mode == 'CBC':
                iv = build_iv(iv_text, 16)
                key, salt = derive_or_use_key(key_data, key_size)
                padder = sym_padding.PKCS7(128).padder()
                padded = padder.update(plaintext) + padder.finalize()
                enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
                ct = enc.update(padded) + enc.finalize()
                iv_b64 = base64.b64encode(iv).decode()
                salt_b64 = base64.b64encode(salt).decode() if salt else None
                tag_b64 = None
            elif mode == 'GCM':
                iv = build_iv(iv_text, 12)
                key, salt = derive_or_use_key(key_data, key_size)
                enc = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
                ct = enc.update(plaintext) + enc.finalize()
                iv_b64 = base64.b64encode(iv).decode()
                salt_b64 = base64.b64encode(salt).decode() if salt else None
                tag_b64 = base64.b64encode(enc.tag).decode()
            else:
                flash('Invalid AES mode')
                return redirect(url_for('encrypt_symmetric'))
        elif algorithm == '3DES':
            if key_size != 24:
                flash('Invalid 3DES key size')
                return redirect(url_for('encrypt_symmetric'))
            if mode == 'CBC':
                iv = build_iv(iv_text, 8)
                key, salt = derive_or_use_key(key_data, 24)
                padder = sym_padding.PKCS7(64).padder()
                padded = padder.update(plaintext) + padder.finalize()
                enc = Cipher(TripleDES(key), modes.CBC(iv)).encryptor()
                ct = enc.update(padded) + enc.finalize()
                iv_b64 = base64.b64encode(iv).decode()
                salt_b64 = base64.b64encode(salt).decode() if salt else None
                tag_b64 = None
            elif mode == 'CFB':
                iv = build_iv(iv_text, 8)
                key, salt = derive_or_use_key(key_data, 24)
                enc = Cipher(TripleDES(key), decrepit_modes.CFB(iv)).encryptor()
                ct = enc.update(plaintext) + enc.finalize()
                iv_b64 = base64.b64encode(iv).decode()
                salt_b64 = base64.b64encode(salt).decode() if salt else None
                tag_b64 = None
            else:
                flash('Invalid 3DES mode')
                return redirect(url_for('encrypt_symmetric'))
        else:
            flash('Unknown algorithm')
            return redirect(url_for('encrypt_symmetric'))
    except Exception as e:
        flash('Encryption error: ' + str(e))
        return redirect(url_for('encrypt_symmetric'))
    out = {
        'algorithm': algorithm,
        'key_size': key_size,
        'mode': mode,
        'iv': iv_b64,
        'salt': salt_b64,
        'ciphertext': base64.b64encode(ct).decode(),
        'tag': tag_b64,
        'original_filename': f.filename
    }
    out_bytes = json.dumps(out, indent=2).encode()
    d = user_file_dir(session['username'])
    rel, name = save_file(d, f"{secure_filename(f.filename)}.enc", out_bytes)
    get_db().execute('INSERT INTO files (username, filename, stored_name, uploaded_at) VALUES (?, ?, ?, ?)',
                     (session['username'], name, rel, now()))
    get_db().commit()
    flash('File encrypted')
    return redirect(url_for('files'))


@app.route('/decrypt/symmetric', methods=['GET', 'POST'])
@login_required
def decrypt_symmetric():
    if request.method == 'GET':
        return render_template('decrypt_sym.html')
    if 'file' not in request.files or request.files['file'].filename == '':
        flash('No encrypted file selected')
        return redirect(url_for('decrypt_symmetric'))
    f = request.files['file']
    try:
        data = json.loads(f.read())
    except Exception:
        flash('Invalid encrypted file')
        return redirect(url_for('decrypt_symmetric'))
    algorithm = data['algorithm']
    key_size = data['key_size']
    mode = data['mode']
    iv = base64.b64decode(data['iv'])
    salt = base64.b64decode(data['salt']) if data.get('salt') else None
    ciphertext = base64.b64decode(data['ciphertext'])
    tag = base64.b64decode(data['tag']) if data.get('tag') else None
    original = data.get('original_filename', 'decrypted')
    key_source = request.form.get('key_source', '')
    key_data = b''
    if key_source == 'file':
        if 'key_file' not in request.files or request.files['key_file'].filename == '':
            flash('Key file required')
            return redirect(url_for('decrypt_symmetric'))
        key_data = request.files['key_file'].read()
    else:
        key_text = request.form.get('key_text', '')
        if not key_text:
            flash('Key text required')
            return redirect(url_for('decrypt_symmetric'))
        key_data = key_text.encode()
    try:
        key = make_key_for_decrypt(key_data, key_size, salt)
    except Exception as e:
        flash('Invalid key: ' + str(e))
        return redirect(url_for('decrypt_symmetric'))
    try:
        if algorithm == 'AES':
            if mode == 'CBC':
                dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
                pt = dec.update(ciphertext) + dec.finalize()
                unpadder = sym_padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(pt) + unpadder.finalize()
            elif mode == 'GCM':
                dec = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
                plaintext = dec.update(ciphertext) + dec.finalize()
            else:
                flash('Unsupported mode')
                return redirect(url_for('decrypt_symmetric'))
        elif algorithm == '3DES':
            if mode == 'CBC':
                dec = Cipher(TripleDES(key), modes.CBC(iv)).decryptor()
                pt = dec.update(ciphertext) + dec.finalize()
                unpadder = sym_padding.PKCS7(64).unpadder()
                plaintext = unpadder.update(pt) + unpadder.finalize()
            elif mode == 'CFB':
                dec = Cipher(TripleDES(key), decrepit_modes.CFB(iv)).decryptor()
                plaintext = dec.update(ciphertext) + dec.finalize()
            else:
                flash('Unsupported mode')
                return redirect(url_for('decrypt_symmetric'))
        else:
            flash('Unsupported algorithm')
            return redirect(url_for('decrypt_symmetric'))
    except Exception as e:
        flash('Decryption failed: ' + str(e))
        return redirect(url_for('decrypt_symmetric'))
    d = user_file_dir(session['username'])
    rel, name = save_file(d, original, plaintext)
    get_db().execute('INSERT INTO files (username, filename, stored_name, uploaded_at) VALUES (?, ?, ?, ?)',
                     (session['username'], name, rel, now()))
    get_db().commit()
    flash('File decrypted')
    return redirect(url_for('files'))


@app.route('/encrypt/asymmetric', methods=['GET', 'POST'])
@login_required
def encrypt_asymmetric():
    if request.method == 'GET':
        public_keys = get_db().execute("SELECT * FROM keys WHERE username = ? AND key_type = 'RSA-Public'", (session['username'],)).fetchall()
        return render_template('encrypt_asym.html', keys=public_keys)
    if 'file' not in request.files or request.files['file'].filename == '':
        flash('No file selected')
        return redirect(url_for('encrypt_asymmetric'))
    f = request.files['file']
    key_source = request.form.get('key_source', '')
    pub_data = b''
    if key_source == 'saved':
        key_id = request.form.get('key_id', '')
        if not key_id:
            flash('No public key selected')
            return redirect(url_for('encrypt_asymmetric'))
        row = get_db().execute('SELECT * FROM keys WHERE id = ? AND username = ? AND key_type = ?',
                               (key_id, session['username'], 'RSA-Public')).fetchone()
        if not row:
            flash('Public key not found')
            return redirect(url_for('encrypt_asymmetric'))
        pub_data = (KEYS_DIR / row['stored_name']).read_bytes()
    else:
        if 'public_key' not in request.files or request.files['public_key'].filename == '':
            flash('Public key file required')
            return redirect(url_for('encrypt_asymmetric'))
        pub_data = request.files['public_key'].read()
    try:
        public_key = serialization.load_pem_public_key(pub_data)
    except Exception:
        flash('Invalid public key')
        return redirect(url_for('encrypt_asymmetric'))
    plaintext = f.read()
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    enc = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    tag = enc.tag
    encrypted_key = public_key.encrypt(aes_key, asym_padding.OAEP(asym_padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    out = {
        'algorithm': 'RSA-AES-GCM',
        'encrypted_key': base64.b64encode(encrypted_key).decode(),
        'iv': base64.b64encode(iv).decode(),
        'tag': base64.b64encode(tag).decode(),
        'ciphertext': base64.b64encode(ct).decode(),
        'original_filename': f.filename
    }
    out_bytes = json.dumps(out, indent=2).encode()
    d = user_file_dir(session['username'])
    rel, name = save_file(d, f"{secure_filename(f.filename)}.rsa", out_bytes)
    get_db().execute('INSERT INTO files (username, filename, stored_name, uploaded_at) VALUES (?, ?, ?, ?)',
                     (session['username'], name, rel, now()))
    get_db().commit()
    flash('File encrypted')
    return redirect(url_for('files'))


@app.route('/decrypt/asymmetric', methods=['GET', 'POST'])
@login_required
def decrypt_asymmetric():
    if request.method == 'GET':
        private_keys = get_db().execute("SELECT * FROM keys WHERE username = ? AND key_type = 'RSA-Private'", (session['username'],)).fetchall()
        return render_template('decrypt_asym.html', keys=private_keys)
    if 'file' not in request.files or request.files['file'].filename == '':
        flash('No file selected')
        return redirect(url_for('decrypt_asymmetric'))
    f = request.files['file']
    try:
        data = json.loads(f.read())
    except Exception:
        flash('Invalid encrypted file')
        return redirect(url_for('decrypt_asymmetric'))
    key_source = request.form.get('key_source', '')
    priv_data = b''
    if key_source == 'saved':
        key_id = request.form.get('key_id', '')
        if not key_id:
            flash('No private key selected')
            return redirect(url_for('decrypt_asymmetric'))
        row = get_db().execute('SELECT * FROM keys WHERE id = ? AND username = ? AND key_type = ?',
                               (key_id, session['username'], 'RSA-Private')).fetchone()
        if not row:
            flash('Private key not found')
            return redirect(url_for('decrypt_asymmetric'))
        priv_data = (KEYS_DIR / row['stored_name']).read_bytes()
    else:
        if 'private_key' not in request.files or request.files['private_key'].filename == '':
            flash('Private key file required')
            return redirect(url_for('decrypt_asymmetric'))
        priv_data = request.files['private_key'].read()
    try:
        private_key = serialization.load_pem_private_key(priv_data, password=None)
    except Exception:
        flash('Invalid private key')
        return redirect(url_for('decrypt_asymmetric'))
    try:
        encrypted_key = base64.b64decode(data['encrypted_key'])
        iv = base64.b64decode(data['iv'])
        tag = base64.b64decode(data['tag'])
        ct = base64.b64decode(data['ciphertext'])
        aes_key = private_key.decrypt(encrypted_key, asym_padding.OAEP(asym_padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
        dec = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag)).decryptor()
        plaintext = dec.update(ct) + dec.finalize()
    except Exception:
        flash('Decryption failed')
        return redirect(url_for('decrypt_asymmetric'))
    d = user_file_dir(session['username'])
    rel, name = save_file(d, data.get('original_filename', 'decrypted'), plaintext)
    get_db().execute('INSERT INTO files (username, filename, stored_name, uploaded_at) VALUES (?, ?, ?, ?)',
                     (session['username'], name, rel, now()))
    get_db().commit()
    flash('File decrypted')
    return redirect(url_for('files'))


@app.route('/hash', methods=['GET', 'POST'])
@login_required
def hash_file():
    if request.method == 'GET':
        return render_template('hash.html')
    if 'file' not in request.files or request.files['file'].filename == '':
        flash('No file selected')
        return redirect(url_for('hash_file'))
    f = request.files['file']
    data = f.read()
    sha2 = hashlib.sha256(data).hexdigest()
    sha3 = hashlib.sha3_256(data).hexdigest()
    return render_template('hash.html', sha2=sha2, sha3=sha3, filename=f.filename)


@app.route('/hash/compare', methods=['GET', 'POST'])
@login_required
def hash_compare():
    if request.method == 'GET':
        return render_template('hash_compare.html')
    method = request.form.get('method', 'sha256')
    compare_hash = request.form.get('hash', '').strip().lower()
    file_hash = ''
    if 'file' in request.files and request.files['file'].filename:
        f = request.files['file']
        data = f.read()
        if method == 'sha256':
            file_hash = hashlib.sha256(data).hexdigest()
        else:
            file_hash = hashlib.sha3_256(data).hexdigest()
    else:
        file_hash = request.form.get('file_hash', '').strip().lower()
    match = hmac.compare_digest(file_hash, compare_hash) if file_hash and compare_hash else False
    return render_template('hash_compare.html', file_hash=file_hash, compare_hash=compare_hash, match=match, method=method)


@app.route('/password', methods=['GET', 'POST'])
@login_required
def password():
    generated = None
    if request.method == 'POST':
        try:
            length = int(request.form.get('length', '16'))
        except ValueError:
            flash('Invalid length')
            return redirect(url_for('password'))
        if length < 1 or length > 63:
            flash('Length must be between 1 and 63')
            return redirect(url_for('password'))
        upper = 'upper' in request.form
        lower = 'lower' in request.form
        digits = 'digits' in request.form
        special = 'special' in request.form
        generated = generate_password(length, upper, lower, digits, special)
    return render_template('password.html', password=generated)


@app.route('/share', methods=['GET', 'POST'])
@login_required
def share():
    if request.method == 'GET':
        private_keys = get_db().execute("SELECT * FROM keys WHERE username = ? AND key_type = 'ECDH-Private'", (session['username'],)).fetchall()
        return render_template('share.html', keys=private_keys)
    key_id = request.form.get('key_id', '')
    if not key_id:
        flash('Select your private key')
        return redirect(url_for('share'))
    row = get_db().execute('SELECT * FROM keys WHERE id = ? AND username = ? AND key_type = ?',
                           (key_id, session['username'], 'ECDH-Private')).fetchone()
    if not row:
        flash('Private key not found')
        return redirect(url_for('share'))
    if 'public_key' not in request.files or request.files['public_key'].filename == '':
        flash('Peer public key required')
        return redirect(url_for('share'))
    pub_data = request.files['public_key'].read()
    priv_data = (KEYS_DIR / row['stored_name']).read_bytes()
    try:
        private_key = serialization.load_pem_private_key(priv_data, password=None)
        public_key = serialization.load_pem_public_key(pub_data)
        shared = private_key.exchange(ec.ECDH(), public_key)
        derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'shared').derive(shared)
    except Exception as e:
        flash('Key exchange failed: ' + str(e))
        return redirect(url_for('share'))
    d = user_key_dir(session['username'])
    rel, name = save_key(d, f"shared_{row['name']}.key", derived)
    get_db().execute('INSERT INTO keys (username, name, key_type, stored_name, created_at) VALUES (?, ?, ?, ?, ?)',
                     (session['username'], f"shared-{row['name']}", 'AES-256-Shared', rel, now()))
    get_db().commit()
    flash('Shared key derived and saved')
    return redirect(url_for('keys'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
