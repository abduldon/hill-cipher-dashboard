import os, json, math
from datetime import datetime
from functools import wraps
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-secret-key-before-deployment')
database_url = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(BASE_DIR, 'database.db'))
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class Operation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    operation_type = db.Column(db.String(20), nullable=False)
    input_text = db.Column(db.Text, nullable=False)
    key = db.Column(db.String(500), nullable=False)
    result = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user = db.relationship('User', backref=db.backref('operations', lazy=True, cascade='all, delete-orphan'))


def parse_matrix(raw, size):
    """Accept rows separated by semicolons/newlines and entries by commas/spaces."""
    try:
        rows = [r.strip() for r in raw.replace('\n', ';').split(';') if r.strip()]
        matrix = [[int(x.strip()) % 26 for x in row.replace(',', ' ').split()] for row in rows]
    except (ValueError, AttributeError):
        raise ValueError('Enter integers in the key matrix, separated by commas; separate rows with semicolons.')
    if len(matrix) != size or any(len(row) != size for row in matrix):
        raise ValueError(f'For a {size}×{size} cipher, enter exactly {size} rows with {size} integers per row.')
    return matrix


def determinant(m):
    n = len(m)
    if n == 2:
        return m[0][0]*m[1][1] - m[0][1]*m[1][0]
    a,b,c = m[0]; d,e,f = m[1]; g,h,i = m[2]
    return a*(e*i-f*h) - b*(d*i-f*g) + c*(d*h-e*g)


def mod_inverse(a, modulus=26):
    a %= modulus
    for x in range(1, modulus):
        if (a*x) % modulus == 1:
            return x
    raise ValueError(f'The matrix determinant ({a}) has no multiplicative inverse modulo 26. Choose a different key matrix whose determinant is coprime to 26.')


def matrix_inverse_mod26(m):
    n = len(m); det = determinant(m) % 26; inv_det = mod_inverse(det)
    if n == 2:
        adj = [[m[1][1], -m[0][1]], [-m[1][0], m[0][0]]]
    else:
        # Adjugate is the transpose of the cofactor matrix.
        cof = []
        for r in range(3):
            row=[]
            for c in range(3):
                minor=[[m[i][j] for j in range(3) if j != c] for i in range(3) if i != r]
                value=minor[0][0]*minor[1][1]-minor[0][1]*minor[1][0]
                row.append(((-1)**(r+c))*value)
            cof.append(row)
        adj = [[cof[c][r] for c in range(3)] for r in range(3)]
    return [[(inv_det*adj[r][c]) % 26 for c in range(n)] for r in range(n)], det, inv_det


def hill_cipher(text, matrix, decrypt=False):
    n=len(matrix)
    inv_matrix, det, inv_det = matrix_inverse_mod26(matrix) if decrypt else (None, determinant(matrix)%26, None)
    active = [i for i,ch in enumerate(text) if ch.isascii() and ch.isalpha()]
    letters = [text[i].upper() for i in active]
    padded = 0
    if not decrypt:
        padded = (-len(letters)) % n
        letters += ['X'] * padded
    elif len(letters) % n:
        raise ValueError(f'Ciphertext must contain a multiple of {n} alphabetic characters for {n}×{n} decryption. Check the ciphertext and matrix size.')
    working_matrix = inv_matrix if decrypt else matrix
    output_letters=[]; steps=[]
    for start in range(0, len(letters), n):
        block=letters[start:start+n]
        vals=[ord(ch)-65 for ch in block]
        result_vals=[sum(working_matrix[r][c]*vals[c] for c in range(n)) % 26 for r in range(n)]
        result_block=[chr(v+65) for v in result_vals]
        output_letters.extend(result_block)
        steps.append({'position': start//n+1, 'input_block': ''.join(block), 'input_values': vals,
                      'matrix': working_matrix, 'raw_sums': [sum(working_matrix[r][c]*vals[c] for c in range(n)) for r in range(n)],
                      'result_values': result_vals, 'result_block': ''.join(result_block),
                      'formula': 'C = K × P (mod 26)' if not decrypt else 'P = K⁻¹ × C (mod 26)'})
    # Preserve nonletters in their original positions; any padding is appended at the end.
    chars=list(text)
    for index, ch in zip(active, output_letters[:len(active)]):
        chars[index] = ch if text[index].isupper() else ch.lower()
    result=''.join(chars)
    if padded:
        result += ''.join(output_letters[len(active):])
    return result, steps, {'size':n, 'determinant_mod26':det, 'determinant_inverse':inv_det, 'inverse_matrix':inv_matrix, 'padding_added':padded}


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapper

@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        user=User.query.filter_by(username=request.form.get('username','').strip()).first()
        if user and check_password_hash(user.password_hash, request.form.get('password','')):
            session.clear(); session['user_id']=user.id; session['username']=user.username
            return redirect(request.args.get('next') or url_for('dashboard'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/api/operate', methods=['POST'])
@login_required
def operate():
    data=request.get_json(silent=True) or request.form
    text=(data.get('message') or '').strip('\n')
    mode=(data.get('mode') or 'encrypt').lower()
    try: size=int(data.get('matrix_size', 2))
    except (ValueError, TypeError): size=0
    raw_matrix=data.get('key_matrix') or ''
    if not text.strip(): return jsonify(error='Please enter a message.'),400
    if size not in (2,3): return jsonify(error='Choose a 2×2 or 3×3 matrix.'),400
    if mode not in ('encrypt','decrypt'): return jsonify(error='Choose encryption or decryption.'),400
    try:
        matrix=parse_matrix(raw_matrix,size)
        det=determinant(matrix)%26
        if math.gcd(det,26)!=1:
            raise ValueError(f'This key matrix is not invertible modulo 26: determinant ≡ {det} (mod 26), and gcd({det}, 26) ≠ 1. Choose a matrix whose determinant is coprime to 26.')
        result, steps, meta=hill_cipher(text,matrix,mode=='decrypt')
    except ValueError as e: return jsonify(error=str(e)),400
    key_json=json.dumps({'size':size,'matrix':matrix}, separators=(',',':'))
    op=Operation(user_id=session['user_id'],operation_type=mode.title(),input_text=text,key=key_json,result=result)
    db.session.add(op); db.session.commit()
    return jsonify(result=result,steps=steps,metadata=meta,operation_id=op.id,stats=stats_for(session['user_id']))

def stats_for(user_id):
    ops=Operation.query.filter_by(user_id=user_id).all()
    encrypted=sum(o.operation_type=='Encrypt' for o in ops); decrypted=sum(o.operation_type=='Decrypt' for o in ops)
    sizes=[]
    for o in ops:
        try: sizes.append(json.loads(o.key).get('size',2))
        except Exception: sizes.append(2)
    return {'total':len(ops),'encrypted':encrypted,'decrypted':decrypted,'avg_key_length':round(sum(sizes)/len(sizes),1) if sizes else 0, 'avg_matrix_size':round(sum(sizes)/len(sizes),1) if sizes else 0}

@app.route('/api/statistics')
@login_required
def api_statistics(): return jsonify(stats_for(session['user_id']))

@app.route('/history')
@login_required
def history():
    ops=Operation.query.filter_by(user_id=session['user_id']).order_by(Operation.created_at.desc()).all()
    return render_template('history.html',operations=ops)

@app.route('/history/<int:operation_id>')
@login_required
def view_operation(operation_id):
    op=Operation.query.filter_by(id=operation_id,user_id=session['user_id']).first_or_404()
    return jsonify(id=op.id,operation_type=op.operation_type,input_text=op.input_text,key=op.key,result=op.result,created_at=op.created_at.strftime('%Y-%m-%d %H:%M UTC'))

@app.route('/history/delete/<int:operation_id>',methods=['POST'])
@login_required
def delete_operation(operation_id):
    op=Operation.query.filter_by(id=operation_id,user_id=session['user_id']).first_or_404(); db.session.delete(op); db.session.commit(); flash('Operation deleted.','success'); return redirect(url_for('history'))

@app.route('/how-it-works')
@login_required
def how_it_works(): return render_template('how_it_works.html')

@app.route('/download',methods=['POST'])
@login_required
def download_result():
    payload=BytesIO(request.form.get('result','').encode('utf-8')); payload.seek(0)
    return send_file(payload,as_attachment=True,download_name='hill_cipher_result.txt',mimetype='text/plain')

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        db.session.add(User(username='admin',password_hash=generate_password_hash(os.environ.get('ADMIN_PASSWORD','admin123')))); db.session.commit()

if __name__=='__main__': app.run(debug=os.environ.get('FLASK_DEBUG')=='1',host='0.0.0.0',port=int(os.environ.get('PORT',5000)))
