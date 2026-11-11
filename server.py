"""119안심콜 QR 홍보 통계. 시민 식별정보를 통계 DB에 저장하지 않음."""
import os, json, sqlite3, hashlib, hmac, secrets, time, threading
from pathlib import Path
from datetime import datetime, timezone, timedelta
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlsplit, parse_qs, urlencode
import base64
ROOT=Path(__file__).resolve().parent
DB=Path(os.environ.get('COUNTER_DB',str(ROOT/'stats.sqlite3')))
TARGET='https://u119.nfa.go.kr/'
KST=timezone(timedelta(hours=9))
LOCK=threading.Lock()
FAILURES=[] # 실패 시각만 메모리에 저장, IP 미저장
QR_SECRET=secrets.token_bytes(32)
def make_ticket():
    payload=f'{int(time.time())}:{secrets.token_hex(12)}'
    sig=hmac.new(QR_SECRET,payload.encode(),hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode((payload+':'+sig).encode()).decode().rstrip('=')
def ticket_ok(ticket):
    try:
        if len(ticket)>256:return False
        raw=base64.urlsafe_b64decode(ticket+'='*((-len(ticket))%4)).decode()
        timestamp,nonce,sig=raw.split(':')
        if not (timestamp.isdigit() and len(nonce)==24):return False
        if abs(time.time()-int(timestamp))>1800:return False
        expected=hmac.new(QR_SECRET,(timestamp+':'+nonce).encode(),hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected,sig)
    except (ValueError,UnicodeError,TypeError):return False


def db():
    DB.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    c=sqlite3.connect(DB,timeout=15)
    os.chmod(DB,0o600)
    c.execute('CREATE TABLE IF NOT EXISTS daily (day TEXT PRIMARY KEY, visits INTEGER NOT NULL DEFAULT 0, clicks INTEGER NOT NULL DEFAULT 0)')
    c.execute('CREATE TABLE IF NOT EXISTS admin_auth (id INTEGER PRIMARY KEY CHECK(id=1), salt BLOB NOT NULL, digest BLOB NOT NULL)')
    return c

def digest(p,s):return hashlib.pbkdf2_hmac('sha256',p.encode('utf-8'),s,260000)
def initialize():
    with db() as c:
        if not c.execute('SELECT 1 FROM admin_auth WHERE id=1').fetchone():
            initial=os.environ.get('ADMIN_TOKEN')
            if not initial or len(initial)<24:raise RuntimeError('ADMIN_TOKEN must be set to at least 24 characters')
            salt=secrets.token_bytes(16)
            c.execute('INSERT INTO admin_auth VALUES(1,?,?)',(salt,digest(initial,salt)))
            print('Administrator password initialized securely.',flush=True)

def auth(p):
    now=time.monotonic()
    with LOCK:
        FAILURES[:]=[t for t in FAILURES if now-t<300]
        if len(FAILURES)>=20:return False
    with db() as c: row=c.execute('SELECT salt,digest FROM admin_auth WHERE id=1').fetchone()
    good=bool(row and isinstance(p,str) and hmac.compare_digest(digest(p,row[0]),row[1]))
    if len(p)>128:return False
    if not good:
        with LOCK:FAILURES.append(now)
    return good

def increment(column):
    day=datetime.now(KST).date().isoformat()
    with db() as c:
        c.execute('INSERT OR IGNORE INTO daily(day) VALUES(?)',(day,))
        c.execute('UPDATE daily SET '+column+'='+column+'+1 WHERE day=?',(day,))

class Handler(SimpleHTTPRequestHandler):
    def __init__(self,*args,**kwargs):super().__init__(*args,directory=str(ROOT),**kwargs)
    # HTTP 요청 로그는 IP/요청주소를 포함할 수 있으므로 이 프로그램에서는 기록하지 않음.
    def log_message(self,format,*args):pass
    def end_headers(self):
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Content-Security-Policy',"default-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.send_header('Cache-Control','no-store')
        self.send_header('Permissions-Policy','camera=(), microphone=(), geolocation=()')
        super().end_headers()
    def json(self,status,data):
        b=json.dumps(data,ensure_ascii=False).encode('utf-8')
        self.send_response(status);self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
    def redirect(self,location):
        self.send_response(302);self.send_header('Location',location);self.send_header('Content-Length','0');self.end_headers()
    def do_HEAD(self):
        # Never delegate HEAD to the unrestricted filesystem handler.
        self.send_response(405);self.send_header('Content-Length','0');self.end_headers()
    def do_GET(self):
        parsed=urlsplit(self.path);path=parsed.path
        if path=='/healthz':
            with db() as c:c.execute('SELECT 1').fetchone()
            return self.json(200,{'status':'ok'})
        if path=='/qr':
            increment('visits');return self.redirect('/index.html?'+urlencode({'ticket':make_ticket()}))
        if path=='/go':
            if ticket_ok(parse_qs(parsed.query).get('ticket',[''])[0]):increment('clicks')
            return self.redirect(TARGET)
        if path=='/api/stats':
            if not auth(self.headers.get('X-Admin-Token','')):return self.json(403,{'error':'관리자 인증 실패 또는 일시적 접근 제한'})
            today=datetime.now(KST).date().isoformat()
            with db() as c:
                totals=c.execute('SELECT COALESCE(SUM(visits),0),COALESCE(SUM(clicks),0) FROM daily').fetchone()
                current=c.execute('SELECT visits,clicks FROM daily WHERE day=?',(today,)).fetchone() or (0,0)
            return self.json(200,dict(visits=totals[0],clicks=totals[1],today_visits=current[0],today_clicks=current[1]))
        if path=='/':self.path='/index.html'
        elif path not in ('/index.html','/admin.html','/static/guide.png'):
            return self.json(404,{'error':'Not found'})
        else:self.path=path
        return super().do_GET()
    def do_POST(self):
        if urlsplit(self.path).path!='/api/admin/change-password':return self.json(404,{'error':'Not found'})
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=4096:return self.json(400,{'error':'잘못된 요청 크기'})
            body=json.loads(self.rfile.read(length))
            old,new=body.get('current_password'),body.get('new_password')
            if not isinstance(old,str) or not isinstance(new,str):return self.json(400,{'error':'잘못된 형식'})
            if not auth(old):return self.json(403,{'error':'현재 비밀번호가 올바르지 않습니다.'})
            if not 12<=len(new)<=128 or new==old:return self.json(400,{'error':'새 비밀번호는 12~128자이고 기존과 달라야 합니다.'})
            salt=secrets.token_bytes(16)
            with db() as c:c.execute('UPDATE admin_auth SET salt=?,digest=? WHERE id=1',(salt,digest(new,salt)))
            return self.json(200,{'message':'비밀번호 변경 완료'})
        except (ValueError,TypeError,json.JSONDecodeError):return self.json(400,{'error':'잘못된 요청'})

if __name__=='__main__':
    initialize()
    port=int(os.environ.get('PORT','8000'))
    # 기본은 로컬에서만 접속. 기관 공개 배포는 보안 담당자가 HTTPS 프록시 뒤에 연결.
    host=os.environ.get('BIND_HOST','0.0.0.0')
    print('119 service ready',flush=True)
    ThreadingHTTPServer((host,port),Handler).serve_forever()
