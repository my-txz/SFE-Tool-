import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
import threading
import os
import sys
import time
import shutil
import platform
import hashlib
import json
from datetime import datetime
import base64
import secrets
import concurrent.futures
from functools import partial

from bottle import Bottle, run, request, response, template, redirect

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as cpadding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

try:
    from Crypto.Cipher import DES, Blowfish, ARC2, AES as PyAes, ChaCha20, Camellia, CAST
    from Crypto.Cipher import Salsa20
    HAVE_CAMELLIA = True
    HAVE_BLOWFISH = True
    HAVE_ARC2 = True
    HAVE_CAST = True
    HAVE_SALSA20 = True
except ImportError:
    HAVE_CAMELLIA = HAVE_BLOWFISH = HAVE_ARC2 = HAVE_CAST = HAVE_SALSA20 = False

USERS_FILE = "web_users.json"
VERIF_FILE = "web_verif.json"
LOGS_DIR = "user_logs"
if not os.path.isdir(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)

web_app = Bottle()
SESSION = {}
VERIFCODES = {}  # {username: {"verify_code": ..., "token": ..., "expire": ...}}

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def hash_pwd(pwd, salt):
    # 强密码检查
    if len(pwd) < 8 or pwd.isdigit() or pwd.isalpha() or pwd.lower() == pwd or pwd.upper() == pwd:
        return ""
    return hashlib.sha256((pwd + salt).encode("utf-8")).hexdigest()

def save_verifcodes():
    with open(VERIF_FILE, "w", encoding="utf-8") as f:
        json.dump(VERIFCODES, f, ensure_ascii=False, indent=2)

def load_verifcodes():
    global VERIFCODES
    if os.path.exists(VERIF_FILE):
        with open(VERIF_FILE, "r", encoding="utf-8") as f:
            VERIFCODES = json.load(f)

def gen_verify_token():
    return secrets.token_hex(16)

def gen_verify_code():
    return str(secrets.randbelow(900000) + 100000)

def password_strength(pwd):
    score = 0
    if len(pwd) >= 8: score += 1
    if any(c.islower() for c in pwd): score += 1
    if any(c.isupper() for c in pwd): score += 1
    if any(c.isdigit() for c in pwd): score += 1
    if any(c in "!@#$%^&*()-_=+[{]};:'\",<.>/?\\|" for c in pwd): score += 1
    return score

def safe_username(un):
    return all(c.isalnum() or c in "_-." for c in un) and (3 <= len(un) <= 24)

@web_app.route('/')
def home():
    return template('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>注册/登录</title>
        <style>
            body { font-family: '微软雅黑'; background: #e0eafc; }
            .box { width: 370px; margin: 100px auto; padding: 40px; background: #fff; border-radius: 16px; box-shadow: 0 8px 24px #b2bec3; }
            .btn { margin-top: 12px; background: #0984e3; color: #fff; border: none; padding: 10px 28px; border-radius: 6px; font-size: 16px; cursor:pointer; }
            .btn:hover { background: #fdcb6e; color: #2d3436; }
            input { width: 96%; padding: 8px; margin-bottom: 14px; border-radius: 6px; border: 1px solid #b2bec3; }
            .warn { color: #d35400; font-size: 13px; }
        </style>
        <script>
        function checkReg() {
          var u = document.getElementById('regu').value;
          var p = document.getElementById('regp').value;
          if(u.length < 3) { alert('用户名太短'); return false;}
          if(p.length < 8) { alert('密码太短'); return false;}
          return true;
        }
        </script>
    </head>
    <body>
        <div class="box">
        <h2>Found - Encryptor 账号登录</h2>
        <form action="/login" method="post" autocomplete="off">
            用户名: <input name="username" required autocomplete="off">
            密码: <input name="password" type="password" required autocomplete="off">
            <button class="btn" type="submit">登录</button>
        </form>
        <hr>
        <h3>注册新用户</h3>
        <form action="/register" method="post" autocomplete="off" onsubmit="return checkReg();">
            用户名: <input id="regu" name="username" required autocomplete="off">
            <span class="warn">3-24位，仅限字母数字下划线等</span>
            密码: <input id="regp" name="password" type="password" required autocomplete="off">
            <span class="warn">8位以上，含数字、大小写字母/符号</span>
            <button class="btn" type="submit">注册</button>
        </form>
        </div>
    </body>
    </html>
    ''')

@web_app.route('/login', method="POST")
def do_login():
    users = load_users()
    username = request.forms.get("username").strip()
    password = request.forms.get("password")
    if not safe_username(username):
        return "<script>alert('用户名不合法');window.location='/';</script>"
    if username not in users:
        return "<script>alert('账号不存在');window.location='/';</script>"
    salt = users[username]['salt']
    hp = hash_pwd(password, salt)
    if hp != users[username]['password']:
        return "<script>alert('密码错误或密码强度不足');window.location='/';</script>"
    verify_code = gen_verify_code()
    token = gen_verify_token()
    VERIFCODES[username] = {
        "verify_code": verify_code,
        "token": token,
        "expire": time.time() + 600  # 10分钟
    }
    save_verifcodes()
    return template('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>校验码与凭证码</title>
        <style>
            body { font-family: '微软雅黑'; background: #e0eafc; }
            .box { width: 400px; margin: 100px auto; padding: 40px; background: #fff; border-radius: 16px; box-shadow: 0 8px 24px #b2bec3; }
            .code { font-size: 20px; color: #d35400; }
        </style>
    </head>
    <body>
        <div class="box">
        <h3>登录成功，请在客户端输入以下校验码和凭证码</h3>
        <div>用户名: <b>{{username}}</b></div>
        <div>校验码: <span class="code">{{verify_code}}</span></div>
        <div>凭证码: <span class="code">{{token}}</span></div>
        <div style="margin-top:16px;color:#888">有效期10分钟</div>
        </div>
    </body>
    </html>
    ''', username=username, verify_code=verify_code, token=token)

@web_app.route('/register', method="POST")
def do_register():
    users = load_users()
    username = request.forms.get("username").strip()
    password = request.forms.get("password")
    if not safe_username(username):
        return "<script>alert('用户名仅限字母数字下划线等3-24位');window.location='/';</script>"
    if len(password) < 8 or password_strength(password) < 4:
        return "<script>alert('密码必须8位以上且包含大小写字母数字/符号');window.location='/';</script>"
    if username in users:
        return "<script>alert('账号已存在');window.location='/';</script>"
    salt = secrets.token_hex(8)
    h = hash_pwd(password, salt)
    if not h:
        return "<script>alert('密码强度不足');window.location='/';</script>"
    users[username] = {'password': h, 'salt': salt}
    save_users(users)
    udir = os.path.join(LOGS_DIR, username)
    if not os.path.exists(udir):
        os.makedirs(udir, exist_ok=True)
    verify_code = gen_verify_code()
    token = gen_verify_token()
    VERIFCODES[username] = {
        "verify_code": verify_code,
        "token": token,
        "expire": time.time() + 600
    }
    save_verifcodes()
    return template('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>注册成功</title>
        <style>
            body { font-family: '微软雅黑'; background: #e0eafc; }
            .box { width: 400px; margin: 100px auto; padding: 40px; background: #fff; border-radius: 16px; box-shadow: 0 8px 24px #b2bec3; }
            .code { font-size: 20px; color: #0984e3; }
        </style>
    </head>
    <body>
        <div class="box">
        <h3>注册成功，请在客户端输入以下校验码和凭证码</h3>
        <div>用户名: <b>{{username}}</b></div>
        <div>校验码: <span class="code">{{verify_code}}</span></div>
        <div>凭证码: <span class="code">{{token}}</span></div>
        <div style="margin-top:16px;color:#888">有效期10分钟</div>
        </div>
    </body>
    </html>
    ''', username=username, verify_code=verify_code, token=token)

def start_web():
    load_verifcodes()
    threading.Thread(target=lambda: run(web_app, host="127.0.0.1", port=8799, quiet=True), daemon=True).start()

def verify_login(username, verify_code, token):
    load_verifcodes()
    data = VERIFCODES.get(username)
    if not data:
        return False, "未找到校验码"
    if data["verify_code"] != verify_code:
        return False, "校验码错误"
    if data["token"] != token:
        return False, "凭证码错误"
    if time.time() > data["expire"]:
        return False, "校验码已过期"
    return True, "校验通过"

# ================= 加密算法/文件操作模块 =================
class CryptoEngine:
    @staticmethod
    def derive_key(password: str, salt: bytes, length: int):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=100_000, backend=default_backend())
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_aes(data: bytes, password: str):
        salt = secrets.token_bytes(16)
        key = CryptoEngine.derive_key(password, salt, 32)
        iv = secrets.token_bytes(16)
        padder = cpadding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return b"AES" + salt + iv + ct

    @staticmethod
    def decrypt_aes(data: bytes, password: str):
        assert data[:3] == b"AES"
        salt = data[3:19]
        iv = data[19:35]
        ct = data[35:]
        key = CryptoEngine.derive_key(password, salt, 32)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = cpadding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    @staticmethod
    def encrypt_des(data: bytes, password: str):
        salt = secrets.token_bytes(8)
        key = CryptoEngine.derive_key(password, salt, 8)
        iv = secrets.token_bytes(8)
        pad_len = 8 - len(data) % 8
        padded_data = data + bytes([pad_len] * pad_len)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        ct = cipher.encrypt(padded_data)
        return b"DES" + salt + iv + ct

    @staticmethod
    def decrypt_des(data: bytes, password: str):
        assert data[:3] == b"DES"
        salt = data[3:11]
        iv = data[11:19]
        ct = data[19:]
        key = CryptoEngine.derive_key(password, salt, 8)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_data = cipher.decrypt(ct)
        pad_len = padded_data[-1]
        return padded_data[:-pad_len]

    @staticmethod
    def encrypt_chacha(data: bytes, password: str):
        salt = secrets.token_bytes(16)
        key = CryptoEngine.derive_key(password, salt, 32)
        nonce = secrets.token_bytes(16)
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data)
        return b"CHC" + salt + nonce + ct

    @staticmethod
    def decrypt_chacha(data: bytes, password: str):
        assert data[:3] == b"CHC"
        salt = data[3:19]
        nonce = data[19:35]
        ct = data[35:]
        key = CryptoEngine.derive_key(password, salt, 32)
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ct)

    @staticmethod
    def encrypt_camellia(data: bytes, password: str):
        if not HAVE_CAMELLIA:
            raise RuntimeError("Camellia算法需要安装pycryptodome")
        salt = secrets.token_bytes(16)
        key = CryptoEngine.derive_key(password, salt, 32)
        iv = secrets.token_bytes(16)
        pad_len = 16 - len(data) % 16
        padded_data = data + bytes([pad_len] * pad_len)
        cipher = Camellia.new(key, Camellia.MODE_CBC, iv)
        ct = cipher.encrypt(padded_data)
        return b"CAM" + salt + iv + ct

    @staticmethod
    def decrypt_camellia(data: bytes, password: str):
        assert data[:3] == b"CAM"
        salt = data[3:19]
        iv = data[19:35]
        ct = data[35:]
        key = CryptoEngine.derive_key(password, salt, 32)
        cipher = Camellia.new(key, Camellia.MODE_CBC, iv)
        padded_data = cipher.decrypt(ct)
        pad_len = padded_data[-1]
        return padded_data[:-pad_len]

    @staticmethod
    def encrypt_blowfish(data: bytes, password: str):
        if not HAVE_BLOWFISH:
            raise RuntimeError("Blowfish算法需要安装pycryptodome")
        salt = secrets.token_bytes(8)
        key = CryptoEngine.derive_key(password, salt, 16)
        iv = secrets.token_bytes(8)
        pad_len = 8 - len(data) % 8
        padded_data = data + bytes([pad_len] * pad_len)
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        ct = cipher.encrypt(padded_data)
        return b"BLF" + salt + iv + ct

    @staticmethod
    def decrypt_blowfish(data: bytes, password: str):
        assert data[:3] == b"BLF"
        salt = data[3:11]
        iv = data[11:19]
        ct = data[19:]
        key = CryptoEngine.derive_key(password, salt, 16)
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        padded_data = cipher.decrypt(ct)
        pad_len = padded_data[-1]
        return padded_data[:-pad_len]

    @staticmethod
    def encrypt_arc2(data: bytes, password: str):
        if not HAVE_ARC2:
            raise RuntimeError("ARC2算法需要安装pycryptodome")
        salt = secrets.token_bytes(8)
        key = CryptoEngine.derive_key(password, salt, 16)
        iv = secrets.token_bytes(8)
        pad_len = 8 - len(data) % 8
        padded_data = data + bytes([pad_len] * pad_len)
        cipher = ARC2.new(key, ARC2.MODE_CBC, iv)
        ct = cipher.encrypt(padded_data)
        return b"RC2" + salt + iv + ct

    @staticmethod
    def decrypt_arc2(data: bytes, password: str):
        assert data[:3] == b"RC2"
        salt = data[3:11]
        iv = data[11:19]
        ct = data[19:]
        key = CryptoEngine.derive_key(password, salt, 16)
        cipher = ARC2.new(key, ARC2.MODE_CBC, iv)
        padded_data = cipher.decrypt(ct)
        pad_len = padded_data[-1]
        return padded_data[:-pad_len]

    @staticmethod
    def encrypt_cast(data: bytes, password: str):
        if not HAVE_CAST:
            raise RuntimeError("CAST算法需要安装pycryptodome")
        salt = secrets.token_bytes(8)
        key = CryptoEngine.derive_key(password, salt, 16)
        iv = secrets.token_bytes(8)
        pad_len = 8 - len(data) % 8
        padded_data = data + bytes([pad_len] * pad_len)
        cipher = CAST.new(key, CAST.MODE_CBC, iv)
        ct = cipher.encrypt(padded_data)
        return b"CST" + salt + iv + ct

    @staticmethod
    def decrypt_cast(data: bytes, password: str):
        assert data[:3] == b"CST"
        salt = data[3:11]
        iv = data[11:19]
        ct = data[19:]
        key = CryptoEngine.derive_key(password, salt, 16)
        cipher = CAST.new(key, CAST.MODE_CBC, iv)
        padded_data = cipher.decrypt(ct)
        pad_len = padded_data[-1]
        return padded_data[:-pad_len]

    @staticmethod
    def encrypt_salsa20(data: bytes, password: str):
        if not HAVE_SALSA20:
            raise RuntimeError("Salsa20算法需要安装pycryptodome")
        salt = secrets.token_bytes(8)
        key = CryptoEngine.derive_key(password, salt, 32)
        nonce = secrets.token_bytes(8)
        cipher = Salsa20.new(key=key, nonce=nonce)
        ct = cipher.encrypt(data)
        return b"S20" + salt + nonce + ct

    @staticmethod
    def decrypt_salsa20(data: bytes, password: str):
        assert data[:3] == b"S20"
        salt = data[3:11]
        nonce = data[11:19]
        ct = data[19:]
        key = CryptoEngine.derive_key(password, salt, 32)
        cipher = Salsa20.new(key=key, nonce=nonce)
        return cipher.decrypt(ct)

ALGO_MAP = {
    "AES": (CryptoEngine.encrypt_aes, CryptoEngine.decrypt_aes),
    "DES": (CryptoEngine.encrypt_des, CryptoEngine.decrypt_des),
    "ChaCha20": (CryptoEngine.encrypt_chacha, CryptoEngine.decrypt_chacha),
}
if HAVE_CAMELLIA:
    ALGO_MAP["Camellia"] = (CryptoEngine.encrypt_camellia, CryptoEngine.decrypt_camellia)
if HAVE_BLOWFISH:
    ALGO_MAP["Blowfish"] = (CryptoEngine.encrypt_blowfish, CryptoEngine.decrypt_blowfish)
if HAVE_ARC2:
    ALGO_MAP["ARC2"] = (CryptoEngine.encrypt_arc2, CryptoEngine.decrypt_arc2)
if HAVE_CAST:
    ALGO_MAP["CAST"] = (CryptoEngine.encrypt_cast, CryptoEngine.decrypt_cast)
if HAVE_SALSA20:
    ALGO_MAP["Salsa20"] = (CryptoEngine.encrypt_salsa20, CryptoEngine.decrypt_salsa20)

class FileManager:
    @staticmethod
    def walk_files(path, recursive=True, file_filter=None):
        filelist = []
        if os.path.isfile(path):
            if (not file_filter) or file_filter(path):
                filelist.append(path)
        else:
            for root, _, files in os.walk(path):
                for name in files:
                    fpath = os.path.join(root, name)
                    if (not file_filter) or file_filter(fpath):
                        filelist.append(fpath)
                if not recursive:
                    break
        return filelist

    @staticmethod
    def get_file_info(path):
        if os.path.isfile(path):
            stat = os.stat(path)
            return {
                "类型": "文件",
                "文件名": os.path.basename(path),
                "大小": stat.st_size,
                "修改时间": time.ctime(stat.st_mtime),
                "加密状态": "加密文件" if path.endswith(".enc") else "普通文件"
            }
        else:
            count, total = 0, 0
            for root, _, files in os.walk(path):
                for name in files:
                    count += 1
                    total += os.path.getsize(os.path.join(root, name))
            return {
                "类型": "文件夹",
                "文件夹名": os.path.basename(path),
                "文件数": count,
                "总大小": total
            }

    @staticmethod
    def backup_file(path, backup_dir, username):
        if not os.path.exists(path):
            return False
        userdir = os.path.join(backup_dir, username)
        if not os.path.isdir(userdir):
            os.makedirs(userdir, exist_ok=True)
        bak_path = os.path.join(userdir, os.path.basename(path) + ".bak")
        shutil.copy2(path, bak_path)
        return bak_path

def button_scale_effect(btn):
    def on_enter(e):
        btn.config(font=("微软雅黑", 13, "bold"), bg="#e17055", fg="#fff")
    def on_leave(e):
        btn.config(font=("微软雅黑", 11), bg="#0984e3", fg="#fff")
    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    btn.config(bg="#0984e3", fg="#fff", relief="flat", activebackground="#fdcb6e", activeforeground="#2d3436")

class EncryptorApp:
    def __init__(self, root):
        start_web()
        self.root = root
        self.root.title("Found-Encryptor 多用户安全加密工具")
        self.root.geometry("950x790")
        self.root.resizable(False, False)
        self.engine = CryptoEngine()
        self.file_manager = FileManager()
        self.backup_dir = ""  # 用户指定的备份目录
        self.username = None

        self._build_widgets()
        self._build_options()
        self.root.after(800, self.guide_user)

    def _build_widgets(self):
        title = tk.Label(self.root, text="多用户安全加密工具",
                         bg="#f8c291", font=("微软雅黑", 18, "bold"), fg="#2d3436")
        title.place(x=0, y=8, width=950, height=42)

        self.path_var = tk.StringVar()
        self.algo_var = tk.StringVar(value="AES")
        self.passwd_var = tk.StringVar()
        self.status_var = tk.StringVar(value="请先登录")
        self.backup_var = tk.BooleanVar(value=True)
        self.overwrite_var = tk.BooleanVar(value=True)
        self.recursive_var = tk.BooleanVar(value=True)
        self.backup_show_var = tk.StringVar(value="备份目录: 未选择")
        self.username_var = tk.StringVar(value="未登录")

        self.login_btn = tk.Button(self.root, text="输入校验登录", command=self.verify_login_ui,
                                   font=("微软雅黑", 11), bg="#fdcb6e", fg="#2d3436")
        self.login_btn.place(x=800, y=16, width=110, height=32)

        self.reg_btn = tk.Button(self.root, text="注册/登录页面", command=self.open_web_login,
                                 font=("微软雅黑", 11), bg="#00b894", fg="#fff")
        self.reg_btn.place(x=640, y=16, width=140, height=32)

        tk.Label(self.root, text="当前用户：", font=("微软雅黑", 12), bg="#f8c291").place(x=80, y=70)
        self.user_label = tk.Label(self.root, textvariable=self.username_var,
                                   font=("微软雅黑", 12), bg="#f8c291", fg="#00b894")
        self.user_label.place(x=170, y=70)

        tk.Label(self.root, text="路径：", font=("微软雅黑", 13), bg="#f8c291").place(x=60, y=120)
        tk.Entry(self.root, textvariable=self.path_var, width=80, font=("微软雅黑", 12)).place(x=140, y=122)
        tk.Button(self.root, text="浏览", command=self.select_file, font=("微软雅黑", 11)).place(x=800, y=118)
        tk.Button(self.root, text="浏览文件夹", command=self.select_folder, font=("微软雅黑", 11)).place(x=870, y=118)

        tk.Label(self.root, text="算法：", font=("微软雅黑", 13), bg="#f8c291").place(x=60, y=180)
        algo_list = list(ALGO_MAP.keys())
        self.algo_box = ttk.Combobox(self.root, textvariable=self.algo_var,
                                     values=algo_list, state="readonly", font=("微软雅黑", 12))
        self.algo_box.place(x=140, y=180, width=150)

        tk.Label(self.root, text="密码：", font=("微软雅黑", 13), bg="#f8c291").place(x=60, y=240)
        self.passwd_entry = tk.Entry(self.root, textvariable=self.passwd_var, show="*", width=40, font=("微软雅黑", 12))
        self.passwd_entry.place(x=140, y=242)
        self.showpwd_btn = tk.Button(self.root, text="显示", command=self.toggle_password, font=("微软雅黑", 11), bg="#fdcb6e", fg="#2d3436")
        self.showpwd_btn.place(x=490, y=238)

        self.encrypt_btn = tk.Button(self.root, text="加密", command=self.encrypt, state="disabled")
        self.encrypt_btn.place(x=290, y=300, width=120, height=38)
        button_scale_effect(self.encrypt_btn)
        self.decrypt_btn = tk.Button(self.root, text="解密", command=self.decrypt, state="disabled")
        self.decrypt_btn.place(x=470, y=300, width=120, height=38)
        button_scale_effect(self.decrypt_btn)

        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=750, mode="determinate")
        self.progress.place(x=100, y=360)

        self.status_label = tk.Label(self.root, textvariable=self.status_var, bg="#f8c291", anchor="w", width=110, font=("微软雅黑", 11))
        self.status_label.place(x=60, y=400)

        tk.Label(self.root, textvariable=self.backup_show_var, bg="#f8c291", fg="#e17055", font=("微软雅黑", 11)).place(x=60, y=430)

        tk.Checkbutton(self.root, text="加密/解密后删除原文件", variable=self.overwrite_var, bg="#f8c291", font=("微软雅黑", 11)).place(x=140, y=465)
        tk.Checkbutton(self.root, text="自动备份原文件", variable=self.backup_var, bg="#f8c291", font=("微软雅黑", 11)).place(x=340, y=465)
        tk.Checkbutton(self.root, text="递归子文件夹", variable=self.recursive_var, bg="#f8c291", font=("微软雅黑", 11)).place(x=540, y=465)

        tk.Label(self.root, text="操作日志：", font=("微软雅黑", 13), bg="#f8c291").place(x=60, y=500)
        self.log_text = tk.Text(self.root, width=110, height=10, state="disabled", bg="#f7f1e3", font=("微软雅黑", 11))
        self.log_text.place(x=60, y=540)

    def _build_options(self):
        pass

    def guide_user(self):
        messagebox.showinfo(
            "欢迎使用",
            "请先进入注册/登录页面，注册新用户或登录，成功后输入校验码和凭证码进行客户端校验。\n官网：hogdor.mysxl.cn"
        )

    def open_web_login(self):
        import webbrowser
        webbrowser.open("http://127.0.0.1:8799/")

    def verify_login_ui(self):
        username = simpledialog.askstring("校验登录", "请输入用户名：")
        verify_code = simpledialog.askstring("校验登录", "请输入校验码：")
        token = simpledialog.askstring("校验登录", "请输入凭证码：")
        if not username or not verify_code or not token:
            messagebox.showwarning("登录失败", "所有项均需填写")
            return
        ok, msg = verify_login(username, verify_code, token)
        if ok:
            self.username_var.set(username)
            self.username = username
            self.status_var.set(f"欢迎，{username}！")
            self.encrypt_btn["state"] = "normal"
            self.decrypt_btn["state"] = "normal"
            messagebox.showinfo("登录成功", "校验码和凭证码通过，已登录。")
        else:
            self.status_var.set("请先登录")
            self.username = None
            self.username_var.set("未登录")
            self.encrypt_btn["state"] = "disabled"
            self.decrypt_btn["state"] = "disabled"
            messagebox.showerror("登录失败", msg)

    def log(self, msg):
        if not self.username:
            return
        now = datetime.now().strftime("%H:%M:%S")
        logline = f"[{now}] {msg}\n"
        self.log_text.config(state="normal")
        self.log_text.insert("end", logline)
        self.log_text.see("end")
        self.log_text.config(state="disabled")
        userdir = os.path.join(LOGS_DIR, self.username)
        if not os.path.isdir(userdir):
            os.makedirs(userdir, exist_ok=True)
        today = datetime.now().strftime("%Y%m%d") + ".log"
        with open(os.path.join(userdir, today), "a", encoding="utf-8") as f:
            f.write(logline)

    def clear_log(self):
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, "end")
        self.log_text.config(state="disabled")

    def export_log(self):
        log = self.log_text.get(1.0, "end").strip()
        if not log:
            messagebox.showinfo("导出日志", "无日志内容")
            return
        path = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log Files", "*.log"), ("All Files", "*.*")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(log)
            messagebox.showinfo("导出日志", f"日志已保存到: {path}")

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.path_var.set(path)
            self.status_var.set(f"已选择文件: {os.path.basename(path)}")
            self.log(f"选择文件：{path}")

    def select_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.path_var.set(path)
            self.status_var.set(f"已选择文件夹: {os.path.basename(path)}")
            self.log(f"选择文件夹：{path}")

    def select_backup_dir(self):
        backup_dir = filedialog.askdirectory(title="选择备份存储目录")
        if backup_dir:
            self.backup_dir = backup_dir
            self.backup_show_var.set(f"备份目录: {backup_dir}")
            self.log(f"选择备份目录: {backup_dir}")

    def set_algorithm(self, algo):
        self.algo_var.set(algo)
        self.status_var.set(f"已选择算法: {algo}")
        self.log(f"选择算法: {algo}")

    def toggle_password(self):
        if self.passwd_entry.cget('show') == '':
            self.passwd_entry.config(show="*")
            self.showpwd_btn.config(text="显示")
        else:
            self.passwd_entry.config(show="")
            self.showpwd_btn.config(text="隐藏")

    def open_in_explorer(self):
        path = self.path_var.get()
        if not path or not os.path.exists(path):
            messagebox.showwarning("提示", "请先选择文件或文件夹")
            return
        FileManager.open_file_in_explorer(path)

    def encrypt(self):
        self._start_crypto("encrypt")

    def decrypt(self):
        self._start_crypto("decrypt")

    def _start_crypto(self, mode):
        path = self.path_var.get()
        password = self.passwd_var.get()
        algo = self.algo_var.get()
        if not self.username:
            messagebox.showwarning("用户提示", "请先在右上角登录并校验")
            return
        if not path or not os.path.exists(path):
            self.status_var.set("请选择有效的文件或文件夹")
            return
        if not password or len(password) < 6:
            self.status_var.set("密码至少6位")
            return
        recursive = self.recursive_var.get()
        if recursive:
            filelist = FileManager.walk_files(path, recursive=True)
        else:
            filelist = [path] if os.path.isfile(path) else [os.path.join(path, x) for x in os.listdir(path) if os.path.isfile(os.path.join(path, x))]
        if mode == "encrypt":
            files = [f for f in filelist if not f.endswith(".enc") and not f.endswith(".bak")]
        else:
            files = [f for f in filelist if f.endswith(".enc")]
        if not files:
            messagebox.showinfo("操作提示", "无有效文件可处理")
            return
        if self.backup_var.get() and not self.backup_dir:
            messagebox.showwarning("备份提示", "请先选择备份存储目录")
            return
        self.progress["value"] = 0
        self.progress["maximum"] = len(files)
        self.status_var.set(f"{('加密' if mode=='encrypt' else '解密')}中，共{len(files)}个文件")
        self.encrypt_btn["state"] = "disabled"
        self.decrypt_btn["state"] = "disabled"
        self.root.update()
        backup = self.backup_var.get()
        overwrite = self.overwrite_var.get()
        backup_dir = self.backup_dir
        username = self.username

        def progress_callback(filepath, success, msg):
            self.progress["value"] += 1
            if not success:
                self.status_var.set(f"{os.path.basename(filepath)}失败: {msg}")
                self.log(f"{os.path.basename(filepath)} 失败: {msg}")
            else:
                self.status_var.set(f"{os.path.basename(filepath)}完成")
                self.log(f"{os.path.basename(filepath)} 完成")
            self.root.update()

        def process_file(filepath, password, algo, mode, progress_callback, backup=False, overwrite=True, backup_dir=None, username=None):
            try:
                if mode == "encrypt" and not filepath.endswith(".enc"):
                    with open(filepath, "rb") as f:
                        data = f.read()
                    enc_data = ALGO_MAP[algo][0](data, password)
                    outpath = filepath + ".enc"
                    if backup and backup_dir and username:
                        FileManager.backup_file(filepath, backup_dir, username)
                    with open(outpath, "wb") as f:
                        f.write(enc_data)
                    if overwrite:
                        os.remove(filepath)
                    progress_callback(filepath, True, "")
                elif mode == "decrypt" and filepath.endswith(".enc"):
                    with open(filepath, "rb") as f:
                        data = f.read()
                    dec_data = ALGO_MAP[algo][1](data, password)
                    outpath = filepath[:-4]
                    if backup and backup_dir and username:
                        FileManager.backup_file(filepath, backup_dir, username)
                    with open(outpath, "wb") as f:
                        f.write(dec_data)
                    if overwrite:
                        os.remove(filepath)
                    progress_callback(filepath, True, "")
                else:
                    progress_callback(filepath, False, "文件类型或扩展名不匹配")
            except Exception as e:
                progress_callback(filepath, False, str(e))

        def task():
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                futures = []
                for f in files:
                    futures.append(executor.submit(process_file, f, password, algo, mode, progress_callback, backup, overwrite, backup_dir, username))
                concurrent.futures.wait(futures)
            self.status_var.set("全部完成")
            self.encrypt_btn["state"] = "normal"
            self.decrypt_btn["state"] = "normal"
            self.log(f"{'加密' if mode=='encrypt' else '解密'}全部完成")

        threading.Thread(target=task, daemon=True).start()

if __name__ == "__main__":
    try:
        import cryptography
        import Crypto
    except ImportError:
        print("请先安装依赖：pip install cryptography pycryptodome bottle")
        sys.exit(1)
    root = tk.Tk()
    app = EncryptorApp(root)
    root.mainloop()