
import os, json, time as pytime, re
from typing import Tuple, Dict, Any, Optional

import requests
from flask import Flask, request, jsonify, session, render_template_string

# ----------------------------
# App & Config
# ----------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

GRAPH_BASE = "https://graph.facebook.com/v20.0"
RUPLOAD_BASE = "https://rupload.facebook.com/video-upload/v13.0"
VERSION = "2.0-min"

TOKENS_FILE = os.environ.get("TOKENS_FILE", "tokens.json")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

ACCESS_PIN = os.environ.get("ACCESS_PIN", "").strip()

SETTINGS: Dict[str, Any] = {
    "app": {"app_id": os.environ.get("FB_APP_ID", ""), "app_secret": os.environ.get("FB_APP_SECRET", "")},
    "webhook_verify_token": os.environ.get("WEBHOOK_VERIFY_TOKEN", "verify-token"),
    "cooldown_until": 0,
    "last_usage": {},
    "poll_intervals": {"notif": 60, "conv": 120},
    "_last_events": [],
    "throttle": {"global_min_interval": float(os.environ.get("GLOBAL_MIN_INTERVAL", "1.0")),
                 "per_page_min_interval": float(os.environ.get("PER_PAGE_MIN_INTERVAL", "2.0"))},
    "last_call_ts": {},
    "_recent_posts": []
}

# ----------------------------
# Simple PIN gate for /api/*
# ----------------------------
@app.before_request
def _require_pin_for_api():
    if not ACCESS_PIN:
        return
    path = request.path or ""
    if not path.startswith("/api/"):
        return
    if path in ("/api/pin/status", "/api/pin/login", "/api/pin/logout"):
        return
    if not session.get("pin_ok", False):
        return jsonify({"error": "PIN_REQUIRED"}), 401

@app.route("/api/pin/status")
def api_pin_status():
    return jsonify({"ok": bool(session.get("pin_ok", False)), "need_pin": bool(ACCESS_PIN)}), 200

@app.route("/api/pin/login", methods=["POST"])
def api_pin_login():
    body = request.get_json(force=True) or {}
    pin = (body.get("pin") or "").strip()
    if not ACCESS_PIN or (pin and pin == ACCESS_PIN):
        session["pin_ok"] = True
        return jsonify({"ok": True}), 200
    return jsonify({"error": "INVALID_PIN"}), 403

@app.route("/api/pin/logout", methods=["POST"])
def api_pin_logout():
    session.pop("pin_ok", None)
    return jsonify({"ok": True}), 200

# ----------------------------
# Helpers: tokens
# ----------------------------
def load_tokens() -> Dict[str, Any]:
    if not os.path.exists(TOKENS_FILE):
        return {}
    with open(TOKENS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_tokens(data: dict):
    os.makedirs(os.path.dirname(TOKENS_FILE) or ".", exist_ok=True)
    with open(TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def app_cfg() -> Tuple[Optional[str], Optional[str]]:
    a = SETTINGS.get("app", {}) or {}
    return a.get("app_id"), a.get("app_secret")

# ----------------------------
# Helpers: throttle & guard
# ----------------------------
def _wait_throttle(key: str):
    now = pytime.time()
    last_ts = SETTINGS["last_call_ts"].get(key, 0.0)
    if key.startswith("page:"):
        gap = SETTINGS["throttle"]["per_page_min_interval"]
    else:
        gap = SETTINGS["throttle"]["global_min_interval"]
    g_last = SETTINGS["last_call_ts"].get("global", 0.0)
    g_gap = SETTINGS["throttle"]["global_min_interval"]
    sleep_for = max(0.0, last_ts + gap - now, g_last + g_gap - now)
    if sleep_for > 0:
        pytime.sleep(sleep_for)
    SETTINGS["last_call_ts"][key] = pytime.time()
    SETTINGS["last_call_ts"]["global"] = pytime.time()

def _hash_content(s: str) -> str:
    import hashlib
    return hashlib.sha256((s or "").strip().encode("utf-8")).hexdigest()

def _recent_content_guard(kind: str, key: str, content: str, within_sec: int = 3600) -> bool:
    now = int(pytime.time())
    h = _hash_content(content)
    SETTINGS["_recent_posts"] = [x for x in SETTINGS["_recent_posts"] if now - x["ts"] <= within_sec]
    for x in SETTINGS["_recent_posts"]:
        if x["type"] == kind and x["key"] == key and x["content_hash"] == h:
            return True
    SETTINGS["_recent_posts"].append({"ts": now, "type": kind, "key": key, "content_hash": h})
    return False

# ----------------------------
# Helpers: Graph API + Rate-limit
# ----------------------------
def _update_usage_and_cooldown(r: requests.Response):
    try:
        hdr = r.headers or {}
        usage = hdr.get("x-app-usage") or hdr.get("X-App-Usage") or ""
        pusage = hdr.get("x-page-usage") or hdr.get("X-Page-Usage") or ""
        SETTINGS["last_usage"] = {"app": usage, "page": pusage}
        for key in ["x-app-usage", "X-App-Usage", "x-page-usage", "X-Page-Usage"]:
            if key in hdr:
                try:
                    u = hdr[key]
                    if isinstance(u, str):
                        u = json.loads(u)
                    top = max(int(u.get("call_count", 0)), int(u.get("total_time", 0)), int(u.get("total_cputime", 0)))
                    now = int(pytime.time())
                    if top >= 90: SETTINGS["cooldown_until"] = max(SETTINGS.get("cooldown_until", 0), now + 300)
                    elif top >= 80: SETTINGS["cooldown_until"] = max(SETTINGS.get("cooldown_until", 0), now + 120)
                except Exception:
                    pass
    except Exception:
        pass

def _respect_cooldown() -> int:
    now = int(pytime.time())
    cu = int(SETTINGS.get("cooldown_until", 0) or 0)
    if now < cu:
        return cu - now
    return 0

def _handle_429_and_maybe_retry(r: requests.Response, attempt: int):
    try:
        ra = int(r.headers.get("Retry-After", "0") or "0")
    except Exception:
        ra = 300
    SETTINGS["cooldown_until"] = max(SETTINGS.get("cooldown_until", 0), int(pytime.time()) + max(ra, 120))
    if attempt == 0 and ra <= 5:
        pytime.sleep(ra or 1)
        return None, -1
    return {"error": "RATE_LIMIT", "retry_after": ra}, 429

def graph_get(path: str, params: Dict[str, Any], token: Optional[str], ttl: int = 0, ctx_key: Optional[str] = None):
    rem = _respect_cooldown()
    if rem > 0:
        return {"error": "RATE_LIMIT", "retry_after": rem}, 429
    url = f"{GRAPH_BASE}/{path}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    attempts = 0
    while True:
        try:
            _wait_throttle("global")
            if ctx_key: _wait_throttle(ctx_key)
            r = requests.get(url, params=params, headers=headers, timeout=60)
            _update_usage_and_cooldown(r)
            if r.status_code == 429:
                data, st = _handle_429_and_maybe_retry(r, attempts)
                if st == -1: attempts += 1; continue
                return data, st
            if r.status_code >= 400:
                try: return r.json(), r.status_code
                except Exception: return {"error": r.text}, r.status_code
            return r.json(), 200
        except requests.RequestException as e:
            return {"error": str(e)}, 500

def graph_post(path: str, data: Dict[str, Any], token: Optional[str], ctx_key: Optional[str] = None):
    rem = _respect_cooldown()
    if rem > 0:
        return {"error": "RATE_LIMIT", "retry_after": rem}, 429
    url = f"{GRAPH_BASE}/{path}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    attempts = 0
    while True:
        try:
            _wait_throttle("global")
            if ctx_key: _wait_throttle(ctx_key)
            r = requests.post(url, data=data, headers=headers, timeout=120)
            _update_usage_and_cooldown(r)
            if r.status_code == 429:
                data2, st = _handle_429_and_maybe_retry(r, attempts)
                if st == -1: attempts += 1; continue
                return data2, st
            if r.status_code >= 400:
                try: return r.json(), r.status_code
                except Exception: return {"error": r.text}, r.status_code
            return r.json(), 200
        except requests.RequestException as e:
            return {"error": str(e)}, 500

def graph_post_multipart(path: str, files: Dict[str, Any], form: Dict[str, Any], token: Optional[str], ctx_key: Optional[str] = None):
    rem = _respect_cooldown()
    if rem > 0:
        return {"error": "RATE_LIMIT", "retry_after": rem}, 429
    url = f"{GRAPH_BASE}/{path}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    attempts = 0
    while True:
        try:
            _wait_throttle("global")
            if ctx_key: _wait_throttle(ctx_key)
            r = requests.post(url, files=files, data=form, headers=headers, timeout=300)
            _update_usage_and_cooldown(r)
            if r.status_code == 429:
                data2, st = _handle_429_and_maybe_retry(r, attempts)
                if st == -1: attempts += 1; continue
                return data2, st
            if r.status_code >= 400:
                try: return r.json(), r.status_code
                except Exception: return {"error": r.text}, r.status_code
            return r.json(), 200
        except requests.RequestException as e:
            return {"error": str(e)}, 500

# ------- ENV-based page tokens (no app id/secret needed) -------
def _env_get_tokens():
    raw = os.environ.get("PAGE_TOKENS", "") or ""
    mapping, loose_tokens = {}, []
    raw = raw.strip()
    if not raw:
        return mapping, loose_tokens
    try:
        if raw.startswith("{"):
            obj = json.loads(raw)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k and v: mapping[str(k)] = str(v)
            return mapping, loose_tokens
    except Exception:
        pass
    parts = [x.strip() for x in re.split(r"[\\n,]+", raw) if x.strip()]
    for x in parts:
        if "|" in x or ":" in x or "=" in x:
            for sep in ("|", ":", "="):
                if sep in x:
                    pid, tok = x.split(sep, 1)
                    pid, tok = pid.strip(), tok.strip()
                    if pid and tok: mapping[pid] = tok
                    break
        else:
            loose_tokens.append(x)
    return mapping, loose_tokens

def _env_resolve_loose_tokens(existing: dict):
    pages = []
    _, loose = _env_get_tokens()
    for tok in loose:
        d, st = graph_get("me", {"fields": "id,name"}, tok, ttl=0)
        if st == 200 and isinstance(d, dict) and d.get("id"):
            pid = str(d["id"]); existing.setdefault(pid, tok)
            pages.append({"id": pid, "name": d.get("name", ""), "access_token": tok})
    return pages

def _env_pages_list():
    mp, _ = _env_get_tokens()
    pages = []
    for pid, tok in mp.items():
        name = ""
        try:
            d, st = graph_get(str(pid), {"fields": "name"}, tok, ttl=0)
            if st == 200 and isinstance(d, dict): name = d.get("name", "")
        except Exception:
            pass
        pages.append({"id": str(pid), "name": name or str(pid), "access_token": tok})
    pages.extend(_env_resolve_loose_tokens(mp))
    return pages

def get_page_access_token(page_id: str, user_token: str) -> Optional[str]:
    # ENV first
    mp, _ = _env_get_tokens()
    if str(page_id) in mp:
        return mp[str(page_id)]
    store = load_tokens()
    pages = store.get("pages") or {}
    if page_id in pages:
        return pages[page_id]
    data, st = graph_get("me/accounts", {"limit": 200}, user_token, ttl=0)
    if st == 200 and isinstance(data, dict):
        found = {}
        for p in data.get("data", []):
            pid = str(p.get("id")); pat = p.get("access_token")
            if pid and pat: found[pid] = pat
        if found: store["pages"] = found; save_tokens(store)
        return found.get(page_id)
    return None

def _ctx_key_for_page(page_id: str) -> str:
    return f"page:{page_id}"

# ----------------------------
# UI (Only Posts & Inbox)
# ----------------------------
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Facebook Page Manager (Minimal)</title>
  <style>
    :root{--bg:#f6f7f9;--card:#fff;--b:#e6e8eb;--primary:#1976d2;--muted:#6b7280}
    *{box-sizing:border-box} body{margin:0;font-family:system-ui,Segoe UI,Arial,sans-serif;background:var(--bg)}
    .container{max-width:1100px;margin:18px auto;padding:0 16px}
    h1{margin:0 0 12px;font-size:20px}
    .tabs{display:flex;gap:8px;margin-bottom:8px}
    .tabs button{padding:8px 12px;border:1px solid var(--b);border-radius:999px;background:#fff;cursor:pointer}
    .tabs button.active{background:var(--primary);color:#fff;border-color:var(--primary)}
    .panel{display:none} .panel.active{display:block}
    .row{display:flex;gap:12px;flex-wrap:wrap}
    .col{flex:1 1 420px;min-width:320px}
    .card{background:var(--card);border:1px solid var(--b);border-radius:12px;padding:12px}
    textarea,input,select{width:100%;padding:9px;border:1px solid var(--b);border-radius:10px}
    .list{padding:6px;border:1px dashed var(--b);border-radius:10px;background:#fafafa;max-height:320px;overflow:auto}
    .status{margin-top:6px;font-size:12px;color:var(--muted)}
    .toolbar{display:flex;gap:8px;margin-top:8px}
    .item{display:flex;justify-content:space-between;padding:6px 8px;border-bottom:1px dashed var(--b)}
    .item:last-child{border-bottom:none}
  </style>
</head>
<body>
  <div class="container">
    <h1>Facebook Page Manager (Completed)</h1>
    <div class="tabs">
      <button id="tab-posts" class="active">Đăng bài</button>
      <button id="tab-inbox">Tin nhắn</button>
    </div>

    <div id="panel-posts" class="panel active">
      <div class="row">
        <div class="col">
          <div class="card">
            <h3>Fanpage</h3>
            <div class="list" id="pages"></div>
            <div class="status" id="pages_status"></div>
          </div>
          <div class="card" style="margin-top:12px">
            <h3>AI soạn nội dung</h3>
            <textarea id="ai_prompt" rows="4" placeholder="Gợi ý chủ đề, ưu đãi, CTA..."></textarea>
            <div class="toolbar">
              <input id="ai_keyword" placeholder="Từ khoá chính (VD: MB66)"/>
              <input id="ai_link" placeholder="Link chính thức (VD: https://...)"/>
            </div>
            <div class="toolbar">
              <select id="ai_tone"><option value="thân thiện">Giọng: Thân thiện</option><option value="chuyên nghiệp">Chuyên nghiệp</option></select>
              <select id="ai_length"><option value="ngắn">Ngắn</option><option value="vừa">Vừa</option><option value="dài">Dài</option></select>
              <button class="btn" id="btn_ai">Tạo nội dung</button><span class="status">Cần OPENAI_API_KEY</span>
            </div>
            <div class="status" id="ai_status"></div>
          </div>
        </div>
        <div class="col">
          <div class="card">
            <h3>Đăng nội dung</h3>
            <textarea id="post_text" rows="6" placeholder="Nội dung bài viết..."></textarea>
            <div class="toolbar"><label>Loại</label>
              <select id="post_type"><option value="feed">Feed</option><option value="reels">Reels</option></select>
              <input type="file" id="video_input" accept="video/*"/>
            </div>
            <div class="toolbar">
              <input type="file" id="photo_input" accept="image/*"/>
              <input type="text" id="media_caption" placeholder="Caption (tuỳ chọn)"/>
            </div>
            <div class="toolbar">
              <button id="btn_publish">Đăng</button>
            </div>
            <div class="status" id="post_status"></div>
          </div>
        </div>
      </div>
    </div>

    <div id="panel-inbox" class="panel">
      <div class="row">
        <div class="col">
          <h3>Chọn Page</h3>
          <select id="inbox_page"></select>
          <button id="btn_load_conv" style="margin-top:6px">Tải hội thoại</button>
          <div class="list" id="conv_list" style="margin-top:8px"></div>
        </div>
        <div class="col">
          <h3>Hội thoại</h3>
          <div class="list" id="msg_list" style="min-height:260px"></div>
          <div class="toolbar">
            <input id="msg_text" placeholder="Nhập tin nhắn..."/>
            <button id="btn_send">Gửi</button>
          </div>
          <div class="status" id="inbox_status"></div>
        </div>
      </div>
    </div>
  </div>

  <div class="pin-overlay" id="pin_overlay" style="position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;align-items:center;justify-content:center;z-index:9999">
    <div style="background:#fff;border-radius:12px;padding:16px;min-width:300px">
      <h3>Nhập PIN để truy cập</h3>
      <input id="pin_input" type="password" placeholder="PIN" style="width:100%;padding:9px;border:1px solid #e6e8eb;border-radius:10px"/>
      <div class="toolbar"><button id="btn_pin_ok">Xác nhận</button></div>
      <div class="status" id="pin_status"></div>
    </div>
  </div>

<script>
const $ = (sel) => document.querySelector(sel);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function ensurePin(){
  try{
    const r = await fetch('/api/pin/status');
    const d = await r.json();
    if(d.need_pin && !d.ok){ $('#pin_overlay').style.display = 'flex'; }
  }catch(e){}
}
$('#btn_pin_ok').onclick = async () => {
  const pin = ($('#pin_input').value||'').trim();
  if(!pin){ $('#pin_status').textContent='Nhập PIN trước'; return; }
  const r = await fetch('/api/pin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin})});
  const d = await r.json();
  if(d.ok){ $('#pin_overlay').style.display='none'; loadPages(); } else { $('#pin_status').textContent='PIN sai'; }
};

function showTab(name){
  ['posts','inbox'].forEach(id => {
    const tab   = document.getElementById('tab-' + id);
    const panel = document.getElementById('panel-' + id);
    if (tab)   tab.classList.toggle('active', id === name);
    if (panel) panel.classList.toggle('active', id === name);
  });
}
document.getElementById('tab-posts')?.addEventListener('click', ()=>showTab('posts'));
document.getElementById('tab-inbox')?.addEventListener('click', ()=>{ showTab('inbox'); loadPagesToSelect('inbox_page'); });

const pagesBox = $('#pages');
const pagesStatus = $('#pages_status');

async function loadPages(){
  pagesBox.innerHTML = '<div class="status">Đang tải...</div>';
  try{
    const r = await fetch('/api/pages');
    const d = await r.json();
    if(d.error){ pagesStatus.textContent = JSON.stringify(d); return; }
    const arr = d.data || [];
    arr.sort((a,b)=> (a.name||'').localeCompare(b.name||'', 'vi', {sensitivity:'base'}));
    pagesBox.innerHTML = arr.map(p => (
      '<div class="item"><span>'+(p.name||'')+'</span><input type="checkbox" class="pg" value="'+p.id+'" data-name="'+(p.name||'')+'"></div>'
    )).join('');
    pagesStatus.textContent = 'Tải ' + arr.length + ' page.';
  }catch(e){ pagesStatus.textContent = 'Lỗi tải danh sách page'; }
}
function selectedPageIds(){ return Array.from(document.querySelectorAll('.pg:checked')).map(i=>i.value); }

async function loadPagesToSelect(selectId){
  const sel = $('#'+selectId);
  try{
    const r = await fetch('/api/pages'); const d = await r.json();
    const arr = d.data || [];
    sel.innerHTML = '<option value="">--Chọn page--</option>' + arr.map(p=>'<option value="'+p.id+'">'+p.name+'</option>').join('');
  }catch(e){ sel.innerHTML = '<option>Không tải được</option>'; }
}

// AI writer
$('#btn_ai').onclick = async () => {
  const prompt = ($('#ai_prompt').value||'').trim();
  const tone = $('#ai_tone').value;
  const length = $('#ai_length').value;
  const keyword = ($('#ai_keyword').value||'MB66').trim();
  const link = ($('#ai_link').value||'').trim();
  const st = $('#ai_status');
  if(!OPENAI_API_KEY_PLACEHOLDER){ st.textContent='Cần OPENAI_API_KEY trên server'; return; }
  st.textContent = 'Đang tạo nội dung...';
  try{
    const r = await fetch('/api/ai/generate', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({prompt, tone, length, keyword, link})});
    const d = await r.json();
    if(d.error){ st.textContent='Lỗi: '+JSON.stringify(d); return; }
    $('#post_text').value = d.text || '';
    st.textContent = 'Đã chèn nội dung vào khung soạn.';
  }catch(e){ st.textContent = 'Lỗi gọi AI'; }
};

// Publish
$('#btn_publish').onclick = async () => {
  const pages = selectedPageIds();
  const text = ($('#post_text').value||'').trim();
  const type = $('#post_type').value;
  const photo = $('#photo_input').files[0] || null;
  const video = $('#video_input').files[0] || null;
  const caption = ($('#media_caption').value||'');
  const st = $('#post_status');

  if(!pages.length){ st.textContent='Chọn ít nhất một page'; return; }
  if(type === 'feed' && !text && !photo && !video){ st.textContent='Cần nội dung hoặc tệp'; return; }
  if(type === 'reels' && !video){ st.textContent='Cần chọn video cho Reels'; return; }

  st.textContent='Đang đăng...';
  try{
    const results = [];
    for(const pid of pages){
      let d;
      if(type === 'feed'){
        if(video){
          const fd = new FormData();
          fd.append('video', video);
          fd.append('description', caption || text || '');
          const r = await fetch('/api/pages/'+pid+'/video', {method:'POST', body: fd});
          d = await r.json();
        }else if(photo){
          const fd = new FormData();
          fd.append('photo', photo);
          fd.append('caption', caption || text || '');
          const r = await fetch('/api/pages/'+pid+'/photo', {method:'POST', body: fd});
          d = await r.json();
        }else{
          const r = await fetch('/api/pages/'+pid+'/post', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({message: text})});
          d = await r.json();
        }
      }else{
        const fd = new FormData();
        fd.append('video', video);
        fd.append('description', caption || text || '');
        const r = await fetch('/api/pages/'+pid+'/reel', {method:'POST', body: fd});
        d = await r.json();
      }
      if(d.error){ results.push('❌ ' + pid + ': ' + JSON.stringify(d)); }
      else{
        const link = d.permalink_url ? ' · <a target="_blank" href="'+d.permalink_url+'">Mở bài</a>' : '';
        results.push('✅ ' + pid + link);
      }
      await sleep(1200 + Math.floor(Math.random()*1200));
    }
    st.innerHTML = results.join('<br/>');
  }catch(e){ st.textContent='Lỗi đăng'; }
};

// INBOX
let currentThread = null;
let currentRecipient = null;

$('#btn_load_conv').onclick = async () => {
  const pid = $('#inbox_page').value;
  const st = $('#inbox_status');
  if(!pid){ st.textContent='Chưa chọn page'; return; }
  st.textContent='Đang tải hội thoại...';
  try{
    const r = await fetch('/api/pages/'+pid+'/conversations');
    const d = await r.json();
    if(d.error){ st.textContent='Lỗi: '+JSON.stringify(d); return; }
    const arr = d.data || [];
    $('#conv_list').innerHTML = arr.map(cv => {
      let display = cv.id;
      try{
        const parts = (cv.participants && cv.participants.data) ? cv.participants.data : [];
        const other = parts.find(p => p.id !== pid);
        if(other && other.name) display = other.name;
      }catch(_){}
      return '<div class="item"><a href="#" data-id="'+cv.id+'" class="open-thread">'+display+'</a><span>'+(cv.updated_time||'')+'</span></div>';
    }).join('');
    $('#conv_list').querySelectorAll('.open-thread').forEach(a => {
      a.addEventListener('click', async (e) => { e.preventDefault(); const tid = a.getAttribute('data-id'); await openThread(pid, tid); });
    });
    st.textContent='Đã tải ' + arr.length + ' hội thoại.';
  }catch(e){ st.textContent='Lỗi tải hội thoại'; }
};

async function openThread(pageId, threadId){
  const st = $('#inbox_status');
  st.textContent='Đang tải tin nhắn...';
  try{
    const r = await fetch('/api/pages/'+pageId+'/conversations/'+threadId);
    const d = await r.json();
    if(d.error){ st.textContent='Lỗi: '+JSON.stringify(d); return; }
    const msgs = (d.messages && d.messages.data) ? d.messages.data : [];
    currentThread = threadId;
    let rec = null;
    for(const m of msgs){
      const tos = (m.to && m.to.data) ? m.to.data : [];
      const fr = m.from || {};
      for(const t of tos){ if(t.id !== pageId){ rec = t.id; break; } }
      if(!rec && fr.id !== pageId){ rec = fr.id; }
      if(rec) break;
    }
    currentRecipient = rec;
    const fmt = (iso) => { try{ return new Date(iso).toLocaleString(); }catch(_){ return iso||''; } };
    $('#msg_list').innerHTML = msgs.map(m => {
      const fromId = (m.from && m.from.id) ? m.from.id : '';
      const fromName = (m.from && (m.from.name||m.from.id)) ? (m.from.name||m.from.id) : 'Unknown';
      const cls = (fromId === pageId) ? 'me' : 'other';
      const text = (m.message || '[attachment]');
      const time = fmt(m.created_time||'');
      return '<div class="'+cls+'"><div><b>'+fromName+'</b> · '+time+'</div><div>'+text+'</div></div>';
    }).join('');
    st.textContent='Đã tải ' + msgs.length + ' tin nhắn.' + (currentRecipient ? '' : ' (Chưa xác định người nhận)');
  }catch(e){ st.textContent='Lỗi tải tin nhắn'; }
}

$('#btn_send').onclick = async () => {
  const pid = $('#inbox_page').value;
  const text = ($('#msg_text').value||'').trim();
  const st = $('#inbox_status');
  if(!pid){ st.textContent='Chưa chọn page'; return; }
  if(!text){ st.textContent='Nhập nội dung trước'; return; }
  if(!currentRecipient){ st.textContent='Chưa xác định người nhận — hãy mở một thread trước.'; return; }
  st.textContent='Đang gửi...';
  try{
    const r = await fetch('/api/pages/'+pid+'/messages', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({recipient_id: currentRecipient, text})});
    const d = await r.json();
    if(d.error){ st.textContent='Lỗi: '+JSON.stringify(d); return; }
    st.textContent='Đã gửi.';
    if(currentThread){ await openThread(pid, currentThread); }
    $('#msg_text').value='';
  }catch(e){ st.textContent='Lỗi gửi tin nhắn'; }
};

// Init
window.addEventListener('load', ()=>{ ensurePin().then(loadPages); });
</script>
</body>
</html>"""

@app.route("/")
def index():
    html = INDEX_HTML.replace("OPENAI_API_KEY_PLACEHOLDER", "1" if OPENAI_API_KEY else "")
    return render_template_string(html)

# ----------------------------
# APIs: pages & posting & reels
# ----------------------------
def reels_start(page_id: str, page_token: str):
    return graph_post(f"{page_id}/video_reels", {"upload_phase": "start"}, page_token, ctx_key=_ctx_key_for_page(page_id))

def reels_finish(page_id: str, page_token: str, video_id: str, description: str):
    return graph_post(f"{page_id}/video_reels", {"upload_phase": "finish", "video_id": video_id, "description": description}, page_token, ctx_key=_ctx_key_for_page(page_id))

@app.route("/api/pages")
def api_list_pages():
    token = session.get("user_access_token") or (load_tokens().get("user_long") or {}).get("access_token")
    if token:
        data, status = graph_get("me/accounts", {"limit": 200}, token, ttl=0)
        return jsonify(data), status
    # Fallback: ENV PAGE_TOKENS
    try:
        env_pages = _env_pages_list()
        if env_pages:
            return jsonify({"data": env_pages}), 200
    except Exception:
        pass
    return jsonify({"error": "NOT_LOGGED_IN"}), 401

@app.route("/api/pages/<page_id>/post", methods=["POST"])
def api_post_to_page(page_id):
    token = session.get("user_access_token") or (load_tokens().get("user_long") or {}).get("access_token")
    if not token and not _env_get_tokens()[0].get(str(page_id)):
        return jsonify({"error": "NOT_LOGGED_IN"}), 401
    message = (request.get_json(force=True).get("message") or "").strip()
    if not message: return jsonify({"error":"EMPTY_MESSAGE"}), 400
    if _recent_content_guard("post", page_id, message, within_sec=3600):
        return jsonify({"error":"DUPLICATE_MESSAGE"}), 429
    page_token = get_page_access_token(page_id, token or "")
    if not page_token: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
    data, status = graph_post(f"{page_id}/feed", {"message": message}, page_token, ctx_key=_ctx_key_for_page(page_id))
    try:
        if status == 200 and isinstance(data, dict) and data.get("id"):
            d2, s2 = graph_get(data["id"], {"fields": "permalink_url"}, page_token, ttl=0, ctx_key=_ctx_key_for_page(page_id))
            if s2 == 200 and isinstance(d2, dict) and d2.get("permalink_url"):
                data["permalink_url"] = d2["permalink_url"]
    except Exception: pass
    return jsonify(data), status

@app.route("/api/pages/<page_id>/photo", methods=["POST"])
def api_post_photo(page_id):
    token = session.get("user_access_token") or (load_tokens().get("user_long") or {}).get("access_token")
    if not token and not _env_get_tokens()[0].get(str(page_id)):
        return jsonify({"error": "NOT_LOGGED_IN"}), 401
    page_token = get_page_access_token(page_id, token or "")
    if not page_token: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
    if "photo" not in request.files: return jsonify({"error":"MISSING_PHOTO"}), 400
    file = request.files["photo"]
    cap = request.form.get("caption","")
    if cap and _recent_content_guard("photo_caption", page_id, cap, within_sec=3600):
        return jsonify({"error":"DUPLICATE_CAPTION"}), 429
    files = {"source": (file.filename, file.stream, file.mimetype or "application/octet-stream")}
    form = {"caption": cap, "published": "true"}
    data, status = graph_post_multipart(f"{page_id}/photos", files, form, page_token, ctx_key=_ctx_key_for_page(page_id))
    try:
        if status == 200 and isinstance(data, dict):
            pid = data.get("id") or data.get("post_id")
            if pid:
                d2, s2 = graph_get(str(pid), {"fields": "permalink_url"}, page_token, ttl=0, ctx_key=_ctx_key_for_page(page_id))
                if s2 == 200 and isinstance(d2, dict) and d2.get("permalink_url"):
                    data["permalink_url"] = d2["permalink_url"]
    except Exception: pass
    return jsonify(data), status

@app.route("/api/pages/<page_id>/video", methods=["POST"])
def api_post_video(page_id):
    token = session.get("user_access_token") or (load_tokens().get("user_long") or {}).get("access_token")
    if not token and not _env_get_tokens()[0].get(str(page_id)):
        return jsonify({"error": "NOT_LOGGED_IN"}), 401
    page_token = get_page_access_token(page_id, token or "")
    if not page_token: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
    if "video" not in request.files: return jsonify({"error":"MISSING_VIDEO"}), 400
    file = request.files["video"]
    desc = request.form.get("description","")
    if desc and _recent_content_guard("video_desc", page_id, desc, within_sec=3600):
        return jsonify({"error":"DUPLICATE_DESCRIPTION"}), 429
    files = {"source": (file.filename, file.stream, file.mimetype or "application/octet-stream")}
    form = {"description": desc}
    data, status = graph_post_multipart(f"{page_id}/videos", files, form, page_token, ctx_key=_ctx_key_for_page(page_id))
    try:
        if status == 200 and isinstance(data, dict):
            vid = data.get("id") or data.get("video_id")
            if vid:
                d2, s2 = graph_get(str(vid), {"fields": "permalink_url"}, page_token, ttl=0, ctx_key=_ctx_key_for_page(page_id))
                if s2 == 200 and isinstance(d2, dict) and d2.get("permalink_url"):
                    data["permalink_url"] = d2["permalink_url"]
    except Exception: pass
    return jsonify(data), status

@app.route("/api/pages/<page_id>/reel", methods=["POST"])
def api_post_reel(page_id):
    token = session.get("user_access_token") or (load_tokens().get("user_long") or {}).get("access_token")
    if not token and not _env_get_tokens()[0].get(str(page_id)):
        return jsonify({"error": "NOT_LOGGED_IN"}), 401
    page_token = get_page_access_token(page_id, token or "")
    if not page_token: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
    if "video" not in request.files: return jsonify({"error":"MISSING_VIDEO"}), 400
    file = request.files["video"]
    desc = request.form.get("description","")
    start_res, st1 = reels_start(page_id, page_token)
    if st1 != 200 or not isinstance(start_res, dict) or "video_id" not in start_res:
        return jsonify({"error":"REELS_START_FAILED", "detail": start_res}), st1
    video_id = start_res.get("video_id")
    headers = {"Authorization": f"OAuth {page_token}", "offset": "0", "Content-Type": "application/octet-stream"}
    try:
        data_bytes = file.stream.read()
        _wait_throttle("global")
        ru = requests.post(f"{RUPLOAD_BASE}/{video_id}", headers=headers, data=data_bytes, timeout=600)
        if ru.status_code >= 400:
            try: return jsonify({"error":"REELS_RUPLOAD_FAILED", "detail": ru.json()}), ru.status_code
            except Exception: return jsonify({"error":"REELS_RUPLOAD_FAILED", "detail": ru.text}), ru.status_code
    except Exception as e:
        return jsonify({"error":"REELS_RUPLOAD_EXCEPTION", "detail": str(e)}), 500
    fin_res, st3 = reels_finish(page_id, page_token, video_id, desc)
    if st3 != 200: return jsonify({"error":"REELS_FINISH_FAILED", "detail": fin_res}), st3
    try:
        vid = fin_res.get("video_id") or video_id
        d2, s2 = graph_get(str(vid), {"fields": "permalink_url"}, page_token, ttl=0, ctx_key=_ctx_key_for_page(page_id))
        if s2 == 200 and isinstance(d2, dict) and d2.get("permalink_url"):
            fin_res["permalink_url"] = d2["permalink_url"]
    except Exception: pass
    return jsonify(fin_res), 200

# ----------------------------
# INBOX APIs
# ----------------------------
@app.route("/api/pages/<page_id>/conversations")
def api_list_conversations(page_id):
    token = session.get("user_access_token") or (load_tokens().get("user_long") or {}).get("access_token")
    if not token and not _env_get_tokens()[0].get(str(page_id)):
        return jsonify({"error": "NOT_LOGGED_IN"}), 401
    page_token = get_page_access_token(page_id, token or "")
    if not page_token: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
    fields = "id,link,updated_time,unread_count,participants,senders"
    data, st = graph_get(f"{page_id}/conversations", {"fields": fields, "limit": 20}, page_token, ttl=0, ctx_key=_ctx_key_for_page(page_id))
    return jsonify(data), st

@app.route("/api/pages/<page_id>/conversations/<thread_id>")
def api_get_conversation(page_id, thread_id):
    token = session.get("user_access_token") or (load_tokens().get("user_long") or {}).get("access_token")
    if not token and not _env_get_tokens()[0].get(str(page_id)):
        return jsonify({"error": "NOT_LOGGED_IN"}), 401
    page_token = get_page_access_token(page_id, token or "")
    if not page_token: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
    fields = "id,link,messages.limit(50){id,created_time,from,to,message,attachments,shares,permalink_url},participants"
    data, st = graph_get(thread_id, {"fields": fields}, page_token, ttl=0, ctx_key=_ctx_key_for_page(page_id))
    try:
        id2name = {}
        for pcp in (data.get("participants", {}) or {}).get("data", []) if isinstance(data, dict) else []:
            pid = pcp.get("id"); nm = pcp.get("name")
            if pid and nm: id2name[str(pid)] = nm
        msgs = (data.get("messages", {}) or {}).get("data", []) if isinstance(data, dict) else []
        for m in msgs:
            fr = m.get("from") or {}
            if fr.get("id") and not fr.get("name"):
                if str(fr["id"]) in id2name:
                    fr["name"] = id2name[str(fr["id"])]
                    m["from"] = fr
    except Exception:
        pass
    return jsonify(data), st

@app.route("/api/pages/<page_id>/messages", methods=["POST"])
def api_send_message(page_id):
    token = session.get("user_access_token") or (load_tokens().get("user_long") or {}).get("access_token")
    if not token and not _env_get_tokens()[0].get(str(page_id)):
        return jsonify({"error": "NOT_LOGGED_IN"}), 401
    page_token = get_page_access_token(page_id, token or "")
    if not page_token: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
    body = request.get_json(force=True)
    recipient_id = (body.get("recipient_id") or "").strip()
    text = (body.get("text") or "").strip()
    if not recipient_id or not text:
        return jsonify({"error":"MISSING_RECIPIENT_OR_TEXT"}), 400
    data = {
        "recipient": json.dumps({"id": recipient_id}),
        "message": json.dumps({"text": text}),
        "messaging_type": "RESPONSE"
    }
    res, st = graph_post(f"{page_id}/messages", data, page_token, ctx_key=_ctx_key_for_page(page_id))
    return jsonify(res), st

# ----------------------------
# AI writer & webhook/diagnostics
# ----------------------------
@app.route("/api/ai/generate", methods=["POST"])
def api_ai_generate():
    if not OPENAI_API_KEY:
        return jsonify({"error":"NO_OPENAI_API_KEY"}), 400
    body = request.get_json(force=True)
    prompt = (body.get("prompt") or "").strip()
    tone = (body.get("tone") or "thân thiện")
    length = (body.get("length") or "vừa")
    keyword = (body.get("keyword") or "MB66").strip()
    link = (body.get("link") or "").strip()
    if not prompt:
        prompt = f"Viết thân bài giới thiệu {keyword} ngắn gọn, khuyến khích truy cập link chính thức để đảm bảo an toàn và ổn định."
    try:
        sys = ("Bạn là copywriter mạng xã hội tiếng Việt. "
               f"Giọng {tone}, độ dài {length}. Viết tự nhiên, không hashtag, không chèn link.")
        user_prompt = f"Chủ đề: {prompt}\nNếu có link chính thức: {link}"
        headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
        payload = {"model": OPENAI_MODEL, "messages":[{"role":"system","content":sys},{"role":"user","content":user_prompt}], "temperature":0.8}
        r = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=60)
        if r.status_code >= 400:
            try: return jsonify({"error":"OPENAI_ERROR", "detail": r.json()}), r.status_code
            except Exception: return jsonify({"error":"OPENAI_ERROR", "detail": r.text}), r.status_code
        data = r.json()
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content","").strip()
        return jsonify({"text": text}), 200
    except Exception as e:
        return jsonify({"error":"OPENAI_EXCEPTION", "detail": str(e)}), 500

@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    if request.method == "GET":
        verify = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")
        if verify == SETTINGS.get("webhook_verify_token"):
            return challenge or "", 200
        return "Forbidden", 403
    try:
        data = request.get_json(force=True)
    except Exception:
        data = {"error": "invalid json"}
    SETTINGS["_last_events"].append({"ts": int(pytime.time()), "data": data})
    SETTINGS["_last_events"] = SETTINGS["_last_events"][-100:]
    return "ok", 200

@app.route("/webhook/events")
def webhook_events():
    return jsonify(SETTINGS.get("_last_events", [])[-20:]), 200

@app.route("/api/usage")
def api_usage():
    now = int(pytime.time())
    return jsonify({"cooldown_remaining": max(0, int(SETTINGS.get("cooldown_until",0) or 0) - now),
                    "last_usage": SETTINGS.get("last_usage", {}),
                    "poll_intervals": SETTINGS.get("poll_intervals")}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)


# =============== Diagnostics helpers ===============
def _safe_jsonify_error(e: Exception, tag: str):
    try:
        return jsonify({"error": tag, "detail": str(e)}), 500
    except Exception:
        return "internal error", 500

@app.route("/api/debug/page/<page_id>/has_token")
def api_debug_has_token(page_id):
    try:
        mp, _ = _env_get_tokens()
        env_has = str(page_id) in mp
        store = load_tokens()
        file_has = str(page_id) in (store.get("pages") or {})
        return jsonify({"env_has": env_has, "file_has": file_has}), 200
    except Exception as e:
        return _safe_jsonify_error(e, "DEBUG_EXCEPTION")

# Override endpoints with safer try/except wrappers
@app.route("/api/pages/<page_id>/conversations.safe")
def api_list_conversations_safe(page_id):
    try:
        token = session.get("user_access_token") or (load_tokens().get("user_long") or {}).get("access_token")
        if not token and not _env_get_tokens()[0].get(str(page_id)):
            return jsonify({"error": "NOT_LOGGED_IN"}), 401
        page_token = get_page_access_token(page_id, token or "")
        if not page_token: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
        fields = "id,link,updated_time,unread_count,participants,senders"
        data, st = graph_get(f"{page_id}/conversations", {"fields": fields, "limit": 20}, page_token, ttl=0, ctx_key=_ctx_key_for_page(page_id))
        return jsonify(data), st
    except Exception as e:
        return _safe_jsonify_error(e, "CONVERSATIONS_EXCEPTION")

@app.route("/api/pages/<page_id>/post.safe", methods=["POST"])
def api_post_to_page_safe(page_id):
    try:
        token = session.get("user_access_token") or (load_tokens().get("user_long") or {}).get("access_token")
        if not token and not _env_get_tokens()[0].get(str(page_id)):
            return jsonify({"error": "NOT_LOGGED_IN"}), 401
        body = request.get_json(force=True, silent=True) or {}
        message = (body.get("message") or "").strip()
        if not message: return jsonify({"error":"EMPTY_MESSAGE"}), 400
        if _recent_content_guard("post", page_id, message, within_sec=3600):
            return jsonify({"error":"DUPLICATE_MESSAGE"}), 429
        page_token = get_page_access_token(page_id, token or "")
        if not page_token: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
        data, status = graph_post(f"{page_id}/feed", {"message": message}, page_token, ctx_key=_ctx_key_for_page(page_id))
        return jsonify(data), status
    except Exception as e:
        return _safe_jsonify_error(e, "POST_EXCEPTION")
