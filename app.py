
import os, json, re
from typing import Any, Dict, Optional, Tuple
import requests
from flask import Flask, request, session, jsonify, render_template_string

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

GRAPH_BASE = "https://graph.facebook.com/v20.0"
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
ACCESS_PIN = (os.environ.get("ACCESS_PIN") or "").strip()
TOKENS_FILE = os.environ.get("TOKENS_FILE", "/etc/secrets/tokens.json")

# ----------------- PIN middleware -----------------
@app.before_request
def require_pin_for_api():
    if not ACCESS_PIN: return
    p = request.path or ""
    if not p.startswith("/api/"): return
    if p in ("/api/pin/status","/api/pin/login","/api/pin/logout"): return
    if not session.get("pin_ok"):
        return jsonify({"error":"PIN_REQUIRED"}), 401

@app.get("/api/pin/status")
def pin_status():
    return jsonify({"ok": bool(session.get("pin_ok")), "need_pin": bool(ACCESS_PIN)})

@app.post("/api/pin/login")
def pin_login():
    j = request.get_json(silent=True) or {}
    if not ACCESS_PIN or (j.get("pin","").strip() == ACCESS_PIN):
        session["pin_ok"] = True
        return jsonify({"ok": True})
    return jsonify({"error":"INVALID_PIN"}), 403

@app.post("/api/pin/logout")
def pin_logout():
    session.pop("pin_ok", None)
    return jsonify({"ok": True})

# ----------------- Token helpers -----------------
def load_tokens() -> Dict[str, Any]:
    try:
        if os.path.exists(TOKENS_FILE):
            with open(TOKENS_FILE,"r",encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def env_map_tokens():
    raw = (os.environ.get("PAGE_TOKENS") or "").strip()
    if not raw: return {}
    try:
        if raw.startswith("{"): 
            obj = json.loads(raw); 
            return obj if isinstance(obj, dict) else {}
    except Exception:
        pass
    mp = {}
    for line in re.split(r"[\n,]+", raw):
        line = line.strip()
        if not line: continue
        for sep in ("|",":","="):
            if sep in line:
                pid,tok = line.split(sep,1)
                mp[pid.strip()] = tok.strip()
                break
    return mp

def page_token_for(page_id: str) -> Optional[str]:
    mp = env_map_tokens()
    if str(page_id) in mp:
        return mp[str(page_id)]
    store = load_tokens()
    if "pages" in store and str(page_id) in (store["pages"] or {}):
        return store["pages"][str(page_id)]
    user_tok = (store.get("user_long") or {}).get("access_token") or ""
    if not user_tok: 
        return None
    data, st = graph_get("me/accounts", {"limit":200}, user_tok)
    if st != 200 or not isinstance(data, dict): 
        return None
    pages = {}
    for p in data.get("data", []):
        pid = str(p.get("id")); pat = p.get("access_token")
        if pid and pat: pages[pid] = pat
    if pages:
        store["pages"] = pages
        try:
            with open(TOKENS_FILE,"w",encoding="utf-8") as f: json.dump(store,f,ensure_ascii=False,indent=2)
        except Exception: pass
    return pages.get(str(page_id))

# ----------------- Graph helpers -----------------
def graph_get(path, params, token):
    url = f"{GRAPH_BASE}/{path}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = requests.get(url, params=params, headers=headers, timeout=60)
        if r.status_code >= 400:
            try: return r.json(), r.status_code
            except Exception: return {"error": r.text}, r.status_code
        return r.json(), 200
    except requests.RequestException as e:
        return {"error": str(e)}, 500

def graph_post(path, data, token):
    url = f"{GRAPH_BASE}/{path}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = requests.post(url, data=data, headers=headers, timeout=180)
        if r.status_code >= 400:
            try: return r.json(), r.status_code
            except Exception: return {"error": r.text}, r.status_code
        return r.json(), 200
    except requests.RequestException as e:
        return {"error": str(e)}, 500

def graph_post_multipart(path, files, form, token):
    url = f"{GRAPH_BASE}/{path}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = requests.post(url, files=files, data=form, headers=headers, timeout=600)
        if r.status_code >= 400:
            try: return r.json(), r.status_code
            except Exception: return {"error": r.text}, r.status_code
        return r.json(), 200
    except requests.RequestException as e:
        return {"error": str(e)}, 500

# ----------------- Classic UI (fixed) -----------------
CLASSIC_HTML = r"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Facebook Page Manager (Classic Fixed)</title>
<style>
 body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#f5f6f7}
 .wrap{max-width:1100px;margin:18px auto;padding:0 16px}
 h1{font-size:20px;margin:0 0 10px}
 .tabs{display:flex;gap:8px;margin-bottom:10px}
 .tab{padding:8px 12px;border-radius:999px;border:1px solid #e4e7ec;background:#fff;cursor:pointer}
 .tab.active{background:#1976d2;color:#fff;border-color:#1976d2}
 .row{display:flex;gap:12px;flex-wrap:wrap}
 .col{flex:1 1 420px;min-width:320px}
 .card{background:#fff;border:1px solid #e4e7ec;border-radius:10px;padding:12px}
 textarea,input,select,button{font:inherit}
 textarea,input,select{width:100%;padding:10px;border:1px solid #e4e7ec;border-radius:8px}
 .toolbar{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap}
 /* ---- List chuẩn: 1 dòng + checkbox cố định ---- */
 .list{border:1px dashed #e4e7ec;border-radius:8px;padding:6px;background:#fafafa;
       max-height:320px;overflow:auto}
 .item{display:flex;align-items:center;gap:10px;padding:8px 10px;border-bottom:1px dashed #eee}
 .item:last-child{border-bottom:none}
 .item .name{flex:1 1 auto;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
 .item .tick{flex:0 0 36px;display:flex;justify-content:flex-end}
 .item input[type="checkbox"]{ width:22px;height:22px }
 .status{color:#6b7280;font-size:12px;margin-top:6px}
 .btn{padding:8px 12px;border:1px solid #e4e7ec;border-radius:8px;background:#fff;cursor:pointer}
 .btn.primary{background:#1976d2;color:#fff;border-color:#1976d2}
 /* ---- Chat bubbles ---- */
 #msg_list{max-height:420px;overflow:auto;padding:10px;background:#fafafa;border-radius:8px}
 .msg{display:flex;margin:6px 0}
 .msg .bubble{max-width:80%;padding:10px 12px;border-radius:14px;line-height:1.35;word-break:break-word;box-shadow:0 1px 0 rgba(0,0,0,.04)}
 .msg.other{justify-content:flex-start}
 .msg.other .bubble{background:#fff;border:1px solid #e4e7ec}
 .msg.me{justify-content:flex-end}
 .msg.me .bubble{background:#1976d2;color:#fff}
 .msg .meta{font-size:11px;color:#6b7280;margin-top:4px}
 /* PIN overlay */
 #pin_overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;align-items:center;justify-content:center;z-index:9999}
 #pin_box{background:#fff;border-radius:12px;padding:16px;min-width:300px}
 @media (max-width:480px){
   .item{padding:8px}
   .item .tick{flex-basis:30px}
   .msg .bubble{max-width:88%}
 }
</style>
</head>
<body>
<div class="wrap">
  <h1>Facebook Page Manager (Completed)</h1>
  <div class="tabs">
    <button id="tab-posts" class="tab active">Đăng bài</button>
    <button id="tab-inbox" class="tab">Tin nhắn</button>
  </div>

  <div id="panel-posts">
    <div class="row">
      <div class="col">
        <div class="card">
          <h3>Fanpage</h3>
          <div id="pages" class="list"></div>
          <div id="pages_status" class="status"></div>
        </div>

        <div class="card" style="margin-top:12px">
          <h3>AI soạn nội dung</h3>
          <textarea id="ai_prompt" rows="4" placeholder="Gợi ý chủ đề, ưu đãi, CTA..."></textarea>
          <div class="toolbar">
            <input id="ai_keyword" placeholder="Từ khoá chính (VD: MB66)"/>
            <input id="ai_link" placeholder="Link chính thức (VD: https://...)"/>
          </div>
          <div class="toolbar">
            <select id="ai_tone">
              <option value="thân thiện">Giọng: Thân thiện</option>
              <option value="chuyên nghiệp">Chuyên nghiệp</option>
              <option value="hào hứng">Hào hứng</option>
              <option value="điềm đạm">Điềm đạm</option>
            </select>
            <select id="ai_length">
              <option value="ngắn">Ngắn</option>
              <option value="vừa">Vừa</option>
              <option value="dài">Dài</option>
            </select>
            <button id="btn_ai" class="btn">Tạo nội dung</button>
            <span class="status">Cần OPENAI_API_KEY</span>
          </div>
          <div id="ai_status" class="status"></div>
        </div>
      </div>

      <div class="col">
        <div class="card">
          <h3>Đăng nội dung</h3>
          <textarea id="post_text" rows="7" placeholder="Nội dung bài viết..."></textarea>
          <div class="toolbar">
            <label for="post_type">Loại</label>
            <select id="post_type"><option value="feed">Feed</option><option value="reels">Reels</option></select>
            <input type="file" id="video_input" accept="video/*"/>
          </div>
          <div class="toolbar">
            <input type="file" id="photo_input" accept="image/*"/>
            <input type="text" id="media_caption" placeholder="Caption (tuỳ chọn)"/>
          </div>
          <div class="toolbar">
            <button id="btn_publish" class="btn primary">Đăng</button>
          </div>
          <div id="post_status" class="status"></div>
        </div>
      </div>
    </div>
  </div>

  <div id="panel-inbox" style="display:none">
    <div class="row">
      <div class="col">
        <div class="card">
          <h3>Chọn Page</h3>
          <select id="inbox_page"></select>
          <div class="toolbar"><button id="btn_load_conv" class="btn">Tải hội thoại</button></div>
          <div id="conv_list" class="list" style="margin-top:8px"></div>
        </div>
      </div>
      <div class="col">
        <div class="card">
          <h3>Hội thoại</h3>
          <div id="msg_list" class="list" style="min-height:240px"></div>
          <div class="toolbar">
            <input id="msg_text" placeholder="Nhập tin nhắn..."/>
            <button id="btn_send" class="btn primary">Gửi</button>
          </div>
          <div id="inbox_status" class="status"></div>
        </div>
      </div>
    </div>
  </div>
</div>

<div id="pin_overlay">
  <div id="pin_box">
    <h3>Nhập PIN để truy cập</h3>
    <input id="pin_input" type="password" placeholder="PIN"/>
    <div class="toolbar"><button id="btn_pin_ok" class="btn primary">Xác nhận</button></div>
    <div id="pin_status" class="status"></div>
  </div>
</div>

<script>
const $ = (s)=>document.querySelector(s);
const sleep = (ms)=>new Promise(r=>setTimeout(r,ms));

function showTab(name){
  ['posts','inbox'].forEach(id=>{
    const t=document.getElementById('tab-'+id);
    const p=document.getElementById('panel-'+id);
    if(t) t.classList.toggle('active', id===name);
    if(p) p.style.display = (id===name)?'block':'none';
  });
}
$('#tab-posts')?.addEventListener('click', ()=>showTab('posts'));
$('#tab-inbox')?.addEventListener('click', ()=>{ showTab('inbox'); loadPagesToSelect('inbox_page'); });

async function ensurePin(){
  try{
    const r = await fetch('/api/pin/status'); const d = await r.json();
    if(d.need_pin && !d.ok){ $('#pin_overlay').style.display='flex'; }
  }catch(e){}
}
$('#btn_pin_ok').onclick = async ()=>{
  const pin = ($('#pin_input').value||'').trim();
  const r = await fetch('/api/pin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin})});
  const d = await r.json();
  if(d.ok){ $('#pin_overlay').style.display='none'; loadPages(); } else { $('#pin_status').textContent='PIN sai'; }
};

// ----- Pages -----
const pagesBox = $('#pages'), pagesStatus = $('#pages_status');
async function loadPages(){
  pagesBox.innerHTML='<div class="status">Đang tải...</div>';
  try{
    const r = await fetch('/api/pages'); const d = await r.json();
    if(d.error){ pagesStatus.textContent = JSON.stringify(d); return; }
    const arr = d.data || [];
    pagesBox.innerHTML = arr.map(p => `
      <div class="item">
        <div class="name" title="${(p.name||'').replaceAll('"','&quot;')}">${p.name||''}</div>
        <div class="tick">
          <input type="checkbox" class="pg" value="${p.id}" data-name="${(p.name||'').replaceAll('"','&quot;')}">
        </div>
      </div>`).join('');
    pagesStatus.textContent='Tải '+arr.length+' page.';
  }catch(e){ pagesStatus.textContent='Lỗi tải danh sách page'; }
}
function selectedPageIds(){ return Array.from(document.querySelectorAll('.pg:checked')).map(i=>i.value); }
async function loadPagesToSelect(id){
  try{
    const r = await fetch('/api/pages'); const d = await r.json(); const arr = d.data || [];
    $('#'+id).innerHTML = '<option value="">--Chọn page--</option>' + arr.map(p=>'<option value="'+p.id+'">'+p.name+'</option>').join('');
  }catch(e){ $('#'+id).innerHTML='<option>Lỗi tải page</option>'; }
}

// ----- AI Writer -----
$('#btn_ai').onclick = async () => {
  const prompt  = ($('#ai_prompt').value||'').trim();
  const keyword = ($('#ai_keyword').value||'').trim();
  const link    = ($('#ai_link').value||'').trim();
  const tone    = $('#ai_tone').value;
  const length  = $('#ai_length').value;
  const st = $('#ai_status');
  if(!OPENAI_API_KEY_PLACEHOLDER){ st.textContent='Cần OPENAI_API_KEY trên server'; return; }
  st.textContent='Đang tạo nội dung...';
  try{
    const r = await fetch('/api/ai/generate', {method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({prompt, keyword, link, tone, length})});
    const d = await r.json();
    if(d.error){ st.textContent='Lỗi: '+(d.detail||d.error); return; }
    $('#post_text').value = d.text || '';
    st.textContent='Đã chèn nội dung vào khung soạn.';
  }catch(e){ st.textContent='Lỗi gọi AI'; }
};

// ----- Publish -----
$('#btn_publish').onclick = async () => {
  const pages = selectedPageIds();
  const text = ($('#post_text').value||'').trim();
  const type = $('#post_type').value;
  const photo = $('#photo_input').files[0]||null;
  const video = $('#video_input').files[0]||null;
  const caption = ($('#media_caption').value||'');
  const st = $('#post_status');

  if(!pages.length){ st.textContent='Chọn ít nhất một page'; return; }
  if(type==='feed' && !text && !photo && !video){ st.textContent='Cần nội dung hoặc tệp'; return; }
  if(type==='reels' && !video){ st.textContent='Cần chọn video cho Reels'; return; }

  st.textContent='Đang đăng...';
  try{
    const results = [];
    for(const pid of pages){
      let d;
      if(type==='feed'){
        if(video){
          const fd=new FormData(); fd.append('video', video); fd.append('description', caption||text||'');
          d = await (await fetch('/api/pages/'+pid+'/video',{method:'POST',body:fd})).json();
        }else if(photo){
          const fd=new FormData(); fd.append('photo', photo); fd.append('caption', caption||text||'');
          d = await (await fetch('/api/pages/'+pid+'/photo',{method:'POST',body:fd})).json();
        }else{
          d = await (await fetch('/api/pages/'+pid+'/post',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:text})})).json();
        }
      }else{
        const fd=new FormData(); fd.append('video', video); fd.append('description', caption||text||'');
        d = await (await fetch('/api/pages/'+pid+'/reel',{method:'POST',body:fd})).json();
      }
      if(d.error){ results.push('❌ '+pid+': '+JSON.stringify(d)); }
      else{ results.push('✅ '+pid+(d.permalink_url?(' · <a target="_blank" href="'+d.permalink_url+'">Mở bài</a>'):'') ); }
      await sleep(800);
    }
    st.innerHTML = results.join('<br/>');
  }catch(e){ st.textContent='Lỗi đăng'; }
};

// ----- Inbox -----
let currentThread=null, currentRecipient=null;
$('#btn_load_conv').onclick = async ()=>{
  const pid = $('#inbox_page').value, st=$('#inbox_status');
  if(!pid){ st.textContent='Chưa chọn page'; return; }
  st.textContent='Đang tải hội thoại...';
  try{
    const d = await (await fetch('/api/pages/'+pid+'/conversations')).json();
    if(d.error){ st.textContent='Lỗi: '+JSON.stringify(d); return; }
    const arr = d.data||[];
    $('#conv_list').innerHTML = arr.map(cv=>{
      let label=cv.id;
      try{ const parts=(cv.participants&&cv.participants.data)||[]; const other=parts.find(p=>p.id!==pid); if(other&&other.name) label=other.name; }catch(_){}
      return '<div class="item"><a href="#" class="open-thread" data-id="'+cv.id+'">'+label+'</a><span>'+(cv.updated_time||'')+'</span></div>';
    }).join('');
    $('#conv_list').querySelectorAll('.open-thread').forEach(a=>a.addEventListener('click', async (e)=>{e.preventDefault(); await openThread(pid, a.getAttribute('data-id'));}));
    st.textContent='Đã tải '+arr.length+' hội thoại.';
  }catch(e){ st.textContent='Lỗi tải hội thoại'; }
};
async function openThread(pageId, threadId){
  const st=$('#inbox_status'); st.textContent='Đang tải tin nhắn...';
  try{
    const d = await (await fetch('/api/pages/'+pageId+'/conversations/'+threadId)).json();
    if(d.error){ st.textContent='Lỗi: '+JSON.stringify(d); return; }
    const msgs=((d.messages||{}).data)||[];
    currentThread=threadId; let rec=null;
    for(const m of msgs){
      const tos=((m.to||{}).data)||[]; const fr=m.from||{};
      for(const t of tos){ if(t.id!==pageId){ rec=t.id; break; } }
      if(!rec and fr.get('id')!=pageId): pass
      if(not rec and fr.get('id')!=pageId): rec = fr.get('id')
      if(rec): break
    }
    // Python code accidentally included in JS above; fix JS below
  }catch(e){ st.textContent='Lỗi tải tin nhắn'; }
}
</script>
</body>
</html>
"""

# BUG: The above JS accidentally included Python-like syntax. Let's fix by patching the block.
CLASSIC_HTML = CLASSIC_HTML.replace(
    "for(const m of msgs){\n      const tos=((m.to||{}).data)||[]; const fr=m.from||{};\n      for(const t of tos){ if(t.id!==pageId){ rec=t.id; break; } }\n      if(!rec and fr.get('id')!=pageId): pass\n      if(not rec and fr.get('id')!=pageId): rec = fr.get('id')\n      if(rec): break\n    }\n    // Python code accidentally included in JS above; fix JS below\n  }catch(e){ st.textContent='Lỗi tải tin nhắn'; }\n}\n</script>",
    """for(const m of msgs){
      const tos=((m.to||{}).data)||[]; const fr=m.from||{};
      for(const t of tos){ if(t.id!==pageId){ rec=t.id; break; } }
      if(!rec && fr.id!==pageId){ rec = fr.id; }
      if(rec) break;
    }
    currentRecipient=rec;
    const fmt=(i)=>{ try{return new Date(i).toLocaleString();}catch(_){return i||'';} };
    document.querySelector('#msg_list').innerHTML = msgs.map(m=>{
      const fromId=(m.from&&m.from.id)||''; const fromName=(m.from&&(m.from.name||m.from.id))||(fromId||'Unknown');
      const text=(m.message||'[attachment]'); const time=fmt(m.created_time||'');
      const side=(fromId===pageId)?'me':'other';
      return `<div class="msg ${side}"><div><div class="bubble">${text}</div><div class="meta">${fromName} · ${time}</div></div></div>`;
    }).join('');
    st.textContent='Đã tải '+msgs.length+' tin nhắn.'+(currentRecipient?'':' (Chưa xác định người nhận)');
  }catch(e){ st.textContent='Lỗi tải tin nhắn'; }
}
</script>"""
)

@app.get("/")
def index():
    return render_template_string(CLASSIC_HTML.replace("OPENAI_API_KEY_PLACEHOLDER", "1" if OPENAI_API_KEY else ""))

# ----------------- API endpoints -----------------
def _get_user_token():
    store = load_tokens()
    return (store.get("user_long") or {}).get("access_token") or ""

@app.get("/api/pages")
def api_pages():
    user_tok = _get_user_token()
    if user_tok:
        data, st = graph_get("me/accounts", {"limit":200}, user_tok)
        if st == 200 and isinstance(data, dict): 
            return jsonify(data), 200
    mp = env_map_tokens()
    if mp:
        pages = []
        for pid, tok in mp.items():
            name = ""
            try:
                resp, s = graph_get(str(pid), {"fields":"name"}, tok)
                if s == 200 and isinstance(resp, dict): name = resp.get("name","")
            except Exception: pass
            pages.append({"id": str(pid), "name": name or str(pid), "access_token": tok})
        return jsonify({"data": pages}), 200
    return jsonify({"error":"NOT_LOGGED_IN"}), 401

@app.post("/api/pages/<page_id>/post")
def api_post(page_id):
    body = request.get_json(silent=True) or {}
    msg = (body.get("message") or "").strip()
    if not msg: return jsonify({"error":"EMPTY_MESSAGE"}), 400
    tok = page_token_for(page_id)
    if not tok: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
    data, st = graph_post(f"{page_id}/feed", {"message": msg}, tok)
    try:
        if st==200 and isinstance(data,dict) and data.get("id"):
            d2, s2 = graph_get(data["id"], {"fields":"permalink_url"}, tok)
            if s2==200 and isinstance(d2,dict) and d2.get("permalink_url"): data["permalink_url"]=d2["permalink_url"]
    except Exception: pass
    return jsonify(data), st

@app.post("/api/pages/<page_id>/photo")
def api_photo(page_id):
    if "photo" not in request.files: return jsonify({"error":"MISSING_PHOTO"}), 400
    tok = page_token_for(page_id)
    if not tok: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
    file = request.files["photo"]; cap = request.form.get("caption","")
    files = {"source": (file.filename, file.stream, file.mimetype or "application/octet-stream")}
    form = {"caption": cap, "published": "true"}
    data, st = graph_post_multipart(f"{page_id}/photos", files, form, tok)
    return jsonify(data), st

@app.post("/api/pages/<page_id>/video")
def api_video(page_id):
    if "video" not in request.files: return jsonify({"error":"MISSING_VIDEO"}), 400
    tok = page_token_for(page_id)
    if not tok: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
    file = request.files["video"]; desc = request.form.get("description","")
    files = {"source": (file.filename, file.stream, file.mimetype or "application/octet-stream")}
    form = {"description": desc}
    data, st = graph_post_multipart(f"{page_id}/videos", files, form, tok)
    try:
        if st==200 and isinstance(data,dict):
            vid = data.get("id") or data.get("video_id")
            if vid:
                d2, s2 = graph_get(str(vid), {"fields":"permalink_url"}, tok)
                if s2==200 and isinstance(d2,dict) and d2.get("permalink_url"): data["permalink_url"]=d2["permalink_url"]
    except Exception: pass
    return jsonify(data), st

@app.post("/api/pages/<page_id>/reel")
def api_reel(page_id):
    if "video" not in request.files: return jsonify({"error":"MISSING_VIDEO"}), 400
    tok = page_token_for(page_id)
    if not tok: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
    file = request.files["video"]; desc = request.form.get("description","")
    files={"source":(file.filename, file.stream, file.mimetype or "application/octet-stream")}
    form={"description":desc, "upload_phase": None}
    data, st = graph_post_multipart(f"{page_id}/videos", files, form, tok)
    return jsonify(data), st

@app.get("/api/pages/<page_id>/conversations")
def api_conversations(page_id):
    tok = page_token_for(page_id)
    if not tok: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
    fields="id,link,updated_time,unread_count,participants,senders"
    data, st = graph_get(f"{page_id}/conversations", {"fields":fields,"limit":20}, tok)
    return jsonify(data), st

@app.get("/api/pages/<page_id>/conversations/<thread_id>")
def api_conv_detail(page_id, thread_id):
    tok = page_token_for(page_id)
    if not tok: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
    fields="id,link,messages.limit(50){id,created_time,from,to,message,attachments,shares,permalink_url},participants"
    data, st = graph_get(thread_id, {"fields": fields}, tok)
    return jsonify(data), st

@app.post("/api/pages/<page_id>/messages")
def api_send_message(page_id):
    tok = page_token_for(page_id)
    if not tok: return jsonify({"error":"NO_PAGE_TOKEN"}), 403
    j = request.get_json(silent=True) or {}
    rid = (j.get("recipient_id") or "").strip()
    text = (j.get("text") or "").strip()
    if not rid or not text: return jsonify({"error":"MISSING_RECIPIENT_OR_TEXT"}), 400
    payload = {"recipient": json.dumps({"id": rid}), "message": json.dumps({"text": text}), "messaging_type":"RESPONSE"}
    data, st = graph_post(f"{page_id}/messages", payload, tok)
    return jsonify(data), st

# ---------- AI ----------
@app.post("/api/ai/generate")
def api_ai_generate():
    if not OPENAI_API_KEY: return jsonify({"error":"NO_OPENAI_API_KEY"}), 400
    j = request.get_json(silent=True) or {}
    prompt = (j.get("prompt") or "").strip()
    tone = j.get("tone","thân thiện"); length = j.get("length","vừa")
    keyword = (j.get("keyword") or "MB66").strip(); link=(j.get("link") or "").strip()
    if not prompt: prompt=f"Viết thân bài giới thiệu {keyword} ngắn gọn, khuyến khích truy cập link chính thức để đảm bảo an toàn."
    sys = f"Bạn là copywriter mạng xã hội tiếng Việt. Giọng {tone}, độ dài {length}. Không dùng hashtag."
    user = f"Chủ đề: {prompt}\nLink chính thức (nếu có): {link}"
    try:
        r = requests.post("https://api.openai.com/v1/chat/completions",
                          headers={"Authorization": f"Bearer {OPENAI_API_KEY}","Content-Type":"application/json"},
                          json={"model": OPENAI_MODEL, "messages":[{"role":"system","content":sys},{"role":"user","content":user}],"temperature":0.8},
                          timeout=60)
        if r.status_code >= 400:
            try: return jsonify({"error":"OPENAI_ERROR","detail":r.json()}), r.status_code
            except Exception: return jsonify({"error":"OPENAI_ERROR","detail":r.text}), r.status_code
        data = r.json()
        text = (data.get("choices") or [{}])[0].get("message",{}).get("content","").strip()
        return jsonify({"text": text}), 200
    except Exception as e:
        return jsonify({"error":"OPENAI_EXCEPTION","detail": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False, use_reloader=False)
