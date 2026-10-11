// ═══════════════════════════════════
//  CIFER v4  ·  main.js
// ═══════════════════════════════════

const API = 'http://127.0.0.1:5000';

// ── CURSOR ──
const cur   = document.getElementById('cur');
const cring = document.getElementById('cring');
if(cur){
  let mx=0,my=0,rx=0,ry=0;
  document.addEventListener('mousemove', e=>{ mx=e.clientX; my=e.clientY; cur.style.left=mx+'px'; cur.style.top=my+'px'; });
  function ringAnim(){ rx+=(mx-rx)*.12; ry+=(my-ry)*.12; if(cring){ cring.style.left=rx+'px'; cring.style.top=ry+'px'; } requestAnimationFrame(ringAnim); }
  ringAnim();
  document.querySelectorAll('a,button,.btn,.upload-zone,.fil-btn,.toggle,.stat-card').forEach(el=>{
    el.addEventListener('mouseenter',()=>{ if(cring){cring.style.width='54px';cring.style.height='54px';cring.style.opacity='.9';} });
    el.addEventListener('mouseleave',()=>{ if(cring){cring.style.width='34px';cring.style.height='34px';cring.style.opacity='.55';} });
  });
}

// ── NAV TOGGLE ──
window.toggleMenu = () => {
  document.querySelector('.nav-links')?.classList.toggle('open');
  document.querySelector('.nav-right')?.classList.toggle('open');
};

// ── SCROLL FADE-UP ──
const io = new IntersectionObserver(entries=>{
  entries.forEach(e=>{ if(e.isIntersecting) e.target.classList.add('vis'); });
},{threshold:0.07});
document.querySelectorAll('.fade-up').forEach(el=>io.observe(el));

// ── PARTICLES ──
function spawnParticles(){
  const canvas=document.getElementById('bg-canvas');
  if(!canvas) return;
  const colors=['#3b9eff','#00d4ff','#6610f2','#0d6efd','#00e676'];
  for(let i=0;i<35;i++){
    const p=document.createElement('div');
    p.className='particle';
    const sz=1+Math.random()*2.5;
    p.style.cssText=`width:${sz}px;height:${sz}px;background:${colors[Math.floor(Math.random()*colors.length)]};left:${Math.random()*100}vw;bottom:-10px;animation-duration:${10+Math.random()*18}s;animation-delay:${Math.random()*18}s;border-radius:50%`;
    canvas.appendChild(p);
  }
}
spawnParticles();

// ── TOAST ──
window.toast = (msg,type='success',dur=3800)=>{
  const icons={success:'✅',danger:'❌',warning:'⚠️',info:'💠'};
  const c=document.getElementById('toast-container');
  if(!c)return;
  const t=document.createElement('div');
  t.className='toast';
  t.innerHTML=`<span class="toast-ico">${icons[type]||'💠'}</span><span style="flex:1">${msg}</span><button class="toast-x" onclick="rmToast(this.parentElement)">✕</button>`;
  c.appendChild(t);
  setTimeout(()=>rmToast(t),dur);
};
window.rmToast = el=>{ if(!el)return; el.classList.add('out'); setTimeout(()=>el.remove(),260); };

// ── MODAL ──
window.openModal = (title,body,onOk)=>{
  document.getElementById('global-modal')?.remove();
  const m=document.createElement('div');
  m.id='global-modal'; m.className='modal-bg';
  m.innerHTML=`<div class="modal-box"><button class="modal-x" onclick="closeModal()">✕</button><h3 style="font-family:var(--fh);font-size:.9rem;margin-bottom:1.2rem;color:var(--b1)">${title}</h3><div>${body}</div>${onOk?`<div style="display:flex;gap:.75rem;margin-top:1.5rem"><button class="btn btn-primary" style="flex:1" onclick="(${onOk})();closeModal()">Confirm</button><button class="btn btn-outline" style="flex:1" onclick="closeModal()">Cancel</button></div>`:''}</div>`;
  m.addEventListener('click',e=>{ if(e.target===m) closeModal(); });
  document.body.appendChild(m);
};
window.closeModal = ()=>{
  const m=document.getElementById('global-modal');
  if(m){m.style.animation='fadeOut .2s ease forwards';setTimeout(()=>m.remove(),200);}
};

// ── PW STRENGTH ──
window.pwStrength = (val,barId,lblId)=>{
  let s=0;
  if(val.length>=8)s+=30; if(val.length>=12)s+=15;
  if(/[A-Z]/.test(val))s+=20; if(/[0-9]/.test(val))s+=20; if(/[!@#$%^&*]/.test(val))s+=15;
  const b=document.getElementById(barId), l=document.getElementById(lblId);
  if(!b)return;
  b.style.width=Math.min(s,100)+'%';
  if(s<40){b.style.background='var(--danger)';if(l)l.textContent='Weak';}
  else if(s<70){b.style.background='var(--warn)';if(l)l.textContent='Medium';}
  else{b.style.background='var(--success)';if(l)l.textContent='Strong ✓';}
};

// ── OTP INPUT NAVIGATION ──
window.otpNext = (el,idx)=>{
  el.value=el.value.replace(/\D/,'');
  const inputs=document.querySelectorAll('.otp-row input');
  if(el.value&&idx<inputs.length-1) inputs[idx+1].focus();
};
window.otpBack = (e,idx)=>{
  if(e.key==='Backspace'){
    const inputs=document.querySelectorAll('.otp-row input');
    if(!inputs[idx].value&&idx>0){inputs[idx-1].value='';inputs[idx-1].focus();}
  }
};

// ── API helper ──
window.apiFetch = async(url,opts={})=>{
  const res = await fetch(API+url, {
    credentials:'include',
    headers:{'Content-Type':'application/json',...(opts.headers||{})},
    ...opts
  });
  return res;
};

// ── AUTH STATE ──
window.loadAuthState = async()=>{
  try{
    const res=await apiFetch('/api/me');
    const d=await res.json();
    const user_el=document.getElementById('nav-user');
    const auth_btns=document.getElementById('nav-auth-btns');
    const logout_btn=document.getElementById('nav-logout');
    if(d.logged_in){
      if(user_el) user_el.textContent=d.user.name;
      if(auth_btns) auth_btns.style.display='none';
      if(logout_btn) logout_btn.style.display='block';
    } else {
      if(user_el) user_el.textContent='';
      if(auth_btns) auth_btns.style.display='flex';
      if(logout_btn) logout_btn.style.display='none';
    }
    return d;
  }catch(e){ return {logged_in:false}; }
};

// ── LOGOUT ──
window.doLogout = async()=>{
  await apiFetch('/api/logout',{method:'POST'});
  toast('Logged out','info');
  setTimeout(()=>window.location.href=(window.location.pathname.includes('/pages/')?'':'')+'pages/login.html',600);
};

// Ripple effect
document.addEventListener('click',e=>{
  const btn=e.target.closest('.btn-primary,.btn-outline');
  if(!btn)return;
  const r=document.createElement('span');
  const rect=btn.getBoundingClientRect();
  r.style.cssText=`position:absolute;border-radius:50%;background:rgba(255,255,255,.2);width:4px;height:4px;left:${e.clientX-rect.left}px;top:${e.clientY-rect.top}px;transform:scale(0);animation:ripple .5s ease;pointer-events:none`;
  btn.style.position='relative';btn.style.overflow='hidden';
  btn.appendChild(r);setTimeout(()=>r.remove(),500);
});
const rippleStyle=document.createElement('style');
rippleStyle.textContent='@keyframes ripple{to{transform:scale(50);opacity:0}}@keyframes fadeOut{to{opacity:0}}';
document.head.appendChild(rippleStyle);

// Init
loadAuthState();
