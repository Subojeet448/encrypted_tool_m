import { useState, useCallback, useEffect, useRef } from "react";
import Head from "next/head";

/* ═══════════════════════════════════════════════
   CONSTANTS
═══════════════════════════════════════════════ */
const DEVELOPER  = "Subojeet Mandal";
const LS_NAME    = "aescrypt_username";
const LS_THEME   = "aescrypt_theme";
const LS_RGB     = "aescrypt_rgb";
const LS_COLOR   = "aescrypt_color";
const LS_PW_PFX  = "aescrypt_pw_";
const MIN_PW     = 6;

const PRESET_COLORS = [
  "#C8FF00","#00FFEA","#FF4D6D","#FF9F1C","#A78BFA","#38BDF8","#F472B6","#34D399"
];

/* ═══════════════════════════════════════════════
   CRYPTO
═══════════════════════════════════════════════ */
async function deriveKey(pass, salt) {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
    raw, { name: "AES-GCM", length: 256 }, false, ["encrypt","decrypt"]
  );
}
function toB64(bytes) {
  let b = "";
  for (let i = 0; i < bytes.length; i++) b += String.fromCharCode(bytes[i]);
  return btoa(b).replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"");
}
function fromB64(s) {
  s = s.trim().replace(/-/g,"+").replace(/_/g,"/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function encryptFull(text, pass) {
  if (!text.trim()) throw new Error("Message khali hai");
  if (pass.length < MIN_PW) throw new Error(`Password kam se kam ${MIN_PW} characters ka hona chahiye`);
  const enc  = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(pass, salt);
  const ct   = await crypto.subtle.encrypt({ name:"AES-GCM", iv, tagLength:128 }, key, enc.encode(text.trim()));
  const cb   = new Uint8Array(ct);
  const pk   = new Uint8Array(28 + cb.length);
  pk.set(salt,0); pk.set(iv,16); pk.set(cb,28);
  return toB64(pk);
}
async function decryptFull(b64, pass) {
  if (!b64.trim()) throw new Error("Encrypted text khali hai");
  if (!pass.trim()) throw new Error("Password dalo");
  let pk;
  try { pk = fromB64(b64); } catch { throw new Error("Invalid Base64 format"); }
  if (pk.length < 44) throw new Error("Data corrupted ya incomplete hai");
  const key = await deriveKey(pass, pk.slice(0,16));
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name:"AES-GCM", iv:pk.slice(16,28), tagLength:128 }, key, pk.slice(28));
  } catch { throw new Error("Decryption failed — galat password ya tampered data"); }
  return new TextDecoder("utf-8",{fatal:true}).decode(plain);
}

/* ═══════════════════════════════════════════════
   PASSWORD HELPERS
═══════════════════════════════════════════════ */
function rndPick(cs, n) {
  return Array.from(crypto.getRandomValues(new Uint8Array(n))).map(b => cs[b%cs.length]).join("");
}
function genPass(len) {
  const L="abcdefghijklmnopqrstuvwxyz", U="ABCDEFGHIJKLMNOPQRSTUVWXYZ", D="0123456789", S="!@#$%^&*-_+=?";
  const base = rndPick(U,2)+rndPick(L,3)+rndPick(D,3)+rndPick(S,2);
  const rest = rndPick(L+U+D+S, len-base.length);
  const arr  = (base+rest).split("");
  const rnd  = crypto.getRandomValues(new Uint32Array(arr.length));
  for (let i=arr.length-1;i>0;i--){const j=rnd[i]%(i+1);[arr[i],arr[j]]=[arr[j],arr[i]];}
  return arr.join("");
}
function strength(pw) {
  if (!pw) return {s:0,l:"",c:"#3A3F55"};
  let s=0;
  if(pw.length>=8)s++; if(pw.length>=12)s++;
  if(/[A-Z]/.test(pw)&&/[a-z]/.test(pw))s++;
  if(/[0-9]/.test(pw))s++;
  if(/[^A-Za-z0-9]/.test(pw))s++;
  return [{s:0,l:"Very Weak",c:"#FF4444"},{s:1,l:"Weak",c:"#FF9F1C"},{s:2,l:"Fair",c:"#FFD93D"},{s:3,l:"Strong",c:"#6BCB77"},{s:4,l:"Very Strong",c:"#C8FF00"}][Math.min(s,4)];
}

/* ═══════════════════════════════════════════════
   RGB ANIMATION HOOK
═══════════════════════════════════════════════ */
function useRGB(enabled) {
  const [col, setCol] = useState("#C8FF00");
  const ref = useRef(null);
  useEffect(() => {
    if (!enabled) { if(ref.current) cancelAnimationFrame(ref.current); return; }
    let h = 0;
    const tick = () => {
      h = (h+0.4)%360;
      setCol(`hsl(${h},100%,55%)`);
      ref.current = requestAnimationFrame(tick);
    };
    ref.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(ref.current);
  }, [enabled]);
  return col;
}

/* ═══════════════════════════════════════════════
   COMPONENT
═══════════════════════════════════════════════ */
export default function Home() {
  /* theme */
  const [dark,    setDark]    = useState(true);
  const [rgb,     setRgb]     = useState(false);
  const [accent,  setAccent]  = useState("#C8FF00");
  const [username,setUsername]= useState("S - MANDAL");
  /* settings panel */
  const [settOpen,setSettOpen]= useState(false);
  const [locked,  setLocked]  = useState(false);
  const [lockPIN, setLockPIN] = useState("");
  const [pinInput,setPinInput]= useState("");
  const [pinErr,  setPinErr]  = useState(false);
  /* crypto */
  const [mode,    setMode]    = useState("encrypt");
  const [pwMode,  setPwMode]  = useState("manual");
  const [autoLen, setAutoLen] = useState(14);
  const [password,setPassword]= useState("");
  const [showPw,  setShowPw]  = useState(false);
  const [input,   setInput]   = useState("");
  const [output,  setOutput]  = useState("");
  const [error,   setError]   = useState("");
  const [info,    setInfo]    = useState("");
  const [loading, setLoading] = useState(false);
  const [outCopied,setOutCopied]=useState(false);
  const [pwCopied, setPwCopied] =useState(false);
  const [saved,   setSaved]   = useState(false);
  /* editing username */
  const [editName,setEditName]=useState(false);
  const [tmpName, setTmpName] =useState("");

  const rgbColor = useRGB(rgb);
  const ac = rgb ? rgbColor : accent;
  const str = strength(password);

  /* load saved prefs */
  useEffect(()=>{
    try {
      const n=localStorage.getItem(LS_NAME); if(n) setUsername(n);
      const t=localStorage.getItem(LS_THEME); if(t) setDark(t==="dark");
      const r=localStorage.getItem(LS_RGB); if(r) setRgb(r==="1");
      const c=localStorage.getItem(LS_COLOR); if(c) setAccent(c);
    } catch{}
  },[]);

  function savePrefs(updates={}) {
    try {
      const n=updates.name??username; const t=updates.dark??dark; const r=updates.rgb??rgb; const c=updates.color??accent;
      localStorage.setItem(LS_NAME,n);
      localStorage.setItem(LS_THEME,t?"dark":"light");
      localStorage.setItem(LS_RGB,r?"1":"0");
      localStorage.setItem(LS_COLOR,c);
    } catch{}
  }

  function flash(msg,type="info"){
    if(type==="info") setInfo(msg); else setError(msg);
    setTimeout(()=>{setInfo("");setError("");},3500);
  }

  /* username */
  const startEditName=()=>{ setTmpName(username); setEditName(true); };
  const saveName=()=>{
    const n=tmpName.trim()||username;
    setUsername(n); setEditName(false);
    savePrefs({name:n}); flash("✅ Name save ho gaya");
  };

  /* theme toggles */
  const toggleDark=()=>{ const v=!dark; setDark(v); savePrefs({dark:v}); };
  const toggleRgb=()=>{ const v=!rgb; setRgb(v); savePrefs({rgb:v}); };
  const setColor=(c)=>{ setAccent(c); savePrefs({color:c}); };

  /* lock */
  const tryUnlock=()=>{
    if(!lockPIN||pinInput===lockPIN){ setLocked(false); setPinInput(""); setPinErr(false); }
    else { setPinErr(true); setTimeout(()=>setPinErr(false),1500); }
  };

  /* password */
  const handleGen=useCallback(()=>{
    const pw=genPass(autoLen); setPassword(pw); setShowPw(false);
    flash(`⚡ ${autoLen}-char strong password generate ho gaya`);
  },[autoLen]);

  const savePw=()=>{
    if(!password){flash("Pehle password type karo","err");return;}
    try{ localStorage.setItem(LS_PW_PFX+"user",password); setSaved(true); flash("💾 Password browser mein save ho gaya"); setTimeout(()=>setSaved(false),3000); }
    catch{ flash("Save failed — localStorage blocked","err"); }
  };
  const copyPw=async()=>{ if(!password)return; await navigator.clipboard.writeText(password); setPwCopied(true); setTimeout(()=>setPwCopied(false),2000); };
  const copyOut=async()=>{ if(!output)return; await navigator.clipboard.writeText(output); setOutCopied(true); setTimeout(()=>setOutCopied(false),2000); };

  /* load saved pw */
  useEffect(()=>{
    try{ const p=localStorage.getItem(LS_PW_PFX+"user"); if(p) setPassword(p); }catch{}
  },[]);

  function validate(){
    if(!password.trim()) return "Password dalo — zaruri hai";
    if(password.trim().length<MIN_PW) return `Password kam se kam ${MIN_PW} characters ka hona chahiye`;
    if(!input.trim()) return "Message khali hai";
    if(mode==="decrypt"){
      try{ const b=fromB64(input.trim()); if(b.length<44) return "Valid encrypted text nahi lagta"; }
      catch{ return "Valid Base64 encrypted string nahi hai"; }
    }
    return null;
  }

  const handleProcess=useCallback(async()=>{
    setError("");setOutput("");setInfo("");
    const e=validate(); if(e){setError(e);return;}
    setLoading(true);
    try{
      if(mode==="encrypt"){
        setInfo("🔐 AES-256-GCM encryption chal rahi hai…");
        const r=await encryptFull(input,password);
        setOutput(r); setInfo("✅ Encrypted! Base64 output ready.");
        setTimeout(()=>setInfo(""),4000);
      } else {
        setInfo("📦 Base64 decode + AES-GCM decryption…");
        const r=await decryptFull(input,password);
        setOutput(r); setInfo("✅ Decryption successful!");
        setTimeout(()=>setInfo(""),4000);
      }
    } catch(err){ setError("❌ "+err.message); setInfo(""); }
    setLoading(false);
  // eslint-disable-next-line
  },[input,password,mode]);

  const clearAll=()=>{setInput("");setOutput("");setError("");setInfo("");};

  /* ─── STYLES ─────────────────────────────── */
  const bg   = dark?"#07080D":"#F0F2F8";
  const sf   = dark?"#0D0F17":"#FFFFFF";
  const sf2  = dark?"#11141F":"#F5F7FF";
  const bd   = dark?"#1C2030":"#D8DCF0";
  const tx   = dark?"#D4D8EF":"#1A1D2E";
  const dim  = dark?"#3A3F55":"#8890B0";

  return (
    <>
      <Head>
        <title>AESCRYPT — Military Grade Encryption</title>
        <meta name="description" content="AES-256-GCM + Base64 Double Layer Encryption by Subojeet Mandal" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;700&family=Bebas+Neue&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
      </Head>

      <style>{`
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
        html{scroll-behavior:smooth}
        body{
          background:${bg};color:${tx};
          font-family:'Inter',sans-serif;
          min-height:100vh;overflow-x:hidden;
          transition:background .3s,color .3s;
        }
        ${dark?`body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
          background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(200,255,0,0.005) 3px,rgba(200,255,0,0.005) 4px)}`:""}
        .mono{font-family:'IBM Plex Mono',monospace}
        .disp{font-family:'Bebas Neue',cursive}
        .wrap{position:relative;z-index:1;max-width:720px;margin:0 auto;padding:0 16px 80px}

        /* TOP BAR */
        .topbar{
          position:sticky;top:0;z-index:100;
          display:flex;align-items:center;justify-content:space-between;
          padding:14px 20px;
          background:${dark?"rgba(7,8,13,0.92)":"rgba(240,242,248,0.92)"};
          backdrop-filter:blur(12px);
          border-bottom:1px solid ${bd};
          gap:12px;
        }
        .top-name{
          font-family:'Bebas Neue',cursive;
          font-size:1.6rem;letter-spacing:3px;
          color:${ac};
          text-shadow:0 0 20px ${ac}66;
          cursor:pointer;transition:all .2s;
          white-space:nowrap;
        }
        .top-name:hover{opacity:.8}
        .name-input{
          font-family:'Bebas Neue',cursive;font-size:1.6rem;letter-spacing:3px;
          color:${ac};background:transparent;border:none;
          border-bottom:2px solid ${ac};outline:none;width:220px;
        }
        .top-right{display:flex;align-items:center;gap:8px}
        .icon-btn{
          width:36px;height:36px;border-radius:10px;
          border:1px solid ${bd};background:transparent;
          cursor:pointer;display:flex;align-items:center;justify-content:center;
          font-size:1rem;transition:all .18s;color:${dim};
        }
        .icon-btn:hover{border-color:${ac};color:${ac}}
        .icon-btn.active{border-color:${ac};background:${ac}18;color:${ac}}

        /* SETTINGS PANEL */
        .sett-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:200;display:flex;justify-content:flex-end}
        .sett-panel{
          width:min(320px,100vw);height:100vh;
          background:${dark?"#09090F":"#fff"};
          border-left:1px solid ${bd};
          display:flex;flex-direction:column;overflow-y:auto;
        }
        .sett-head{
          padding:20px;border-bottom:1px solid ${bd};
          display:flex;align-items:center;justify-content:space-between;
          position:sticky;top:0;background:${dark?"#09090F":"#fff"};z-index:1;
        }
        .sett-title{font-family:'Bebas Neue',cursive;font-size:1.4rem;letter-spacing:2px;color:${ac}}
        .sett-body{padding:20px;display:flex;flex-direction:column;gap:20px}
        .sett-row{display:flex;align-items:center;justify-content:space-between;gap:12px}
        .sett-label{font-size:.72rem;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:${dim}}
        .toggle{
          width:44px;height:24px;border-radius:100px;
          border:none;cursor:pointer;position:relative;transition:background .2s;
          background:${ac};flex-shrink:0;
        }
        .toggle.off{background:${bd}}
        .toggle::after{
          content:'';position:absolute;width:18px;height:18px;
          background:#fff;border-radius:50%;top:3px;left:3px;transition:.2s;
        }
        .toggle.on::after{transform:translateX(20px)}
        .color-grid{display:flex;flex-wrap:wrap;gap:8px}
        .color-dot{
          width:28px;height:28px;border-radius:50%;cursor:pointer;
          border:2px solid transparent;transition:all .18s;
        }
        .color-dot:hover{transform:scale(1.15)}
        .color-dot.active{border-color:#fff;box-shadow:0 0 0 2px ${ac}}
        .sett-section{font-size:.6rem;letter-spacing:2px;text-transform:uppercase;color:${dim};padding-bottom:6px;border-bottom:1px solid ${bd}}
        .name-edit-row{display:flex;gap:8px}
        .sett-input{
          flex:1;padding:8px 12px;background:${sf2};border:1px solid ${bd};
          border-radius:8px;color:${tx};font-family:'Inter',sans-serif;font-size:.8rem;outline:none;
        }
        .sett-input:focus{border-color:${ac}}
        .sett-btn{
          padding:8px 16px;border-radius:8px;border:1px solid ${ac};
          background:${ac}18;color:${ac};font-size:.7rem;font-weight:700;
          text-transform:uppercase;letter-spacing:1px;cursor:pointer;white-space:nowrap;
          transition:all .18s;
        }
        .sett-btn:hover{background:${ac};color:#07080D}

        /* LOCK OVERLAY */
        .lock-overlay{
          position:fixed;inset:0;z-index:300;
          background:${dark?"rgba(7,8,13,0.97)":"rgba(240,242,248,0.97)"};
          display:flex;flex-direction:column;align-items:center;justify-content:center;gap:20px;
          backdrop-filter:blur(8px);
        }
        .lock-icon{font-size:3rem;animation:pulse 2s infinite}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
        .lock-title{font-family:'Bebas Neue',cursive;font-size:2rem;letter-spacing:3px;color:${ac}}
        .lock-sub{font-size:.75rem;color:${dim};letter-spacing:1px}
        .pin-input{
          width:200px;text-align:center;padding:12px 16px;
          background:${sf};border:2px solid ${pinErr?"#FF4D6D":bd};
          border-radius:12px;color:${tx};font-family:'IBM Plex Mono',monospace;
          font-size:1.2rem;letter-spacing:4px;outline:none;transition:border-color .2s;
        }
        .pin-input:focus{border-color:${ac}}
        .unlock-btn{
          padding:12px 32px;background:${ac};color:#07080D;
          font-weight:700;font-size:.8rem;letter-spacing:2px;text-transform:uppercase;
          border:none;border-radius:10px;cursor:pointer;transition:all .2s;
        }
        .unlock-btn:hover{opacity:.85}

        /* HERO */
        .hero{
          text-align:center;padding:48px 20px 32px;
        }
        .hero-lock{font-size:3.5rem;margin-bottom:12px;filter:drop-shadow(0 0 20px ${ac}66)}
        .hero-title{
          font-family:'Bebas Neue',cursive;font-size:4rem;letter-spacing:4px;
          color:${ac};text-shadow:0 0 40px ${ac}55;line-height:1;
          margin-bottom:8px;
        }
        .hero-sub{font-size:.72rem;letter-spacing:3px;text-transform:uppercase;color:${dim};margin-bottom:6px}
        .hero-by{font-size:.65rem;color:${ac}88;letter-spacing:2px}
        .hero-by b{color:${ac}}

        /* PIPELINE STRIP */
        .pipeline{
          display:flex;align-items:center;justify-content:center;
          gap:0;margin:0 0 24px;
          background:${sf};border:1px solid ${bd};border-radius:12px;
          padding:10px 16px;flex-wrap:wrap;row-gap:4px;overflow-x:auto;
        }
        .pip{font-family:'IBM Plex Mono',monospace;font-size:.58rem;letter-spacing:1px;text-transform:uppercase;color:${ac};font-weight:700;white-space:nowrap}
        .par{font-size:.6rem;color:${dim};margin:0 6px}
        .pdot{width:6px;height:6px;border-radius:50%;background:${ac};display:inline-block;animation:pulse 2s infinite;margin-right:8px;flex-shrink:0}

        /* MODE TOGGLE */
        .mode-row{display:flex;justify-content:center;margin-bottom:24px;gap:0}
        .mode-toggle{display:flex;border:1px solid ${bd};border-radius:12px;overflow:hidden}
        .mbtn{
          padding:12px 40px;font-family:'IBM Plex Mono',monospace;
          font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:2px;
          border:none;cursor:pointer;background:transparent;color:${dim};transition:all .18s;white-space:nowrap;
        }
        .mbtn.active{background:${ac};color:#07080D}

        /* MAIN CARD */
        .card{
          background:${sf};border:1px solid ${bd};border-radius:16px;
          overflow:hidden;margin-bottom:16px;
        }
        .card-head{
          padding:14px 18px;border-bottom:1px solid ${bd};
          display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;
        }
        .card-title{font-size:.6rem;letter-spacing:3px;text-transform:uppercase;color:${dim};font-weight:600}
        .card-badge{
          font-family:'IBM Plex Mono',monospace;font-size:.55rem;
          padding:3px 10px;border-radius:100px;
          background:${ac}18;color:${ac};border:1px solid ${ac}44;letter-spacing:1px;
        }

        /* MESSAGE BOX */
        .msg-wrap{position:relative}
        .big-textarea{
          width:100%;min-height:160px;padding:18px;
          background:transparent;border:none;outline:none;
          color:${tx};font-family:'IBM Plex Mono',monospace;
          font-size:.8rem;resize:vertical;line-height:1.8;
        }
        .big-textarea::placeholder{color:${dim};font-style:italic}
        .big-textarea[readonly]{color:${ac}}
        .char-count{
          position:absolute;bottom:10px;right:12px;
          font-family:'IBM Plex Mono',monospace;font-size:.55rem;color:${dim};
        }

        /* PASSWORD SECTION */
        .pw-section{padding:16px 18px;border-top:1px solid ${bd};display:flex;flex-direction:column;gap:12px}
        .pw-mode-bar{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
        .pw-mode-label{font-size:.6rem;letter-spacing:2px;text-transform:uppercase;color:${dim};font-weight:600}
        .pw-toggle{display:flex;border:1px solid ${bd};border-radius:8px;overflow:hidden}
        .pmb{padding:6px 16px;font-family:'IBM Plex Mono',monospace;font-size:.6rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;border:none;cursor:pointer;background:transparent;color:${dim};transition:.15s}
        .pmb.active{background:${sf2};color:${tx};border-right:1px solid ${bd}}

        /* Auto row */
        .auto-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
        .auto-lbl{font-family:'IBM Plex Mono',monospace;font-size:.58rem;color:${dim};text-transform:uppercase;letter-spacing:1px}
        .len-btns{display:flex;gap:4px}
        .lbtn{
          padding:5px 12px;border-radius:6px;border:1px solid ${bd};
          background:transparent;color:${dim};font-family:'IBM Plex Mono',monospace;
          font-size:.6rem;cursor:pointer;transition:.15s;
        }
        .lbtn.active{border-color:${ac};color:${ac};background:${ac}12}
        .gen-btn{
          padding:8px 18px;border-radius:8px;border:1px solid ${ac};
          background:${ac}12;color:${ac};font-family:'IBM Plex Mono',monospace;
          font-size:.65rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;
          cursor:pointer;transition:.18s;white-space:nowrap;
        }
        .gen-btn:hover{background:${ac};color:#07080D}
        .auto-hint{font-family:'IBM Plex Mono',monospace;font-size:.55rem;color:${dim};font-style:italic}

        /* manual-pw hint */
        .pw-hint{font-family:'IBM Plex Mono',monospace;font-size:.6rem;color:${dim};text-align:center;padding:6px 0}

        /* PW input */
        .pw-input-row{display:flex;gap:8px}
        .pw-rel{flex:1;position:relative}
        .pw-icon-l{position:absolute;left:13px;top:50%;transform:translateY(-50%);font-size:.85rem;pointer-events:none}
        .pw-field{
          width:100%;padding:12px 44px 12px 38px;
          background:${sf2};border:1px solid ${bd};border-radius:10px;
          color:${ac};font-family:'IBM Plex Mono',monospace;font-size:.8rem;
          outline:none;transition:border-color .2s;letter-spacing:.5px;
        }
        .pw-field:focus{border-color:${ac}}
        .pw-field::placeholder{color:${dim};font-style:italic;letter-spacing:0;font-size:.72rem}
        .eye-btn{
          position:absolute;right:10px;top:50%;transform:translateY(-50%);
          background:transparent;border:none;cursor:pointer;
          color:${dim};font-size:.85rem;padding:4px;line-height:1;transition:.15s;
        }
        .eye-btn:hover{color:${tx}}

        /* strength */
        .str-row{display:flex;align-items:center;gap:10px}
        .str-bars{display:flex;gap:4px;flex:1}
        .sbar{height:3px;border-radius:2px;flex:1;background:${bd};transition:background .3s}
        .str-lbl{font-family:'IBM Plex Mono',monospace;font-size:.55rem;letter-spacing:1px;text-transform:uppercase;min-width:72px;text-align:right}
        .str-len{font-family:'IBM Plex Mono',monospace;font-size:.55rem;color:${dim}}

        /* pw actions */
        .pw-actions{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
        .pabtn{
          padding:7px 14px;border-radius:8px;border:1px solid ${bd};
          background:transparent;color:${dim};font-family:'IBM Plex Mono',monospace;
          font-size:.6rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;
          cursor:pointer;transition:.18s;white-space:nowrap;
        }
        .pabtn:disabled{opacity:.3;cursor:not-allowed}
        .pabtn.sv{border-color:${ac}44;color:${ac}}
        .pabtn.sv:not(:disabled):hover{background:${ac};color:#07080D;border-color:${ac}}
        .pabtn.cp:not(:disabled):hover{color:#4DFFEF;border-color:#4DFFEF}
        .pabtn.dl:hover{color:#FF4D6D;border-color:#FF4D6D}
        .pw-note{font-family:'IBM Plex Mono',monospace;font-size:.5rem;color:${dim};margin-left:auto}

        /* INFO / ERROR */
        .info{padding:10px 16px;border-radius:10px;margin-bottom:14px;font-family:'IBM Plex Mono',monospace;font-size:.68rem;line-height:1.6;border:1px solid ${ac}28;background:${ac}08;color:${ac}}
        .errbar{padding:10px 16px;border-radius:10px;margin-bottom:14px;font-family:'IBM Plex Mono',monospace;font-size:.68rem;line-height:1.6;border:1px solid #FF4D6D44;background:#FF4D6D0A;color:#FF4D6D}

        /* PROCESS BTN */
        .proc-wrap{display:flex;justify-content:center;margin:20px 0 10px}
        .proc-btn{
          padding:15px 60px;background:${ac};color:#07080D;
          font-family:'IBM Plex Mono',monospace;font-weight:700;font-size:.85rem;
          letter-spacing:3px;text-transform:uppercase;border:none;border-radius:14px;
          cursor:pointer;transition:all .2s;
          box-shadow:0 0 0 rgba(0,0,0,0);
        }
        .proc-btn:hover:not(:disabled){box-shadow:0 0 32px ${ac}44;transform:translateY(-2px)}
        .proc-btn:active:not(:disabled){transform:scale(.97)}
        .proc-btn:disabled{opacity:.35;cursor:not-allowed}
        .spinner{display:inline-block;width:13px;height:13px;border:2px solid rgba(0,0,0,.25);border-top-color:#000;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:8px}
        @keyframes spin{to{transform:rotate(360deg)}}

        /* OUTPUT CARD */
        .output-card{background:${sf};border:2px solid ${ac}44;border-radius:16px;overflow:hidden;margin-bottom:16px}
        .output-head{padding:12px 18px;border-bottom:1px solid ${ac}22;display:flex;align-items:center;justify-content:space-between}
        .copy-btn{
          padding:6px 16px;border-radius:7px;border:1px solid ${ac}44;
          background:${ac}0e;color:${ac};font-family:'IBM Plex Mono',monospace;
          font-size:.6rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;
          cursor:pointer;transition:.18s;
        }
        .copy-btn:not(:disabled):hover{background:${ac};color:#07080D;border-color:${ac}}
        .copy-btn:disabled{opacity:.3;cursor:not-allowed}

        /* STATS */
        .stats{display:flex;gap:8px;margin-top:16px;flex-wrap:wrap}
        .stat{background:${sf};border:1px solid ${bd};border-radius:10px;padding:12px 16px;flex:1;min-width:80px}
        .stat-v{font-family:'Bebas Neue',cursive;font-size:1.6rem;color:${ac};line-height:1}
        .stat-l{font-size:.5rem;letter-spacing:2px;text-transform:uppercase;color:${dim};margin-top:3px}

        /* HOW IT WORKS */
        .how-section{margin-top:48px;padding:0 4px}
        .how-title{font-family:'Bebas Neue',cursive;font-size:2rem;letter-spacing:3px;color:${ac};margin-bottom:4px}
        .how-sub{font-size:.7rem;color:${dim};margin-bottom:24px;letter-spacing:1px}
        .how-card{background:${sf};border:1px solid ${bd};border-radius:14px;padding:20px;margin-bottom:12px;display:flex;gap:16px}
        .how-num{font-family:'Bebas Neue',cursive;font-size:2.5rem;color:${ac}44;line-height:1;flex-shrink:0;width:40px}
        .how-content{}
        .how-h{font-size:.8rem;font-weight:700;letter-spacing:1px;margin-bottom:4px;color:${tx}}
        .how-p{font-size:.72rem;color:${dim};line-height:1.7}
        .how-code{font-family:'IBM Plex Mono',monospace;font-size:.65rem;background:${sf2};border:1px solid ${bd};border-radius:6px;padding:8px 12px;margin-top:8px;color:${ac};line-height:1.6}

        /* FOOTER */
        .footer{text-align:center;padding:32px 0 0;display:flex;flex-direction:column;align-items:center;gap:6px}
        .footer-brand{font-family:'Bebas Neue',cursive;font-size:1.3rem;letter-spacing:3px;color:${ac}88}
        .footer-powered{font-family:'IBM Plex Mono',monospace;font-size:.58rem;letter-spacing:2px;color:${dim}}
        .footer-powered b{color:${ac}88;font-weight:700}

        /* SCROLLBAR */
        ::-webkit-scrollbar{width:4px}
        ::-webkit-scrollbar-track{background:transparent}
        ::-webkit-scrollbar-thumb{background:${bd};border-radius:4px}
        ::-webkit-scrollbar-thumb:hover{background:${ac}55}
      `}</style>

      {/* ── LOCK OVERLAY ── */}
      {locked && (
        <div className="lock-overlay">
          <div className="lock-icon">🔒</div>
          <div className="lock-title">LOCKED</div>
          <div className="lock-sub">PIN dalo settings unlock karne ke liye</div>
          <input
            className="pin-input"
            type="password"
            maxLength={8}
            placeholder="● ● ● ●"
            value={pinInput}
            onChange={e=>setPinInput(e.target.value)}
            onKeyDown={e=>e.key==="Enter"&&tryUnlock()}
            autoFocus
          />
          {pinErr && <div style={{color:"#FF4D6D",fontSize:".7rem",fontFamily:"IBM Plex Mono"}}>Galat PIN — dobara try karo</div>}
          <button className="unlock-btn" onClick={tryUnlock}>🔓 Unlock</button>
        </div>
      )}

      {/* ── SETTINGS PANEL ── */}
      {settOpen && (
        <div className="sett-overlay" onClick={()=>setSettOpen(false)}>
          <div className="sett-panel" onClick={e=>e.stopPropagation()}>
            <div className="sett-head">
              <span className="sett-title">Settings</span>
              <button className="icon-btn" onClick={()=>setSettOpen(false)}>✕</button>
            </div>
            <div className="sett-body">

              <div className="sett-section">Profile</div>
              <div>
                <div className="sett-label" style={{marginBottom:8}}>Display Name</div>
                <div className="name-edit-row">
                  <input className="sett-input" value={tmpName} onChange={e=>setTmpName(e.target.value)}
                    onKeyDown={e=>e.key==="Enter"&&saveName()}
                    placeholder="Apna naam likho…"
                    defaultValue={username}
                    onFocus={e=>{if(!tmpName)setTmpName(username)}}
                  />
                  <button className="sett-btn" onClick={saveName}>Save</button>
                </div>
                <div style={{fontSize:".58rem",color:dim,marginTop:6,fontFamily:"IBM Plex Mono"}}>Yeh naam top par dikhega aur save rahega</div>
              </div>

              <div className="sett-section">Appearance</div>

              <div className="sett-row">
                <span className="sett-label">Dark Mode</span>
                <button className={`toggle ${dark?"on":"off"}`} onClick={toggleDark} />
              </div>

              <div className="sett-row">
                <span className="sett-label">RGB Color (Auto Cycle)</span>
                <button className={`toggle ${rgb?"on":"off"}`} onClick={toggleRgb} />
              </div>

              {!rgb && (
                <div>
                  <div className="sett-label" style={{marginBottom:10}}>Accent Color</div>
                  <div className="color-grid">
                    {PRESET_COLORS.map(c=>(
                      <div key={c} className={`color-dot${accent===c?" active":""}`}
                        style={{background:c}} onClick={()=>setColor(c)} />
                    ))}
                  </div>
                </div>
              )}

              <div className="sett-section">Lock Settings</div>
              <div>
                <div className="sett-label" style={{marginBottom:8}}>Scroll Lock PIN (optional)</div>
                <div className="name-edit-row">
                  <input className="sett-input" type="password" maxLength={8}
                    placeholder="PIN set karo (blank = no lock)"
                    value={lockPIN} onChange={e=>setLockPIN(e.target.value)}
                  />
                </div>
                <div style={{fontSize:".58rem",color:dim,marginTop:6,fontFamily:"IBM Plex Mono"}}>
                  PIN set karo — phir lock button se lock hoga
                </div>
              </div>

              <div style={{background:sf2,border:`1px solid ${bd}`,borderRadius:10,padding:14}}>
                <div style={{fontFamily:"IBM Plex Mono",fontSize:".62rem",color:ac,fontWeight:700,marginBottom:4}}>ℹ Privacy Note</div>
                <div style={{fontFamily:"IBM Plex Mono",fontSize:".6rem",color:dim,lineHeight:1.7}}>
                  Name, theme, RGB, color — sirf browser mein save hota hai.<br/>
                  Password bhi local hai. Koi data server pe nahi jaata.<br/>
                  Messages save nahi hote — 100% private.
                </div>
              </div>

            </div>
          </div>
        </div>
      )}

      {/* ── TOP BAR ── */}
      <div className="topbar">
        {editName ? (
          <input className="name-input" autoFocus value={tmpName}
            onChange={e=>setTmpName(e.target.value)}
            onBlur={saveName} onKeyDown={e=>e.key==="Enter"&&saveName()}
          />
        ) : (
          <div className="top-name" onClick={startEditName} title="Click to edit name">{username}</div>
        )}
        <div className="top-right">
          <button className={`icon-btn${dark?"":" active"}`} onClick={toggleDark} title={dark?"Light Mode":"Dark Mode"}>
            {dark?"☀️":"🌙"}
          </button>
          <button className={`icon-btn${locked?" active":""}`}
            onClick={()=>{ if(locked){setLocked(false)}else{setLocked(true);} }}
            title={locked?"Unlock":"Lock"}>
            {locked?"🔒":"🔓"}
          </button>
          <button className="icon-btn active" onClick={()=>{ setSettOpen(true); setTmpName(username); }} title="Settings">
            ⚙️
          </button>
        </div>
      </div>

      <div className="wrap">

        {/* ── HERO ── */}
        <div className="hero">
          <div className="hero-lock">🛡️</div>
          <div className="hero-title">AESCRYPT</div>
          <div className="hero-sub">Military Grade · Client Side · Zero Knowledge</div>
          <div className="hero-by">Built by <b>Subojeet Mandal</b> · Hard Military Level Encryption</div>
        </div>

        {/* ── PIPELINE ── */}
        <div className="pipeline">
          <div className="pdot"/>
          {mode==="encrypt" ? (<>
            <span className="pip">Plain Text</span><span className="par">→</span>
            <span className="pip">AES-256-GCM</span><span className="par">→</span>
            <span className="pip">Base64 Encode</span><span className="par">→</span>
            <span className="pip">Encrypted Output</span>
          </>) : (<>
            <span className="pip">Base64 Input</span><span className="par">→</span>
            <span className="pip">Base64 Decode</span><span className="par">→</span>
            <span className="pip">AES-256-GCM</span><span className="par">→</span>
            <span className="pip">Plain Text</span>
          </>)}
        </div>

        {/* ── MODE ── */}
        <div className="mode-row">
          <div className="mode-toggle">
            <button className={`mbtn${mode==="encrypt"?" active":""}`}
              onClick={()=>{setMode("encrypt");clearAll();}}>🔒 Encrypt</button>
            <button className={`mbtn${mode==="decrypt"?" active":""}`}
              onClick={()=>{setMode("decrypt");clearAll();}}>🔓 Decrypt</button>
          </div>
        </div>

        {/* ── MAIN CARD ── */}
        <div className="card">
          <div className="card-head">
            <span className="card-title">
              {mode==="encrypt" ? "Message — Plain Text" : "Encrypted Message — Base64"}
            </span>
            <span className="card-badge">
              {mode==="encrypt" ? "AES-256-GCM + Base64" : "Base64 → AES-GCM"}
            </span>
          </div>

          {/* Message textarea */}
          <div className="msg-wrap">
            <textarea className="big-textarea"
              placeholder={mode==="encrypt"
                ? "Yahan apna message likho ya paste karo jo encrypt karna hai…"
                : "Yahan pura encrypted Base64 string paste karo jo decrypt karna hai…"}
              value={input}
              onChange={e=>{setInput(e.target.value);setOutput("");setError("");setInfo("");}}
            />
            <div className="char-count">{input.length}</div>
          </div>

          {/* ── PASSWORD SECTION ── */}
          <div className="pw-section">
            <div className="pw-mode-bar">
              <span className="pw-mode-label">🔑 Password</span>
              <div className="pw-toggle">
                <button className={`pmb${pwMode==="manual"?" active":""}`} onClick={()=>setPwMode("manual")}>Manual</button>
                <button className={`pmb${pwMode==="auto"?" active":""}`} onClick={()=>setPwMode("auto")}>Auto</button>
              </div>
            </div>

            {/* AUTO mode */}
            {pwMode==="auto" && (
              <div className="auto-row">
                <span className="auto-lbl">Length:</span>
                <div className="len-btns">
                  {[12,13,14,15].map(n=>(
                    <button key={n} className={`lbtn${autoLen===n?" active":""}`} onClick={()=>setAutoLen(n)}>{n}</button>
                  ))}
                </div>
                <button className="gen-btn" onClick={handleGen}>⚡ Generate</button>
                <span className="auto-hint">8–5000 char supported</span>
              </div>
            )}

            {/* MANUAL hint */}
            {pwMode==="manual" && (
              <div className="pw-hint">Apna koi bhi password type karo (8–5000 characters)</div>
            )}

            {/* Password input — only show eye when manual, auto shows no eye after generate */}
            <div className="pw-input-row">
              <div className="pw-rel">
                <span className="pw-icon-l">🔑</span>
                <input className="pw-field"
                  type={pwMode==="auto" ? "text" : (showPw?"text":"password")}
                  placeholder={pwMode==="auto"
                    ? "Auto password yahan aayega (8–5000 char supported)…"
                    : "Apna password yahan type karo…"}
                  value={password}
                  onChange={e=>{setPassword(e.target.value);setError("");}}
                />
                {pwMode==="manual" && (
                  <button className="eye-btn" onClick={()=>setShowPw(p=>!p)}>
                    {showPw?"🙈":"👁"}
                  </button>
                )}
              </div>
            </div>

            {/* Strength meter */}
            {password && (
              <div className="str-row">
                <div className="str-bars">
                  {[1,2,3,4].map(i=>(
                    <div key={i} className="sbar" style={{background:i<=str.s?str.c:undefined}}/>
                  ))}
                </div>
                <span className="str-lbl" style={{color:str.c}}>{str.l}</span>
                <span className="str-len">{password.length} chars</span>
              </div>
            )}

            {/* Actions */}
            <div className="pw-actions">
              <button className="pabtn sv" onClick={savePw} disabled={!password}>
                {saved?"✅ Saved!":"💾 Save Password"}
              </button>
              <button className="pabtn cp" onClick={copyPw} disabled={!password}>
                {pwCopied?"✓ Copied":"📋 Copy"}
              </button>
              <button className="pabtn dl" onClick={()=>{
                try{localStorage.removeItem(LS_PW_PFX+"user");}catch{}
                flash("🗑 Saved password hata diya gaya");
              }}>🗑 Delete</button>
              <span className="pw-note">Local only · no server</span>
            </div>
          </div>

          {/* PROCESS BUTTON */}
          <div className="proc-wrap">
            <button className="proc-btn" onClick={handleProcess}
              disabled={loading||!input.trim()||!password.trim()}>
              {loading&&<span className="spinner"/>}
              {loading?"Processing…":mode==="encrypt"?"🔒 Encrypt → Base64":"🔓 Base64 → Decrypt"}
            </button>
          </div>
        </div>

        {/* INFO / ERROR */}
        {info  && <div className="info">{info}</div>}
        {error && <div className="errbar">{error}</div>}

        {/* OUTPUT */}
        {output && (
          <div className="output-card">
            <div className="output-head">
              <span className="card-title" style={{color:ac}}>
                {mode==="encrypt"?"✅ Encrypted Output (Base64)":"✅ Decrypted Message"}
              </span>
              <button className="copy-btn" onClick={copyOut}>
                {outCopied?"✓ Copied!":"📋 Copy"}
              </button>
            </div>
            <div className="msg-wrap">
              <textarea className="big-textarea" readOnly value={output} style={{minHeight:120}}/>
              <div className="char-count">{output.length}</div>
            </div>
          </div>
        )}

        {/* STATS */}
        {output && (
          <div className="stats">
            <div className="stat"><div className="stat-v">{input.length}</div><div className="stat-l">Input Chars</div></div>
            <div className="stat"><div className="stat-v">{output.length}</div><div className="stat-l">Output Chars</div></div>
            <div className="stat"><div className="stat-v">256</div><div className="stat-l">Key Bits</div></div>
            <div className="stat"><div className="stat-v">GCM</div><div className="stat-l">Auth Mode</div></div>
            <div className="stat"><div className="stat-v">B64</div><div className="stat-l">Encoding</div></div>
          </div>
        )}

        {/* HOW IT WORKS */}
        <div className="how-section" id="how">
          <div className="how-title">HOW IT WORKS</div>
          <div className="how-sub">Samjho kaise kaam karta hai yeh encryption tool</div>

          <div className="how-card">
            <div className="how-num">01</div>
            <div className="how-content">
              <div className="how-h">Message + Password Do</div>
              <div className="how-p">Apna message box mein likho aur ek strong password choose karo. Auto generate bhi kar sakte ho 12–15 character ka jo uppercase, lowercase, digits aur symbols sab mix karta hai.</div>
            </div>
          </div>

          <div className="how-card">
            <div className="how-num">02</div>
            <div className="how-content">
              <div className="how-h">PBKDF2 Key Derivation</div>
              <div className="how-p">Tumhara password seedha use nahi hota. Pehle usse 250,000 iterations ke saath PBKDF2-SHA256 se ek 256-bit key banayi jaati hai. Random salt ke saath — har baar alag key.</div>
              <div className="how-code">Password + Random Salt(128-bit) → PBKDF2-SHA256 × 250,000 → AES-256 Key</div>
            </div>
          </div>

          <div className="how-card">
            <div className="how-num">03</div>
            <div className="how-content">
              <div className="how-h">AES-256-GCM Encryption</div>
              <div className="how-p">Message ko AES-256-GCM se encrypt kiya jaata hai — yeh military grade encryption hai. GCM mode authentication bhi karta hai taki koi data tamper na kar sake.</div>
              <div className="how-code">Message → AES-256-GCM(key, random IV) → Ciphertext + Auth Tag</div>
            </div>
          </div>

          <div className="how-card">
            <div className="how-num">04</div>
            <div className="how-content">
              <div className="how-h">Base64 Encoding — Final Output</div>
              <div className="how-p">Encrypted bytes ko Base64 URL-safe format mein convert kiya jaata hai. Salt + IV + Ciphertext sab ek hi string mein pack hote hain — easy share karne ke liye.</div>
              <div className="how-code">Salt(16B) + IV(12B) + Ciphertext → Pack → Base64 URL-safe String</div>
            </div>
          </div>

          <div className="how-card">
            <div className="how-num">05</div>
            <div className="how-content">
              <div className="how-h">Decrypt Karna — Reverse Pipeline</div>
              <div className="how-p">Decrypt karte waqt Base64 ko pehle decode karo, phir salt aur IV nikaalo, key dobara derive karo same password se, aur AES-GCM se original message wapas pao.</div>
              <div className="how-code">Base64 → Unpack → Derive Key → AES-GCM Decrypt → Plain Text</div>
            </div>
          </div>

          <div className="how-card" style={{borderColor:`${ac}44`}}>
            <div className="how-num">🛡</div>
            <div className="how-content">
              <div className="how-h" style={{color:ac}}>100% Client Side — Zero Server</div>
              <div className="how-p">Sab kuch tumhare browser mein hota hai. Koi bhi data — message, password, encrypted output — kisi server pe nahi jaata. Web Crypto API use hoti hai jo browser ka built-in secure function hai.</div>
            </div>
          </div>
        </div>

        {/* FOOTER */}
        <div className="footer">
          <div className="footer-brand">AESCRYPT</div>
          <div className="footer-powered">
            Built by <b>Subojeet Mandal</b> · Hard Military Level Encryption · Client Side
          </div>
          <div className="footer-powered" style={{marginTop:4}}>
            <b>Powered by Mandal</b> · AES-256-GCM + Base64 · Zero Knowledge · No Server
          </div>
        </div>

      </div>
    </>
  );
}
