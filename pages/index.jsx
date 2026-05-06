import { useState, useCallback, useEffect, useRef } from "react";

/* ═══════════════════════════════════════════════
   CONSTANTS
═══════════════════════════════════════════════ */
const LS_NAME    = "aescrypt_username";
const LS_THEME   = "aescrypt_theme";
const LS_RGB     = "aescrypt_rgb";
const LS_COLOR   = "aescrypt_color";
const LS_PW_PFX  = "aescrypt_pw_";
const LS_PIN     = "aescrypt_pin";

const PRESET_COLORS = [
  "#A78BFA","#C8FF00","#00FFEA","#FF4D6D","#FF9F1C","#38BDF8","#F472B6","#34D399"
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
  if (!text.trim()) throw new Error("Message is empty");
  if (!pass.trim()) throw new Error("Password is required");
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
  if (!b64.trim()) throw new Error("Encrypted text is empty");
  if (!pass.trim()) throw new Error("Password is required");
  let pk;
  try { pk = fromB64(b64); } catch { throw new Error("Invalid Base64 format"); }
  if (pk.length < 44) throw new Error("Data is corrupted or incomplete");
  const key = await deriveKey(pass, pk.slice(0,16));
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name:"AES-GCM", iv:pk.slice(16,28), tagLength:128 }, key, pk.slice(28));
  } catch { throw new Error("Decryption failed — wrong password or tampered data"); }
  return new TextDecoder("utf-8",{fatal:true}).decode(plain);
}

/* File encryption helpers */
async function encryptFile(arrayBuffer, pass) {
  if (!pass.trim()) throw new Error("Password is required");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(pass, salt);
  const ct   = await crypto.subtle.encrypt({ name:"AES-GCM", iv, tagLength:128 }, key, arrayBuffer);
  const cb   = new Uint8Array(ct);
  const pk   = new Uint8Array(28 + cb.length);
  pk.set(salt,0); pk.set(iv,16); pk.set(cb,28);
  return pk;
}
async function decryptFile(arrayBuffer, pass) {
  if (!pass.trim()) throw new Error("Password is required");
  const pk = new Uint8Array(arrayBuffer);
  if (pk.length < 44) throw new Error("File is corrupted or not encrypted by AESCRYPT");
  const key = await deriveKey(pass, pk.slice(0,16));
  try {
    const plain = await crypto.subtle.decrypt({ name:"AES-GCM", iv:pk.slice(16,28), tagLength:128 }, key, pk.slice(28));
    return plain;
  } catch { throw new Error("Decryption failed — wrong password or file tampered"); }
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
  return [{s:0,l:"Very Weak",c:"#FF4444"},{s:1,l:"Weak",c:"#FF9F1C"},{s:2,l:"Fair",c:"#FFD93D"},{s:3,l:"Strong",c:"#6BCB77"},{s:4,l:"Very Strong",c:"#A78BFA"}][Math.min(s,4)];
}

/* ═══════════════════════════════════════════════
   RGB ANIMATION HOOK
═══════════════════════════════════════════════ */
function useRGB(enabled) {
  const [col, setCol] = useState("#A78BFA");
  const ref = useRef(null);
  useEffect(() => {
    if (!enabled) { if(ref.current) cancelAnimationFrame(ref.current); return; }
    let h = 270;
    const tick = () => {
      h = (h+0.4)%360;
      setCol(`hsl(${h},100%,70%)`);
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
  const [accent,  setAccent]  = useState("#A78BFA");
  const [username,setUsername]= useState("S - MANDAL");
  /* settings panel */
  const [settOpen,setSettOpen]= useState(false);
  /* lock — scroll lock, tap to unlock */
  const [locked,  setLocked]  = useState(false);
  /* PIN setup state */
  const [pinSetupStep, setPinSetupStep] = useState(0); // 0=not setup, 1=enter first, 2=confirm
  const [pinFirst,  setPinFirst]  = useState("");
  const [pinConfirm,setPinConfirm]= useState("");
  const [savedPin,  setSavedPin]  = useState("");
  const [pinInput,  setPinInput]  = useState("");
  const [pinErr,    setPinErr]    = useState(false);
  const [showSavedPin, setShowSavedPin] = useState(false);
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
  /* file mode */
  const [fileMode, setFileMode] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileOutput, setFileOutput]   = useState(null);
  const [fileLoading,setFileLoading]  = useState(false);
  const [fileError,  setFileError]    = useState("");
  const [fileInfo,   setFileInfo]     = useState("");
  const fileRef = useRef(null);
  const encFileRef = useRef(null);

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
      const p=localStorage.getItem(LS_PIN); if(p) setSavedPin(p);
      const pw=localStorage.getItem(LS_PW_PFX+"user"); if(pw) setPassword(pw);
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
    savePrefs({name:n}); flash("✅ Name saved");
  };

  /* theme toggles */
  const toggleDark=()=>{ const v=!dark; setDark(v); savePrefs({dark:v}); };
  const toggleRgb=()=>{ const v=!rgb; setRgb(v); savePrefs({rgb:v}); };
  const setColor=(c)=>{ setAccent(c); savePrefs({color:c}); };

  /* lock — tap to toggle */
  const toggleLock=()=>{
    if(locked){ setLocked(false); setPinInput(""); setPinErr(false); }
    else { setLocked(true); }
  };

  /* PIN unlock on tap of overlay */
  const handleOverlayTap=()=>{
    if(!savedPin){ setLocked(false); return; }
    // Show pin input if has PIN
  };

  const tryUnlock=()=>{
    if(!savedPin||pinInput===savedPin){ setLocked(false); setPinInput(""); setPinErr(false); }
    else { setPinErr(true); setTimeout(()=>setPinErr(false),1500); }
  };

  /* PIN Setup flow */
  const startPinSetup=()=>{ setPinSetupStep(1); setPinFirst(""); setPinConfirm(""); };
  const submitPinFirst=()=>{
    if(pinFirst.length!==4){ setPinErr(true); setTimeout(()=>setPinErr(false),1200); return; }
    setPinSetupStep(2);
  };
  const submitPinConfirm=()=>{
    if(pinConfirm!==pinFirst){ setPinErr(true); setTimeout(()=>setPinErr(false),1200); return; }
    setSavedPin(pinFirst);
    try{ localStorage.setItem(LS_PIN,pinFirst); }catch{}
    setPinSetupStep(0); setPinFirst(""); setPinConfirm("");
    flash("✅ PIN saved successfully");
  };
  const clearPin=()=>{
    setSavedPin(""); setPinSetupStep(0);
    try{ localStorage.removeItem(LS_PIN); }catch{}
    flash("🗑 PIN removed");
  };

  /* password */
  const handleGen=useCallback(()=>{
    const pw=genPass(autoLen); setPassword(pw); setShowPw(false);
    flash(`⚡ ${autoLen}-char strong password generated`);
  },[autoLen]);

  const savePw=()=>{
    if(!password){flash("Enter a password first","err");return;}
    try{ localStorage.setItem(LS_PW_PFX+"user",password); setSaved(true); flash("💾 Password saved to browser"); setTimeout(()=>setSaved(false),3000); }
    catch{ flash("Save failed — localStorage blocked","err"); }
  };
  const copyPw=async()=>{ if(!password)return; await navigator.clipboard.writeText(password); setPwCopied(true); setTimeout(()=>setPwCopied(false),2000); };
  const copyOut=async()=>{ if(!output)return; await navigator.clipboard.writeText(output); setOutCopied(true); setTimeout(()=>setOutCopied(false),2000); };

  function validate(){
    if(!password.trim()) return "Password is required";
    if(!input.trim()) return "Message is empty";
    if(mode==="decrypt"){
      try{ const b=fromB64(input.trim()); if(b.length<44) return "This doesn't look like a valid encrypted text"; }
      catch{ return "Not a valid Base64 encrypted string"; }
    }
    return null;
  }

  const handleProcess=useCallback(async()=>{
    setError("");setOutput("");setInfo("");
    const e=validate(); if(e){setError(e);return;}
    setLoading(true);
    try{
      if(mode==="encrypt"){
        setInfo("🔐 AES-256-GCM encryption running…");
        const r=await encryptFull(input,password);
        setOutput(r); setInfo("✅ Encrypted! Base64 output is ready.");
        setTimeout(()=>setInfo(""),4000);
      } else {
        setInfo("📦 Base64 decode + AES-GCM decryption…");
        const r=await decryptFull(input,password);
        setOutput(r); setInfo("✅ Decryption successful!");
        setTimeout(()=>setInfo(""),4000);
      }
    } catch(err){ setError("❌ "+err.message); setInfo(""); }
    setLoading(false);
  },[input,password,mode]);

  const clearAll=()=>{setInput("");setOutput("");setError("");setInfo("");};

  /* FILE ENCRYPT */
  const handleFileEncrypt=async()=>{
    if(!selectedFile){setFileError("Select a file first");return;}
    if(!password.trim()){setFileError("Password is required");return;}
    setFileLoading(true); setFileError(""); setFileOutput(null);
    try{
      setFileInfo("🔐 Reading and encrypting file…");
      const buf=await selectedFile.arrayBuffer();
      const enc=await encryptFile(buf,password);
      const blob=new Blob([enc],{type:"application/octet-stream"});
      const url=URL.createObjectURL(blob);
      setFileOutput({url,name:selectedFile.name+".aescrypt",size:enc.byteLength});
      setFileInfo("✅ File encrypted successfully!");
      setTimeout(()=>setFileInfo(""),4000);
    }catch(err){setFileError("❌ "+err.message);setFileInfo("");}
    setFileLoading(false);
  };

  const handleFileDecrypt=async()=>{
    if(!selectedFile){setFileError("Select an encrypted file first (.aescrypt)");return;}
    if(!password.trim()){setFileError("Password is required");return;}
    setFileLoading(true); setFileError(""); setFileOutput(null);
    try{
      setFileInfo("📦 Decrypting file…");
      const buf=await selectedFile.arrayBuffer();
      const dec=await decryptFile(buf,password);
      // Remove .aescrypt extension
      let outName=selectedFile.name.endsWith(".aescrypt")?selectedFile.name.slice(0,-9):selectedFile.name+"_decrypted";
      const blob=new Blob([dec],{type:"application/octet-stream"});
      const url=URL.createObjectURL(blob);
      setFileOutput({url,name:outName,size:dec.byteLength});
      setFileInfo("✅ File decrypted successfully!");
      setTimeout(()=>setFileInfo(""),4000);
    }catch(err){setFileError("❌ "+err.message);setFileInfo("");}
    setFileLoading(false);
  };

  const fmtSize=(n)=>{
    if(n<1024)return n+"B";
    if(n<1024*1024)return (n/1024).toFixed(1)+"KB";
    return (n/(1024*1024)).toFixed(2)+"MB";
  };

  /* ─── STYLES ─────────────────────────────── */
  const bg   = dark?"#07080D":"#F0F2F8";
  const sf   = dark?"#0D0F17":"#FFFFFF";
  const sf2  = dark?"#11141F":"#F5F7FF";
  const bd   = dark?"#1C2030":"#D8DCF0";
  const tx   = dark?"#D4D8EF":"#1A1D2E";
  const dim  = dark?"#3A3F55":"#8890B0";

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;700&family=Bebas+Neue&family=Inter:wght@400;500;600;700&display=swap');
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
        html{scroll-behavior:smooth}
        body{
          background:${bg};color:${tx};
          font-family:'Inter',sans-serif;
          min-height:100vh;overflow-x:hidden;
          transition:background .3s,color .3s;
        }
        ${dark?`body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
          background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(167,139,250,0.004) 3px,rgba(167,139,250,0.004) 4px)}`:""}
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
          width:min(340px,100vw);height:100vh;
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
        .pin-display-box{
          background:${sf2};border:1px solid ${ac}44;border-radius:10px;
          padding:14px 16px;display:flex;flex-direction:column;gap:8px;
        }
        .pin-val{font-family:'IBM Plex Mono',monospace;font-size:1.4rem;letter-spacing:8px;color:${ac};text-align:center}
        .pin-actions{display:flex;gap:8px;justify-content:center;flex-wrap:wrap}
        .pin-step-box{
          background:${sf2};border:1px solid ${ac}33;border-radius:10px;
          padding:16px;display:flex;flex-direction:column;gap:12px;align-items:center;
        }
        .pin-step-label{font-size:.68rem;letter-spacing:1px;text-transform:uppercase;color:${dim};font-family:'IBM Plex Mono',monospace}
        .pin-step-input{
          width:160px;text-align:center;padding:10px 16px;
          background:${sf};border:2px solid ${pinErr?"#FF4D6D":bd};
          border-radius:10px;color:${tx};font-family:'IBM Plex Mono',monospace;
          font-size:1.1rem;letter-spacing:6px;outline:none;transition:border-color .2s;
        }
        .pin-step-input:focus{border-color:${ac}}

        /* LOCK OVERLAY */
        .lock-overlay{
          position:fixed;inset:0;z-index:300;
          background:${dark?"rgba(7,8,13,0.97)":"rgba(240,242,248,0.97)"};
          display:flex;flex-direction:column;align-items:center;justify-content:center;gap:20px;
          backdrop-filter:blur(8px);cursor:pointer;
        }
        .lock-icon{font-size:4rem;animation:float 3s ease-in-out infinite}
        @keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-12px)}}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
        .lock-title{font-family:'Bebas Neue',cursive;font-size:2.5rem;letter-spacing:4px;color:${ac}}
        .lock-tap-hint{font-size:.75rem;color:${dim};letter-spacing:2px;font-family:'IBM Plex Mono',monospace;animation:pulse 2s infinite}
        .lock-pin-area{display:flex;flex-direction:column;align-items:center;gap:12px;cursor:default}
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
        .hero{text-align:center;padding:48px 20px 32px}
        .hero-lock{font-size:3.5rem;margin-bottom:12px;filter:drop-shadow(0 0 20px ${ac}66)}
        .hero-title{
          font-family:'Bebas Neue',cursive;font-size:4rem;letter-spacing:4px;
          color:${ac};text-shadow:0 0 40px ${ac}55;line-height:1;margin-bottom:8px;
        }
        .hero-sub{font-size:.72rem;letter-spacing:3px;text-transform:uppercase;color:${dim};margin-bottom:6px}
        .hero-by{font-size:.65rem;color:${ac}88;letter-spacing:2px}
        .hero-by b{color:${ac}}

        /* PIPELINE STRIP */
        .pipeline{
          display:flex;align-items:center;justify-content:center;gap:0;
          margin:0 0 24px;background:${sf};border:1px solid ${bd};
          border-radius:12px;padding:10px 16px;flex-wrap:wrap;row-gap:4px;overflow-x:auto;
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

        /* TABS (text/file) */
        .tab-row{display:flex;justify-content:center;margin-bottom:18px}
        .tab-bar{display:flex;border:1px solid ${bd};border-radius:10px;overflow:hidden}
        .tbtn{
          padding:9px 28px;font-family:'IBM Plex Mono',monospace;font-size:.65rem;
          font-weight:700;text-transform:uppercase;letter-spacing:1.5px;
          border:none;cursor:pointer;background:transparent;color:${dim};transition:.18s;
        }
        .tbtn.active{background:${sf2};color:${ac};border-bottom:2px solid ${ac}}

        /* MAIN CARD */
        .card{background:${sf};border:1px solid ${bd};border-radius:16px;overflow:hidden;margin-bottom:16px}
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
        .char-count{position:absolute;bottom:10px;right:12px;font-family:'IBM Plex Mono',monospace;font-size:.55rem;color:${dim}}

        /* FILE UPLOAD AREA */
        .file-drop{
          margin:20px 18px;border:2px dashed ${bd};border-radius:14px;
          padding:32px 20px;text-align:center;cursor:pointer;transition:.2s;
          background:${sf2};
        }
        .file-drop:hover{border-color:${ac};background:${ac}08}
        .file-drop-icon{font-size:2.5rem;margin-bottom:10px}
        .file-drop-title{font-family:'IBM Plex Mono',monospace;font-size:.8rem;font-weight:700;color:${ac};letter-spacing:1px}
        .file-drop-sub{font-family:'IBM Plex Mono',monospace;font-size:.6rem;color:${dim};margin-top:6px;line-height:1.7}
        .file-selected{
          margin:16px 18px;background:${sf2};border:1px solid ${ac}44;
          border-radius:12px;padding:14px 16px;display:flex;align-items:center;gap:12px;
        }
        .file-icon{font-size:1.6rem;flex-shrink:0}
        .file-name{font-family:'IBM Plex Mono',monospace;font-size:.7rem;color:${ac};font-weight:700;word-break:break-all}
        .file-meta{font-family:'IBM Plex Mono',monospace;font-size:.6rem;color:${dim};margin-top:3px}
        .file-clear{margin-left:auto;background:transparent;border:1px solid ${bd};border-radius:7px;
          padding:5px 10px;cursor:pointer;color:${dim};font-size:.6rem;transition:.15s;flex-shrink:0}
        .file-clear:hover{color:#FF4D6D;border-color:#FF4D6D}

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

        /* FILE OUTPUT */
        .file-out-card{
          background:${sf};border:2px solid ${ac}44;border-radius:16px;
          padding:20px 18px;margin-bottom:16px;display:flex;flex-direction:column;gap:14px;
        }
        .dl-btn{
          padding:13px 32px;background:${ac};color:#07080D;
          font-family:'IBM Plex Mono',monospace;font-weight:700;font-size:.8rem;
          letter-spacing:2px;text-transform:uppercase;border:none;border-radius:11px;
          cursor:pointer;text-decoration:none;display:inline-block;text-align:center;transition:.2s;
        }
        .dl-btn:hover{opacity:.85;transform:translateY(-1px)}

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
        .how-h{font-size:.8rem;font-weight:700;letter-spacing:1px;margin-bottom:4px;color:${tx}}
        .how-p{font-size:.72rem;color:${dim};line-height:1.7}
        .how-code{font-family:'IBM Plex Mono',monospace;font-size:.65rem;background:${sf2};border:1px solid ${bd};border-radius:6px;padding:8px 12px;margin-top:8px;color:${ac};line-height:1.6}

        /* FOOTER */
        .footer{text-align:center;padding:32px 0 0;display:flex;flex-direction:column;align-items:center;gap:6px}
        .footer-brand{font-family:'Bebas Neue',cursive;font-size:1.3rem;letter-spacing:3px;color:${ac}88}
        .footer-powered{font-family:'IBM Plex Mono',monospace;font-size:.58rem;letter-spacing:2px;color:${dim}}
        .footer-powered b{color:${ac}88;font-weight:700}

        ::-webkit-scrollbar{width:4px}
        ::-webkit-scrollbar-track{background:transparent}
        ::-webkit-scrollbar-thumb{background:${bd};border-radius:4px}
        ::-webkit-scrollbar-thumb:hover{background:${ac}55}

        input[type=file]{display:none}
      `}</style>

      {/* ── LOCK OVERLAY ── */}
      {locked && (
        <div className="lock-overlay" onClick={!savedPin ? ()=>setLocked(false) : undefined}>
          <div className="lock-icon">🔒</div>
          <div className="lock-title">LOCKED</div>
          {!savedPin ? (
            <div className="lock-tap-hint">TAP ANYWHERE TO UNLOCK</div>
          ) : (
            <div className="lock-pin-area" onClick={e=>e.stopPropagation()}>
              <div className="lock-tap-hint">ENTER PIN TO UNLOCK</div>
              <input
                className="pin-input"
                type="password"
                maxLength={4}
                placeholder="● ● ● ●"
                value={pinInput}
                onChange={e=>setPinInput(e.target.value)}
                onKeyDown={e=>e.key==="Enter"&&tryUnlock()}
                autoFocus
              />
              {pinErr && <div style={{color:"#FF4D6D",fontSize:".7rem",fontFamily:"IBM Plex Mono"}}>Wrong PIN — try again</div>}
              <button className="unlock-btn" onClick={tryUnlock}>🔓 Unlock</button>
            </div>
          )}
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

              {/* PROFILE */}
              <div className="sett-section">Profile</div>
              <div>
                <div className="sett-label" style={{marginBottom:8}}>Display Name</div>
                <div className="name-edit-row">
                  <input className="sett-input" value={tmpName}
                    onChange={e=>setTmpName(e.target.value)}
                    onKeyDown={e=>e.key==="Enter"&&saveName()}
                    placeholder="Enter your name…"
                    onFocus={e=>{if(!tmpName)setTmpName(username)}}
                  />
                  <button className="sett-btn" onClick={saveName}>Save</button>
                </div>
                <div style={{fontSize:".58rem",color:dim,marginTop:6,fontFamily:"IBM Plex Mono"}}>This name appears at the top and is saved locally</div>
              </div>

              {/* APPEARANCE */}
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

              {/* KEY / PIN */}
              <div className="sett-section">Key & Lock</div>

              {pinSetupStep===0 && (
                <div style={{display:"flex",flexDirection:"column",gap:12}}>
                  {savedPin ? (
                    <div className="pin-display-box">
                      <div style={{fontSize:".62rem",color:ac,fontFamily:"IBM Plex Mono",fontWeight:700,textAlign:"center",letterSpacing:1}}>🔑 Saved PIN</div>
                      <div className="pin-val">{showSavedPin ? savedPin.split("").join(" ") : "● ● ● ●"}</div>
                      <div className="pin-actions">
                        <button className="sett-btn" onClick={()=>setShowSavedPin(p=>!p)}>
                          {showSavedPin?"🙈 Hide":"👁 Show"}
                        </button>
                        <button className="sett-btn" onClick={startPinSetup}>✏️ Change</button>
                        <button className="sett-btn" style={{borderColor:"#FF4D6D",color:"#FF4D6D",background:"#FF4D6D10"}} onClick={clearPin}>🗑 Remove</button>
                      </div>
                      <div style={{fontSize:".58rem",color:dim,fontFamily:"IBM Plex Mono",textAlign:"center"}}>Lock button uses this PIN to protect the app</div>
                    </div>
                  ) : (
                    <div style={{display:"flex",flexDirection:"column",gap:8}}>
                      <div style={{fontSize:".62rem",color:dim,fontFamily:"IBM Plex Mono",lineHeight:1.7}}>
                        Set a 4-digit PIN to lock the app. Without a PIN, tapping the lock icon still scrolls-locks — tap anywhere to unlock.
                      </div>
                      <button className="sett-btn" onClick={startPinSetup}>🔑 Set PIN</button>
                    </div>
                  )}
                </div>
              )}

              {pinSetupStep===1 && (
                <div className="pin-step-box">
                  <div className="pin-step-label">Enter new 4-digit PIN</div>
                  <input className="pin-step-input" type="password" maxLength={4}
                    placeholder="● ● ● ●" value={pinFirst}
                    onChange={e=>setPinFirst(e.target.value.replace(/\D/g,"").slice(0,4))}
                    onKeyDown={e=>e.key==="Enter"&&submitPinFirst()}
                    autoFocus
                    style={{borderColor:pinErr?"#FF4D6D":undefined}}
                  />
                  {pinErr && <div style={{color:"#FF4D6D",fontSize:".65rem",fontFamily:"IBM Plex Mono"}}>PIN must be exactly 4 digits</div>}
                  <div style={{display:"flex",gap:8}}>
                    <button className="sett-btn" onClick={submitPinFirst}>Next →</button>
                    <button className="sett-btn" style={{borderColor:dim,color:dim,background:"transparent"}} onClick={()=>setPinSetupStep(0)}>Cancel</button>
                  </div>
                </div>
              )}

              {pinSetupStep===2 && (
                <div className="pin-step-box">
                  <div className="pin-step-label">Confirm PIN</div>
                  <input className="pin-step-input" type="password" maxLength={4}
                    placeholder="● ● ● ●" value={pinConfirm}
                    onChange={e=>setPinConfirm(e.target.value.replace(/\D/g,"").slice(0,4))}
                    onKeyDown={e=>e.key==="Enter"&&submitPinConfirm()}
                    autoFocus
                    style={{borderColor:pinErr?"#FF4D6D":undefined}}
                  />
                  {pinErr && <div style={{color:"#FF4D6D",fontSize:".65rem",fontFamily:"IBM Plex Mono"}}>PINs do not match — try again</div>}
                  <div style={{display:"flex",gap:8}}>
                    <button className="sett-btn" onClick={submitPinConfirm}>✅ Save PIN</button>
                    <button className="sett-btn" style={{borderColor:dim,color:dim,background:"transparent"}} onClick={()=>setPinSetupStep(0)}>Cancel</button>
                  </div>
                </div>
              )}

              {/* PRIVACY NOTE */}
              <div style={{background:sf2,border:`1px solid ${bd}`,borderRadius:10,padding:14}}>
                <div style={{fontFamily:"IBM Plex Mono",fontSize:".62rem",color:ac,fontWeight:700,marginBottom:4}}>ℹ Privacy Note</div>
                <div style={{fontFamily:"IBM Plex Mono",fontSize:".6rem",color:dim,lineHeight:1.7}}>
                  Name, theme, RGB, color, PIN — saved in browser only.<br/>
                  Password is local too. No data goes to any server.<br/>
                  Messages are never saved — 100% private.
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
          <button className={`icon-btn${locked?" active":""}`} onClick={toggleLock} title={locked?"Unlock":"Lock"}>
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
          <div className="hero-by">Built by <b>Subojeet Mandal</b> · AES-256-GCM Encryption</div>
        </div>

        {/* ── PIPELINE ── */}
        <div className="pipeline">
          <div className="pdot"/>
          {!fileMode ? (
            mode==="encrypt" ? (<>
              <span className="pip">Plain Text</span><span className="par">→</span>
              <span className="pip">AES-256-GCM</span><span className="par">→</span>
              <span className="pip">Base64 Encode</span><span className="par">→</span>
              <span className="pip">Encrypted Output</span>
            </>) : (<>
              <span className="pip">Base64 Input</span><span className="par">→</span>
              <span className="pip">Base64 Decode</span><span className="par">→</span>
              <span className="pip">AES-256-GCM</span><span className="par">→</span>
              <span className="pip">Plain Text</span>
            </>)
          ) : (
            mode==="encrypt" ? (<>
              <span className="pip">Any File</span><span className="par">→</span>
              <span className="pip">AES-256-GCM</span><span className="par">→</span>
              <span className="pip">.aescrypt</span>
            </>) : (<>
              <span className="pip">.aescrypt File</span><span className="par">→</span>
              <span className="pip">AES-256-GCM</span><span className="par">→</span>
              <span className="pip">Original File</span>
            </>)
          )}
        </div>

        {/* ── MODE ── */}
        <div className="mode-row">
          <div className="mode-toggle">
            <button className={`mbtn${mode==="encrypt"?" active":""}`}
              onClick={()=>{setMode("encrypt");clearAll();setSelectedFile(null);setFileOutput(null);setFileError("");setFileInfo("");}}>🔒 Encrypt</button>
            <button className={`mbtn${mode==="decrypt"?" active":""}`}
              onClick={()=>{setMode("decrypt");clearAll();setSelectedFile(null);setFileOutput(null);setFileError("");setFileInfo("");}}>🔓 Decrypt</button>
          </div>
        </div>

        {/* ── TEXT / FILE TABS ── */}
        <div className="tab-row">
          <div className="tab-bar">
            <button className={`tbtn${!fileMode?" active":""}`} onClick={()=>{setFileMode(false);setSelectedFile(null);setFileOutput(null);setFileError("");setFileInfo("");}}>
              📝 Text
            </button>
            <button className={`tbtn${fileMode?" active":""}`} onClick={()=>{setFileMode(true);clearAll();setOutput("");}}>
              📁 File
            </button>
          </div>
        </div>

        {/* ── TEXT MODE ── */}
        {!fileMode && (
          <div className="card">
            <div className="card-head">
              <span className="card-title">
                {mode==="encrypt" ? "Message — Plain Text" : "Encrypted Message — Base64"}
              </span>
              <span className="card-badge">
                {mode==="encrypt" ? "AES-256-GCM + Base64" : "Base64 → AES-GCM"}
              </span>
            </div>

            <div className="msg-wrap">
              <textarea className="big-textarea"
                placeholder={mode==="encrypt"
                  ? "Type or paste your message to encrypt here…"
                  : "Paste the full encrypted Base64 string to decrypt here…"}
                value={input}
                onChange={e=>{setInput(e.target.value);setOutput("");setError("");setInfo("");}}
              />
              <div className="char-count">{input.length}</div>
            </div>

            {/* PASSWORD */}
            <div className="pw-section">
              <div className="pw-mode-bar">
                <span className="pw-mode-label">🔑 Password</span>
                <div className="pw-toggle">
                  <button className={`pmb${pwMode==="manual"?" active":""}`} onClick={()=>setPwMode("manual")}>Manual</button>
                  <button className={`pmb${pwMode==="auto"?" active":""}`} onClick={()=>setPwMode("auto")}>Auto</button>
                </div>
              </div>

              {pwMode==="auto" && (
                <div className="auto-row">
                  <span className="auto-lbl">Length:</span>
                  <div className="len-btns">
                    {[12,13,14,15].map(n=>(
                      <button key={n} className={`lbtn${autoLen===n?" active":""}`} onClick={()=>setAutoLen(n)}>{n}</button>
                    ))}
                  </div>
                  <button className="gen-btn" onClick={handleGen}>⚡ Generate</button>
                  <span className="auto-hint">No min limit</span>
                </div>
              )}

              {pwMode==="manual" && (
                <div className="pw-hint">Type any password — no minimum length, use at your own risk</div>
              )}

              <div className="pw-input-row">
                <div className="pw-rel">
                  <span className="pw-icon-l">🔑</span>
                  <input className="pw-field"
                    type={pwMode==="auto" ? "text" : (showPw?"text":"password")}
                    placeholder={pwMode==="auto"
                      ? "Auto password will appear here…"
                      : "Type your password here — any length…"}
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

              <div className="pw-actions">
                <button className="pabtn sv" onClick={savePw} disabled={!password}>
                  {saved?"✅ Saved!":"💾 Save Password"}
                </button>
                <button className="pabtn cp" onClick={copyPw} disabled={!password}>
                  {pwCopied?"✓ Copied":"📋 Copy"}
                </button>
                <button className="pabtn dl" onClick={()=>{
                  try{localStorage.removeItem(LS_PW_PFX+"user");}catch{}
                  setPassword("");
                  flash("🗑 Saved password deleted");
                }}>🗑 Delete</button>
                <span className="pw-note">Local only · no server</span>
              </div>
            </div>

            <div className="proc-wrap">
              <button className="proc-btn" onClick={handleProcess}
                disabled={loading||!input.trim()||!password.trim()}>
                {loading&&<span className="spinner"/>}
                {loading?"Processing…":mode==="encrypt"?"🔒 Encrypt → Base64":"🔓 Base64 → Decrypt"}
              </button>
            </div>
          </div>
        )}

        {/* ── FILE MODE ── */}
        {fileMode && (
          <div className="card">
            <div className="card-head">
              <span className="card-title">
                {mode==="encrypt" ? "Select File to Encrypt" : "Select .aescrypt File to Decrypt"}
              </span>
              <span className="card-badge">
                {mode==="encrypt" ? "Any File Type" : ".aescrypt → Original"}
              </span>
            </div>

            {/* File picker */}
            {!selectedFile ? (
              <div className="file-drop" onClick={()=>fileRef.current?.click()}>
                <div className="file-drop-icon">{mode==="encrypt"?"📂":"🔒"}</div>
                <div className="file-drop-title">
                  {mode==="encrypt" ? "Click to select any file" : "Click to select .aescrypt file"}
                </div>
                <div className="file-drop-sub">
                  Supports: PNG, JPG, PDF, JS, JSX, TXT, JSON, PY, ZIP, and all other formats<br/>
                  Everything encrypted client-side — no upload to any server
                </div>
                <input ref={fileRef} type="file"
                  accept={mode==="decrypt"?".aescrypt,*":"*"}
                  onChange={e=>{
                    const f=e.target.files?.[0];
                    if(f){setSelectedFile(f);setFileOutput(null);setFileError("");setFileInfo("");}
                    e.target.value="";
                  }}
                />
              </div>
            ) : (
              <div className="file-selected">
                <div className="file-icon">
                  {selectedFile.name.match(/\.(png|jpg|jpeg|gif|webp)$/i)?"🖼️":
                   selectedFile.name.match(/\.(pdf)$/i)?"📄":
                   selectedFile.name.match(/\.(js|jsx|ts|tsx|py|json)$/i)?"💻":
                   selectedFile.name.match(/\.(zip|rar|7z)$/i)?"📦":
                   selectedFile.name.match(/\.aescrypt$/i)?"🔒":"📁"}
                </div>
                <div>
                  <div className="file-name">{selectedFile.name}</div>
                  <div className="file-meta">{fmtSize(selectedFile.size)} · {selectedFile.type||"unknown type"}</div>
                </div>
                <button className="file-clear" onClick={()=>{setSelectedFile(null);setFileOutput(null);setFileError("");setFileInfo("");}}>✕ Remove</button>
              </div>
            )}

            {/* Password for file */}
            <div className="pw-section">
              <div className="pw-mode-bar">
                <span className="pw-mode-label">🔑 Password</span>
                <div className="pw-toggle">
                  <button className={`pmb${pwMode==="manual"?" active":""}`} onClick={()=>setPwMode("manual")}>Manual</button>
                  <button className={`pmb${pwMode==="auto"?" active":""}`} onClick={()=>setPwMode("auto")}>Auto</button>
                </div>
              </div>
              {pwMode==="auto" && (
                <div className="auto-row">
                  <span className="auto-lbl">Length:</span>
                  <div className="len-btns">
                    {[12,13,14,15].map(n=>(
                      <button key={n} className={`lbtn${autoLen===n?" active":""}`} onClick={()=>setAutoLen(n)}>{n}</button>
                    ))}
                  </div>
                  <button className="gen-btn" onClick={handleGen}>⚡ Generate</button>
                </div>
              )}
              {pwMode==="manual" && <div className="pw-hint">Type any password — no minimum limit</div>}
              <div className="pw-input-row">
                <div className="pw-rel">
                  <span className="pw-icon-l">🔑</span>
                  <input className="pw-field"
                    type={showPw?"text":"password"}
                    placeholder="Password to encrypt/decrypt this file…"
                    value={password}
                    onChange={e=>setPassword(e.target.value)}
                  />
                  <button className="eye-btn" onClick={()=>setShowPw(p=>!p)}>
                    {showPw?"🙈":"👁"}
                  </button>
                </div>
              </div>
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
            </div>

            <div className="proc-wrap">
              <button className="proc-btn"
                disabled={fileLoading||!selectedFile||!password.trim()}
                onClick={mode==="encrypt"?handleFileEncrypt:handleFileDecrypt}>
                {fileLoading&&<span className="spinner"/>}
                {fileLoading?"Processing…":mode==="encrypt"?"🔒 Encrypt File":"🔓 Decrypt File"}
              </button>
            </div>
          </div>
        )}

        {/* INFO / ERROR */}
        {(info||fileInfo)  && <div className="info">{info||fileInfo}</div>}
        {(error||fileError)&& <div className="errbar">{error||fileError}</div>}

        {/* TEXT OUTPUT */}
        {!fileMode && output && (
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

        {/* FILE OUTPUT */}
        {fileMode && fileOutput && (
          <div className="file-out-card">
            <div style={{display:"flex",alignItems:"center",gap:10}}>
              <span style={{fontSize:"1.8rem"}}>✅</span>
              <div>
                <div style={{fontFamily:"IBM Plex Mono",fontSize:".75rem",color:ac,fontWeight:700}}>
                  {mode==="encrypt"?"File Encrypted Successfully":"File Decrypted Successfully"}
                </div>
                <div style={{fontFamily:"IBM Plex Mono",fontSize:".6rem",color:dim,marginTop:3}}>
                  {fileOutput.name} · {fmtSize(fileOutput.size)}
                </div>
              </div>
            </div>
            <a className="dl-btn" href={fileOutput.url} download={fileOutput.name}>
              ⬇️ Download {fileOutput.name}
            </a>
            <div style={{fontFamily:"IBM Plex Mono",fontSize:".58rem",color:dim,lineHeight:1.7}}>
              {mode==="encrypt"
                ? "Share this .aescrypt file — only someone with the correct password can open it."
                : "Your original file has been restored. Save it somewhere safe."}
            </div>
          </div>
        )}

        {/* TEXT STATS */}
        {!fileMode && output && (
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
          <div className="how-sub">Understanding the encryption pipeline</div>

          <div className="how-card">
            <div className="how-num">01</div>
            <div className="how-content">
              <div className="how-h">Provide Message + Password</div>
              <div className="how-p">Type your message and choose a password — any length, no minimum. You can also auto-generate a strong 12–15 character password with uppercase, lowercase, digits, and symbols mixed in. File mode accepts any file type: PNG, JPG, PDF, JS, JSX, TXT, JSON, and more.</div>
            </div>
          </div>

          <div className="how-card">
            <div className="how-num">02</div>
            <div className="how-content">
              <div className="how-h">PBKDF2 Key Derivation</div>
              <div className="how-p">Your password is never used directly. First it goes through PBKDF2-SHA256 with 250,000 iterations and a random salt to generate a 256-bit key. The random salt ensures every encryption produces a different key — even with the same password.</div>
              <div className="how-code">Password + Random Salt(128-bit) → PBKDF2-SHA256 × 250,000 → AES-256 Key</div>
            </div>
          </div>

          <div className="how-card">
            <div className="how-num">03</div>
            <div className="how-content">
              <div className="how-h">AES-256-GCM Encryption</div>
              <div className="how-p">The message or file is encrypted with AES-256-GCM — military grade encryption used by governments and banks. GCM mode also provides authentication, so any tampering with the encrypted data is detected during decryption.</div>
              <div className="how-code">Data → AES-256-GCM(key, random IV) → Ciphertext + Auth Tag</div>
            </div>
          </div>

          <div className="how-card">
            <div className="how-num">04</div>
            <div className="how-content">
              <div className="how-h">Base64 Encoding — Final Output</div>
              <div className="how-p">For text mode, encrypted bytes are converted to a URL-safe Base64 string. Salt + IV + Ciphertext are all packed into one portable string — easy to copy and share. Files are saved as .aescrypt binary format.</div>
              <div className="how-code">Salt(16B) + IV(12B) + Ciphertext → Pack → Base64 / .aescrypt File</div>
            </div>
          </div>

          <div className="how-card">
            <div className="how-num">05</div>
            <div className="how-content">
              <div className="how-h">Decryption — Reverse Pipeline</div>
              <div className="how-p">To decrypt: decode Base64 (or read the .aescrypt file), extract the salt and IV, re-derive the key using the same password, then AES-GCM decrypts the original data. Wrong password = decryption fails completely.</div>
              <div className="how-code">Base64 / File → Unpack → Derive Key → AES-GCM Decrypt → Original Data</div>
            </div>
          </div>

          <div className="how-card" style={{borderColor:`${ac}44`}}>
            <div className="how-num">🛡</div>
            <div className="how-content">
              <div className="how-h" style={{color:ac}}>100% Client Side — Zero Server</div>
              <div className="how-p">Everything happens in your browser. No message, no password, no encrypted data, no file ever leaves your device. The Web Crypto API — your browser's built-in secure crypto engine — does all the work. No tracking, no logs, no server.</div>
            </div>
          </div>
        </div>

        {/* FOOTER */}
        <div className="footer">
          <div className="footer-brand">AESCRYPT</div>
          <div className="footer-powered">Built by <b>Subojeet Mandal</b> · Military Level Encryption · Client Side</div>
          <div className="footer-powered" style={{marginTop:4}}>
            <b>AES-256-GCM + Base64</b> · Zero Knowledge · No Server · No Tracking
          </div>
        </div>

      </div>
    </>
  );
}
