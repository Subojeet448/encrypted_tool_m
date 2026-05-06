import { useState, useCallback, useEffect } from "react";
import Head from "next/head";

/* ═══════════════════════════════════════════════════════════
   CONFIG
═══════════════════════════════════════════════════════════ */
const USERS = [
  { id: 1, name: "Alice",   color: "#C8FF00", avatar: "A" },
  { id: 2, name: "Bob",     color: "#FF4D6D", avatar: "B" },
  { id: 3, name: "Charlie", color: "#4DFFEF", avatar: "C" },
  { id: 4, name: "Diana",   color: "#FF9F1C", avatar: "D" },
];
const DEVELOPER  = "@MANDAL4482";
const LS_KEY_PFX = "aescrypt_pw_";   // localStorage key prefix per user
const MIN_PW_LEN = 6;                // minimum password length

/* ═══════════════════════════════════════════════════════════
   CRYPTO PIPELINE
   ENCRYPT: plaintext → AES-256-GCM → pack bytes → Base64
   DECRYPT: Base64 → unpack bytes → AES-256-GCM → plaintext
═══════════════════════════════════════════════════════════ */

async function deriveKey(passphrase, salt) {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey(
    "raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 250_000, hash: "SHA-256" },
    raw,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function b64ToBytes(b64) {
  let s = b64.trim().replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function encryptFull(plaintext, passphrase) {
  if (!plaintext.trim()) throw new Error("Text khali hai");
  if (passphrase.trim().length < MIN_PW_LEN)
    throw new Error(`Password kam se kam ${MIN_PW_LEN} characters ka hona chahiye`);

  const enc    = new TextEncoder();
  const salt   = crypto.getRandomValues(new Uint8Array(16));
  const iv     = crypto.getRandomValues(new Uint8Array(12));
  const key    = await deriveKey(passphrase, salt);
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: 128 }, key, enc.encode(plaintext.trim())
  );
  const cb = new Uint8Array(cipher);
  const packed = new Uint8Array(16 + 12 + cb.length);
  packed.set(salt, 0);
  packed.set(iv,   16);
  packed.set(cb,   28);
  return bytesToB64(packed);
}

async function decryptFull(b64Input, passphrase) {
  if (!b64Input.trim()) throw new Error("Encrypted text khali hai");
  if (!passphrase.trim()) throw new Error("Password dalo");

  let packed;
  try { packed = b64ToBytes(b64Input); }
  catch { throw new Error("Invalid Base64 — pura encrypted string paste karo"); }

  if (packed.length < 44)
    throw new Error("Data too short — corrupted ya incomplete ciphertext");

  const salt   = packed.slice(0,  16);
  const iv     = packed.slice(16, 28);
  const cipher = packed.slice(28);
  const key    = await deriveKey(passphrase, salt);

  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: 128 }, key, cipher
    );
  } catch {
    throw new Error("Decryption failed — galat password ya tampered/corrupted data");
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(plain);
}

/* ═══════════════════════════════════════════════════════════
   PASSWORD HELPERS
═══════════════════════════════════════════════════════════ */
const LOWER  = "abcdefghijklmnopqrstuvwxyz";
const UPPER  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBS  = "!@#$%^&*-_+=?";

function cryptoPick(charset, n) {
  const rnd = crypto.getRandomValues(new Uint8Array(n));
  return Array.from(rnd).map(b => charset[b % charset.length]).join("");
}

function generatePassword(length = 14) {
  const mandatory = cryptoPick(UPPER,1) + cryptoPick(LOWER,2) +
                    cryptoPick(DIGITS,2) + cryptoPick(SYMBS,1);
  const all  = LOWER + UPPER + DIGITS + SYMBS;
  const rest = cryptoPick(all, length - mandatory.length);
  const arr  = (mandatory + rest).split("");
  const rnd  = crypto.getRandomValues(new Uint32Array(arr.length));
  for (let i = arr.length - 1; i > 0; i--) {
    const j = rnd[i] % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join("");
}

function pwStrength(pw) {
  if (!pw) return { score: 0, label: "", color: "#3A3F55" };
  let s = 0;
  if (pw.length >= 8)  s++;
  if (pw.length >= 12) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  const idx = Math.min(s, 4);
  return [
    { score: 0, label: "Very Weak",   color: "#FF4D4D" },
    { score: 1, label: "Weak",        color: "#FF9F1C" },
    { score: 2, label: "Fair",        color: "#FFD93D" },
    { score: 3, label: "Strong",      color: "#6BCB77" },
    { score: 4, label: "Very Strong", color: "#C8FF00" },
  ][idx];
}

/* ═══════════════════════════════════════════════════════════
   COMPONENT
═══════════════════════════════════════════════════════════ */
export default function Home() {
  const [activeUser, setActiveUser] = useState(USERS[0]);
  const [mode,       setMode]       = useState("encrypt");
  const [pwMode,     setPwMode]     = useState("manual");
  const [autoLen,    setAutoLen]    = useState(14);
  const [password,   setPassword]   = useState("");
  const [showPw,     setShowPw]     = useState(false);
  const [input,      setInput]      = useState("");
  const [output,     setOutput]     = useState("");
  const [error,      setError]      = useState("");
  const [info,       setInfo]       = useState("");
  const [loading,    setLoading]    = useState(false);
  const [outCopied,  setOutCopied]  = useState(false);
  const [pwCopied,   setPwCopied]   = useState(false);
  const [savedFlag,  setSavedFlag]  = useState(false);

  const strength = pwStrength(password);

  /* Load saved password when user switches */
  useEffect(() => {
    try {
      const saved = localStorage.getItem(LS_KEY_PFX + activeUser.id);
      if (saved) {
        setPassword(saved);
        flash(`💾 ${activeUser.name} ka saved password load ho gaya`, "info");
      } else {
        setPassword("");
      }
    } catch { /* localStorage unavailable */ }
    setOutput(""); setError("");
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeUser]);

  function flash(msg, type = "info") {
    if (type === "info") setInfo(msg); else setError(msg);
    setTimeout(() => { setInfo(""); setError(""); }, 3500);
  }

  const savePassword = () => {
    if (!password) { flash("Pehle password dalo", "err"); return; }
    try {
      localStorage.setItem(LS_KEY_PFX + activeUser.id, password);
      setSavedFlag(true);
      flash(`✅ ${activeUser.name} ka password browser mein save ho gaya`);
      setTimeout(() => setSavedFlag(false), 3000);
    } catch { flash("Save nahi ho saka — localStorage blocked", "err"); }
  };

  const deleteSavedPw = () => {
    try { localStorage.removeItem(LS_KEY_PFX + activeUser.id); }
    catch { /* ignore */ }
    flash(`🗑 ${activeUser.name} ka saved password hata diya gaya`);
  };

  const handleAutoGenerate = useCallback(() => {
    const pw = generatePassword(autoLen);
    setPassword(pw);
    setShowPw(true);
    flash(`⚡ ${autoLen}-character strong password ready — save karna mat bhulna!`);
  }, [autoLen]);

  const copyPw = async () => {
    if (!password) return;
    await navigator.clipboard.writeText(password);
    setPwCopied(true); setTimeout(() => setPwCopied(false), 2000);
  };
  const copyOutput = async () => {
    if (!output) return;
    await navigator.clipboard.writeText(output);
    setOutCopied(true); setTimeout(() => setOutCopied(false), 2000);
  };

  /* Validation before process */
  function validate() {
    if (!password.trim())
      return "Password/key dalo — yeh zaruri hai";
    if (password.trim().length < MIN_PW_LEN)
      return `Password kam se kam ${MIN_PW_LEN} characters ka hona chahiye (abhi: ${password.trim().length})`;
    if (!input.trim())
      return "Input text khali hai";
    if (mode === "decrypt") {
      try {
        const bytes = b64ToBytes(input.trim());
        if (bytes.length < 44)
          return "Yeh valid encrypted text nahi lagta — pura Base64 string paste karo";
      } catch {
        return "Input valid Base64 encrypted string nahi hai — check karo";
      }
    }
    return null;
  }

  const handleProcess = useCallback(async () => {
    setError(""); setOutput(""); setInfo("");
    const err = validate();
    if (err) { setError(err); return; }
    setLoading(true);
    try {
      if (mode === "encrypt") {
        setInfo("🔐 AES-256-GCM encryption chal rahi hai…");
        const result = await encryptFull(input, password);
        setInfo("✅ Encrypted! Base64 output ready.");
        setOutput(result);
        setTimeout(() => setInfo(""), 4000);
      } else {
        setInfo("📦 Base64 decode ho raha hai…");
        await new Promise(r => setTimeout(r, 60));
        setInfo("🔓 AES-GCM decryption chal rahi hai…");
        const plain = await decryptFull(input, password);
        setInfo("✅ Decryption successful — original text wapas aa gaya!");
        setOutput(plain);
        setTimeout(() => setInfo(""), 4000);
      }
    } catch (e) {
      setError("❌ " + e.message);
      setInfo("");
    }
    setLoading(false);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [input, password, mode]);

  const clearAll = () => { setInput(""); setOutput(""); setError(""); setInfo(""); };

  /* ─── RENDER ────────────────────────────────────────── */
  return (
    <>
      <Head>
        <title>AESCRYPT — AES-256-GCM + Base64</title>
        <meta name="description" content="Double-layer AES-256-GCM + Base64 Encryption Tool" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:ital,wght@0,400;0,500;0,700;1,400&family=Bebas+Neue&display=swap" rel="stylesheet" />
      </Head>

      <style>{`
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
        :root{
          --bg:#07080D;--sf:#0D0F17;--sf2:#11141F;--sf3:#161925;
          --bd:#1C2030;--bd2:#252A3A;
          --ac:#C8FF00;--red:#FF4D6D;--amber:#FF9F1C;--cyan:#4DFFEF;
          --dim:#3A3F55;--text:#D4D8EF;
          --mono:'IBM Plex Mono',monospace;--disp:'Bebas Neue',cursive;
        }
        html,body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;overflow-x:hidden}
        body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
          background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(200,255,0,0.007) 3px,rgba(200,255,0,0.007) 4px)}
        .wrap{position:relative;z-index:1;max-width:980px;margin:0 auto;padding:24px 16px 64px}

        /* HEADER */
        .hdr{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:26px;gap:16px;flex-wrap:wrap}
        .logo{font-family:var(--disp);font-size:3.4rem;line-height:1;letter-spacing:3px;color:var(--ac);text-shadow:0 0 40px rgba(200,255,0,0.3)}
        .logo-sub{font-size:.55rem;letter-spacing:4px;text-transform:uppercase;color:var(--dim);margin-top:3px}
        .dev-tag{font-size:.58rem;letter-spacing:2px;color:rgba(200,255,0,0.4);margin-top:5px}
        .dev-tag b{color:var(--ac)}

        /* USERS */
        .user-row{display:flex;align-items:center;gap:8px;background:var(--sf);border:1px solid var(--bd);border-radius:100px;padding:6px 10px}
        .u-label{font-size:.52rem;letter-spacing:2px;text-transform:uppercase;color:var(--dim);padding:0 4px}
        .u-btn{width:34px;height:34px;border-radius:50%;border:2px solid transparent;background:var(--sf2);cursor:pointer;font-weight:700;font-size:.78rem;transition:all .18s;display:flex;align-items:center;justify-content:center}
        .u-btn:hover{transform:scale(1.1)}
        .u-btn.active{transform:scale(1.13)}

        /* PIPELINE */
        .pipeline{display:flex;align-items:center;gap:0;margin-bottom:18px;background:var(--sf);border:1px solid var(--bd);border-radius:12px;padding:10px 16px;flex-wrap:wrap;row-gap:4px}
        .pip-step{font-size:.58rem;letter-spacing:1px;text-transform:uppercase;color:var(--ac);font-weight:700}
        .pip-arrow{font-size:.65rem;color:var(--dim);margin:0 7px}
        .dot{width:6px;height:6px;border-radius:50%;background:var(--ac);display:inline-block;animation:pulse 2s infinite;margin-right:8px;flex-shrink:0}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.2}}

        /* MODE */
        .mode-bar{display:flex;align-items:center;gap:10px;margin-bottom:18px;flex-wrap:wrap}
        .mode-toggle{display:flex;border:1px solid var(--bd);border-radius:10px;overflow:hidden}
        .m-btn{padding:10px 30px;font-family:var(--mono);font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:2px;border:none;cursor:pointer;background:transparent;color:var(--dim);transition:all .18s;white-space:nowrap}
        .m-btn.active{background:var(--ac);color:#07080D}

        /* PASSWORD CARD */
        .pw-card{background:var(--sf);border:1px solid var(--bd);border-radius:14px;overflow:hidden;margin-bottom:16px}
        .pw-head{padding:12px 18px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:10px;flex-wrap:wrap}
        .pw-title{font-size:.58rem;letter-spacing:3px;text-transform:uppercase;color:var(--dim)}
        .pw-mode-toggle{display:flex;border:1px solid var(--bd);border-radius:8px;overflow:hidden;margin-left:auto}
        .pm-btn{padding:6px 18px;font-family:var(--mono);font-size:.6rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;border:none;cursor:pointer;background:transparent;color:var(--dim);transition:all .16s}
        .pm-btn.active{background:var(--sf3);color:var(--text)}

        .pw-body{padding:14px 18px;display:flex;flex-direction:column;gap:11px}

        /* Auto row */
        .auto-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
        .auto-label{font-size:.56rem;letter-spacing:1px;text-transform:uppercase;color:var(--dim)}
        .len-btns{display:flex;gap:5px}
        .len-btn{padding:5px 13px;border-radius:7px;border:1px solid var(--bd);background:transparent;color:var(--dim);font-family:var(--mono);font-size:.62rem;cursor:pointer;transition:all .15s}
        .len-btn.active{border-color:var(--ac);color:var(--ac);background:rgba(200,255,0,.06)}
        .gen-btn{padding:8px 22px;border-radius:8px;border:1px solid var(--ac);background:rgba(200,255,0,.07);color:var(--ac);font-family:var(--mono);font-size:.65rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;cursor:pointer;transition:all .18s;white-space:nowrap}
        .gen-btn:hover{background:var(--ac);color:#07080D}

        /* Input row */
        .pw-input-row{display:flex;gap:8px}
        .pw-wrap{flex:1;position:relative}
        .pw-icon{position:absolute;left:13px;top:50%;transform:translateY(-50%);font-size:.8rem;pointer-events:none}
        .pw-input{width:100%;padding:11px 42px 11px 36px;background:var(--sf2);border:1px solid var(--bd);border-radius:10px;color:var(--ac);font-family:var(--mono);font-size:.78rem;outline:none;transition:border-color .2s;letter-spacing:.5px}
        .pw-input:focus{border-color:var(--ac)}
        .pw-input::placeholder{color:var(--dim);letter-spacing:0;font-style:italic;font-size:.72rem}
        .eye-btn{position:absolute;right:10px;top:50%;transform:translateY(-50%);background:transparent;border:none;cursor:pointer;color:var(--dim);font-size:.8rem;padding:4px;line-height:1;transition:color .15s}
        .eye-btn:hover{color:var(--text)}

        /* Strength */
        .str-row{display:flex;align-items:center;gap:10px}
        .str-bars{display:flex;gap:4px;flex:1}
        .s-bar{height:3px;border-radius:2px;flex:1;background:var(--bd2);transition:background .3s}
        .str-label{font-size:.55rem;letter-spacing:1px;text-transform:uppercase;min-width:72px;text-align:right}
        .str-len{font-size:.55rem;color:var(--dim)}

        /* PW actions */
        .pw-actions{display:flex;gap:7px;flex-wrap:wrap;align-items:center}
        .pa-btn{padding:7px 14px;border-radius:8px;border:1px solid var(--bd);background:transparent;color:var(--dim);font-family:var(--mono);font-size:.6rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;cursor:pointer;transition:all .18s;white-space:nowrap}
        .pa-btn:disabled{opacity:.3;cursor:not-allowed}
        .pa-btn.save{border-color:rgba(200,255,0,.25);color:var(--ac)}
        .pa-btn.save:not(:disabled):hover{background:var(--ac);color:#07080D;border-color:var(--ac)}
        .pa-btn.cp:not(:disabled):hover{color:var(--cyan);border-color:var(--cyan)}
        .pa-btn.del:hover{color:var(--red);border-color:var(--red)}
        .pa-note{font-size:.5rem;color:#1e2235;margin-left:auto}

        /* INFO / ERROR */
        .info-bar{padding:9px 16px;border-radius:10px;border:1px solid rgba(200,255,0,.18);background:rgba(200,255,0,.04);color:var(--ac);font-size:.68rem;margin-bottom:14px;line-height:1.6}
        .err-bar{padding:9px 16px;border-radius:10px;border:1px solid rgba(255,77,109,.28);background:rgba(255,77,109,.05);color:var(--red);font-size:.68rem;margin-bottom:14px;line-height:1.6}

        /* PANELS */
        .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
        @media(max-width:620px){.grid{grid-template-columns:1fr}}
        .panel{background:var(--sf);border:1px solid var(--bd);border-radius:14px;overflow:hidden;display:flex;flex-direction:column}
        .p-head{padding:11px 16px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between}
        .p-label{font-size:.55rem;letter-spacing:3px;text-transform:uppercase;color:var(--dim)}
        .p-meta{font-size:.55rem;color:#252840}
        textarea{flex:1;width:100%;min-height:200px;padding:14px 16px;background:transparent;border:none;outline:none;color:var(--text);font-family:var(--mono);font-size:.75rem;resize:vertical;line-height:1.75}
        textarea::placeholder{color:#1e2235;font-style:italic;font-size:.72rem}
        textarea[readonly]{color:var(--ac)}
        .p-foot{padding:9px 14px;border-top:1px solid var(--bd);display:flex;gap:7px;flex-wrap:wrap;align-items:center}

        /* PROCESS BTN */
        .proc-wrap{display:flex;justify-content:center;margin:18px 0 10px}
        .proc-btn{padding:14px 54px;background:var(--ac);color:#07080D;font-family:var(--mono);font-weight:700;font-size:.82rem;letter-spacing:3px;text-transform:uppercase;border:none;border-radius:12px;cursor:pointer;transition:all .2s}
        .proc-btn:hover:not(:disabled){box-shadow:0 0 28px rgba(200,255,0,0.22);transform:translateY(-1px)}
        .proc-btn:active:not(:disabled){transform:scale(.97)}
        .proc-btn:disabled{opacity:.35;cursor:not-allowed}
        .spinner{display:inline-block;width:13px;height:13px;border:2px solid rgba(0,0,0,.25);border-top-color:#000;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:8px}
        @keyframes spin{to{transform:rotate(360deg)}}

        /* STATS */
        .stats{display:flex;gap:8px;margin-top:14px;flex-wrap:wrap}
        .stat{background:var(--sf);border:1px solid var(--bd);border-radius:10px;padding:11px 16px;flex:1;min-width:80px}
        .stat-v{font-family:var(--disp);font-size:1.5rem;color:var(--ac);line-height:1}
        .stat-l{font-size:.5rem;letter-spacing:2px;text-transform:uppercase;color:var(--dim);margin-top:3px}

        /* GENERIC BTNS */
        .btn{padding:6px 14px;border-radius:7px;border:1px solid var(--bd);background:transparent;color:#555;font-family:var(--mono);font-size:.6rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;cursor:pointer;transition:all .18s}
        .btn:disabled{opacity:.3;cursor:not-allowed}
        .btn-copy{border-color:rgba(200,255,0,.22);color:var(--ac)}
        .btn-copy:not(:disabled):hover{background:var(--ac);color:#07080D;border-color:var(--ac)}
        .btn-clear:hover{color:var(--red);border-color:var(--red)}

        /* FOOTER */
        .site-footer{text-align:center;padding:28px 0 0;font-size:.52rem;letter-spacing:2px;color:#181c2a}
        .site-footer b{color:rgba(200,255,0,.35)}
      `}</style>

      <div className="wrap">

        {/* HEADER */}
        <header className="hdr">
          <div>
            <div className="logo">AESCRYPT</div>
            <div className="logo-sub">Double-Layer · AES-256-GCM + Base64</div>
            <div className="dev-tag">Developer: <b>{DEVELOPER}</b></div>
          </div>
          <div className="user-row">
            <span className="u-label">User</span>
            {USERS.map(u => (
              <button key={u.id}
                className={`u-btn${activeUser.id === u.id ? " active" : ""}`}
                style={{
                  color: u.color,
                  borderColor: activeUser.id === u.id ? u.color : "transparent",
                  boxShadow: activeUser.id === u.id ? `0 0 14px ${u.color}44` : "none"
                }}
                onClick={() => setActiveUser(u)} title={u.name}>
                {u.avatar}
              </button>
            ))}
          </div>
        </header>

        {/* PIPELINE */}
        <div className="pipeline">
          <div className="dot" />
          {mode === "encrypt" ? (
            <>
              <span className="pip-step">Plain Text</span>
              <span className="pip-arrow">→</span>
              <span className="pip-step">AES-256-GCM</span>
              <span className="pip-arrow">→</span>
              <span className="pip-step">Base64 Encode</span>
              <span className="pip-arrow">→</span>
              <span className="pip-step">Encrypted Output</span>
            </>
          ) : (
            <>
              <span className="pip-step">Base64 Input</span>
              <span className="pip-arrow">→</span>
              <span className="pip-step">Base64 Decode</span>
              <span className="pip-arrow">→</span>
              <span className="pip-step">AES-256-GCM</span>
              <span className="pip-arrow">→</span>
              <span className="pip-step">Plain Text</span>
            </>
          )}
        </div>

        {/* MODE */}
        <div className="mode-bar">
          <div className="mode-toggle">
            <button className={`m-btn${mode==="encrypt"?" active":""}`}
              onClick={() => { setMode("encrypt"); setOutput(""); setError(""); setInfo(""); }}>
              🔒 Encrypt
            </button>
            <button className={`m-btn${mode==="decrypt"?" active":""}`}
              onClick={() => { setMode("decrypt"); setOutput(""); setError(""); setInfo(""); }}>
              🔓 Decrypt
            </button>
          </div>
        </div>

        {/* PASSWORD CARD */}
        <div className="pw-card">
          <div className="pw-head">
            <span className="pw-title">🔑 Password / Secret Key</span>
            <div className="pw-mode-toggle">
              <button className={`pm-btn${pwMode==="manual"?" active":""}`}
                onClick={() => setPwMode("manual")}>Manual</button>
              <button className={`pm-btn${pwMode==="auto"?" active":""}`}
                onClick={() => setPwMode("auto")}>Auto</button>
            </div>
          </div>

          <div className="pw-body">

            {/* AUTO: length selector + generate */}
            {pwMode === "auto" && (
              <div className="auto-row">
                <span className="auto-label">Length:</span>
                <div className="len-btns">
                  {[12, 13, 14, 15].map(n => (
                    <button key={n}
                      className={`len-btn${autoLen===n?" active":""}`}
                      onClick={() => setAutoLen(n)}>{n}</button>
                  ))}
                </div>
                <button className="gen-btn" onClick={handleAutoGenerate}>
                  ⚡ Generate
                </button>
                <span style={{fontSize:".56rem",color:"var(--dim)"}}>
                  Uppercase + lowercase + digits + symbols guaranteed
                </span>
              </div>
            )}

            {/* Password field (always visible) */}
            <div className="pw-input-row">
              <div className="pw-wrap">
                <span className="pw-icon">🔑</span>
                <input
                  className="pw-input"
                  type={showPw ? "text" : "password"}
                  placeholder={pwMode === "auto"
                    ? "Generate button dabao ya manually type karo…"
                    : "Apna password / passphrase yahan type karo…"}
                  value={password}
                  onChange={e => { setPassword(e.target.value); setError(""); }}
                />
                <button className="eye-btn" onClick={() => setShowPw(p => !p)}>
                  {showPw ? "🙈" : "👁"}
                </button>
              </div>
            </div>

            {/* Strength meter */}
            {password && (
              <div className="str-row">
                <div className="str-bars">
                  {[1,2,3,4].map(i => (
                    <div key={i} className="s-bar"
                      style={{ background: i <= strength.score ? strength.color : undefined }} />
                  ))}
                </div>
                <span className="str-label" style={{ color: strength.color }}>{strength.label}</span>
                <span className="str-len">{password.length} chars</span>
              </div>
            )}

            {/* Action buttons */}
            <div className="pw-actions">
              <button className={`pa-btn save`} onClick={savePassword} disabled={!password}>
                {savedFlag ? "✅ Saved!" : "💾 Save Password"}
              </button>
              <button className="pa-btn cp" onClick={copyPw} disabled={!password}>
                {pwCopied ? "✓ Copied" : "📋 Copy"}
              </button>
              <button className="pa-btn del" onClick={deleteSavedPw}>
                🗑 Delete Saved
              </button>
              <span className="pa-note">Browser localStorage only · no server</span>
            </div>

          </div>
        </div>

        {/* INFO / ERROR */}
        {info  && <div className="info-bar">{info}</div>}
        {error && <div className="err-bar">{error}</div>}

        {/* TEXT PANELS */}
        <div className="grid">
          <div className="panel">
            <div className="p-head">
              <span className="p-label">
                {mode === "encrypt" ? "Plain Text Input" : "Base64 Encrypted Input"}
              </span>
              <span className="p-meta">{input.length} chars</span>
            </div>
            <textarea
              placeholder={mode === "encrypt"
                ? "Encrypt karne wala text yahan likho ya paste karo…"
                : "Pura Base64 encrypted string yahan paste karo…"}
              value={input}
              onChange={e => { setInput(e.target.value); setOutput(""); setError(""); setInfo(""); }}
            />
            <div className="p-foot">
              <button className="btn btn-clear" onClick={clearAll}>🗑 Clear All</button>
            </div>
          </div>

          <div className="panel">
            <div className="p-head">
              <span className="p-label">
                {mode === "encrypt" ? "Base64 Encrypted Output" : "Decrypted Plain Text"}
              </span>
              <span className="p-meta">{output.length} chars</span>
            </div>
            <textarea
              readOnly
              placeholder={mode === "encrypt"
                ? "Encrypted Base64 output yahan aayega…"
                : "Original plain text yahan aayega…"}
              value={output}
            />
            <div className="p-foot">
              <button className="btn btn-copy" onClick={copyOutput} disabled={!output}>
                {outCopied ? "✓ Copied!" : "📋 Copy Output"}
              </button>
            </div>
          </div>
        </div>

        {/* PROCESS BUTTON */}
        <div className="proc-wrap">
          <button className="proc-btn"
            onClick={handleProcess}
            disabled={loading || !input.trim() || !password.trim()}>
            {loading && <span className="spinner" />}
            {loading ? "Processing…" : mode === "encrypt"
              ? "🔒 Encrypt → Base64"
              : "🔓 Base64 → Decrypt"}
          </button>
        </div>

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

        {/* FOOTER */}
        <div className="site-footer">
          AESCRYPT · Developer: <b>{DEVELOPER}</b> · AES-256-GCM + Base64 · 100% Browser-side · No data sent anywhere
        </div>

      </div>
    </>
  );
}
