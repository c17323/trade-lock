import {
  Buffer,
  defaultChainInfo,
  mainnetClient,
  roundAt,
  roundTime,
  timelockDecrypt,
  timelockEncrypt,
} from "tlock-js";

const STORAGE_KEY = "tradeLock.v1";
const CHAIN = defaultChainInfo;
const client = mainnetClient();

const ALPHABET =
  "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
const PASSWORD_LENGTH = 24;

const dom = {
  setup: document.getElementById("setup"),
  locked: document.getElementById("locked"),
  form: document.getElementById("setupForm"),
  unlockAt: document.getElementById("unlockAt"),
  label: document.getElementById("label"),
  password: document.getElementById("password"),
  generate: document.getElementById("generate"),
  ack: document.getElementById("ack"),
  lockBtn: document.getElementById("lockBtn"),
  setupStatus: document.getElementById("setupStatus"),
  lockLabel: document.getElementById("lockLabel"),
  lockState: document.getElementById("lockState"),
  cdDays: document.getElementById("cdDays"),
  cdHours: document.getElementById("cdHours"),
  cdMinutes: document.getElementById("cdMinutes"),
  cdSeconds: document.getElementById("cdSeconds"),
  unlockAtText: document.getElementById("unlockAtText"),
  fingerprint: document.getElementById("fingerprint"),
  decrypt: document.getElementById("decrypt"),
  export: document.getElementById("export"),
  reset: document.getElementById("reset"),
  lockStatus: document.getElementById("lockStatus"),
  reveal: document.getElementById("reveal"),
  secret: document.getElementById("secret"),
  copySecret: document.getElementById("copySecret"),
  importTop: document.getElementById("importTop"),
  importFile: document.getElementById("importFile"),
  clock: document.getElementById("clock"),
};

let data = null;
let timer = null;
let busy = false;
let revealed = false;
let lastSecret = "";

/* ---------- formatting ---------- */

const pad = (n) => String(n).padStart(2, "0");

function toLocalInputValue(ts) {
  const d = new Date(ts);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(
    d.getHours()
  )}:${pad(d.getMinutes())}`;
}

function formatDateTime(ts) {
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(ts));
}

function formatClock(ts) {
  return new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(ts));
}

/* ---------- random / hash ---------- */

function randomPassword(length = PASSWORD_LENGTH) {
  const out = [];
  const max = 256 - (256 % ALPHABET.length);
  while (out.length < length) {
    const buf = new Uint8Array(length * 2);
    crypto.getRandomValues(buf);
    for (const byte of buf) {
      if (byte < max && out.length < length) {
        out.push(ALPHABET[byte % ALPHABET.length]);
      }
    }
  }
  return out.join("");
}

async function fingerprint(text) {
  try {
    const bytes = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(digest)]
      .slice(0, 8)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  } catch {
    // Display-only fallback for non-secure contexts; not used for security.
    let h = 0x811c9dc5;
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return (h >>> 0).toString(16).padStart(8, "0");
  }
}

/* ---------- storage ---------- */

function load() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed.ciphertext !== "string") return null;
    return parsed;
  } catch {
    return null;
  }
}

function save(next) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    return true;
  } catch (err) {
    dom.setupStatus.textContent =
      "无法写入浏览器存储（可能是隐私模式）。请先导出备份，否则刷新会丢失密文。";
    return false;
  }
}

/* ---------- round math ---------- */

function nextRoundForTime(targetMs) {
  let round = roundAt(targetMs, CHAIN);
  // If the target is already in the past or within the next few seconds,
  // move to a round that is comfortably in the future.
  while (roundTime(CHAIN, round) <= Date.now() + 4000) {
    round += 1;
  }
  return round;
}

/* ---------- setup ---------- */

function resetForm() {
  const target = Date.now() + 7 * 24 * 60 * 60 * 1000;
  dom.unlockAt.value = toLocalInputValue(target);
  dom.unlockAt.min = toLocalInputValue(Date.now() + 60 * 1000);
  dom.label.value = "";
  dom.password.value = randomPassword();
  dom.ack.checked = false;
}

async function createLock(event) {
  event.preventDefault();
  if (busy) return;

  const target = new Date(dom.unlockAt.value).getTime();
  const password = dom.password.value;
  const label = dom.label.value.trim();

  if (!Number.isFinite(target) || target <= Date.now() + 30_000) {
    dom.setupStatus.textContent = "解锁时间至少要在 1 分钟之后。";
    return;
  }
  if (password.length < 8) {
    dom.setupStatus.textContent = "密码太短了，至少 8 位。";
    return;
  }
  if (!dom.ack.checked) {
    dom.setupStatus.textContent = "请先确认你理解锁定后果。";
    return;
  }

  busy = true;
  dom.lockBtn.disabled = true;
  dom.lockBtn.textContent = "正在加密…";
  dom.setupStatus.textContent = "正在向 drand 信标计算未来轮次，并在本地加密。";

  try {
    const round = nextRoundForTime(target);
    const unlockAt = roundTime(CHAIN, round);
    const ciphertext = await timelockEncrypt(
      round,
      Buffer.from(password, "utf8"),
      client
    );
    const next = {
      v: 1,
      ciphertext,
      round,
      unlockAt,
      createdAt: Date.now(),
      label: label || "未命名锁定",
      chainHash: CHAIN.hash,
      fingerprint: await fingerprint(ciphertext),
    };

    if (!save(next)) {
      // Even if storage failed, show the lock so the user can export it.
    }
    data = next;
    lastSecret = "";
    dom.password.value = "";
    dom.setupStatus.textContent = "";
    render();
  } catch (err) {
    dom.setupStatus.textContent = `加密失败：${String(err.message || err)}`;
  } finally {
    busy = false;
    dom.lockBtn.disabled = false;
    dom.lockBtn.textContent = "加密并锁定";
  }
}

/* ---------- locked view ---------- */

function render() {
  if (data) {
    dom.setup.hidden = true;
    dom.locked.hidden = false;
    dom.lockLabel.textContent = data.label;
    dom.unlockAtText.textContent = formatDateTime(data.unlockAt);
    dom.fingerprint.textContent = data.fingerprint || "—";
    dom.reveal.hidden = true;
    dom.secret.textContent = "—";
    dom.lockStatus.textContent = "";
    revealed = false;
    startTimer();
    tick();
  } else {
    dom.setup.hidden = false;
    dom.locked.hidden = true;
    stopTimer();
    resetForm();
  }
}

function startTimer() {
  stopTimer();
  timer = setInterval(tick, 250);
}

function stopTimer() {
  if (timer) clearInterval(timer);
  timer = null;
}

function tick() {
  const now = Date.now();
  dom.clock.textContent = formatClock(now);
  if (!data) return;

  const remaining = Math.max(0, data.unlockAt - now);
  const days = Math.floor(remaining / 86_400_000);
  const hours = Math.floor((remaining % 86_400_000) / 3_600_000);
  const minutes = Math.floor((remaining % 3_600_000) / 60_000);
  const seconds = Math.floor((remaining % 60_000) / 1000);

  dom.cdDays.textContent = String(days).padStart(2, "0");
  dom.cdHours.textContent = pad(hours);
  dom.cdMinutes.textContent = pad(minutes);
  dom.cdSeconds.textContent = pad(seconds);

  const open = remaining <= 0;
  dom.lockState.textContent = open ? "可解锁" : "锁定期";
  dom.lockState.classList.toggle("open", open);
  if (revealed && open) {
    dom.decrypt.disabled = true;
    dom.decrypt.textContent = "已解锁";
    return;
  }
  dom.decrypt.disabled = !open || busy;
  dom.decrypt.textContent = open ? "解密" : "还没到时间";
}

/* ---------- decrypt ---------- */

async function decryptLock() {
  if (!data || busy) return;
  if (Date.now() < data.unlockAt - 1000) return;

  busy = true;
  dom.decrypt.disabled = true;
  dom.decrypt.textContent = "解密中…";
  dom.lockStatus.textContent = "正在获取 drand 随机信标…";

  try {
    let plaintext = null;
    let lastError = null;
    for (let attempt = 0; attempt < 20; attempt++) {
      try {
        plaintext = await timelockDecrypt(data.ciphertext, client);
        break;
      } catch (err) {
        lastError = err;
        const text = String(err.message || err);
        if (text.includes("too early")) {
          dom.lockStatus.textContent = `信标还没出块，${3} 秒后重试（${attempt + 1}/20）…`;
          await new Promise((r) => setTimeout(r, 3000));
          continue;
        }
        throw err;
      }
    }
    if (!plaintext) throw lastError || new Error("拿不到信标");

    lastSecret = plaintext.toString("utf8");
    revealed = true;
    dom.secret.textContent = lastSecret;
    dom.reveal.hidden = false;
    dom.lockStatus.textContent = "已解锁。密码没有写入存储，刷新后需要重新解密。";
    dom.decrypt.textContent = "已解锁";
    dom.decrypt.disabled = true;
    dom.reveal.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (err) {
    dom.lockStatus.textContent = `解密失败：${String(
      err.message || err
    )}。请检查网络后重试。`;
    dom.decrypt.textContent = "重试解密";
    dom.decrypt.disabled = false;
  } finally {
    busy = false;
  }
}

/* ---------- backup ---------- */

function exportBackup() {
  if (!data) return;
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const stamp = formatDateTime(data.createdAt).replace(/[^\d]/g, "").slice(0, 12);
  a.href = url;
  a.download = `trade-lock-backup-${stamp}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  dom.lockStatus.textContent =
    "备份已导出。把这个文件放到网盘/另一台设备；它只有密文。";
}

function importBackup(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const parsed = JSON.parse(String(reader.result));
      if (
        !parsed ||
        typeof parsed.ciphertext !== "string" ||
        !Number.isFinite(parsed.round) ||
        !Number.isFinite(parsed.unlockAt)
      ) {
        throw new Error("不是有效的锁单备份文件");
      }
      if (data && !confirm("导入会覆盖当前这条锁定记录，继续？")) return;
      data = {
        v: 1,
        ciphertext: parsed.ciphertext,
        round: parsed.round,
        unlockAt: parsed.unlockAt,
        createdAt: parsed.createdAt || Date.now(),
        label: parsed.label || "导入的锁定",
        chainHash: parsed.chainHash || CHAIN.hash,
        fingerprint: parsed.fingerprint || "",
      };
      save(data);
      render();
    } catch (err) {
      alert(`导入失败：${String(err.message || err)}`);
    }
  };
  reader.readAsText(file);
}

/* ---------- reset ---------- */

function resetLock() {
  if (!data) return;
  const ok = confirm(
    "删除本地记录不会提前解锁。\n\n如果你还没导出备份，这串密码将永久丢失。确定删除？"
  );
  if (!ok) return;
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* ignore */
  }
  data = null;
  lastSecret = "";
  dom.reveal.hidden = true;
  render();
}

/* ---------- clipboard ---------- */

async function copySecret() {
  if (!lastSecret) return;
  try {
    await navigator.clipboard.writeText(lastSecret);
    dom.copySecret.textContent = "已复制";
    setTimeout(() => (dom.copySecret.textContent = "复制"), 1600);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = lastSecret;
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
      dom.copySecret.textContent = "已复制";
      setTimeout(() => (dom.copySecret.textContent = "复制"), 1600);
    } catch {
      alert("复制失败，请长按密码手动复制。");
    }
    ta.remove();
  }
}

/* ---------- wiring ---------- */

dom.form.addEventListener("submit", createLock);
dom.generate.addEventListener("click", () => {
  dom.password.value = randomPassword();
});
dom.decrypt.addEventListener("click", decryptLock);
dom.export.addEventListener("click", exportBackup);
dom.reset.addEventListener("click", resetLock);
dom.copySecret.addEventListener("click", copySecret);
dom.importTop.addEventListener("click", () => dom.importFile.click());
dom.importFile.addEventListener("change", () => {
  const file = dom.importFile.files && dom.importFile.files[0];
  importBackup(file);
  dom.importFile.value = "";
});

data = load();
render();
dom.clock.textContent = formatClock(Date.now());
setInterval(() => {
  dom.clock.textContent = formatClock(Date.now());
}, 1000);

if ("serviceWorker" in navigator && location.protocol === "https:") {
  navigator.serviceWorker.register("./sw.js").catch(() => {});
}
