import { decryptText, encryptText } from "./crypto.mjs";

const form = document.querySelector("#cipher-form");
const encryptTab = document.querySelector("#encrypt-tab");
const decryptTab = document.querySelector("#decrypt-tab");
const source = document.querySelector("#source-input");
const passphrase = document.querySelector("#passphrase");
const passphraseToggle = document.querySelector("#passphrase-toggle");
const submitButton = document.querySelector("#submit-button");
const output = document.querySelector("#output");
const copyButton = document.querySelector("#copy-button");
const status = document.querySelector("#form-status");

const modes = {
  encrypt: {
    source: "明文",
    sourceHint: "输入要加密的文本",
    passwordHint: "请选择较长、难以猜测的口令。",
    help: "收件人需要密文信封和同一个口令才能解密。",
    output: "密文信封",
    outputHint: "生成的密文信封将显示在这里",
    action: "生成密文信封",
    success: "加密完成，可以复制密文信封。",
    run: encryptText,
  },
  decrypt: {
    source: "密文信封",
    sourceHint: "粘贴完整的密文信封",
    passwordHint: "请使用加密时的口令，注意大小写和空格。",
    help: "密文通过完整性校验后才会显示明文。",
    output: "解密文本",
    outputHint: "解密后的文本将显示在这里",
    action: "解密文本",
    success: "完整性校验通过，已还原明文。",
    run: decryptText,
  },
};

const cryptoAvailable = Boolean(globalThis.crypto?.subtle);
let mode;
let busy = false;

function showStatus(message = "", error = false) {
  status.textContent = message;
  status.dataset.error = String(error);
}

function clearResult() {
  output.value = "";
  copyButton.disabled = true;
  showStatus();
}

function setPassphraseVisible(visible) {
  passphrase.type = visible ? "text" : "password";
  passphraseToggle.setAttribute("aria-pressed", String(visible));
}

function setMode(nextMode) {
  if (busy || mode === nextMode) return;
  mode = nextMode;
  const config = modes[mode];
  const encrypting = mode === "encrypt";

  form.reset();
  setPassphraseVisible(false);
  clearResult();
  encryptTab.setAttribute("aria-pressed", String(encrypting));
  decryptTab.setAttribute("aria-pressed", String(!encrypting));
  document.querySelector("#mode-help").textContent = config.help;
  document.querySelector("#source-label").textContent = config.source;
  document.querySelector("#passphrase-help").textContent = config.passwordHint;
  document.querySelector("#output-label").textContent = config.output;
  source.placeholder = config.sourceHint;
  source.classList.toggle("encoded", !encrypting);
  output.placeholder = config.outputHint;
  output.classList.toggle("encoded", encrypting);
  submitButton.textContent = config.action;
  submitButton.disabled = !cryptoAvailable;

  if (!cryptoAvailable) showStatus("当前环境无法使用 Web Crypto，请通过本机服务器或 HTTPS 打开。", true);
}

function setBusy(active) {
  busy = active;
  if (active) setPassphraseVisible(false);
  for (const control of [encryptTab, decryptTab, source, passphrase, passphraseToggle, submitButton]) {
    control.disabled = active;
  }
  submitButton.textContent = active ? "处理中…" : modes[mode].action;
}

encryptTab.addEventListener("click", () => setMode("encrypt"));
decryptTab.addEventListener("click", () => setMode("decrypt"));
passphraseToggle.addEventListener("click", () => {
  if (!busy) setPassphraseVisible(passphrase.type === "password");
});
form.addEventListener("input", () => {
  if (cryptoAvailable) clearResult();
});
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!cryptoAvailable || busy) return;

  clearResult();
  setBusy(true);
  try {
    output.value = await modes[mode].run(source.value, passphrase.value);
    copyButton.disabled = false;
    showStatus(modes[mode].success);
  } catch (error) {
    showStatus(error.message || "处理失败，请检查输入后重试。", true);
  } finally {
    setBusy(false);
  }
});

copyButton.addEventListener("click", async () => {
  const result = output.value;
  try {
    await navigator.clipboard.writeText(result);
    if (output.value === result) showStatus("已复制结果。");
  } catch {
    if (output.value !== result) return;
    output.focus();
    output.select();
    showStatus("无法自动复制，已选中结果，请手动复制。", true);
  }
});

setMode("encrypt");
