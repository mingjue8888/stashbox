/* ===== 页面逻辑（函数式 + RxJS Observable） ===== */
(function () {
    "use strict";
    const $ = (id) => document.getElementById(id);
    const { fromEvent, of, from, defer, pipe } = rxjs;
    const { map, switchMap, startWith, catchError } = rxjs.operators;

    /* ---------- 加密实例（参数写死，不暴露给用户） ---------- */
    const crypt = argon2id_aes256gcm({
        argonMemory: 262144,  // 256 MiB
        argonTimes: 32,
        argonParallelism: 2
    });

    /* ---------- 页面加载时清空输入框，避免浏览器自动填充残留 ---------- */
    const clearInputs = () => {
        ["encPass", "encText", "encOut", "decPass", "decBox", "decOut"]
            .forEach((id) => { const el = $(id); if (el) el.value = ""; });
    };
    clearInputs();
    window.addEventListener("load", clearInputs);

    /* ---------- 国际化（右上角按钮切换中/英文，文本可逐个校对） ---------- */
    const I18N = {
        lang: "zh",
        dict: {
            zh: {
                title: "偷偷藏点私房钱",
                browserTitle: "私房钱 - 全程无网络请求，本机运行的加密工具",
                subtitle: "全程无网络请求，本机运行的加密工具，运用了 <i>Argon2id</i> 和 <i>AES-256-GCM</i> 的算法",
                encTitle: "加密", decTitle: "解密",
                encPassLabel: "密码", encPassPh: "请输入只有你自己知道的密码",
                encTextLabel: "明文", encTextPh: "请输入你要加密的文本内容，加密后明文建议不要保留",
                btnEncrypt: "加密", encOutLabel: "密文",
                encOutPh: "加密结果将在这里显示，建议备几份藏在你能找到的别人不知道的任意互联网角落里",
                btnCopy: "复制密文",
                decPassLabel: "密码", decPassPh: "请输入只有你自己知道的密码",
                decBoxLabel: "密文", decBoxPh: "请粘贴你上一次藏好的加密文本",
                btnDecrypt: "解密", decOutLabel: "明文",
                decOutPh: "解密结果将在这里显示，拿回你原有的明文后，请不要逗留太久，把浏览痕迹删掉",
                btnCopyPlain: "复制明文",
                footer1: "锁定算法：Argon2id · 内存 256MB · 迭代 32 次 · 并行度 2 · 盐 16B · 密钥长度 32B · AES-256-GCM · IV 12B · 认证 tag 16B · 密文格式 &lt;盐&gt;.&lt;iv&gt;.&lt;认证 tag&gt;.&lt;算法结果&gt;，每份密文独立随机盐，认证 tag 承载完整性校验，密文被篡改或密码错误将无法解密。",
                footer2: "浏览器端运行，使用 Web Crypto 与 argon2-browser(WASM)，所有计算均在本机完成。",
                passLen: "密码至少 16 位", passSpace: "密码中间不能有空格",
                passLower: "密码需包含小写字母", passUpper: "密码需包含大写字母",
                passNum: "密码需包含数字", passSym: "密码需包含标点符号",
                needEncText: "请填写要加密的明文", needBox: "请粘贴密文",
                encWorking: "加密中", encDone: "加密完成", encFail: "加密失败：",
                decWorking: "解密中", decDone: "解密成功，认证通过", decFail: "解密失败：",
                decFailTail: "。请检查密码和密文是否与加密时一致。",
                copiedEnc: "已复制密文", copiedPlain: "已复制明文",
                copyFallback: "复制失败，已帮你选中，请 Ctrl+C",
                noEnc: "还没有密文可复制", noPlain: "还没有明文可复制"
            },
            en: {
                title: "Stash Box",
                browserTitle: "Stash Box - Using Argon2id and AES-256-GCM",
                subtitle: "A fully offline encryption tool, using <i>Argon2id</i> and <i>AES-256-GCM</i>.",
                encTitle: "Encrypt", decTitle: "Decrypt",
                encPassLabel: "Password", encPassPh: "Enter a password only you know",
                encTextLabel: "Plaintext", encTextPh: "Enter the text to encrypt; don't keep the plaintext after encrypting",
                btnEncrypt: "Encrypt", encOutLabel: "Ciphertext",
                encOutPh: "The encrypted result will show here. Keep a few copies somewhere only you can find",
                btnCopy: "Copy ciphertext",
                decPassLabel: "Password", decPassPh: "Enter a password only you know",
                decBoxLabel: "Ciphertext", decBoxPh: "Paste the ciphertext you stashed last time",
                btnDecrypt: "Decrypt", decOutLabel: "Plaintext",
                decOutPh: "The decrypted result will show here. Once you have it, clear your browsing traces",
                btnCopyPlain: "Copy plaintext",
                footer1: "Locked params: Argon2id · Memory 256MB · Iterations 32 · Parallelism 2 · Salt 16B · Key 32B · AES-256-GCM · IV 12B · Auth tag 16B · Cipher format &lt;salt&gt;.&lt;iv&gt;.&lt;tag&gt;.&lt;result&gt;. Each ciphertext uses an independent random salt; the auth tag verifies integrity. Tampered ciphertext or a wrong password cannot be decrypted.",
                footer2: "Runs in the browser with Web Crypto and argon2-browser (WASM). All computation happens locally.",
                passLen: "At least 16 characters", passSpace: "No spaces allowed",
                passLower: "Needs a lowercase letter", passUpper: "Needs an uppercase letter",
                passNum: "Needs a number", passSym: "Needs a symbol",
                needEncText: "Enter text to encrypt", needBox: "Paste the ciphertext",
                encWorking: "Encrypting…", encDone: "Encrypted", encFail: "Encrypt failed: ",
                decWorking: "Decrypting…", decDone: "Decrypted, authentication passed", decFail: "Decrypt failed: ",
                decFailTail: ". Check that the password and ciphertext match.",
                copiedEnc: "Ciphertext copied", copiedPlain: "Plaintext copied",
                copyFallback: "Copy failed, text selected — press Ctrl+C",
                noEnc: "No ciphertext to copy yet", noPlain: "No plaintext to copy yet"
            }
        },
        t(key) { return this.dict[this.lang][key] != null ? this.dict[this.lang][key] : this.dict.zh[key]; },
        apply() {
            document.title = this.t("browserTitle");
            document.querySelectorAll("[data-i18n]").forEach((el) => { el.innerHTML = this.t(el.dataset.i18n); });
            document.querySelectorAll("[data-i18n-ph]").forEach((el) => { el.placeholder = this.t(el.dataset.i18nPh); });
        },
        init() {
            let stored = null;
            try { const s = localStorage.getItem("stash_lang"); if (s && this.dict[s]) stored = s; } catch (e) {}
            if (stored) { this.lang = stored; const sel = $("langSel"); if (sel) sel.value = stored; }
            this.apply();
        }
    };
    I18N.init();

    /* ---------- 状态构造（纯函数） ---------- */
    const okState = (extra) => {
        const s = { status: "ok" };
        for (const k in extra) s[k] = extra[k];
        return s;
    };
    const errState = (msg) => ({ status: "error", msg });

    /* ---------- 密码校验：前后空格去掉 + 16 位复杂密码 ---------- */
    const validatePassword = (raw) => {
        const pass = (raw || "").trim();                       // 去掉前后空格
        if (pass.length < 16)              return { ok: false, pass: "", msg: I18N.t("passLen") };
        if (/\s/.test(pass))               return { ok: false, pass: "", msg: I18N.t("passSpace") };
        if (!/[a-z]/.test(pass))           return { ok: false, pass: "", msg: I18N.t("passLower") };
        if (!/[A-Z]/.test(pass))           return { ok: false, pass: "", msg: I18N.t("passUpper") };
        if (!/[0-9]/.test(pass))           return { ok: false, pass: "", msg: I18N.t("passNum") };
        if (!/[^A-Za-z0-9]/.test(pass))    return { ok: false, pass: "", msg: I18N.t("passSym") };
        return { ok: true, pass, msg: "" };
    };

    /* ---------- DOM 读取（纯函数） ---------- */
    const readEnc = () => ({ pass: $("encPass").value, text: $("encText").value });
    const readDec = () => ({ pass: $("decPass").value, box: $("decBox").value.trim() });

    /* ---------- 请求校验（纯函数） ---------- */
    const validateEncReq = (f) => {
        if (!f.text.trim()) return errState(I18N.t("needEncText"));
        const v = validatePassword(f.pass);
        return v.ok ? okState({ pass: v.pass, text: f.text }) : errState(v.msg);
    };
    const validateDecReq = (f) => {
        if (!f.box) return errState(I18N.t("needBox"));
        const v = validatePassword(f.pass);
        return v.ok ? okState({ pass: v.pass, box: f.box }) : errState(v.msg);
    };

    /* ---------- 异步操作 → observable（先 working 再 done/error） ---------- */
    // 进入 Argon2 计算前先让出一次事件循环，强制浏览器先绘制 working 态（按钮 loading），
    // 否则 WASM 同步计算直接占满主线程，loading 中间态画不到屏幕上。
    const runTask = (task) => (async () => {
        await new Promise((r) => setTimeout(r, 0));
        return task();
    })();
    const runEncrypt = (req) =>
        defer(() => from(runTask(() => crypt.encrypt(req.pass, req.text)))).pipe(
            map((v) => ({ status: "done", value: v })),
            startWith({ status: "working" }),
            catchError((e) => of(errState(e.message || String(e))))
        );
    const runDecrypt = (req) =>
        defer(() => from(runTask(() => crypt.decrypt(req.pass, req.box)))).pipe(
            map((v) => ({ status: "done", value: v })),
            startWith({ status: "working" }),
            catchError((e) => of(errState(e.message || String(e))))
        );
    const handleOp = (req, run) => (req.status === "ok" ? run(req) : of(req));

    /* ---------- 渲染（纯函数 → DOM） ---------- */
    const btnLoading = (btn, label) => (loading) => {
        btn.disabled = loading;                       // 防误触：计算期间禁用按钮
        btn.classList.toggle("is-loading", loading);
        btn.classList.toggle("is-dark", loading);
        btn.textContent = loading ? "" : label;       // loading 时按钮内不留字，只留转圈
    };
    const showToast = (msg, type) => {
        const toast = $("toast");
        const kind = type === "danger" ? "is-danger" : "is-info";
        toast.classList.remove("is-info", "is-danger");
        toast.classList.add(kind);
        toast.textContent = msg;
        // 用 CSS 动画自动淡出（不受主线程阻塞影响），重触发需先移除 show 再强制重排
        toast.classList.remove("show");
        void toast.offsetWidth;
        toast.classList.add("show");
    };
    const renderEnc = (state) => {
        const setLoading = btnLoading($("btnEncrypt"), I18N.t("btnEncrypt"));
        if (state.status === "working") { setLoading(true); $("encOut").value = ""; showToast(I18N.t("encWorking")); }
        else {
            setLoading(false);
            if (state.status === "done") { $("encOut").value = state.value; showToast(I18N.t("encDone")); }
            else if (state.status === "error") showToast(I18N.t("encFail") + state.msg);
        }
    };
    const renderDec = (state) => {
        const setLoading = btnLoading($("btnDecrypt"), I18N.t("btnDecrypt"));
        if (state.status === "working") { setLoading(true); $("decOut").value = ""; showToast(I18N.t("decWorking")); }
        else {
            setLoading(false);
            if (state.status === "done") { $("decOut").value = state.value; showToast(I18N.t("decDone")); }
            else if (state.status === "error") showToast(I18N.t("decFail") + state.msg + I18N.t("decFailTail"), "danger");
        }
    };

    /* ---------- 复制（RxJS 流） ---------- */
    const renderCopy = (s, okKey, out) => {
        if (s.status === "done") return showToast(I18N.t(okKey));
        if (s.status === "fallback") { out.select(); return showToast(I18N.t("copyFallback")); }
        if (s.status === "none") return showToast(I18N.t(okKey === "copiedEnc" ? "noEnc" : "noPlain"));
    };
    const buildCopy = (btn, out, okKey) => {
        fromEvent(btn, "click").pipe(
            map(() => out.value),
            switchMap((text) =>
                text
                    ? from(navigator.clipboard.writeText(text)).pipe(
                        map(() => ({ status: "done" })),
                        catchError(() => of({ status: "fallback" }))
                    )
                    : of({ status: "none" })
            )
        ).subscribe((s) => renderCopy(s, okKey, out));
    };

    /* ---------- 组装数据流（RxJS 订阅） ---------- */
    fromEvent($("btnEncrypt"), "click").pipe(
        map(readEnc),
        map(validateEncReq),
        switchMap((req) => handleOp(req, runEncrypt))
    ).subscribe(renderEnc);

    fromEvent($("btnDecrypt"), "click").pipe(
        map(readDec),
        map(validateDecReq),
        switchMap((req) => handleOp(req, runDecrypt))
    ).subscribe(renderDec);

    buildCopy($("btnCopy"), $("encOut"), "copiedEnc");
    buildCopy($("btnCopyPlain"), $("decOut"), "copiedPlain");

    /* ---------- 语言切换（下拉框） ---------- */
    fromEvent($("langSel"), "change").subscribe(() => {
        const v = $("langSel").value;
        if (v && I18N.dict[v]) {
            I18N.lang = v;
            try { localStorage.setItem("stash_lang", v); } catch (e) {}
            I18N.apply();
        }
    });

    /* ---------- 密码框长按显示（函数式） ---------- */
    const bindEye = (input, btn) => {
        const show = (e) => { if (e) e.preventDefault(); input.type = "text"; };
        const hide = () => { input.type = "password"; };
        btn.addEventListener("pointerdown", show);
        btn.addEventListener("pointerup", hide);
        btn.addEventListener("pointerleave", hide);
    };
    bindEye($("encPass"), $("encEye"));
    bindEye($("decPass"), $("decEye"));
})();