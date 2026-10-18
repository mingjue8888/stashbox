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
        if (pass.length < 16)              return { ok: false, pass: "", msg: "密码至少 16 位" };
        if (/\s/.test(pass))               return { ok: false, pass: "", msg: "密码中间不能有空格" };
        if (!/[a-z]/.test(pass))           return { ok: false, pass: "", msg: "密码需包含小写字母" };
        if (!/[A-Z]/.test(pass))           return { ok: false, pass: "", msg: "密码需包含大写字母" };
        if (!/[0-9]/.test(pass))           return { ok: false, pass: "", msg: "密码需包含数字" };
        if (!/[^A-Za-z0-9]/.test(pass))    return { ok: false, pass: "", msg: "密码需包含标点符号" };
        return { ok: true, pass, msg: "" };
    };

    /* ---------- DOM 读取（纯函数） ---------- */
    const readEnc = () => ({ pass: $("encPass").value, text: $("encText").value });
    const readDec = () => ({ pass: $("decPass").value, box: $("decBox").value.trim() });

    /* ---------- 请求校验（纯函数） ---------- */
    const validateEncReq = (f) => {
        if (!f.text.trim()) return errState("请填写要加密的明文");
        const v = validatePassword(f.pass);
        return v.ok ? okState({ pass: v.pass, text: f.text }) : errState(v.msg);
    };
    const validateDecReq = (f) => {
        if (!f.box) return errState("请粘贴密文");
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
        const setLoading = btnLoading($("btnEncrypt"), "加密");
        if (state.status === "working") { setLoading(true); $("encOut").value = ""; showToast("加密中"); }
        else {
            setLoading(false);
            if (state.status === "done") { $("encOut").value = state.value; showToast("加密完成"); }
            else if (state.status === "error") showToast("加密失败：" + state.msg);
        }
    };
    const renderDec = (state) => {
        const setLoading = btnLoading($("btnDecrypt"), "解密");
        if (state.status === "working") { setLoading(true); $("decOut").value = ""; showToast("解密中"); }
        else {
            setLoading(false);
            if (state.status === "done") { $("decOut").value = state.value; showToast("解密成功，认证通过"); }
            else if (state.status === "error") showToast("解密失败：" + state.msg + "。请检查密码和密文是否与加密时一致。", "danger");
        }
    };

    /* ---------- 复制（RxJS 流） ---------- */
    const renderCopy = (s, okMsg, out) => {
        if (s.status === "done") return showToast(okMsg);
        if (s.status === "fallback") { out.select(); return showToast("复制失败，已帮你选中，请 Ctrl+C"); }
        if (s.status === "none") return showToast(okMsg === "已复制密文" ? "还没有密文可复制" : "还没有明文可复制");
    };
    const buildCopy = (btn, out, okMsg) => {
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
        ).subscribe((s) => renderCopy(s, okMsg, out));
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

    buildCopy($("btnCopy"), $("encOut"), "已复制密文");
    buildCopy($("btnCopyPlain"), $("decOut"), "已复制明文");

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