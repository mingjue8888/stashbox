/*
 * argon2id-aes256gcm.js — 工厂函数版：Argon2id 派生密钥 + AES-256-GCM 加密（同构）
 *
 * 用法：
 *   const crypt = argon2idAes256gcm({
 *     argonMemory: 65536,     // Argon2 内存（KiB，= 64 MiB）
 *     argonTimes: 3,          // Argon2 迭代次数
 *     argonParallelism: 1     // Argon2 并行度
 *   });
 *   const box  = await crypt.encrypt("主密码", "机密文本");
 *   const text = await crypt.decrypt("主密码", box);   // "机密文本"
 *
 * 密文格式（点分隔字符串，四段均 base64，base64 字母表不含 "."）：
 *   <salt>.<iv>.<tagAuth>.<ciphertext>
 *   - salt      ：Argon2 盐（16B）
 *   - iv        ：AES-GCM IV（12B）
 *   - tagAuth   ：AES-GCM 认证 tag（16B，单独拆出）
 *   - ciphertext：密文（不含 tag）
 *
 * 固定约定（安全最优，锁死不配置）：
 *   - Argon2 算法：Argon2id
 *   - 盐：16 字节随机（每份密文独立）
 *   - 派生密钥：32 字节（AES-256）
 *   - AES：AES-256-GCM（AEAD）
 *   - IV：12 字节（NIST 推荐的 96-bit）
 *   - 认证 tag：16 字节（算法强制 128-bit）
 *
 * 流程：主密码 + 随机盐 → Argon2id 派生 32 字节 AES-256 密钥 → AES-GCM 加密
 *   - 浏览器：Argon2 用 argon2-browser（WASM，需先引入），AES 用 Web Crypto
 *   - Node  ：Argon2 用 Node 24.8+ 原生 crypto.subtle，AES 用 node:crypto
 *
 * 浏览器 `<script>` 引入后全局为 argon2idAes256gcm（工厂函数）。
 */
(function (root, factory) {
    if (typeof module === "object" && typeof module.exports === "object") {
        module.exports = factory();            // CommonJS（Node）
    } else if (typeof define === "function" && define.amd) {
        define([], factory);                   // AMD
    } else {
        root.argon2idAes256gcm = factory();    // 浏览器全局 argon2idAes256gcm
    }
}(typeof self !== "undefined" ? self : this, function () {
    "use strict";

    // ============ 固定常量（安全最优，不开放配置） ============
    var ARG_ALG = "Argon2id";  // 仅 Argon2id
    var SALT_LEN = 16;         // Argon2 盐（字节）
    var KEY_LEN = 32;          // 派生密钥（字节）= AES-256
    var IV_LEN = 12;           // AES-GCM IV（NIST 推荐 96-bit）
    var TAG_LEN = 16;          // AES-GCM 认证 tag（算法强制 128-bit）
    var SEP = ".";             // 密文四段分隔符（base64 不含 "."，安全）

    // ============ 环境探测 ============
    var isNode = typeof process !== "undefined" &&
        process.versions && typeof process.versions.node === "string";

    // ============ 编码工具 ============
    function toU8(input) {
        if (input instanceof Uint8Array) return input;
        if (input instanceof ArrayBuffer) return new Uint8Array(input);
        return new TextEncoder().encode(String(input));
    }
    function bytesToB64(bytes) {
        var bin = "";
        for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return (typeof btoa === "function")
            ? btoa(bin)
            : Buffer.from(bytes).toString("base64");
    }
    function b64ToBytes(b64) {
        var bin = (typeof atob === "function")
            ? atob(b64)
            : Buffer.from(b64, "base64").toString("binary");
        var u8 = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i) & 0xff;
        return u8;
    }
    function randomBytes(n) {
        return (typeof crypto !== "undefined" && crypto.getRandomValues)
            ? crypto.getRandomValues(new Uint8Array(n))
            : new Uint8Array(n);
    }

    // ============ Argon2id：浏览器端（argon2-browser，WASM） ============
    function browserArgon2() {
        var a2 = root.argon2;
        if (!a2) {
            throw new Error("浏览器 Argon2 需要先引入 argon2-browser。请在 argon2id-aes256gcm.js 之前加：" +
                "<script src=\"https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-bundled.min.js\"></script>");
        }
        return a2;
    }
    // 派生 32 字节密钥（Uint8Array）
    async function deriveKeyWeb(password, saltU8, mem, times, parallelism) {
        var a2 = browserArgon2();
        var r = await a2.hash({
            pass: password,
            salt: saltU8,
            time: times,
            mem: mem,
            parallelism: parallelism,
            hashLen: KEY_LEN,
            type: a2.ArgonType.Argon2id
        });
        return r.hash; // Uint8Array 32B
    }

    // ============ Argon2id：Node 端（Node 24.8+ 原生 crypto.subtle） ============
    async function deriveKeyNode(password, saltU8, mem, times, parallelism) {
        var subtle = globalThis.crypto && globalThis.crypto.subtle;
        if (!subtle) {
            throw new Error("Node Argon2 需要 crypto.subtle，请升级到 Node 24.8 或更高版本");
        }
        var key;
        try {
            key = await subtle.importKey("raw-secret", toU8(password), ARG_ALG, false, ["deriveBits"]);
        } catch (e) {
            throw new Error("当前 Node 不支持原生 Argon2（" + e.name + "）。需要 Node 24.8+，当前版本：" +
                (process.version || "未知"));
        }
        var bits = await subtle.deriveBits({
            name: ARG_ALG,
            nonce: saltU8,          // 盐
            memory: mem,             // KiB
            passes: times,           // 迭代次数
            parallelism: parallelism,
            version: 19
        }, key, KEY_LEN * 8);
        return new Uint8Array(bits); // 32B
    }

    // ============ AES-256-GCM ============
    // 浏览器：返回 { iv, tag, data }，tag 与密文分离
    async function aesEncryptWeb(keyU8, text, ivU8, aadB64) {
        var key = await crypto.subtle.importKey("raw", keyU8, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
        var algo = aadB64
            ? { name: "AES-GCM", iv: ivU8, additionalData: b64ToBytes(aadB64) }
            : { name: "AES-GCM", iv: ivU8 };
        var out = new Uint8Array(await crypto.subtle.encrypt(algo, key, toU8(text)));
        // WebCrypto 输出 = ciphertext || tag（末尾 TAG_LEN 字节是 tag），拆开
        var ct = out.subarray(0, out.length - TAG_LEN);
        var tag = out.subarray(out.length - TAG_LEN);
        return { iv: bytesToB64(ivU8), tag: bytesToB64(tag), data: bytesToB64(ct) };
    }
    async function aesDecryptWeb(keyU8, pkg, aadB64) {
        var key = await crypto.subtle.importKey("raw", keyU8, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
        var algo = aadB64
            ? { name: "AES-GCM", iv: b64ToBytes(pkg.iv), additionalData: b64ToBytes(aadB64) }
            : { name: "AES-GCM", iv: b64ToBytes(pkg.iv) };
        // WebCrypto 解密需要 ciphertext || tag 拼回一起
        var ct = b64ToBytes(pkg.data);
        var tag = b64ToBytes(pkg.tag);
        var combined = new Uint8Array(ct.length + tag.length);
        combined.set(ct, 0);
        combined.set(tag, ct.length);
        var plain = await crypto.subtle.decrypt(algo, key, combined);
        return new TextDecoder().decode(plain);
    }
    // Node：返回 { iv, tag, data }，tag 用 getAuthTag() 单独取
    async function aesEncryptNode(keyU8, text, ivU8, aadB64) {
        var c = require("crypto");
        var key = Buffer.from(keyU8);
        var cipher = c.createCipheriv("aes-256-gcm", key, ivU8);
        if (aadB64) cipher.setAAD(Buffer.from(aadB64, "base64"));
        var ct = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]); // 不含 tag
        return { iv: bytesToB64(ivU8), tag: cipher.getAuthTag().toString("base64"), data: ct.toString("base64") };
    }
    async function aesDecryptNode(keyU8, pkg, aadB64) {
        var c = require("crypto");
        var key = Buffer.from(keyU8);
        var d = c.createDecipheriv("aes-256-gcm", key, Buffer.from(pkg.iv, "base64"));
        if (aadB64) d.setAAD(Buffer.from(aadB64, "base64"));
        d.setAuthTag(Buffer.from(pkg.tag, "base64"));
        return Buffer.concat([d.update(Buffer.from(pkg.data, "base64")), d.final()]).toString("utf8");
    }

    // 按环境组装
    var deriveKey = isNode ? deriveKeyNode : deriveKeyWeb;
    var aesEncrypt = isNode ? aesEncryptNode : aesEncryptWeb;
    var aesDecrypt = isNode ? aesDecryptNode : aesDecryptWeb;

    // ============ 能力检测 ============
    var supportCache = null;
    async function supportsArgon2() {
        if (supportCache !== null) return supportCache;
        if (isNode) {
            try {
                var subtle = globalThis.crypto && globalThis.crypto.subtle;
                if (!subtle) return (supportCache = false);
                await subtle.importKey("raw-secret", new Uint8Array(1), ARG_ALG, false, ["deriveBits"]);
                supportCache = true;
            } catch (e) { supportCache = false; }
        } else {
            supportCache = !!root.argon2;
        }
        return supportCache;
    }

    // ============ argon2idAes256gcm 工厂 ============
    function argon2idAes256gcm(config) {
        config = config || {};
        var argonMemory = config.argonMemory || 65536;      // 内存 KiB（= 64 MiB）
        var argonTimes = config.argonTimes || 3;            // 迭代次数
        var argonParallelism = config.argonParallelism || 1; // 并行度

        // 拼密文：<salt>.<iv>.<tagAuth>.<ciphertext>
        function joinBox(saltB64, ivB64, tagB64, dataB64) {
            return saltB64 + SEP + ivB64 + SEP + tagB64 + SEP + dataB64;
        }
        // 解析密文：按 "." 拆四段（base64 不含 "."，安全）
        function splitBox(box) {
            var parts = box.split(SEP);
            if (parts.length !== 4) {
                throw new Error("无效密文格式，应为 <salt>.<iv>.<tagAuth>.<ciphertext>");
            }
            return { salt: parts[0], iv: parts[1], tag: parts[2], data: parts[3] };
        }

        return {
            // encrypt(password, text, aadB64?) -> Promise<string>  "<salt>.<iv>.<tagAuth>.<ciphertext>"
            encrypt: async function (password, text, aadB64) {
                var salt = randomBytes(SALT_LEN);        // 每份密文独立随机盐
                var key = await deriveKey(password, salt, argonMemory, argonTimes, argonParallelism);
                var iv = randomBytes(IV_LEN);
                var box = await aesEncrypt(key, text, iv, aadB64);
                return joinBox(bytesToB64(salt), box.iv, box.tag, box.data);
            },
            // decrypt(password, box, aadB64?) -> Promise<string>
            decrypt: async function (password, box, aadB64) {
                var parts = splitBox(box);
                var key = await deriveKey(password, b64ToBytes(parts.salt), argonMemory, argonTimes, argonParallelism);
                return aesDecrypt(key, parts, aadB64);
            }
        };
    }
    // 静态辅助（挂在函数上，不污染返回的 {encrypt, decrypt}）
    argon2idAes256gcm.supportsArgon2 = supportsArgon2;
    argon2idAes256gcm.DEFAULTS = { argonMemory: 65536, argonTimes: 3, argonParallelism: 1 };
    argon2idAes256gcm.ALG = { argon2: ARG_ALG, aes: "AES-GCM", saltLen: SALT_LEN, keyLen: KEY_LEN, ivLen: IV_LEN, tagLen: TAG_LEN };

    return argon2idAes256gcm;
}));
