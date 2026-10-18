/* ===== 页面逻辑（函数式 + RxJS Observable） ===== */
(function () {
    "use strict";
    const $ = (id) => document.getElementById(id);
    const { fromEvent, of, from, defer } = rxjs;
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

    /* ---------- 国际化（右上角下拉框切换语言，文本可逐个校对） ---------- */
    const I18N = {
        lang: "zh",
        dict: {
            zh: {
                title: "偷偷藏点私房钱",
                browserTitle: "私房钱 - 全程无网络请求，本机运行的加密工具",
                subtitle: "全程无网络请求，本机运行的加密工具，运用了 <em>Argon2id</em> 和 <em>AES-256-GCM</em> 的算法",
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
                subtitle: "A fully offline encryption tool, using <em>Argon2id</em> and <em>AES-256-GCM</em>.",
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
            },
            ko: {
                title: "비상금 보관함",
                browserTitle: "비상금 보관함 - Argon2id와 AES-256-GCM 사용",
                subtitle: "완전히 오프라인으로 동작하는 암호화 도구로, <em>Argon2id</em>와 <em>AES-256-GCM</em>을 사용합니다.",
                encTitle: "암호화", decTitle: "복호화",
                encPassLabel: "비밀번호", encPassPh: "당신만 아는 비밀번호를 입력하세요",
                encTextLabel: "평문", encTextPh: "암호화할 텍스트를 입력하세요. 암호화 후 평문은 남기지 마세요",
                btnEncrypt: "암호화", encOutLabel: "암호문",
                encOutPh: "암호화 결과가 여기에 표시됩니다. 당신만 찾을 수 있는 곳에 여러 개 복사해 두세요",
                btnCopy: "암호문 복사",
                decPassLabel: "비밀번호", decPassPh: "당신만 아는 비밀번호를 입력하세요",
                decBoxLabel: "암호문", decBoxPh: "지난번에 숨겨둔 암호문을 붙여넣으세요",
                btnDecrypt: "복호화", decOutLabel: "평문",
                decOutPh: "복호화 결과가 여기에 표시됩니다. 가져간 후에는 브라우저 기록을 지우세요",
                btnCopyPlain: "평문 복사",
                footer1: "잠긴 매개변수: Argon2id · 메모리 256MB · 반복 32회 · 병렬도 2 · 솔트 16B · 키 32B · AES-256-GCM · IV 12B · 인증 태그 16B · 암호문 형식 &lt;솔트&gt;.&lt;IV&gt;.&lt;태그&gt;.&lt;결과&gt;. 각 암호문은 독립된 무작위 솔트를 사용하며 인증 태그가 무결성을 검증합니다. 암호문이 변조되거나 비밀번호가 틀리면 복호화할 수 없습니다.",
                footer2: "브라우저에서 Web Crypto와 argon2-browser(WASM)로 실행됩니다. 모든 계산은 이 기기에서 이루어집니다.",
                passLen: "최소 16자 이상", passSpace: "공백은 사용할 수 없습니다",
                passLower: "소문자가 필요합니다", passUpper: "대문자가 필요합니다",
                passNum: "숫자가 필요합니다", passSym: "특수문자가 필요합니다",
                needEncText: "암호화할 텍스트를 입력하세요", needBox: "암호문을 붙여넣으세요",
                encWorking: "암호화 중…", encDone: "암호화 완료", encFail: "암호화 실패: ",
                decWorking: "복호화 중…", decDone: "복호화 성공, 인증 통과", decFail: "복호화 실패: ",
                decFailTail: ". 비밀번호와 암호문이 일치하는지 확인하세요.",
                copiedEnc: "암호문 복사됨", copiedPlain: "평문 복사됨",
                copyFallback: "복사 실패, 텍스트가 선택됨 — Ctrl+C를 누르세요",
                noEnc: "복사할 암호문이 없습니다", noPlain: "복사할 평문이 없습니다"
            },
            ja: {
                title: "こっそり貯金箱",
                browserTitle: "こっそり貯金箱 - Argon2idとAES-256-GCMを使用",
                subtitle: "完全オフラインで動作する暗号化ツール。<em>Argon2id</em>と<em>AES-256-GCM</em>を使用します。",
                encTitle: "暗号化", decTitle: "復号化",
                encPassLabel: "パスワード", encPassPh: "自分だけが知るパスワードを入力",
                encTextLabel: "平文", encTextPh: "暗号化するテキストを入力。暗号化後は平文を残さないでください",
                btnEncrypt: "暗号化", encOutLabel: "暗号文",
                encOutPh: "暗号化結果がここに表示されます。自分にしか見つけられない場所にいくつか控えを取っておきましょう",
                btnCopy: "暗号文をコピー",
                decPassLabel: "パスワード", decPassPh: "自分だけが知るパスワードを入力",
                decBoxLabel: "暗号文", decBoxPh: "前回隠した暗号文を貼り付け",
                btnDecrypt: "復号化", decOutLabel: "平文",
                decOutPh: "復号化結果がここに表示されます。取り出したら閲覧履歴を消しましょう",
                btnCopyPlain: "平文をコピー",
                footer1: "固定パラメータ: Argon2id · メモリ256MB · 反復32回 · 並列度2 · ソルト16B · 鍵32B · AES-256-GCM · IV 12B · 認証タグ16B · 暗号文形式 &lt;ソルト&gt;.&lt;IV&gt;.&lt;タグ&gt;.&lt;結果&gt;。各暗号文は独立したランダムソルトを使用し、認証タグが完全性を検証します。改ざんまたはパスワード誤りでは復号できません。",
                footer2: "ブラウザ上でWeb Cryptoとargon2-browser(WASM)を使用。すべての計算はこの端末で行われます。",
                passLen: "16文字以上", passSpace: "スペースは使用不可",
                passLower: "小文字が必要", passUpper: "大文字が必要",
                passNum: "数字が必要", passSym: "記号が必要",
                needEncText: "暗号化するテキストを入力", needBox: "暗号文を貼り付け",
                encWorking: "暗号化中…", encDone: "暗号化完了", encFail: "暗号化失敗: ",
                decWorking: "復号化中…", decDone: "復号化成功、認証通過", decFail: "復号化失敗: ",
                decFailTail: "。パスワードと暗号文が一致するか確認してください。",
                copiedEnc: "暗号文をコピーしました", copiedPlain: "平文をコピーしました",
                copyFallback: "コピー失敗、テキストを選択しました — Ctrl+Cを押してください",
                noEnc: "コピーする暗号文がありません", noPlain: "コピーする平文がありません"
            },
            ru: {
                title: "Тайник для денег",
                browserTitle: "Тайник для денег - Использование Argon2id и AES-256-GCM",
                subtitle: "Полностью офлайн-инструмент шифрования на <em>Argon2id</em> и <em>AES-256-GCM</em>.",
                encTitle: "Шифрование", decTitle: "Расшифровка",
                encPassLabel: "Пароль", encPassPh: "Введите пароль, который знаете только вы",
                encTextLabel: "Открытый текст", encTextPh: "Введите текст для шифрования. После шифрования не оставляйте открытый текст",
                btnEncrypt: "Зашифровать", encOutLabel: "Шифротекст",
                encOutPh: "Результат шифрования появится здесь. Сделайте копии в местах, которые знаете только вы",
                btnCopy: "Копировать шифротекст",
                decPassLabel: "Пароль", decPassPh: "Введите пароль, который знаете только вы",
                decBoxLabel: "Шифротекст", decBoxPh: "Вставьте сохранённый шифротекст",
                btnDecrypt: "Расшифровать", decOutLabel: "Открытый текст",
                decOutPh: "Результат расшифровки появится здесь. Получив текст, очистите историю браузера",
                btnCopyPlain: "Копировать текст",
                footer1: "Параметры: Argon2id · Память 256MB · Итераций 32 · Параллелизм 2 · Соль 16B · Ключ 32B · AES-256-GCM · IV 12B · Тег аутентификации 16B · Формат &lt;соль&gt;.&lt;iv&gt;.&lt;тег&gt;.&lt;результат&gt;. Каждый шифротекст использует независимую соль; тег проверяет целостность. Изменение или неверный пароль делает расшифровку невозможной.",
                footer2: "Работает в браузере на Web Crypto и argon2-browser (WASM). Все вычисления выполняются локально.",
                passLen: "Минимум 16 символов", passSpace: "Пробелы запрещены",
                passLower: "Нужна строчная буква", passUpper: "Нужна заглавная буква",
                passNum: "Нужна цифра", passSym: "Нужен символ",
                needEncText: "Введите текст для шифрования", needBox: "Вставьте шифротекст",
                encWorking: "Шифрование…", encDone: "Зашифровано", encFail: "Ошибка шифрования: ",
                decWorking: "Расшифровка…", decDone: "Расшифровано, аутентификация пройдена", decFail: "Ошибка расшифровки: ",
                decFailTail: ". Проверьте, что пароль и шифротекст совпадают.",
                copiedEnc: "Шифротекст скопирован", copiedPlain: "Текст скопирован",
                copyFallback: "Не удалось скопировать, текст выбран — нажмите Ctrl+C",
                noEnc: "Нет шифротекста для копирования", noPlain: "Нет текста для копирования"
            },
            de: {
                title: "Versteckte Notreserve",
                browserTitle: "Versteckte Notreserve - Mit Argon2id und AES-256-GCM",
                subtitle: "Ein komplett offline laufendes Verschlüsselungswerkzeug mit <em>Argon2id</em> und <em>AES-256-GCM</em>.",
                encTitle: "Verschlüsseln", decTitle: "Entschlüsseln",
                encPassLabel: "Passwort", encPassPh: "Geben Sie ein Passwort ein, das nur Sie kennen",
                encTextLabel: "Klartext", encTextPh: "Geben Sie den zu verschlüsselnden Text ein. Lassen Sie den Klartext nach dem Verschlüsseln nicht zurück",
                btnEncrypt: "Verschlüsseln", encOutLabel: "Chiffrat",
                encOutPh: "Das Ergebnis erscheint hier. Bewahren Sie Kopien an Orten auf, die nur Sie finden",
                btnCopy: "Chiffrat kopieren",
                decPassLabel: "Passwort", decPassPh: "Geben Sie ein Passwort ein, das nur Sie kennen",
                decBoxLabel: "Chiffrat", decBoxPh: "Fügen Sie das zuletzt versteckte Chiffrat ein",
                btnDecrypt: "Entschlüsseln", decOutLabel: "Klartext",
                decOutPh: "Das Ergebnis erscheint hier. Löschen Sie nach dem Abholen Ihre Browser-Spuren",
                btnCopyPlain: "Klartext kopieren",
                footer1: "Feste Parameter: Argon2id · Speicher 256MB · Iterationen 32 · Parallelität 2 · Salt 16B · Schlüssel 32B · AES-256-GCM · IV 12B · Auth-Tag 16B · Format &lt;salt&gt;.&lt;iv&gt;.&lt;tag&gt;.&lt;ergebnis&gt;. Jedes Chiffrat nutzt ein eigenes Zufalls-Salt; das Auth-Tag prüft die Integrität. Manipulation oder falsches Passwort macht die Entschlüsselung unmöglich.",
                footer2: "Läuft im Browser mit Web Crypto und argon2-browser (WASM). Alle Berechnungen erfolgen lokal.",
                passLen: "Mindestens 16 Zeichen", passSpace: "Keine Leerzeichen erlaubt",
                passLower: "Kleinbuchstabe erforderlich", passUpper: "Großbuchstabe erforderlich",
                passNum: "Ziffer erforderlich", passSym: "Symbol erforderlich",
                needEncText: "Geben Sie Text zum Verschlüsseln ein", needBox: "Fügen Sie das Chiffrat ein",
                encWorking: "Verschlüssle…", encDone: "Verschlüsselt", encFail: "Verschlüsselung fehlgeschlagen: ",
                decWorking: "Entschlüssle…", decDone: "Entschlüsselt, Authentifizierung erfolgreich", decFail: "Entschlüsselung fehlgeschlagen: ",
                decFailTail: ". Prüfen Sie, ob Passwort und Chiffrat übereinstimmen.",
                copiedEnc: "Chiffrat kopiert", copiedPlain: "Klartext kopiert",
                copyFallback: "Kopieren fehlgeschlagen, Text ausgewählt — Drücken Sie Ctrl+C",
                noEnc: "Kein Chiffrat zum Kopieren", noPlain: "Kein Klartext zum Kopieren"
            },
            es: {
                title: "Escondite de ahorros",
                browserTitle: "Escondite de ahorros - Usando Argon2id y AES-256-GCM",
                subtitle: "Una herramienta de cifrado que funciona totalmente sin conexión, con <em>Argon2id</em> y <em>AES-256-GCM</em>.",
                encTitle: "Cifrar", decTitle: "Descifrar",
                encPassLabel: "Contraseña", encPassPh: "Introduce una contraseña que solo tú conozcas",
                encTextLabel: "Texto plano", encTextPh: "Introduce el texto a cifrar. No conserves el texto plano después de cifrar",
                btnEncrypt: "Cifrar", encOutLabel: "Texto cifrado",
                encOutPh: "El resultado aparecerá aquí. Guarda copias en lugares que solo tú encuentres",
                btnCopy: "Copiar texto cifrado",
                decPassLabel: "Contraseña", decPassPh: "Introduce una contraseña que solo tú conozcas",
                decBoxLabel: "Texto cifrado", decBoxPh: "Pega el texto cifrado que guardaste la última vez",
                btnDecrypt: "Descifrar", decOutLabel: "Texto plano",
                decOutPh: "El resultado aparecerá aquí. Tras recuperarlo, borra tus rastros de navegación",
                btnCopyPlain: "Copiar texto plano",
                footer1: "Parámetros fijos: Argon2id · Memoria 256MB · Iteraciones 32 · Paralelismo 2 · Sal 16B · Clave 32B · AES-256-GCM · IV 12B · Tag de autenticación 16B · Formato &lt;sal&gt;.&lt;iv&gt;.&lt;tag&gt;.&lt;resultado&gt;. Cada texto cifrado usa una sal aleatoria independiente; el tag verifica la integridad. Texto alterado o contraseña incorrecta impiden el descifrado.",
                footer2: "Se ejecuta en el navegador con Web Crypto y argon2-browser (WASM). Todos los cálculos ocurren en este dispositivo.",
                passLen: "Mínimo 16 caracteres", passSpace: "Sin espacios permitidos",
                passLower: "Se necesita una letra minúscula", passUpper: "Se necesita una letra mayúscula",
                passNum: "Se necesita un número", passSym: "Se necesita un símbolo",
                needEncText: "Introduce el texto a cifrar", needBox: "Pega el texto cifrado",
                encWorking: "Cifrando…", encDone: "Cifrado", encFail: "Error al cifrar: ",
                decWorking: "Descifrando…", decDone: "Descifrado, autenticación correcta", decFail: "Error al descifrar: ",
                decFailTail: ". Comprueba que la contraseña y el texto cifrado coincidan.",
                copiedEnc: "Texto cifrado copiado", copiedPlain: "Texto plano copiado",
                copyFallback: "No se pudo copiar, texto seleccionado — pulsa Ctrl+C",
                noEnc: "No hay texto cifrado para copiar", noPlain: "No hay texto plano para copiar"
            },
            fr: {
                title: "Trésor caché",
                browserTitle: "Trésor caché - Utilisation d'Argon2id et AES-256-GCM",
                subtitle: "Un outil de chiffrement qui fonctionne entièrement hors ligne, avec <em>Argon2id</em> et <em>AES-256-GCM</em>.",
                encTitle: "Chiffrer", decTitle: "Déchiffrer",
                encPassLabel: "Mot de passe", encPassPh: "Saisissez un mot de passe que vous seul connaissez",
                encTextLabel: "Texte clair", encTextPh: "Saisissez le texte à chiffrer. Ne conservez pas le texte clair après le chiffrement",
                btnEncrypt: "Chiffrer", encOutLabel: "Texte chiffré",
                encOutPh: "Le résultat s'affichera ici. Gardez des copies dans des endroits que vous seul pouvez trouver",
                btnCopy: "Copier le texte chiffré",
                decPassLabel: "Mot de passe", decPassPh: "Saisissez un mot de passe que vous seul connaissez",
                decBoxLabel: "Texte chiffré", decBoxPh: "Collez le texte chiffré caché la dernière fois",
                btnDecrypt: "Déchiffrer", decOutLabel: "Texte clair",
                decOutPh: "Le résultat s'affichera ici. Une fois récupéré, effacez vos traces de navigation",
                btnCopyPlain: "Copier le texte clair",
                footer1: "Paramètres fixes : Argon2id · Mémoire 256MB · Itérations 32 · Parallélisme 2 · Sel 16B · Clé 32B · AES-256-GCM · IV 12B · Tag d'authentification 16B · Format &lt;sel&gt;.&lt;iv&gt;.&lt;tag&gt;.&lt;résultat&gt;. Chaque texte chiffré utilise un sel aléatoire indépendant ; le tag vérifie l'intégrité. Un texte modifié ou un mauvais mot de passe rend le déchiffrement impossible.",
                footer2: "S'exécute dans le navigateur avec Web Crypto et argon2-browser (WASM). Tous les calculs se font localement.",
                passLen: "Au moins 16 caractères", passSpace: "Aucun espace autorisé",
                passLower: "Une minuscule est requise", passUpper: "Une majuscule est requise",
                passNum: "Un chiffre est requis", passSym: "Un symbole est requis",
                needEncText: "Saisissez le texte à chiffrer", needBox: "Collez le texte chiffré",
                encWorking: "Chiffrement…", encDone: "Chiffré", encFail: "Échec du chiffrement : ",
                decWorking: "Déchiffrement…", decDone: "Déchiffré, authentification réussie", decFail: "Échec du déchiffrement : ",
                decFailTail: ". Vérifiez que le mot de passe et le texte chiffré correspondent.",
                copiedEnc: "Texte chiffré copié", copiedPlain: "Texte clair copié",
                copyFallback: "Échec de copie, texte sélectionné — appuyez sur Ctrl+C",
                noEnc: "Aucun texte chiffré à copier", noPlain: "Aucun texte clair à copier"
            },
            vi: {
                title: "Hộp tiền để dành",
                browserTitle: "Hộp tiền để dành - Sử dụng Argon2id và AES-256-GCM",
                subtitle: "Công cụ mã hóa hoạt động hoàn toàn ngoại tuyến, sử dụng <em>Argon2id</em> và <em>AES-256-GCM</em>.",
                encTitle: "Mã hóa", decTitle: "Giải mã",
                encPassLabel: "Mật khẩu", encPassPh: "Nhập mật khẩu mà chỉ bạn biết",
                encTextLabel: "Văn bản gốc", encTextPh: "Nhập văn bản cần mã hóa. Đừng giữ lại văn bản gốc sau khi mã hóa",
                btnEncrypt: "Mã hóa", encOutLabel: "Văn bản mã hóa",
                encOutPh: "Kết quả sẽ hiển thị ở đây. Hãy giữ vài bản sao ở nơi chỉ mình bạn tìm thấy",
                btnCopy: "Sao chép văn bản mã hóa",
                decPassLabel: "Mật khẩu", decPassPh: "Nhập mật khẩu mà chỉ bạn biết",
                decBoxLabel: "Văn bản mã hóa", decBoxPh: "Dán văn bản mã hóa bạn đã cất lần trước",
                btnDecrypt: "Giải mã", decOutLabel: "Văn bản gốc",
                decOutPh: "Kết quả sẽ hiển thị ở đây. Sau khi lấy lại, hãy xóa dấu vết duyệt web",
                btnCopyPlain: "Sao chép văn bản gốc",
                footer1: "Tham số cố định: Argon2id · Bộ nhớ 256MB · Số vòng lặp 32 · Độ song song 2 · Muối 16B · Khóa 32B · AES-256-GCM · IV 12B · Thẻ xác thực 16B · Định dạng &lt;muối&gt;.&lt;iv&gt;.&lt;thẻ&gt;.&lt;kết quả&gt;. Mỗi văn bản mã hóa dùng một muối ngẫu nhiên độc lập; thẻ xác thực kiểm tra tính toàn vẹn. Văn bản bị sửa hoặc sai mật khẩu sẽ không thể giải mã.",
                footer2: "Chạy trong trình duyệt với Web Crypto và argon2-browser (WASM). Mọi tính toán đều thực hiện trên thiết bị này.",
                passLen: "Tối thiểu 16 ký tự", passSpace: "Không được có khoảng trắng",
                passLower: "Cần chữ thường", passUpper: "Cần chữ hoa",
                passNum: "Cần chữ số", passSym: "Cần ký tự đặc biệt",
                needEncText: "Nhập văn bản cần mã hóa", needBox: "Dán văn bản mã hóa",
                encWorking: "Đang mã hóa…", encDone: "Đã mã hóa", encFail: "Lỗi mã hóa: ",
                decWorking: "Đang giải mã…", decDone: "Đã giải mã, xác thực thành công", decFail: "Lỗi giải mã: ",
                decFailTail: ". Kiểm tra mật khẩu và văn bản mã hóa có khớp không.",
                copiedEnc: "Đã sao chép văn bản mã hóa", copiedPlain: "Đã sao chép văn bản gốc",
                copyFallback: "Sao chép thất bại, văn bản đã được chọn — nhấn Ctrl+C",
                noEnc: "Chưa có văn bản mã hóa để sao chép", noPlain: "Chưa có văn bản gốc để sao chép"
            },
            th: {
                title: "ที่ซ่อนเงินออม",
                browserTitle: "ที่ซ่อนเงินออม - การใช้ Argon2id และ AES-256-GCM",
                subtitle: "เครื่องมือเข้ารหัสที่ทำงานแบบออฟไลน์เต็มรูปแบบ ใช้ <em>Argon2id</em> และ <em>AES-256-GCM</em>",
                encTitle: "เข้ารหัส", decTitle: "ถอดรหัส",
                encPassLabel: "รหัสผ่าน", encPassPh: "ป้อนรหัสผ่านที่มีเพียงคุณเท่านั้นที่รู้",
                encTextLabel: "ข้อความต้นฉบับ", encTextPh: "ป้อนข้อความที่จะเข้ารหัส อย่าเก็บข้อความต้นฉบับไว้หลังเข้ารหัส",
                btnEncrypt: "เข้ารหัส", encOutLabel: "ข้อความที่เข้ารหัส",
                encOutPh: "ผลลัพธ์จะแสดงที่นี่ เก็บสำเนาไว้หลายที่ที่คุณเท่านั้นหาเจอ",
                btnCopy: "คัดลอกข้อความที่เข้ารหัส",
                decPassLabel: "รหัสผ่าน", decPassPh: "ป้อนรหัสผ่านที่มีเพียงคุณเท่านั้นที่รู้",
                decBoxLabel: "ข้อความที่เข้ารหัส", decBoxPh: "วางข้อความที่เข้ารหัสที่คุณซ่อนไว้ครั้งล่าสุด",
                btnDecrypt: "ถอดรหัส", decOutLabel: "ข้อความต้นฉบับ",
                decOutPh: "ผลลัพธ์จะแสดงที่นี่ หลังจากได้ข้อความกลับมาแล้ว ลบร่องรอยการท่องเว็บของคุณ",
                btnCopyPlain: "คัดลอกข้อความต้นฉบับ",
                footer1: "พารามิเตอร์คงที่: Argon2id · หน่วยความจำ 256MB · รอบ 32 · ความขนาน 2 · เกลือ 16B · คีย์ 32B · AES-256-GCM · IV 12B · แท็กยืนยัน 16B · รูปแบบ &lt;เกลือ&gt;.&lt;iv&gt;.&lt;แท็ก&gt;.&lt;ผลลัพธ์&gt;. ข้อความที่เข้ารหัสแต่ละชิ้นใช้เกลือสุ่มอิสระ แท็กยืนยันตรวจสอบความสมบูรณ์ ข้อความถูกแก้ไขหรือรหัสผ่านผิดจะไม่สามารถถอดรหัสได้",
                footer2: "ทำงานในเบราว์เซอร์ด้วย Web Crypto และ argon2-browser (WASM) การคำนวณทั้งหมดเกิดขึ้นบนอุปกรณ์นี้",
                passLen: "อย่างน้อย 16 ตัวอักษร", passSpace: "ห้ามมีช่องว่าง",
                passLower: "ต้องมีตัวพิมพ์เล็ก", passUpper: "ต้องมีตัวพิมพ์ใหญ่",
                passNum: "ต้องมีตัวเลข", passSym: "ต้องมีสัญลักษณ์",
                needEncText: "ป้อนข้อความที่จะเข้ารหัส", needBox: "วางข้อความที่เข้ารหัส",
                encWorking: "กำลังเข้ารหัส…", encDone: "เข้ารหัสเสร็จ", encFail: "เข้ารหัสล้มเหลว: ",
                decWorking: "กำลังถอดรหัส…", decDone: "ถอดรหัสสำเร็จ ผ่านการยืนยัน", decFail: "ถอดรหัสล้มเหลว: ",
                decFailTail: ". ตรวจสอบว่ารหัสผ่านและข้อความที่เข้ารหัสตรงกัน",
                copiedEnc: "คัดลอกข้อความที่เข้ารหัสแล้ว", copiedPlain: "คัดลอกข้อความต้นฉบับแล้ว",
                copyFallback: "คัดลอกไม่สำเร็จ เลือกข้อความแล้ว — กด Ctrl+C",
                noEnc: "ยังไม่มีข้อความที่เข้ารหัสให้คัดลอก", noPlain: "ยังไม่มีข้อความต้นฉบับให้คัดลอก"
            }
        },
        t(key) { return this.dict[this.lang][key] != null ? this.dict[this.lang][key] : this.dict.en[key]; },
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