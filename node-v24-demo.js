const argon2idAes256gcm = require("./argon2id-aes256gcm.umd.js");

const password = "SuperPassword.123456.IamYourDaddy";
const text = "Hello world!";

const crypt = argon2idAes256gcm({
    argonMemory: 262144,       // Argon2 内存 KiB
    argonTimes: 32,            // 迭代次数
    argonParallelism: 2,      // 并行度
});

(async function() {
    console.time("encrypt");
    const encryptedText  = await crypt.encrypt(password, text);
    console.timeEnd("encrypt");
    console.log(encryptedText);
    console.time("decrypt");
    const sourceText = await crypt.decrypt(password, encryptedText);
    console.timeEnd("decrypt");
    console.log(sourceText);
})();
