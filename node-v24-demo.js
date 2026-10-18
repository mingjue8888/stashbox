const argon2id_aes256gcm = require("./argon2id-aes256gcm.umd.js");

const crypt = argon2id_aes256gcm({
    argonMemory: 262144,
    argonTimes: 32,
    argonParallelism: 2,
});

async function testEncrypt(password, text) {
    console.time("encrypt");
    const encrypted = await crypt.encrypt(password, text);
    console.timeEnd("encrypt");
    console.log(encrypted);
}

async function testDecrypt(password, encryptedText) {
    console.time("decrypt");
    const decrypted = await crypt.decrypt(password, encryptedText);
    console.timeEnd("decrypt");
    console.log(decrypted);
}

testEncrypt("PasswordDemo.123456", "Hello world!");
