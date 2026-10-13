const argon2idAes256gcm = require("./argon2id-aes256gcm.umd.js");

const crypt = argon2idAes256gcm({
    argonMemory: 262144,       // Argon2 内存 KiB
    argonTimes: 32,            // 迭代次数
    argonParallelism: 2,      // 并行度
});

async function main() {
    const box  = await crypt.encrypt("SuperPassword.123456.IamYourDaddy", "Hello world!");
    const text = await crypt.decrypt("SuperPassword.123456.IamYourDaddy", box);

    console.log(box, text);
}

main();