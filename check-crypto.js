const { webcrypto } = require('node:crypto');
const crypto = webcrypto;

async function generateSalt() {
    return crypto.getRandomValues(new Uint8Array(16));
}

async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function encryptData(data, key) {
    const enc = new TextEncoder();
    const encodedData = enc.encode(JSON.stringify(data));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedData
    );

    return {
        ciphertext: bufferToBase64(encryptedContent),
        iv: bufferToBase64(iv),
    };
}

async function decryptData(ciphertext, iv, key) {
    const encryptedContent = base64ToBuffer(ciphertext);
    const ivBuffer = base64ToBuffer(iv);

    const decryptedContent = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBuffer },
        key,
        encryptedContent
    );

    const dec = new TextDecoder();
    return JSON.parse(dec.decode(decryptedContent));
}

function bufferToBase64(buffer) {
    return Buffer.from(buffer).toString('base64');
}

function base64ToBuffer(base64) {
    return new Uint8Array(Buffer.from(base64, 'base64')).buffer;
}

(async () => {
    try {
        console.log("Starting Crypto Verification...");
        const password = "my-secure-password";
        const salt = await generateSalt();
        console.log("Salt generated:", bufferToBase64(salt));

        const key = await deriveKey(password, salt);
        console.log("Key derived successfully.");

        const originalData = { symbol: "BTC", amount: 1.5 };
        console.log("Original Data:", originalData);

        const { ciphertext, iv } = await encryptData(originalData, key);
        console.log("Encrypted:", { ciphertext, iv });

        const decryptedData = await decryptData(ciphertext, iv, key);
        console.log("Decrypted Data:", decryptedData);

        if (JSON.stringify(originalData) === JSON.stringify(decryptedData)) {
            console.log("SUCCESS: Decrypted data matches original.");
        } else {
            console.error("FAILURE: Data mismatch.");
            process.exit(1);
        }
    } catch (error) {
        console.error("Error:", error);
        process.exit(1);
    }
})();
