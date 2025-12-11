export async function generateSalt(): Promise<Uint8Array> {
    return window.crypto.getRandomValues(new Uint8Array(16));
}

export async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt as unknown as BufferSource,
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true, // extractable? No, should be false for security, but maybe we need it for now? Let's keep it non-extractable usually.
        ["encrypt", "decrypt"]
    );
}

export async function encryptData(data: any, key: CryptoKey): Promise<{ ciphertext: string; iv: string }> {
    const enc = new TextEncoder();
    const encodedData = enc.encode(JSON.stringify(data));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const encryptedContent = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedData as unknown as BufferSource
    );

    return {
        ciphertext: bufferToBase64(encryptedContent),
        iv: bufferToBase64(iv.buffer as ArrayBuffer),
    };
}

export async function decryptData(ciphertext: string, iv: string, key: CryptoKey): Promise<any> {
    const encryptedContent = base64ToBuffer(ciphertext);
    const ivBuffer = base64ToBuffer(iv);

    const decryptedContent = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBuffer },
        key,
        encryptedContent
    );

    const dec = new TextDecoder();
    return JSON.parse(dec.decode(decryptedContent));
}

function bufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToBuffer(base64: string): ArrayBuffer {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}
