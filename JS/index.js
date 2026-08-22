import BxlusiveWasm from './bxlusive_wasm.js';

let wasmInstance = null;

async function getModule() {
    if (!wasmInstance) {
        wasmInstance = await BxlusiveWasm();
    }
    return wasmInstance;
}

export const cryptography = {
    async encrypt(data, key = "BxlusiveDefaultSecretKey32Bytes!") {
        const mod = await getModule();
        const textPayload = typeof data === 'object' ? JSON.stringify(data) : String(data);
        const resultJson = mod.encrypt(textPayload, key);
        return JSON.parse(resultJson);
    }
};

export const beast = cryptography;
