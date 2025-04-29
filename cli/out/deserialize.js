"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deserializeCommand = deserializeCommand;
const id_1 = require("@vaultys/id");
const replacer = (key, value) => {
    if (value.type === "Buffer") {
        return Buffer.from(value.data).toString("base64");
    }
    return value;
};
function deserializeCommand(argv) {
    const data = argv.data;
    if (typeof data === "string") {
        const cert = id_1.Challenger.deserializeCertificate(id_1.crypto.Buffer.from(data, "base64"));
        if (!cert)
            throw new Error("An error occurred while deserializing the certificate");
        cert.pk1 = cert.pk1 ? id_1.VaultysId.fromId(cert.pk1).toVersion(1).id : cert.pk1;
        cert.pk2 = cert.pk2 ? id_1.VaultysId.fromId(cert.pk2).toVersion(1).id : cert.pk2;
        console.log(Buffer.from(JSON.stringify(cert, replacer), "utf-8").toString("base64"));
    }
}
