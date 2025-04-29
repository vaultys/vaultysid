"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const yargs_1 = __importDefault(require("yargs/yargs"));
const helpers_1 = require("yargs/helpers");
const generate_1 = require("./generate");
const fromSecret_1 = require("./fromSecret");
const encrypt_1 = require("./encrypt");
const decrypt_1 = require("./decrypt");
const sign_1 = require("./sign");
const verify_1 = require("./verify");
const deserialize_1 = require("./deserialize");
const cli = (0, yargs_1.default)((0, helpers_1.hideBin)(process.argv))
    .scriptName("vaultysid-cli")
    .command("generate [type]", "generate a vaultys identity and get secret", (yargs) => {
    yargs.positional("type", {
        describe: "Type of identity to generate",
        type: "string",
        default: "machine",
        choices: ["machine", "person", "organization"],
    });
}, async (argv) => await (0, generate_1.generateCommand)(argv))
    .command("fromSecret [secret]", "Retrieve a vaultys identity from a secret", (yargs) => {
    yargs.positional("secret", {
        describe: "Secret of identity to retrieve",
        type: "string",
    });
    yargs.option("display", {
        describe: "Information to display",
        type: "string",
        choices: ["did", "fingerprint", "id"],
        demandOption: true,
    });
}, (argv) => (0, fromSecret_1.fromSecretCommand)(argv))
    .command("encrypt <content> [recipients..]", "Use vaultysId to encrypt a content for given identities (return base64 encrypted message)", (yargs) => {
    yargs
        .positional("content", {
        describe: "Content to encrypt",
        type: "string",
        demandOption: true,
    })
        .positional("recipients", {
        describe: "List of recipients ids encoded base64",
        type: "string",
        array: true,
        demandOption: true,
    });
}, async (argv) => await (0, encrypt_1.encryptCommand)(argv))
    .command("decrypt <encryptedMessage> <secret>", "Use vaultysId to decrypt a message with given identity (return decrypted message)", (yargs) => {
    yargs
        .positional("encryptedMessage", {
        describe: "Content to decrypt in base64",
        type: "string",
        demandOption: true,
    })
        .positional("secret", {
        describe: "Secret key of the identity to use for decryption",
        type: "string",
        demandOption: true,
    });
}, async (argv) => await (0, decrypt_1.decryptCommand)(argv))
    .command("verify <content> <signature>", "Use vaultysId to verify a signed content with given identity (return true or false)", (yargs) => {
    yargs
        .option("id", {
        describe: "VautysId in base64",
        type: "string",
        demandOption: true,
    })
        .positional("content", {
        describe: "Content to sign",
        type: "string",
        demandOption: true,
    })
        .positional("signature", {
        describe: "Signature of the content to be verified for id, base64 encoded",
        type: "string",
        demandOption: true,
    });
}, async (argv) => await (0, verify_1.verifyCommand)(argv))
    .command("sign <content> <secret>", "Use vaultysId to sign a content with given identity (return base64 signature)", (yargs) => {
    yargs
        .positional("content", {
        describe: "Content to sign",
        type: "string",
        demandOption: true,
    })
        .positional("secret", {
        describe: "Secret key of the identity to use for signing, encoded base64",
        type: "string",
        demandOption: true,
    });
}, async (argv) => await (0, sign_1.signCommand)(argv))
    .command("deserializeCertificate <data>", "Deserialize a certificate and get base64 encryted object", (yargs) => {
    yargs.positional("data", {
        describe: "Certificate data in base64",
        type: "string",
        demandOption: true,
    });
}, (argv) => (0, deserialize_1.deserializeCommand)(argv))
    .fail((msg, err, yargs) => {
    if (err) {
        console.error(err.message);
    }
    else {
        console.error(msg);
    }
    process.exit(1);
})
    .demandCommand(1, "You need at least one command before moving on")
    .help().argv;
