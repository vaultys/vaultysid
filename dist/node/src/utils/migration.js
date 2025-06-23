"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.migrateVaultysId = migrateVaultysId;
exports.migrateIdManager = migrateIdManager;
const msgpack_1 = require("@msgpack/msgpack");
const crypto_1 = require("../crypto");
const IdManager_1 = require("../IdManager");
function migrateVaultysId(oldVid) {
    const data = (0, msgpack_1.decode)(oldVid.slice(1));
    if (data.x?.length === 96)
        data.x = data.x.slice(0, 32);
    data.p = crypto_1.Buffer.from([]);
    return crypto_1.Buffer.concat([oldVid.slice(0, 1), (0, msgpack_1.encode)(data)]);
}
function migrateIdManager(idManager) {
    const s = idManager.store.substore("contacts");
    for (const did of s.list()) {
        const data = s.get(did);
        const contact = (0, IdManager_1.instanciateContact)(data);
        if (contact.did !== did) {
            s.set(contact.did, { ...contact, oldDid: did });
            s.delete(did);
            //console.log(did, "->", contact.did);
        }
    }
    const apps = idManager.store.substore("registrations");
    for (const did of apps.list()) {
        const data = apps.get(did);
        const site = (0, IdManager_1.instanciateApp)(data);
        if (site) {
            if (site.did !== did) {
                apps.set(site.did, { ...data, site: site.did, oldDid: did });
                apps.delete(did);
                // console.log(did, "->", site.did);
            }
        }
    }
    idManager.store.save();
}
