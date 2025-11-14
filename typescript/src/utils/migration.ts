import { decode, encode } from "@msgpack/msgpack";
import { Buffer } from "../crypto";
import IdManager, { instanciateApp, instanciateContact } from "../IdManager";

export function migrateVaultysId(oldVid: Buffer) {
  const data = decode(oldVid.slice(1)) as { p?: Buffer; x?: Buffer };
  if (data.x?.length === 96) data.x = data.x.slice(0, 32);
  delete data["p"];
  return Buffer.concat([oldVid.slice(0, 1), encode(data)]);
}

export function migrateIdManager(idManager: IdManager) {
  const s = idManager.store.substore("contacts");
  for (const did of s.list()) {
    const data = s.get(did);
    const contact = instanciateContact(data);
    if (contact.did !== did) {
      s.set(contact.did, { ...contact, oldDid: did });
      s.delete(did);
      //console.log(did, "->", contact.did);
    }
  }

  const apps = idManager.store.substore("registrations");
  for (const did of apps.list()) {
    const data = apps.get(did);
    const site = instanciateApp(data);
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
