# VaultysID
Your Swiss Army Knife for the future of Self-Sovereign Identity (SSI). Create, Manage identities and Webs Of Trust independently in a YDNABFT (You Don't Need A Blockchain For That) way. 
Reference Implementation in javascript of the Vaultys Protocol.

[![Build Status](https://github.com/vaultys/vaultysid/workflows/test/badge.svg?branch=main)](https://github.com/vaultys/vaultysid/actions/workflows/test.yml)

## Features
- create and manage ids
- use any FIDO2 or FIDO-U2F compatible hardware key to secure your ID (successfully tested yubikey, feitian, cryptknox, ledger secure-key app or passkey)
- sign and verify - ECDSA and EDDSA
- encrypt and decrypt
- secure handcheck to include any id in your Web of Trust over various channels (Memory, P2P WebRTC, Nostr, build your own)
- backup your WoT (File, LocalStorage)
- nodejs/browser compatible
- pure P2P, no third party service. Vaultys does not handle your data, neither see it pass through its servers.
- no token or whatever to buy to get started!
- free (as in free beer) and open-source for ever
- COMING SOON: complete replacement of login system without password  or email or phone number (aka Web3 "Connect" without the need buying crypto and leaving footprints everywhere!)

#### This library is still in beta. While working, the API might change in the near future

### Security Note
This project use a maximum of reviewed library and minimize dependencies. The code has **NOT** been reviewed by an independent security team, but we are working to sort this out very soon. Use at your own risk.

## Getting Started
Install vaultys lib
`npm add @vaultyshq/id`  

Then you an create a new Vaultys ID: 
```js
import { VaultysId } from '@vaultyshq/id'
const vaultysId = await VaultysId.generate();
// you can distribute this to your friend
console.log(vaultysId.id);

// for DiD fingerprint and didDocument (higly subject to change)
console.log(vaultysId.did);
console.log(vaultysId.didDocument);

// be sure to backup your seed
console.log(vaultysId.getSecret());
```

If you have a FIDO2 Key, you also can create an ID (browser only for now):
```js
import { SoftCredentials } from '@vaultyshq/id';
// -7 = curve NIST P-256, (or -8 of Ed25519 only compatible with some keys like feitian or cryptknox)
const request = SoftCredentials.createRequest(-7);
// you are supposed to plug your key and enter your pin here:
const attestation = await navigator.credentials.create(request);
// create your ID now
const vaultysId = VaultysId.fido2FromAttestation(attestation);
```
Warning: call the function `navigator.credentials.create` and all requests to `sign` data in the same thread as user interaction on Safari, otherwise it will throw an error.

## Managing IDs
The object `VaultysId` is handling basic operations (signature, encryption, verification etc...). However if you want to interact with other Vaultys IDs in your Web of Trust, there is a special IdManager for you that is handling this as well as storage.
For Storage we have available now:
- MemoryStorage: to use a hashmap as backend (in the property _raw)
- LocalStorage: to use Browser LocalStorage as backend.

More to come...

```js
import { MemoryStorage } from '@vaultyshq/id';
const s1 = new MemoryStorage();
const manager1 = new IdManager(vaultysId, s1);

const friend = await VaultysId.generate();
const s2 = new MemoryStorage();
const manager2 = new IdManager(vaultysId, s2);
```

# Channels and Web of Trust
Now we have all setup, both ids need to communicate over a channel (ie throug internet somehow). So we have created the powerful concept of bidirectional channel that serves the base of the P2P WoT system. Everybody will handle their directory of keys that have been signed on both ends during the initial handcheck. Once in your directory, you can build a large set of services communicating over untrusted channels that have their legs in each other Webs of Trust.

For now we have setup several kind of channels:
- MemoryChannel: to communicate in the same nodejs process
- @vaultyshq/channel-peerjs: for P2P communication between browsers (using WebRTC through peerjs lib)
- @vaultyshq/channel-browser and @vaultyshq/channel-server: for classic server/client architecture
- @vaultyshq/channel-patr: be like "I am your Father" to Nostr, squatting its protocol (aka Patr Nostr)
- more to come

if you want to implement your own channel, just implement 3 functions (`send`, `receive` and `close`) and you can use our crytpo implementation that let you automagically encrypt your channel

```js
import { CryptoChannel } from '@vaultyshq/id';

class MyChannel {
  constructor(config){...}
  async send(data){...}
  async receive(){... return someData }
}

const myEnryptedChannel = CryptoChannel.encryptChannel(new MyChannel(config));
// now share `myEnryptedChannel.key` to your friend so he can listen to the other end doing
// const channel = CryptoChannel.encryptChannel(new MyChannel(config), key);
```

```js
import { MemoryChannel } from '@vaultyshq/id'
const channel = MemoryChannel.createBidirectionnalChannel();

// Now let's create a relationship between both and save thekys in their wot
const contacts = await Promise.all([
  manager1.askContact(channel),
  manager2.acceptContact(channel.otherend),
]);

// Access your WoT
manager1.setContactMetadata(manager2.vaultysId.did, "group", "pro");
console.log(manager2.contacts)
```

Obviously from now on, any signed stuff from your service can be checked against the Web of Trust
```js
const myServiceStringWithSomeRandom = "vaultys://myservice?rand=1234567&action=connect";
const signature = manager1.signChallenge(myServiceStringWithSomeRandom);
assert(manager2.getContact(manager1.vaultysId.did).verifyChallenge(myServiceStringWithSomeRandom, signature) === true);
```

We have some ready made functions for files for instance with `idManager.signFile` and `idManager.verifyFile`, the intended use is to replace and automate verification of any data coming from servers or people in your WoT!

## Encryption
You can also encrypt message to a contact or a set of contact (using saltpack behind the wall)

```js
const alice = await VaultysId.generatePerson();
const bob = await VaultysId.generatePerson();
const eve = await VaultysId.generatePerson();
const plaintext = "This message is authentic!";
const recipients = [bob.id, eve.id, alice.id];
const encrypted = await alice.encrypt(plaintext, recipients);

// send the message `encrypted` to Bob and Eve so they can decrypt:
const decryptedBob = await bob.decrypt(encrypted);
const decryptedEve = await eve.decrypt(encrypted);
```

## Final Note
If you use this project and you speak French, you engage to:
- write and say "chiffrer" instead of "crypter"
- write and say "numérique" instead of "digital"

Thanks!

## License
MIT