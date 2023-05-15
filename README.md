# VaultysID
Reference Implementation in javascript of the Vaultys Protocol.


## Getting Started
Install vaultys lib
`npm add @vaultyshq/id @vaultyshq/storage-file`  

Then you an create a new Vaultys ID: 
```js
import { VaultysId } from '@vaultyshq/id'
const vaultysId = await VaultysId.generate();
// you can distribute this to your friend
console.log(vaultys.id);

// for DiD fingerprint
console.log(vaultys.did);
```

The object is handling basic operations (signature, encryption, verification etc...). However if you want to interact with other Vaultys IDs in your Web of Trust, there is a special IdManager for you that is handling this as well as storage.

```js
import { FileStorage } from '@vaultyshq/storage-file'
const s1 = new FileStorage('./me.json');
const manager1 = new IdManager(vaultysId, s1);

const friend = await VaultysId.generate();
const s2 = new FileStorage('./friend.json');
const manager2 = new IdManager(vaultysId, s2);
```

# Channels and Web of Trust
Now we have all setup, both ids need to communicate over a channel (ie throug internet somehow). So we have created the powerful concept of bidirectional channel that serves the base of the P2P WoT system. Everybody will handle their directory of keys that have been signed on both ends during the initial handcheck. Once in your directory, you can build a large set of services communicating over untrusted channels that have their legs in each other Webs of Trust.

For now we have setup several kind of channels:
- MemoryChannel: to communiate in the same nodejs process
- @vaultyshq/channel-peerjs: for P2P communication between various browser (using WebRTC through peerjs lib)
- @vaultyshq/channel-browser and @vaultyshq/channel-server: for classic server/client architecture
- @vaultyshq/channel-patr: squatting Nostr protocol (aka Patr Nostr)
- more to come

```js
import { MemoryChannel } from '@vaultyshq/id'
const channel = MemoryChannel.createBidirectionnalChannel();

// now let's create a relationship between both and save thekys in their wot
const contacts = await Promise.all([
  manager1.askContact(channel),
  manager2.acceptContact(channel.otherend),
]);
```