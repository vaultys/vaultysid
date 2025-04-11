# SmartLink Connection API

This document describes the complete connection lifecycle for the Smartlink application using the VaultysId CLI. Registration and Connection use the same flow.

## 1. Initiation

The connection process begins when the user initiates the authentication flow, for a server located at:

```
https://your-server.com
```

## 2. Connection Key Generation

1. Generate a unique VaultysId for this connection attempt:

```bash
vaultysid-cli generate machine
```

This command will output a secret. Store this secret securely as it will be used for device identification.

2. Retrieve the VaultysId from the stored secret:

```bash
vaultysid-cli fromSecret <your-stored-secret> --display id
```

This command will output the VaultysId in base64 format.

3. Use the VaultysId to initiate the connection:

```bash
curl "https://your-server.com/api/auth/extension/connect?id=<base64-vaultysid>"
```

This will return a JSON response containing an encrypted key.

4. Decrypt the received key:

```bash
vaultysid-cli decrypt <encrypted-key> <your-stored-secret>
```

The output of this command is your connectionKey.

## 3. Connection URL Creation

Construct a URL for the user to connect their Vaultys wallet:

```
vaultys://register?url=https://your-server.com/api/auth/connect&key=<connectionKey>
```

## 4. User Interface Presentation

Present the `vaultys://` URL to the user, either as a clickable link for browser wallets or as a QR code for mobile devices.

## 5. Waiting for User Connection

Poll the server to check the connection status:

```bash
curl -X POST "https://your-server.com/api/auth/extension/listen/<pollingKey>"
```

Where `<pollingKey>` is the SHA256 hash of `connecting-<connectionKey>-vaultys`.

The status codes are as follows:
- `-1`: Connection initialized, waiting for user to authenticate
- `-2`: Connection failed: the user failed to authenticate properly
- `1`: User is authenticating
- `2`: User has successfully authenticated. Check authToken for more information
- `3`: User has successfully authenticated AND the connection token is consumed

## 6. Decrypt authToken and Extract Identification Number

Once you receive a status `2` response with an `authToken`, decrypt it:

```bash
vaultysid-cli decrypt <authToken> <your-stored-secret>
```

The decrypted token will contain:
- `membershipId`: Unique identifier for the user
- `apiKey`: Key to use for API queries
- `expiration`: Expiration time of the API key

For registration, associate the System User with `{membershipId, serverURL}`.
For connection, verify `{membershipId, serverURL}` against the associated System User and grant access accordingly.

Use the `apiKey` for API queries until the `expiration` time.
