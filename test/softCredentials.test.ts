import crypto from "crypto";
import SoftCredentials from "../src/SoftCredentials";
import assert from "assert";
import "./utils";

// credentials request payload
const createRequest = (alg: number) => {
  const challenge = crypto.randomBytes(32);
  return {
    publicKey: {
      challenge,
      rp: {
        name: "Tests ID",
        id: "I am the new guy",
      },
      user: {
        id: Buffer.from("ertyu45678RUTYESEZTYSDYJTUE4576232453", "utf8"),
        name: "john.smith@mail.com",
        displayName: "John Smith",
      },
      pubKeyCredParams: [
        {
          type: "public-key" as const,
          alg,
        },
      ],
    },
  };
};

let attestation: PublicKeyCredential, attestationSafe;

describe("SoftCredentials", () => {
  it("create attestation (ECDSA)", async () => {
    attestation = await SoftCredentials.create(createRequest(-7));
  });
  it("create attestation (EdDSA)", async () => {
    attestationSafe = await SoftCredentials.create(createRequest(-8));
  });

  it("get assertion and verify with attestation using ECDSA", async () => {
    const payload = {
      publicKey: {
        challenge: crypto.randomBytes(32),
        allowCredentials: [
          {
            type: "public-key" as const,
            id: attestation.rawId,
          },
        ],
      },
    };
    const assertion = await SoftCredentials.get(payload);
    assert.equal(SoftCredentials.extractChallenge(Buffer.from(assertion.response.clientDataJSON)), payload.publicKey.challenge.toString("base64"));
    const verified = SoftCredentials.verify(attestation, assertion);
    assert.ok(verified);
  });

  it("verify assertion with attestation using github webauthn json coming from yubikey credentials", async () => {
    const attestationSafe = {
      type: "public-key",
      id: "vLjE6ObBfDZCZSJEqt1HhDokuO6O5Fztx7DSfQts7QEaj0Cbjr0Sry-jVuKdDA3OJwzk8jhygjm6-6WskhsWMyBDcMMtitMStwY7is8G7pCKuUirDZ3-AKZYAqmnF6CqIiLBxSxvDl11iVOMcBgkFwOLf8rGqv05c3k6r2XZ0SA",
      rawId: Buffer.from("vLjE6ObBfDZCZSJEqt1HhDokuO6O5Fztx7DSfQts7QEaj0Cbjr0Sry-jVuKdDA3OJwzk8jhygjm6-6WskhsWMyBDcMMtitMStwY7is8G7pCKuUirDZ3-AKZYAqmnF6CqIiLBxSxvDl11iVOMcBgkFwOLf8rGqv05c3k6r2XZ0SA", "base64"),
      response: {
        clientDataJSON: Buffer.from("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZkl3bFU5NHNNcUsyMVNrX1BYbFIzU2hLU0JVc0t6dFVpX0pqNE5YampSOCIsIm9yaWdpbiI6Imh0dHBzOi8vdmF1bHR5cy5sb2NhLmx0IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ", "base64"),
        attestationObject: Buffer.from("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjh3k-dKamFhxtblpCasfhfE1MJJYpzErYjq2DqvChGolBBAAAAAQAAAAAAAAAAAAAAAAAAAAAAgLy4xOjmwXw2QmUiRKrdR4Q6JLjujuRc7cew0n0LbO0BGo9Am469Eq8vo1binQwNzicM5PI4coI5uvulrJIbFjMgQ3DDLYrTErcGO4rPBu6QirlIqw2d_gCmWAKppxegqiIiwcUsbw5ddYlTjHAYJBcDi3_Kxqr9OXN5Oq9l2dEgpAEBAycgBiFYIO6J63OnkjzyQ--iXSbgm1oLSl3wzlDCy4ohwkbN-l4I", "base64"),
        transports: ["nfc", "usb", "ble", "internal", "hybrid"],
      },
      clientExtensionResults: {},
    };
    const assertion = {
      type: "public-key",
      id: "vLjE6ObBfDZCZSJEqt1HhDokuO6O5Fztx7DSfQts7QEaj0Cbjr0Sry-jVuKdDA3OJwzk8jhygjm6-6WskhsWMyBDcMMtitMStwY7is8G7pCKuUirDZ3-AKZYAqmnF6CqIiLBxSxvDl11iVOMcBgkFwOLf8rGqv05c3k6r2XZ0SA",
      rawId: Buffer.from("vLjE6ObBfDZCZSJEqt1HhDokuO6O5Fztx7DSfQts7QEaj0Cbjr0Sry-jVuKdDA3OJwzk8jhygjm6-6WskhsWMyBDcMMtitMStwY7is8G7pCKuUirDZ3-AKZYAqmnF6CqIiLBxSxvDl11iVOMcBgkFwOLf8rGqv05c3k6r2XZ0SA", "base64"),
      response: {
        clientDataJSON: Buffer.from("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQU9tZmdkbnV4cl8ydWw4T1pMekFXUk1SYkd0NXkzbHIxMURxcnF3UUdMVSIsIm9yaWdpbiI6Imh0dHBzOi8vdmF1bHR5cy5sb2NhLmx0IiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wucWp6OXprL3lhYlBleCJ9", "base64"),
        authenticatorData: Buffer.from("3k-dKamFhxtblpCasfhfE1MJJYpzErYjq2DqvChGolABAAAAIQ", "base64"),
        signature: Buffer.from("_eq8EwX_twQyWjyiCvCDu5JLKEWpMxW9Pz0Qwpt8A5UcHJyGoGQMrssaws-jwqIpKxkVU7MBlHzHUgFULFn5Cw", "base64"),
        userHandle: null,
      },
      clientExtensionResults: {},
    };
    assert.equal(SoftCredentials.extractChallenge(attestationSafe.response.clientDataJSON), "fIwlU94sMqK21Sk/PXlR3ShKSBUsKztUi/Jj4NXjjR8=");
    assert.equal(SoftCredentials.extractChallenge(assertion.response.clientDataJSON), "AOmfgdnuxr/2ul8OZLzAWRMRbGt5y3lr11DqrqwQGLU=");
    // @ts-expect-error mockup
    const verified = SoftCredentials.verify(attestationSafe, assertion);
    assert.ok(verified);
  });

  it("attestation response from yubikey should be verified", async () => {
    const response = {
      clientDataJSON: Buffer.from("eyJjaGFsbGVuZ2UiOiJZTVdFVGYtUDc5aU1iLUJxZFRreVNOUmVPdmE3bksyaVZDOWZpQzhpR3ZZeXB1bkVPQ1pHWjYtWTVPVjFydk1pRGdBaldmRmk2VUMwV3lLR3NqQS1nQSIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9", "base64"),
      attestationObject: Buffer.from("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAIzOihC6Ba80o5JnoYOJJ_EtEVmWQcAvxVCnsCFnVRQZAiAfeIddLPsPl1FeSX8B5xZANcQKGNoO7pb0TZPnuJdebGN4NWOBWQKzMIICrzCCAZegAwIBAgIESFs9tjANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZZdWJpY28gRklETyBQcmV2aWV3IENBMB4XDTE4MDQxMjEwNTcxMFoXDTE4MTIzMTEwNTcxMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTIxMzkzOTEyNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPss3TBDKMVySlDM5vYLrX0nqRtZ4eZvKXuJydQ9wrLHeIm08P-dAijLlG384BsZWJtngEqsl38oGJzNsyV0yiijbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS42MBMGCysGAQQBguUcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMvPkvVjXQiuvSZmGCB8NqTvGqhxyEfkoU-vz63PaaTsG3jEzjl0C7PZ26VxCvqWPJdM3P3e7Kp18sj4RjEHUmkya2PPipOwBd3p0qMQSQ8MeziCPLQ9uvGGb4YShcvaprMv4c21b4piza-znHneNCmmq-ZS4Y23o-vYv085_BEwyLPcmPjSZ5qWysCq7rVvZ7OWwcU1zu5RhSZyUKl8dzK9lAzs5OdRH2fzEewsW2OkB_Ow_jBvAxqwLXXTHuwMFaRfpmBoZuQlcofSrnwJ8KA-K-e0dKTz2zC8EbZrWYrSpbrHKyqxeBT6DkUd8H4tgAd5lOr_yqrtVmIaRfq07NmhhdXRoRGF0YVjElWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRBAAAAAPigEfOMCk0VgAYXER-e3H0AQMLC68jgMVzFOeLNnwklj81o1xzgSj6ZaDflB37Y-P66SLugWcTV6aZvNn-2Ool_RRDiinkufjdkwC3ssy5yXwClAQIDJiABIVggAYD1TSpf120DSVxen8ki56kF1bmT4EXO-P0JnSk5mMwiWCB3TlMZBRqPY6llzDcfHd-oW0EHdaFNgBdlGGFobpHKlw", "base64"),
    };
    // @ts-expect-error mockup
    const info = SoftCredentials.getCertificateInfo(response);
    assert.deepStrictEqual(info, {
      issuer: "CN=Yubico FIDO Preview CA",
      issuerName: "CN=Yubico FIDO Preview CA",
      subject: {
        C: "SE",
        O: "Yubico AB",
        OU: "Authenticator Attestation",
        CN: "Yubico U2F EE Serial 1213939126",
      },
      version: "v3 (2)",
      basicConstraintsCA: false,
    });
    // @ts-expect-error mockup
    assert.ok(await SoftCredentials.verifyPackedAttestation(response));
  });

  it("no attestation in response should be valid and not be verified", async () => {
    const response = {
      attestationObject: Buffer.from("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFk2rw5H3LiaP/1p3XV4I1wW43p60EG8RCpFuQTrBOPiRFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQGV0qcd/M/uuCBaLC0jX8PRZ9e5cEZTKp9Ngf6NCKWSdWinmpK7FYog14m5kfAepzh93Z4hrGD8M57ljxoBKXL0pQECAyYgASFYIIqukdwfB/WgIxfpOO3tGOKIp+xPsx1TCc2UPjC7G7BlIlggNJL1zJSlN2EAFhnKSxihoY6HZXopi1Wte83dgWlosoQ=", "base64"),
      clientDataJSON: Buffer.from("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWXpTYkpBbGIya0N6Qm1xa1U3cG9Nem92LXNONU5HcHRuWUFrUElkRWt4VSIsIm9yaWdpbiI6Imh0dHBzOi8vdmF1bHR5c2lkMi5sb2NhLmx0IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==", "base64"),
    };
    // @ts-expect-error mockup
    const info = SoftCredentials.getCertificateInfo(response);
    assert.equal(info, null);
    // @ts-expect-error mockup
    assert.ok(!(await SoftCredentials.verifyPackedAttestation(response)));
  });

  it("verify assertion with attestation using github webauthn json coming from macosx credentials", async () => {
    const attestationSafe = {
      type: "public-key",
      id: "AdGTqisA0_nFlbOQjjRCElrKVd9jMC7YOM1Lm49AoQFLXfVK8TQZovhN8YEZJaTHU7HBiYYAnCH4wIDADceW0nY_USlc_-KLMwyB_NRLyLgbQ34SULTSYjHF4tPZWO71WgwaXCxp4TPi6L2So0L3w6B_xv9WbvfCKDAp56Jk44k_lQsP431W_g5hY1Psd1r_VOIuuvP-YfluxwWS6C4mn2BLvp_Lbddhn9VU_X6w1HzHJiOZbm1Dlk0Yww",
      rawId: Buffer.from("AdGTqisA0_nFlbOQjjRCElrKVd9jMC7YOM1Lm49AoQFLXfVK8TQZovhN8YEZJaTHU7HBiYYAnCH4wIDADceW0nY_USlc_-KLMwyB_NRLyLgbQ34SULTSYjHF4tPZWO71WgwaXCxp4TPi6L2So0L3w6B_xv9WbvfCKDAp56Jk44k_lQsP431W_g5hY1Psd1r_VOIuuvP-YfluxwWS6C4mn2BLvp_Lbddhn9VU_X6w1HzHJiOZbm1Dlk0Yww", "base64"),
      response: {
        clientDataJSON: Buffer.from("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiYVJFMWVnWjZHMS1BRUVPSXpQbWxOckFnT1N5RWVWRG44OUtDREUxRGRPRSIsIm9yaWdpbiI6Imh0dHBzOi8vdmF1bHR5cy5sb2NhLmx0IiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0", "base64"),
        attestationObject: Buffer.from("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBP95PnSmphYcbW5aQmrH4XxNTCSWKcxK2I6tg6rwoRqJQRWH4It6tzgACNbzGCmSLCyXx8FUDALsB0ZOqKwDT-cWVs5CONEISWspV32MwLtg4zUubj0ChAUtd9UrxNBmi-E3xgRklpMdTscGJhgCcIfjAgMANx5bSdj9RKVz_4oszDIH81EvIuBtDfhJQtNJiMcXi09lY7vVaDBpcLGnhM-LovZKjQvfDoH_G_1Zu98IoMCnnomTjiT-VCw_jfVb-DmFjU-x3Wv9U4i668_5h-W7HBZLoLiafYEu-n8tt12Gf1VT9frDUfMcmI5lubUOWTRjDpQECAyYgASFYIM3N0z1jSTixc7fNwxy1BtBUrNUOiPOm2j7Zlwx6s8eXIlggKB-zZiuYTAaAdPVQuN5EUQeRNX0kjS2oikGCJsymvH8", "base64"),
        transports: ["internal"],
      },
      clientExtensionResults: {},
    };
    const assertion = {
      type: "public-key",
      id: "AdGTqisA0_nFlbOQjjRCElrKVd9jMC7YOM1Lm49AoQFLXfVK8TQZovhN8YEZJaTHU7HBiYYAnCH4wIDADceW0nY_USlc_-KLMwyB_NRLyLgbQ34SULTSYjHF4tPZWO71WgwaXCxp4TPi6L2So0L3w6B_xv9WbvfCKDAp56Jk44k_lQsP431W_g5hY1Psd1r_VOIuuvP-YfluxwWS6C4mn2BLvp_Lbddhn9VU_X6w1HzHJiOZbm1Dlk0Yww",
      rawId: Buffer.from("AdGTqisA0_nFlbOQjjRCElrKVd9jMC7YOM1Lm49AoQFLXfVK8TQZovhN8YEZJaTHU7HBiYYAnCH4wIDADceW0nY_USlc_-KLMwyB_NRLyLgbQ34SULTSYjHF4tPZWO71WgwaXCxp4TPi6L2So0L3w6B_xv9WbvfCKDAp56Jk44k_lQsP431W_g5hY1Psd1r_VOIuuvP-YfluxwWS6C4mn2BLvp_Lbddhn9VU_X6w1HzHJiOZbm1Dlk0Yww", "base64"),
      response: {
        clientDataJSON: Buffer.from("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoibUlySjNsVWxsNXRadjhfa25kMEJEeU12VlVFcnhBY19CWWNkX2hOQ2lZZyIsIm9yaWdpbiI6Imh0dHBzOi8vdmF1bHR5cy5sb2NhLmx0IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ", "base64"),
        authenticatorData: Buffer.from("3k-dKamFhxtblpCasfhfE1MJJYpzErYjq2DqvChGolAFYgu7dQ", "base64"),
        signature: Buffer.from("MEQCIFyGZIbrLunau93lnx0vTkWQjr_CcTkjYhyZ1-szXRPeAiBXwyQRQhMn59eva_CRlZOTQ_TLAgxr3eCWbwa1dQBnTA", "base64"),
        userHandle: Buffer.from("ZGlkOnZhdWx0eXM6MzI2ZjUyY2VkNjRhYmE4YzQ4MWRkMDU3ZDFkODA0MGY0ZWE3MzZiMA", "base64"),
      },
      clientExtensionResults: {},
    };
    assert.equal(SoftCredentials.extractChallenge(attestationSafe.response.clientDataJSON), "aRE1egZ6G1+AEEOIzPmlNrAgOSyEeVDn89KCDE1DdOE=");
    assert.equal(SoftCredentials.extractChallenge(assertion.response.clientDataJSON), "mIrJ3lUll5tZv8/knd0BDyMvVUErxAc/BYcd/hNCiYg=");
    // @ts-expect-error mockup
    const verified = SoftCredentials.verify(attestationSafe, assertion, true);
    assert.ok(verified);
  });
});
