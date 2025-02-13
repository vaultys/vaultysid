import VaultysId from "./VaultysId";
import { Buffer } from "buffer/";
export type ChallengeType = {
    protocol: string;
    service: string;
    timestamp: number;
    pk1?: Buffer;
    pk2?: Buffer;
    nonce?: Buffer;
    sign1?: Buffer;
    sign2?: Buffer;
    metadata?: object;
    state: number;
    error?: string;
};
export default class Challenger {
    state: number;
    vaultysId: VaultysId;
    mykey: Buffer | undefined;
    hisKey: Buffer | undefined;
    liveliness: number;
    challenge: ChallengeType | undefined;
    version: number | undefined;
    constructor(vaultysId: VaultysId, liveliness?: number);
    static verifyCertificate(certificate: Buffer): Promise<boolean>;
    static fromCertificate(certificate: Buffer, liveliness?: number): Promise<Challenger | undefined>;
    static deserializeCertificate: (challenge: Buffer) => ChallengeType;
    static serializeCertificate_v0: ({ protocol, service, timestamp, pk1, pk2, nonce, sign1, sign2, metadata }: {
        protocol: string;
        service: string;
        timestamp: number;
        pk1: Buffer;
        pk2: Buffer;
        nonce: Buffer;
        sign1: Buffer;
        sign2: Buffer;
        metadata: object;
    }) => Buffer;
    static serializeCertificate: (challenge: ChallengeType, version?: 0 | 1) => Buffer;
    setChallenge(challengeString: Buffer): Promise<void>;
    getContext(): {
        protocol: string | undefined;
        service: string | undefined;
        metadata: object | undefined;
    };
    createChallenge(protocol: string, service: string, version?: 0 | 1, metadata?: {}): void;
    getCertificate(): Buffer;
    getUnsignedChallenge(): Buffer;
    getContactDid(): string | null;
    getContactId(): VaultysId;
    static fromString(vaultysId: VaultysId, challengeString: Buffer): Challenger;
    hasFailed(): boolean;
    isComplete(): boolean;
    isSelfAuth(): boolean;
    init(challengeString: Buffer): Promise<void>;
    update(challengeString: Buffer, metadata?: {}): Promise<void>;
}
