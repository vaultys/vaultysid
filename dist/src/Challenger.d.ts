import VaultysId from "./VaultysId";
import { Buffer } from "buffer/";
export type ChallengeType = {
    version: 0 | 1;
    protocol: string;
    service: string;
    timestamp: number;
    pk1?: Buffer;
    pk2?: Buffer;
    nonce?: Buffer;
    sign1?: Buffer;
    sign2?: Buffer;
    metadata: {
        pk1?: Record<string, string>;
        pk2?: Record<string, string>;
    };
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
    version: 0 | 1;
    constructor(vaultysId: VaultysId, liveliness?: number);
    static verifyCertificate(certificate: Buffer): Promise<boolean>;
    static fromCertificate(certificate: Buffer, liveliness?: number): Promise<Challenger | undefined>;
    static deserializeCertificate: (challenge: Buffer) => ChallengeType;
    static serializeCertificate_v0: ({ version, protocol, service, timestamp, pk1, pk2, nonce, sign1, sign2, metadata }: {
        version: 0 | 1;
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
    static serializeCertificate: (challenge: ChallengeType) => Buffer;
    setChallenge(challengeString: Buffer): Promise<void>;
    getContext(): {
        protocol: string | undefined;
        service: string | undefined;
        metadata: {
            pk1?: Record<string, string>;
            pk2?: Record<string, string>;
        } | undefined;
    };
    createChallenge(protocol: string, service: string, version?: 0 | 1, metadata?: Record<string, string>): void;
    getCertificate(): Buffer;
    getUnsignedChallenge(): Buffer;
    getContactDid(): string | null;
    getContactId(): VaultysId;
    static fromString(vaultysId: VaultysId, challengeString: Buffer): Challenger;
    hasFailed(): boolean;
    isComplete(): boolean;
    init(challengeString: Buffer): Promise<void>;
    update(challengeString: Buffer, metadata?: Record<string, string>): Promise<void>;
}
