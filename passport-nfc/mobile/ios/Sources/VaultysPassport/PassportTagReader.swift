import CoreNFC
import Foundation
import VaultysPassportEngine

public struct PassportDataGroups: Sendable {
    public let dg15: Data
    public let dg14: Data?
}

public enum PassportTagReaderError: LocalizedError {
    case invalidCommand
    case timedOut
    case invalidResponse

    public var errorDescription: String? {
        switch self {
        case .invalidCommand: return "The passport command or NFC tag is invalid."
        case .timedOut: return "The passport did not respond in time."
        case .invalidResponse: return "The passport returned an invalid response."
        }
    }
}

/// Operations for a connected ISO 7816 passport tag in a fresh Core NFC session.
public enum PassportTagReader {
    private static let queue = DispatchQueue(label: "io.vaultys.passport")

    public static func read(mrz: String, tag: NFCISO7816Tag) async throws -> PassportDataGroups {
        try await onReaderQueue {
            var error: NSError?
            guard let groups = VaultysPassportaaReadPassport(mrz, TagTransceiver(tag), &error),
                  let dg15 = groups.dG15(), !dg15.isEmpty else {
                if let error { throw error }
                throw PassportTagReaderError.invalidResponse
            }
            let dg14 = groups.dG14().flatMap { $0.isEmpty ? nil : $0 }
            return PassportDataGroups(dg15: dg15, dg14: dg14)
        }
    }

    /// Four packed eight-byte challenges in, four fixed-width signatures out.
    public static func sign(mrz: String, tag: NFCISO7816Tag, challenges: Data, responseLength: Int) async throws -> Data {
        try await onReaderQueue {
            var error: NSError?
            guard let signatures = VaultysPassportaaSignPassport(
                mrz, TagTransceiver(tag), challenges, responseLength, &error
            ) else {
                if let error { throw error }
                throw PassportTagReaderError.invalidResponse
            }
            return signatures
        }
    }

    private static func onReaderQueue<T>(_ operation: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { continuation.resume(with: Result(catching: operation)) }
        }
    }
}

private final class TagTransceiver: NSObject, VaultysPassportaaTransceiverProtocol {
    private let tag: NFCISO7816Tag

    init(_ tag: NFCISO7816Tag) {
        self.tag = tag
    }

    func exchange(_ command: Data?) throws -> Data {
        guard tag.isAvailable, let command, let apdu = NFCISO7816APDU(data: command) else {
            throw PassportTagReaderError.invalidCommand
        }
        let finished = DispatchSemaphore(value: 0)
        var reply = Result<Data, Error>.failure(PassportTagReaderError.invalidResponse)
        tag.sendCommand(apdu: apdu) { data, sw1, sw2, error in
            if let error {
                reply = .failure(error)
            } else {
                var response = data
                response.append(contentsOf: [sw1, sw2])
                reply = .success(response)
            }
            finished.signal()
        }
        guard finished.wait(timeout: .now() + 10) == .success else {
            throw PassportTagReaderError.timedOut
        }
        return try reply.get()
    }
}
