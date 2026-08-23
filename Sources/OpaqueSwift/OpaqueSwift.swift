import Foundation
import COpaque

public enum OpaqueError: Error, Equatable {
    case invalidArgument
    case protocolFailure
    case internalFailure
    case serverIdentityMismatch
    case sessionAlreadyFinished
    case unknown(Int32)
}

extension OpaqueError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidArgument:
            return "OPAQUE received an invalid argument."
        case .protocolFailure:
            return "The OPAQUE protocol step failed."
        case .internalFailure:
            return "The OPAQUE core failed internally."
        case .serverIdentityMismatch:
            return "The server public key does not match the key saved at registration."
        case .sessionAlreadyFinished:
            return "This OPAQUE session is already finished."
        case .unknown(let code):
            return "OPAQUE failed with status code \(code)."
        }
    }
}

public struct OpaqueRegistrationResult: Equatable {
    public let upload: Data
    public let exportKey: Data
    public let serverPublicKey: Data
}

public struct OpaqueLoginResult: Equatable {
    public let finalization: Data
    public let sessionKey: Data
    public let exportKey: Data
    public let serverPublicKey: Data
}

public enum OpaqueClient {
    public static var ffiVersion: UInt32 {
        opaque_swift_ffi_version()
    }

    public static func startRegistration(password: Data) throws -> OpaqueRegistrationSession {
        var requestBuffer = opaque_buffer_t(ptr: nil, len: 0)
        var stateBuffer = opaque_buffer_t(ptr: nil, len: 0)

        let status: Int32 = password.withUnsafeBytes { passwordBytes in
            opaque_client_registration_start(
                passwordBytes.bindMemory(to: UInt8.self).baseAddress,
                passwordBytes.count,
                &requestBuffer,
                &stateBuffer
            )
        }

        guard status == 0 else {
            freeBuffer(&requestBuffer)
            freeBuffer(&stateBuffer)
            throw error(for: status)
        }

        let request = takeData(&requestBuffer)
        let state = takeData(&stateBuffer)
        return OpaqueRegistrationSession(request: request, password: password, state: state)
    }

    public static func startRegistration(password: String) throws -> OpaqueRegistrationSession {
        try startRegistration(password: Data(password.utf8))
    }

    public static func startLogin(password: Data) throws -> OpaqueLoginSession {
        var requestBuffer = opaque_buffer_t(ptr: nil, len: 0)
        var stateBuffer = opaque_buffer_t(ptr: nil, len: 0)

        let status: Int32 = password.withUnsafeBytes { passwordBytes in
            opaque_client_login_start(
                passwordBytes.bindMemory(to: UInt8.self).baseAddress,
                passwordBytes.count,
                &requestBuffer,
                &stateBuffer
            )
        }

        guard status == 0 else {
            freeBuffer(&requestBuffer)
            freeBuffer(&stateBuffer)
            throw error(for: status)
        }

        let request = takeData(&requestBuffer)
        let state = takeData(&stateBuffer)
        return OpaqueLoginSession(request: request, password: password, state: state)
    }

    public static func startLogin(password: String) throws -> OpaqueLoginSession {
        try startLogin(password: Data(password.utf8))
    }

    fileprivate static func error(for status: Int32) -> OpaqueError {
        switch status {
        case 1: return .invalidArgument
        case 2: return .protocolFailure
        case 3: return .internalFailure
        default: return .unknown(status)
        }
    }
}

public final class OpaqueRegistrationSession {
    public let request: Data

    private var password: Data
    private var state: Data
    private var finished = false

    fileprivate init(request: Data, password: Data, state: Data) {
        self.request = request
        self.password = password
        self.state = state
    }

    deinit {
        wipeSecrets()
    }

    public func finish(response: Data) throws -> OpaqueRegistrationResult {
        guard !finished else {
            throw OpaqueError.sessionAlreadyFinished
        }
        finished = true
        defer { wipeSecrets() }

        var uploadBuffer = opaque_buffer_t(ptr: nil, len: 0)
        var exportKeyBuffer = opaque_buffer_t(ptr: nil, len: 0)
        var serverPublicKeyBuffer = opaque_buffer_t(ptr: nil, len: 0)

        let status: Int32 = password.withUnsafeBytes { passwordBytes in
            state.withUnsafeBytes { stateBytes in
                response.withUnsafeBytes { responseBytes in
                    opaque_client_registration_finish(
                        passwordBytes.bindMemory(to: UInt8.self).baseAddress,
                        passwordBytes.count,
                        stateBytes.bindMemory(to: UInt8.self).baseAddress,
                        stateBytes.count,
                        responseBytes.bindMemory(to: UInt8.self).baseAddress,
                        responseBytes.count,
                        &uploadBuffer,
                        &exportKeyBuffer,
                        &serverPublicKeyBuffer
                    )
                }
            }
        }

        guard status == 0 else {
            freeBuffer(&uploadBuffer)
            freeBuffer(&exportKeyBuffer)
            freeBuffer(&serverPublicKeyBuffer)
            throw OpaqueClient.error(for: status)
        }

        return OpaqueRegistrationResult(
            upload: takeData(&uploadBuffer),
            exportKey: takeData(&exportKeyBuffer),
            serverPublicKey: takeData(&serverPublicKeyBuffer)
        )
    }

    private func wipeSecrets() {
        if !password.isEmpty {
            password.resetBytes(in: 0..<password.count)
        }
        if !state.isEmpty {
            state.resetBytes(in: 0..<state.count)
        }
        password.removeAll(keepingCapacity: false)
        state.removeAll(keepingCapacity: false)
    }
}

public final class OpaqueLoginSession {
    public let request: Data

    private var password: Data
    private var state: Data
    private var finished = false

    fileprivate init(request: Data, password: Data, state: Data) {
        self.request = request
        self.password = password
        self.state = state
    }

    deinit {
        wipeSecrets()
    }

    public func finish(
        response: Data,
        expectedServerPublicKey: Data
    ) throws -> OpaqueLoginResult {
        guard !finished else {
            throw OpaqueError.sessionAlreadyFinished
        }
        finished = true
        defer { wipeSecrets() }

        var finalizationBuffer = opaque_buffer_t(ptr: nil, len: 0)
        var sessionKeyBuffer = opaque_buffer_t(ptr: nil, len: 0)
        var exportKeyBuffer = opaque_buffer_t(ptr: nil, len: 0)
        var serverPublicKeyBuffer = opaque_buffer_t(ptr: nil, len: 0)

        let status: Int32 = password.withUnsafeBytes { passwordBytes in
            state.withUnsafeBytes { stateBytes in
                response.withUnsafeBytes { responseBytes in
                    opaque_client_login_finish(
                        passwordBytes.bindMemory(to: UInt8.self).baseAddress,
                        passwordBytes.count,
                        stateBytes.bindMemory(to: UInt8.self).baseAddress,
                        stateBytes.count,
                        responseBytes.bindMemory(to: UInt8.self).baseAddress,
                        responseBytes.count,
                        &finalizationBuffer,
                        &sessionKeyBuffer,
                        &exportKeyBuffer,
                        &serverPublicKeyBuffer
                    )
                }
            }
        }

        guard status == 0 else {
            freeBuffer(&finalizationBuffer)
            freeBuffer(&sessionKeyBuffer)
            freeBuffer(&exportKeyBuffer)
            freeBuffer(&serverPublicKeyBuffer)
            throw OpaqueClient.error(for: status)
        }

        let finalization = takeData(&finalizationBuffer)
        let sessionKey = takeData(&sessionKeyBuffer)
        let exportKey = takeData(&exportKeyBuffer)
        let serverPublicKey = takeData(&serverPublicKeyBuffer)

        guard serverPublicKey == expectedServerPublicKey else {
            throw OpaqueError.serverIdentityMismatch
        }

        return OpaqueLoginResult(
            finalization: finalization,
            sessionKey: sessionKey,
            exportKey: exportKey,
            serverPublicKey: serverPublicKey
        )
    }

    private func wipeSecrets() {
        if !password.isEmpty {
            password.resetBytes(in: 0..<password.count)
        }
        if !state.isEmpty {
            state.resetBytes(in: 0..<state.count)
        }
        password.removeAll(keepingCapacity: false)
        state.removeAll(keepingCapacity: false)
    }
}

private func takeData(_ buffer: inout opaque_buffer_t) -> Data {
    defer {
        opaque_buffer_free(buffer)
        buffer = opaque_buffer_t(ptr: nil, len: 0)
    }

    guard let pointer = buffer.ptr, buffer.len > 0 else {
        return Data()
    }
    return Data(bytes: pointer, count: buffer.len)
}

private func freeBuffer(_ buffer: inout opaque_buffer_t) {
    opaque_buffer_free(buffer)
    buffer = opaque_buffer_t(ptr: nil, len: 0)
}
