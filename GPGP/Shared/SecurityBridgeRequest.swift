import Foundation

/// Owns one XPC request and completes it exactly once, including timeout or disconnect.
nonisolated final class SecurityBridgeRequest<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: ((Result<Value, Error>) -> Void)?
    private var connection: NSXPCConnection?
    private var timeout: DispatchWorkItem?
    private let seconds: TimeInterval
    private let serviceName: String

    init(seconds: TimeInterval, serviceName: String = "com.JimKelley.GPGP.bridge", completion: @escaping (Result<Value, Error>) -> Void) {
        self.seconds = seconds
        self.serviceName = serviceName
        self.completion = completion
    }

    static func error(_ message: String) -> NSError {
        NSError(domain: "com.JimKelley.GPGP.Mail", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    func start(_ operation: (GPGPBridgeProtocol, @escaping (Result<Value, Error>) -> Void) -> Void) {
        let connection = NSXPCConnection(machServiceName: serviceName)
        self.connection = connection
        connection.setCodeSigningRequirement("anchor apple generic and certificate leaf[subject.OU] = \"MV65BFBFT7\" and identifier \"GPGPBridge\"")
        connection.remoteObjectInterface = NSXPCInterface(with: GPGPBridgeProtocol.self)
        connection.invalidationHandler = { self.finish(.failure(Self.error("GPGP helper connection invalidated. Check helper status in GPGP."))) }
        connection.interruptionHandler = { self.finish(.failure(Self.error("GPGP helper connection interrupted."))) }
        let timeout = DispatchWorkItem { self.finish(.failure(Self.error("GPGP helper request timed out."))) }
        self.timeout = timeout
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds, execute: timeout)
        connection.resume()
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in self.finish(.failure(Self.error("GPGP’s background helper is unavailable. Open GPGP → Connection, enable or restart the helper, then try again."))) }) as? GPGPBridgeProtocol else {
            finish(.failure(Self.error("Unable to create GPGP helper interface.")))
            return
        }
        operation(proxy) { self.finish($0) }
    }

    private func finish(_ result: Result<Value, Error>) {
        lock.lock()
        guard let callback = completion else { lock.unlock(); return }
        completion = nil
        let connection = self.connection
        self.connection = nil
        let timeout = self.timeout
        self.timeout = nil
        lock.unlock()
        timeout?.cancel()
        connection?.invalidate()
        callback(result)
    }
}
