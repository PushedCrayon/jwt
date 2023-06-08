import Vapor

extension Request.JWT {
    public var apple: Apple {
        .init(_jwt: self)
    }

    public struct Apple {
        public let _jwt: Request.JWT

        public func verify(applicationIdentifier: String? = nil) -> EventLoopFuture<MyAppleIdentityToken> {
            guard let token = self._jwt._request.headers.bearerAuthorization?.token else {
                self._jwt._request.logger.error("Request is missing JWT bearer header.")
                return self._jwt._request.eventLoop.makeFailedFuture(Abort(.unauthorized))
            }
            return self.verify(token, applicationIdentifier: applicationIdentifier)
        }

        public func verify(_ message: String, applicationIdentifier: String? = nil) -> EventLoopFuture<MyAppleIdentityToken> {
            self.verify([UInt8](message.utf8), applicationIdentifier: applicationIdentifier)
        }

        public func verify<Message>(_ message: Message, applicationIdentifier: String? = nil) -> EventLoopFuture<MyAppleIdentityToken>
            where Message: DataProtocol
        {
            self._jwt._request.application.jwt.apple.signers(
                on: self._jwt._request
            ).flatMapThrowing { signers in
                let token = try signers.verify(message, as: MyAppleIdentityToken.self)
                if let applicationIdentifier = applicationIdentifier ?? self._jwt._request.application.jwt.apple.applicationIdentifier {
                    try token.audience.verifyIntendedAudience(includes: applicationIdentifier)
                }
                return token
            }
        }
    }
}

public struct MyAppleIdentityToken: JWTPayload {
    enum CodingKeys: String, CodingKey {
        case nonce, email
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case issuedAt = "iat"
        case expires = "exp"
        case emailVerified = "email_verified"
        case isPrivateEmail = "is_private_email"
        case nonceSupported = "nonce_supported"
        case orgId = "org_id"
    }

    /// The issuer-registered claim key, which has the value https://appleid.apple.com.
    public let issuer: IssuerClaim

    /// Your `client_id` in your Apple Developer account.
    public let audience: AudienceClaim

    /// The expiry time for the token. This value is typically set to 5 minutes.
    public let expires: ExpirationClaim

    /// The time the token was issued.
    public let issuedAt: IssuedAtClaim

    /// The unique identifier for the user.
    public let subject: SubjectClaim

    /// A Boolean value that indicates whether the transaction is on a nonce-supported platform. If you sent a nonce in the authorization
    /// request but do not see the nonce claim in the ID token, check this claim to determine how to proceed. If this claim returns true you
    /// should treat nonce as mandatory and fail the transaction; otherwise, you can proceed treating the nonce as optional.
    public let nonceSupported: BoolClaim?

    /// A string value used to associate a client session and an ID token. This value is used to mitigate replay attacks and is present only
    /// if passed during the authorization request.
    public let nonce: String?

    /// The user's email address.
    public let email: String?
    
    public let orgId: String?

    /// A Boolean value that indicates whether the service has verified the email. The value of this claim is always true because the servers only return verified email addresses.
    public let emailVerified: BoolClaim?
    
    /// A Boolean value that indicates whether the email shared by the user is the proxy address. It is absent (nil) if the user is not using a proxy email address.
    public let isPrivateEmail: BoolClaim?

    public func verify(using signer: JWTSigner) throws {
        guard self.issuer.value == "https://appleid.apple.com" else {
            throw JWTError.claimVerificationFailure(name: "iss", reason: "Token not provided by Apple")
        }

        try self.expires.verifyNotExpired()
    }
}

extension Application.JWT {
    public var apple: Apple {
        .init(_jwt: self)
    }

    public struct Apple {
        public let _jwt: Application.JWT

        public func signers(on request: Request) -> EventLoopFuture<JWTSigners> {
            self.jwks.get(on: request).flatMapThrowing {
                let signers = JWTSigners()
                try signers.use(jwks: $0)
                return signers
            }
        }

        public var jwks: EndpointCache<JWKS> {
            self.storage.jwks
        }

        public var applicationIdentifier: String? {
            get {
                self.storage.applicationIdentifier
            }
            nonmutating set {
                self.storage.applicationIdentifier = newValue
            }
        }

        private struct Key: StorageKey, LockKey {
            typealias Value = Storage
        }

        private final class Storage {
            let jwks: EndpointCache<JWKS>
            var applicationIdentifier: String?
            init() {
                self.jwks = .init(uri: "https://appleid.apple.com/auth/keys")
                self.applicationIdentifier = nil
            }
        }

        private var storage: Storage {
            if let existing = self._jwt._application.storage[Key.self] {
                return existing
            } else {
                let lock = self._jwt._application.locks.lock(for: Key.self)
                lock.lock()
                defer { lock.unlock() }
                if let existing = self._jwt._application.storage[Key.self] {
                    return existing
                }
                let new = Storage()
                self._jwt._application.storage[Key.self] = new
                return new
            }
        }
    }
}
