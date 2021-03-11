//
//  BoxCurve25519.swift
//  Sodium
//
//  Created by Dmitry Medyuho on 11.03.21.
//  Copyright © 2021 Frank Denis. All rights reserved.
//

import Foundation
import Clibsodium

public struct BoxCurve25519 {
    public let MacBytes = Int(crypto_box_macbytes())
    public let Primitive = String(validatingUTF8:crypto_box_primitive())
    public let BeforenmBytes = Int(crypto_box_beforenmbytes())
    public let SealBytes = Int(crypto_box_sealbytes())

    public typealias MAC = Bytes
    public typealias Beforenm = Bytes
    
    public let ZeroBytes = 32
    public let BoxZeroBytes = 16
}

extension BoxCurve25519 {
    public func open(authenticatedCipherText: Bytes, senderPublicKey: PublicKey, recipientSecretKey: SecretKey, nonce: Nonce) -> Bytes? {
        guard nonce.count == NonceBytes,
              senderPublicKey.count == PublicKeyBytes,
              recipientSecretKey.count == SecretKeyBytes
        else { return nil }
        
        var message = Bytes(count: authenticatedCipherText.count + BoxZeroBytes)
        var cipherText = authenticatedCipherText
        cipherText.insert(contentsOf: Bytes(count: BoxZeroBytes), at: 0)
        
        guard .SUCCESS == crypto_box_curve25519xsalsa20poly1305_open(
            &message,
            cipherText,
            UInt64(message.count),
            nonce,
            senderPublicKey,
            recipientSecretKey
        ).exitCode else { return nil }
        
        message.removeSubrange(..<ZeroBytes)
        
        return message
    }
}

extension BoxCurve25519 {
    public func seal(message: Bytes, recipientPublicKey: PublicKey, senderSecretKey: SecretKey, nonce: Nonce) -> Bytes? {
        guard recipientPublicKey.count == PublicKeyBytes,
            senderSecretKey.count == SecretKeyBytes,
            nonce.count == NonceBytes
        else { return nil }
        
        var authenticatedCipherText = Bytes(count: message.count + ZeroBytes)
        var cipherText = message
        cipherText.insert(contentsOf: Bytes(count: ZeroBytes), at: 0)

        guard .SUCCESS == crypto_box_curve25519xsalsa20poly1305(
            &authenticatedCipherText,
            cipherText,
            CUnsignedLongLong(cipherText.count),
            nonce,
            recipientPublicKey,
            senderSecretKey
        ).exitCode else { return nil }
        
        authenticatedCipherText.removeSubrange(..<BoxZeroBytes)

        return authenticatedCipherText
    }
}

extension BoxCurve25519: KeyPairGenerator {
    public typealias PublicKey = Bytes
    public typealias SecretKey = Bytes

    public var SeedBytes: Int { return Int(crypto_box_seedbytes()) }
    public var PublicKeyBytes: Int { return Int(crypto_box_publickeybytes()) }
    public var SecretKeyBytes: Int { return Int(crypto_box_secretkeybytes()) }

    public static let newKeypair: (
        _ pk: UnsafeMutablePointer<UInt8>,
        _ sk: UnsafeMutablePointer<UInt8>
    ) -> Int32 = crypto_box_curve25519xsalsa20poly1305_keypair

    public static let keypairFromSeed: (
        _ pk: UnsafeMutablePointer<UInt8>,
        _ sk: UnsafeMutablePointer<UInt8>,
        _ seed: UnsafePointer<UInt8>
    ) -> Int32 = crypto_box_curve25519xsalsa20poly1305_seed_keypair
    
    public struct KeyPair: KeyPairProtocol {
        public typealias PublicKey = BoxCurve25519.PublicKey
        public typealias SecretKey = BoxCurve25519.SecretKey
        public let publicKey: PublicKey
        public let secretKey: SecretKey
        
        public init(publicKey: PublicKey, secretKey: SecretKey) {
            self.publicKey = publicKey
            self.secretKey = secretKey
        }
    }
}

extension BoxCurve25519: NonceGenerator {
    public typealias Nonce = Bytes

    public var NonceBytes: Int { return Int(crypto_box_noncebytes()) }
}
