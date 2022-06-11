import CryptoSwift
import Foundation

public struct BIP39 {
    static let keyBitsLength = 11
    static let checksumFactor = 32
    static let PBKDF2Iterations = 2048
    static let PBKDF2KeyLength = 64

    public enum BIP39Error: Error {
        case invalidEntrophyData
        case invalidEntrophyLength
        case invalidMnemonics
    }

    public enum Length: Int, CaseIterable {
        case of128 = 128
        case of160 = 160
        case of192 = 192
        case of224 = 224
        case of256 = 256
    }

    public enum Language {
        case english
        case japanese
        case korean
        case spanish
        case chineseSimplified
        case chineseTraditional
        case french
        case italian
        case czech
        case portuguese
    }

    static public func mnemonics(of length: Length = .of128, in language: Language = .english) throws -> [String]  {
        var entropy = Data(count: length.bytes)
        let randomResult = SecRandomCopyBytes(kSecRandomDefault, entropy.count, &entropy)
        guard randomResult == errSecSuccess else { throw BIP39Error.invalidEntrophyData }
        return try mnemonics(from: entropy)
    }

    static public func mnemonics(from entropy: Data, in language: Language = Language.english) throws -> [String]  {
        guard let length = Length(rawValue: entropy.count * byteLength) else { throw BIP39Error.invalidEntrophyData }
        let checksum = entropy.sha256()
        let wordListLength = (length.rawValue + (length.rawValue / checksumFactor)) / keyBitsLength
        return (entropy + checksum)
            .value(byBits: keyBitsLength)
            .prefix(wordListLength)
            .map { language.words[Int($0)] }
    }

    static public func entropy(from mnemonics: [String], in language: Language = .english) throws -> Data {
        guard mnemonics.count >= Length.minWordCount
                && mnemonics.count <= Length.maxWordCount
                && Length.possibleWordCounts.contains(mnemonics.count) else {
            throw BIP39Error.invalidEntrophyLength
        }

        let bits = mnemonics
            .compactMap { language.words.firstIndex(of: $0) }
            .map { (repeatElement("0", count: keyBitsLength) + String(UInt16($0), radix: 2)).suffix(keyBitsLength) }
            .joined()

        guard bits.count.isMultiple(of: checksumFactor + 1) else { throw BIP39Error.invalidEntrophyLength }
        let checksumBits = bits.suffix(bits.count / (checksumFactor + 1))
        guard let entropy = bits.prefix(bits.count - checksumBits.count).BIP39Entrophy,
              var checksum = entropy.sha256().first else {
            throw BIP39Error.invalidMnemonics
        }
        checksum >>= (byteLength - checksumBits.count)
        guard checksum == UInt8(checksumBits, radix: 2) else {
            throw BIP39Error.invalidMnemonics
        }
        return entropy
    }

    static public func seed(from mnemonics: [String], passphrase: String = "", in language: Language = .english) throws -> Data {
        guard let data = mnemonics.joined(separator: " ").decomposedStringWithCompatibilityMapping.data(using: .utf8),
              let salt = ("mnemonic" + passphrase).decomposedStringWithCompatibilityMapping.data(using: .utf8) else {
            throw BIP39Error.invalidMnemonics
        }
        let seed = try PKCS5.PBKDF2(password: data.bytes,
                                    salt: salt.bytes,
                                    iterations: Self.PBKDF2Iterations,
                                    keyLength: Self.PBKDF2KeyLength,
                                    variant: HMAC.Variant.sha2(.sha512)).calculate()
        return Data(seed)
    }

    static public func seed(from entropy: Data, passphrase: String = "", in language: Language = .english) throws -> Data {
        let mnemonics = try BIP39.mnemonics(from: entropy, in: language)
        return try BIP39.seed(from: mnemonics, passphrase: passphrase, in: language)
    }
}
