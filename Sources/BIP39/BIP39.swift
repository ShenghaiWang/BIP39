import CryptoKit
import Foundation

public struct BIP39 {
    static let keyBitsLength = 11
    enum BIP39Error: Error {
        case entrophyDataError
    }

    public enum Length: Int {
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

        var words: [String] {
            switch self {
            case .english:
                return WordList.english
            case .japanese:
                return WordList.japanese
            case .korean:
                return WordList.korean
            case .spanish:
                return WordList.spanish
            case .chineseSimplified:
                return WordList.chineseSimplified
            case .chineseTraditional:
                return WordList.chineseTraditional
            case .french:
                return WordList.french
            case .italian:
                return WordList.italian
            case .czech:
                return WordList.czech
            case .portuguese:
                return WordList.portuguese
            }
        }
    }

    public static func mnemonics(length: Length = .of128, language: Language = Language.english) throws -> [String]  {
        var entropy = Data(count: length.rawValue / 8)
        let randomResult = SecRandomCopyBytes(kSecRandomDefault, entropy.count, &entropy)
        guard randomResult == errSecSuccess else { throw BIP39Error.entrophyDataError }
        return try mnemonics(entropy: entropy)
    }

    static func mnemonics(entropy: Data, language: Language = Language.english) throws -> [String]  {
        guard let length = Length(rawValue: entropy.count * 8) else { throw BIP39Error.entrophyDataError }
        let checksum = SHA256.hash(data: entropy)
        let wordListLength = (length.rawValue + (length.rawValue / 32)) / keyBitsLength
        return (entropy + checksum.prefix(1))
            .value(byBits: keyBitsLength)
            .prefix(wordListLength)
            .map { language.words[Int($0)] }
    }
}

extension Data {
    /// Calculate values based on the specified bit length bwteen 1...15, or returns empty array
    /// Eg. value of `0001 0011` by `4` will have `[1, 3]`
    func value(byBits bitLength: Int) -> [Int] {
        guard bitLength <= 15, bitLength > 0 else { return [] }
        var result: [Int] = []
        for i in (0..<count * 8 / bitLength) {
            guard let index = valueOf(from: i * bitLength, length: bitLength) else { return [] }
            result.append(Int(index))
        }
        return result
    }

    private func valueOf(from startingBit: Int, length: Int) -> UInt64? {
        let bytes = self[(startingBit / 8) ..< (startingBit+length + 7) / 8]
        let padding = Data(repeating: 0, count: 8 - bytes.count)
        let padded = bytes + padding
        guard let pointee = padded.withUnsafeBytes ({ body in
            body.baseAddress?.assumingMemoryBound(to: UInt64.self).pointee
        }) else { return nil }
        var value = pointee.bigEndian
        value <<= (startingBit % 8)
        value >>= (64 - length)
        return value
    }
}
