import CryptoKit
import Foundation

let byteLength = 8
public struct BIP39 {
    static let keyBitsLength = 11
    static let checksumFactor = 32

    enum BIP39Error: Error {
        case entrophyDataError
        case invalidEntrophyLength
        case invalidMnemonics
    }

    public enum Length: Int, CaseIterable {
        case of128 = 128
        case of160 = 160
        case of192 = 192
        case of224 = 224
        case of256 = 256

        var bitsOfCheckSum: Int {
            rawValue / BIP39.checksumFactor
        }

        var bytes: Int {
            rawValue / byteLength
        }

        var numberOfWords: Int {
            (rawValue + bitsOfCheckSum) / keyBitsLength
        }

        static var minWordCount: Int {
            Length.allCases.map(\.numberOfWords).min() ?? 0
        }

        static var maxWordCount: Int {
            Length.allCases.map(\.numberOfWords).max() ?? 0
        }

        static var possibleWordCounts: [Int] {
            Length.allCases.map(\.numberOfWords)
        }
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

    static public func mnemonics(length: Length = .of128, language: Language = Language.english) throws -> [String]  {
        var entropy = Data(count: length.bytes)
        let randomResult = SecRandomCopyBytes(kSecRandomDefault, entropy.count, &entropy)
        guard randomResult == errSecSuccess else { throw BIP39Error.entrophyDataError }
        return try mnemonics(entropy: entropy)
    }

    static func mnemonics(entropy: Data, language: Language = Language.english) throws -> [String]  {
        guard let length = Length(rawValue: entropy.count * byteLength) else { throw BIP39Error.entrophyDataError }
        let checksum = SHA256.hash(data: entropy)
        let wordListLength = (length.rawValue + (length.rawValue / checksumFactor)) / keyBitsLength
        return (entropy + checksum)
            .value(byBits: keyBitsLength)
            .prefix(wordListLength)
            .map { language.words[Int($0)] }
    }

    static public func entropy(of mnemonics: [String], language: Language = Language.english) throws -> Data {
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
              var checksum = SHA256.hash(data: entropy).makeIterator().first (where: { _ in true }) else {
            throw BIP39Error.invalidMnemonics
        }
        checksum >>= (byteLength - checksumBits.count)
        guard checksum == UInt8(checksumBits, radix: 2) else { throw
            BIP39Error.invalidMnemonics
        }
        return entropy
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

extension StringProtocol {
    var BIP39Entrophy: Data? {
        Data(chunked(by: byteLength).compactMap { UInt8(String($0), radix: 2) })
    }
}


extension Collection {
    func chunked(by distance: Int) -> [[Element]] {
        precondition(distance > 0, "distance must be greater than 0")
        var index = startIndex
        let iterator: AnyIterator<Array<Element>> = AnyIterator({
            let newIndex = self.index(index, offsetBy: distance, limitedBy: endIndex) ?? self.endIndex
            defer { index = newIndex }
            let range = index ..< newIndex
            return index != self.endIndex ? Array(self[range]) : nil
        })
        return Array(iterator)
    }
}
