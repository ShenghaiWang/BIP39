import Foundation

let byteLength = 8

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

    private func valueOf(from startingBit: Int, length: Int) -> UInt32? {
        let bytes = self[(startingBit / 8) ..< (startingBit + length + 7) / 8]
        let padding = Data(repeating: 0, count: 8 - bytes.count)
        let padded = bytes + padding
        guard let pointee = padded.withUnsafeBytes ({ body in
            body.baseAddress?.assumingMemoryBound(to: UInt32.self).pointee
        }) else { return nil }
        var value = pointee.bigEndian
        value <<= (startingBit % 8)
        value >>= (32 - length)
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

extension BIP39.Length {
    var bitsOfCheckSum: Int {
        rawValue / BIP39.checksumFactor
    }

    var bytes: Int {
        rawValue / byteLength
    }

    var numberOfWords: Int {
        (rawValue + bitsOfCheckSum) / BIP39.keyBitsLength
    }

    static var minWordCount: Int {
        BIP39.Length.allCases.map(\.numberOfWords).min() ?? 0
    }

    static var maxWordCount: Int {
        BIP39.Length.allCases.map(\.numberOfWords).max() ?? 0
    }

    static var possibleWordCounts: [Int] {
        BIP39.Length.allCases.map(\.numberOfWords)
    }
}

extension BIP39.Language {
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
