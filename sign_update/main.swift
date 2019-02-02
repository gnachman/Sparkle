//
//  main.swift
//  sign_update
//
//  Created by Kornel on 16/09/2018.
//  Copyright © 2018 Sparkle Project. All rights reserved.
//

import Foundation
import Security

func findKeys(_ encoded: String) -> (Data, Data) {
    if let keys = Data(base64Encoded: encoded) {
        return (keys[0..<64], keys[64..<(64+32)])
    }
    print("Base64 error")
    exit(1)
}

func edSignature(data: Data, publicEdKey: Data, privateEdKey: Data) -> String {
    assert(publicEdKey.count == 32)
    assert(privateEdKey.count == 64)
    let len = data.count;
    var output = Data(count: 64);
    output.withUnsafeMutableBytes({ (output: UnsafeMutablePointer<UInt8>) in
        data.withUnsafeBytes({ (data: UnsafePointer<UInt8>) in
            publicEdKey.withUnsafeBytes({ (publicEdKey: UnsafePointer<UInt8>) in
                privateEdKey.withUnsafeBytes({ (privateEdKey: UnsafePointer<UInt8>) in
                    ed25519_sign(output, data, len, publicEdKey, privateEdKey)
                });
            });
        })
    });
    return output.base64EncodedString();
}

let args = CommandLine.arguments;
if args.count != 3 {
    print("Usage: \(args[0]) <archive to sign> <key>.\n");
    exit(1)
}

let(priv, pub) = findKeys(args[2]);

do {
    let data = try Data.init(contentsOf: URL.init(fileURLWithPath: args[1]), options: .mappedIfSafe);
    let sig = edSignature(data:data , publicEdKey: pub, privateEdKey: priv);
    print(sig)
} catch {
    print("ERROR: ", error)
}
