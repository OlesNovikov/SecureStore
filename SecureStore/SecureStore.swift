/// Copyright (c) 2018 Razeware LLC
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// Notwithstanding the foregoing, you may not use, copy, modify, merge, publish,
/// distribute, sublicense, create a derivative work, and/or sell copies of the
/// Software in any work that is designed, intended, or marketed for pedagogical or
/// instructional purposes related to programming, coding, application development,
/// or information technology.  Permission for such use, copying, modification,
/// merger, publication, distribution, sublicensing, creation of derivative works,
/// or sale is expressly withheld.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
/// THE SOFTWARE.

import Foundation
import Security

public struct SecureStore {
  let secureStoreQueryable: SecureStoreQueryable
  
  public init(secureStoreQueryable: SecureStoreQueryable) {
    self.secureStoreQueryable = secureStoreQueryable
  }
  
  public func setValue(_ value: String, for userAccount: String) throws {
    // 1. Check if it can encode the value to store into a Data type. If that’s not possible, it throws a conversion error.
    guard let encodedPassword = value.data(using: .utf8) else {
      throw SecureStoreError.string2DataConversionError
    }
    
    // 2. Ask the secureStoreQueryable instance for the query to execute and append the account you’re looking for.
    var query = secureStoreQueryable.query
    query[String(kSecAttrAccount)] = userAccount
    
    // 3. Return the keychain item that matches the query.
    var status = SecItemCopyMatching(query as CFDictionary, nil)
    switch status {
      
    // 4. If the query succeeds, it means a password for that account already exists. In this case, you replace the existing password’s value using SecItemUpdate(_:_:)
    case errSecSuccess:
      var attributesToUpdate: [String: Any] = [:]
      attributesToUpdate[String(kSecValueData)] = encodedPassword
      status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
      if status != errSecSuccess {
        throw error(from: status)
      }
      
    // 5. If it cannot find an item, the password for that account does not exist yet. You add the item by invoking SecItemAdd(_:_:)
    case errSecItemNotFound:
      query[String(kSecValueData)] = encodedPassword
      status = SecItemAdd(query as CFDictionary, nil)
      if status != errSecSuccess {
        throw error(from: status)
      }
    default:
      throw error(from: status)
    }
    
  }
  
  public func getValue(for userAccount: String) throws -> String? {
    // 1. Ask secureStoreQueryable for the query to execute
    var query = secureStoreQueryable.query
    query[String(kSecMatchLimit)] = kSecMatchLimitOne         // Ask to return single value
    query[String(kSecReturnAttributes)] = kCFBooleanTrue      // Ask to return with attributes
    query[String(kSecReturnData)] = kCFBooleanTrue            // Ask to return unencrypted data
    query[String(kSecAttrAccount)] = userAccount

    // 2. Perform the search. queryResult will contain a reference to the found item, if available
    var queryResult: AnyObject?
    let status = withUnsafeMutablePointer(to: &queryResult) {
      SecItemCopyMatching(query as CFDictionary, $0)
    }

    switch status {
    // 3. Item was found
    case errSecSuccess:
      guard
        let queriedItem = queryResult as? [String: Any],
        let passwordData = queriedItem[String(kSecValueData)] as? Data,
        let password = String(data: passwordData, encoding: .utf8)
        else {
          throw SecureStoreError.data2StringConversionError
      }
      return password
    // 4. Item wasn't found
    case errSecItemNotFound:
      return nil
    default:
      throw error(from: status)
    }

  }
  
  // remove value for specific key
  public func removeValue(for userAccount: String) throws {
    var query = secureStoreQueryable.query
    query[String(kSecAttrAccount)] = userAccount
    
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw error(from: status)
    }
  }
  
  // remove all values connected with a specific service
  public func removeAllValues() throws {
    let query = secureStoreQueryable.query
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw error(from: status)
    }
    
  }
  
  private func error(from status: OSStatus) -> SecureStoreError {
    let message = SecCopyErrorMessageString(status, nil) as String? ?? NSLocalizedString("Unhandled Error", comment: "")
    return SecureStoreError.unhandledError(message: message)
  }
}
