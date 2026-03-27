import Foundation
import Postbox
import SwiftSignalKit
import MtProtoKit

public func updateProxySettingsInteractively(accountManager: AccountManager<TelegramAccountManagerTypes>, _ f: @escaping (ProxySettings) -> ProxySettings) -> Signal<Bool, NoError> {
    return accountManager.transaction { transaction -> Bool in
        return updateProxySettingsInteractively(transaction: transaction, f)
    }
}

extension ProxyServerSettings {
    var mtProxySettings: MTSocksProxySettings? {
        switch self.connection {
            case let .socks5(username, password):
                return MTSocksProxySettings(ip: self.host, port: UInt16(clamping: self.port), username: username, password: password, secret: nil)
            case let .mtp(secret):
                return MTSocksProxySettings(ip: self.host, port: UInt16(clamping: self.port), username: nil, password: nil, secret: secret)
            case .vless:
                return nil
        }
    }

    func mtVlessProxySettings(connectFd: ((String, UInt16, String, String, String, String, String, UInt16) -> Int32)?) -> MTVlessProxySettings? {
        switch self.connection {
            case let .vless(uuid, publicKey, shortId, serverName):
                let host = self.host
                let port = UInt16(clamping: self.port)
                if let connectFd = connectFd {
                    return MTVlessProxySettings(ip: host, port: port, uuid: uuid, publicKey: publicKey, shortId: shortId, serverName: serverName) { destHost, destPort in
                        return connectFd(host, port, uuid, publicKey, shortId, serverName, destHost, destPort)
                    }
                } else {
                    return MTVlessProxySettings(ip: host, port: port, uuid: uuid, publicKey: publicKey, shortId: shortId, serverName: serverName, connectFd: nil)
                }
            default:
                return nil
        }
    }

    var mtVlessProxySettings: MTVlessProxySettings? {
        return mtVlessProxySettings(connectFd: nil)
    }
}

public func updateProxySettingsInteractively(transaction: AccountManagerModifier<TelegramAccountManagerTypes>, _ f: @escaping (ProxySettings) -> ProxySettings) -> Bool {
    var hasChanges = false
    transaction.updateSharedData(SharedDataKeys.proxySettings, { current in
        let previous = current?.get(ProxySettings.self) ?? ProxySettings.defaultSettings
        let updated = f(previous)
        hasChanges = previous != updated
        return PreferencesEntry(updated)
    })
    return hasChanges
}
