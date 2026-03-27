#import <Foundation/Foundation.h>

@interface VlessConnectHelper : NSObject

/// Start a local TCP listener on 127.0.0.1, return the port.
/// When a client connects, accept + vless_connect + relay in background.
/// Returns 0 on error.
+ (uint16_t)startProxyWithServerHost:(NSString * _Nonnull)serverHost
                          serverPort:(uint16_t)serverPort
                                uuid:(NSString * _Nonnull)uuid
                           publicKey:(NSString * _Nonnull)publicKey
                             shortId:(NSString * _Nonnull)shortId
                          serverName:(NSString * _Nonnull)serverName
                            destHost:(NSString * _Nonnull)destHost
                            destPort:(uint16_t)destPort;

@end
