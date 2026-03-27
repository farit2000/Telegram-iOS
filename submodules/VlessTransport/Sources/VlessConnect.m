#import <VlessTransport/MTVlessConnection.h>
#import <vless.h>

@implementation VlessConnectHelper

+ (uint16_t)startProxyWithServerHost:(NSString *)serverHost
                          serverPort:(uint16_t)serverPort
                                uuid:(NSString *)uuid
                           publicKey:(NSString *)publicKey
                             shortId:(NSString *)shortId
                          serverName:(NSString *)serverName
                            destHost:(NSString *)destHost
                            destPort:(uint16_t)destPort {
    vless_config_t config;
    vless_config_init(&config);
    config.server_host = serverHost.UTF8String;
    config.server_port = serverPort;
    config.uuid = uuid.UTF8String;
    config.dest_host = destHost.UTF8String;
    config.dest_port = destPort;
    config.reality.public_key = publicKey.UTF8String;
    config.reality.server_name = serverName.UTF8String;
    config.reality.short_id = shortId.UTF8String;
    config.reality.fingerprint = VLESS_CHROME_AUTO;
    config.vision_enabled = 1;
    config.connect_timeout_ms = 5000;
    config.io_timeout_ms = 90000;

    uint16_t port = 0;
    int rc = vless_listen_start(&config, &port);
    return rc == 0 ? port : 0;
}

@end
