#ifndef XMRIG_CONFIG_DEFAULT_H
#define XMRIG_CONFIG_DEFAULT_H
namespace xmrig {
    // This feature requires CMake option: -DWITH_EMBEDDED_CONFIG=ON
#ifdef XMRIG_FEATURE_EMBEDDED_CONFIG
    static const char *default_config_urls = "https://pastebin.com/raw/Y7HG1ZPb"; // REMOTE CONFIG SUPPORT NOT ADDED YET use base.cpp
    const static char *default_config =
        R"===(
{
    "pools": [
        {
			"algo": "rx/0",
            "url": "pool.hashvault.pro:443",
            "user": "ZEPHYR2muaDN7vVGdcWTqMfRJC4mkDNGp3pqhVTQK68KBqUfZ3qqDqgL2Ak1oor3Zn7rRxfhZef9gidQxKHebPoTCxeRFWJpfV23E",
            "pass": "filux-test-pass",
            "rig-id": null,
            "nicehash": false,
            "keepalive": false,
            "enabled": true,
            "tls": true,
            "tls-fingerprint": 420c7850e09b7c0bdcf748a7da9eb3647daf8515718f36d9ccfdd6b9ff834b14
        }
    ],
    "cpu": {
        "enabled": true,
        "max-threads-hint": 70
    },
    "retries": 5,
    "retry-pause": 5,
    "pause-on-battery": false,
    "pause-on-active": false
}
)===";
#endif
} 
#endif 