cc_library(
    name = "vless",
    srcs = [
        "vless-lib/src/vless.c",
        "vless-lib/src/vless_reality.c",
        "vless-lib/src/vless_pool.c",
    ],
    hdrs = ["vless-lib/include/vless.h"],
    textual_hdrs = ["vless-lib/src/vless_internal.h"],
    copts = [
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Wno-unused-parameter",
        "-fstack-protector-strong",
        "-fvisibility=hidden",
    ],
    includes = ["vless-lib/include", "vless-lib/src"],
    visibility = ["//visibility:public"],
    deps = [
        "//third-party/boringssl:ssl",
        "//third-party/boringssl:crypto",
    ],
)
