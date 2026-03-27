objc_library(
    name = "VlessTransport",
    enable_modules = True,
    module_name = "VlessTransport",
    srcs = glob([
        "Sources/**/*.m",
    ]),
    hdrs = glob([
        "PublicHeaders/**/*.h",
    ]),
    includes = [
        "PublicHeaders",
    ],
    deps = [
        "//submodules/MtProtoKit:MtProtoKit",
        "//third-party/vless:vless",
    ],
    sdk_frameworks = [
        "Foundation",
    ],
    visibility = [
        "//visibility:public",
    ],
)
