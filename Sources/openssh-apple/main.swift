import Foundation
import FMake

OutputLevel.default = .error

enum Config {
  static let opensshOrigin = "https://github.com/openssh/openssh-portable.git"
  static let opensshBranch = "V_8_6"
  static let opensshVersion = "8.6.0"
  
  static let opensslLibsURL       = "https://github.com/blinksh/openssl-apple/releases/download/v1.1.1k/openssl-libs.zip"
  static let opensslFrameworksURL = "https://github.com/blinksh/openssl-apple/releases/download/v1.1.1k/openssl-dynamic.frameworks.zip"
  
  static let frameworkName = "OpenSSH"
  
  static let platforms: [Platform] = Platform.allCases
  // static let platforms: [Platform] = [.iPhoneOS]
  // static let platforms: [Platform] = [Platform.Catalyst]
}

extension Platform {
  var deploymentTarget: String {
    switch self {
    case .AppleTVOS, .AppleTVSimulator,
         .iPhoneOS, .iPhoneSimulator: return "14.0"
    case .MacOSX, .Catalyst: return "11.0"
    case .WatchOS, .WatchSimulator: return "7.0"
    }
  }
}

try? sh("rm -rf openssh-portable")
try sh("git clone --depth 1 \(Config.opensshOrigin) --branch \(Config.opensshBranch)")
try sh("LC_CTYPE=C find ./openssh-portable -type f -exec sed -i '' -e 's/__progname/blink__progname/' {} \\;")
try sh("cp -f readpass.c sshkey.h authfd.h log.c ssh-sk-helper.c misc.c openssh-portable/")
try sh("LC_CTYPE=C find ./openssh-portable -type f -exec sed -i '' -e 's/ssh_init(/openssh_init(/' {} \\;")
try sh("LC_CTYPE=C find ./openssh-portable -type f -exec sed -i '' -e 's/ssh_free(/openssh_free(/' {} \\;")

try download(url: Config.opensslLibsURL)
try? sh("rm -rf openssl")
try? sh("mkdir -p openssl")
try sh("unzip openssl-libs.zip -d openssl")


try download(url: Config.opensslFrameworksURL)
try? sh("rm -rf openssl-frameworks")
try? sh("mkdir -p openssl-frameworks")
try sh("unzip openssl-dynamic.frameworks.zip -d openssl-frameworks")

let fm = FileManager.default
let cwd = fm.currentDirectoryPath
let opensslLibsRoot = "\(cwd)/openssl/libs/"

var dynamicFrameworkPaths: [String] = []
var staticFrameworkPaths: [String] = []

var headers = [
  "authfd.h",
  "authfile.h",
  "digest.h",
  "match.h",
  "ssh-sk.h",
  "ssh.h",
  "ssh2.h",
  "sshbuf.h",
  "ssherr.h",
  "sshkey.h",
  /* "ssh-pkcs11.h", */
  ]

for p in Config.platforms {
  let ldflags = "-fembed-bitcode"
  let cflags = "-fembed-bitcode"
  let cppflags = "-fembed-bitcode"

  var env = try [
    "PATH": ProcessInfo.processInfo.environment["PATH"] ?? "",
    "APPLE_PLATFORM": p.sdk,
    "APPLE_SDK_PATH": p.sdkPath(),
    "LDFLAGS": ldflags,
    "CFLAGS": cflags,
    "CPPFLAGS": cppflags
  ]

  let sslDir = "\(opensslLibsRoot + p.name)/openssl"

  let frameworkDynamicPath = "frameworks/dynamic/\(p.name)/\(Config.frameworkName).framework"
  let frameworkStaticPath = "frameworks/static/\(p.name)/\(Config.frameworkName).framework"
  dynamicFrameworkPaths.append(frameworkDynamicPath)
  staticFrameworkPaths.append(frameworkStaticPath)

  let targets = ["clean", "libssh.a", "openbsd-compat/libopenbsd-compat.a", "ssh-sk-helper"].joined(separator: " ")
  
  for arch in p.archs {
    print(p, arch)
    env["LDFLAGS"] = "\(ldflags) \(p.ccTarget(arch: arch)) -arch \(arch) \(p.ccMinVersionFlag(p.deploymentTarget))"
    env["CFLAGS"]  = "\( cflags) \(p.ccTarget(arch: arch)) -arch \(arch) \(p.ccMinVersionFlag(p.deploymentTarget))"
    // env["CC"] = "xcrun -sdk \(p.sdk) clang -arch \(arch) -mios-version-min=14.0"
    env["CC"] = "xcrun -sdk \(p.sdk) clang -arch \(arch)"
    // env["CPP"] = "xcrun -sdk \(p.sdk) cpp"

    try cd("openssh-portable") {
      try sh("autoreconf")
      try sh(
        "./configure",
        "--with-ssl-dir=\(sslDir)",
        "--prefix=/usr/bin/openssh",
        "--host=armv64-apple-darwin",
        env: env
      )
      try sh("make \(targets)")
    }

    let libPath = "lib/\(p.name)-\(arch).sdk"
    let binPath = "bin/\(p.name)-\(arch).sdk"
    
    try? sh("rm -rf \(binPath)")
    
    try? sh("rm -rf \(libPath)")
    try? mkdir(libPath)

    try? mkdir("\(binPath)/tmp")
    
    // 1. makeing dylib
    
    try? mkdir("\(binPath)/obj")
    try cd("\(binPath)/obj") {
      try sh("ar -x \(cwd)/openssh-portable/libssh.a")
      try sh("ar -x \(cwd)/openssh-portable/openbsd-compat/libopenbsd-compat.a")
    }

    try sh("cp openssh-portable/ssh-sk.o \(binPath)/obj")

    try sh("echo",
      "libtool",
      "-dynamic",
      "-o \(binPath)/\(Config.frameworkName)",
      "-install_name @rpath/\(Config.frameworkName).framework/\(Config.frameworkName)",
      "-compatibility_version 1.0.0",
      "-current_version 1.0.0",
      "-lSystem",
      "-lz",
      "-lresolv",
      "-Fopenssl-frameworks/\(p.name)",
      "-framework Foundation",
      "-framework openssl",
      //"-arch \(arch)",
      "-\(p.plistMinSDKVersionName) \(p.deploymentTarget)",
      "-syslibroot \(p.sdkPath())",
      "-application_extension",
      "\(binPath)/obj/*.o"
    )
    // dynamic framework
    try sh(
      "ld",
      "\(binPath)/obj/*.o",
      "-dylib",
      "-lSystem",
      "-lz",
      "-lresolv",
      "-Fopenssl-frameworks/\(p.name)",
      "-framework Foundation",
      "-framework openssl",
      "-arch \(arch)",
      "-\(p.plistMinSDKVersionName) \(p.deploymentTarget)",
      "-syslibroot \(p.sdkPath())",
      "-compatibility_version 1.0.0",
      "-current_version 1.0.0",
      "-application_extension",
      "-o \(binPath)/\(Config.frameworkName)"
    )

    try sh(
      "install_name_tool",
      "-id",
      "@rpath/\(Config.frameworkName).framework/\(Config.frameworkName)",
      "\(binPath)/\(Config.frameworkName)"
    )

    // 2. creating static lib
    try sh("mkdir \(libPath)/lib")

    try sh("ar rv \(libPath)/lib/libssh.a \(binPath)/obj/*.o")
    try sh("ranlib \(libPath)/lib/libssh.a")

    try sh("mkdir \(libPath)/include")
    for header in headers {
      try sh("cp openssh-portable/\(header) \(libPath)/include/")
    }
//    try sh("libtool -static -o \(libPath)/lib/libssh.a \(binPath)/obj/*.o")
    try mkdir("\(binPath)/lib")
    try sh(
      "lipo -create \(libPath)/lib/libssh.a -output \(binPath)/tmp/libssh.a"
    )
  }

  guard
    let arch = p.archs.first
  else {
    continue
  }
  
  let libPath = "lib/\(p.name)-\(arch).sdk"
  
  let plist = try p.plist(
    name: Config.frameworkName,
    version: Config.opensshVersion,
    id: "org.openssh",
    minSdkVersion: p.deploymentTarget
  )

  let moduleMap = p.module(name: Config.frameworkName, headers: .umbrellaDir("."))
  
  for path in [frameworkStaticPath, frameworkDynamicPath] {
    try? sh("rm -rf", path)
    try mkdir("\(path)/Headers")
    try sh("cp \(libPath)/include/*.h \(path)/Headers/")
    try write(content: plist, atPath: "\(path)/Info.plist")
    try mkdir("\(path)/Modules")
    try write(content: moduleMap, atPath: "\(path)/Modules/module.modulemap")
  }
  
  let aFiles = p.archs.map { arch -> String in
    "bin/\(p.name)-\(arch).sdk/tmp/*.a"
  }
  
  try sh("libtool -static -o \(frameworkStaticPath)/\(Config.frameworkName) \(aFiles.joined(separator: " "))")
  
  let dylibFiles = p.archs.map { arch -> String in
    "bin/\(p.name)-\(arch).sdk/\(Config.frameworkName)"
  }
  
  try sh("lipo -create \(dylibFiles.joined(separator: " ")) -output \(frameworkDynamicPath)/\(Config.frameworkName)")
  
  if p == .MacOSX || p == .Catalyst {
    for path in [frameworkStaticPath, frameworkDynamicPath] {
      try repackFrameworkToMacOS(at: path, name: Config.frameworkName)
    }
  }
}

try? sh("rm -rf xcframeworks")
try mkdir("xcframeworks/dynamic")
try mkdir("xcframeworks/static")

let xcframeworkName = "\(Config.frameworkName).xcframework"
let xcframeworkdDynamicZipName = "\(Config.frameworkName)-dynamic.xcframework.zip"
let xcframeworkdStaticZipName = "\(Config.frameworkName)-static.xcframework.zip"
try? sh("rm \(xcframeworkdDynamicZipName)")
try? sh("rm \(xcframeworkdStaticZipName)")

try sh(
  "xcodebuild -create-xcframework \(dynamicFrameworkPaths.map {"-framework \($0)"}.joined(separator: " ")) -output xcframeworks/dynamic/\(xcframeworkName)"
)

try cd("xcframeworks/dynamic/") {
  try sh("zip --symlinks -r ../../\(xcframeworkdDynamicZipName) \(xcframeworkName)")
}

try sh(
  "xcodebuild -create-xcframework \(staticFrameworkPaths.map {"-framework \($0)"}.joined(separator: " ")) -output xcframeworks/static/\(xcframeworkName)"
)


try cd("xcframeworks/static/") {
  try sh("zip --symlinks -r ../../\(xcframeworkdStaticZipName) \(xcframeworkName)")
}


let releaseMD =
  """
    | File                          | SHA256                                       |
    | ----------------------------- |:--------------------------------------------:|
    | \(xcframeworkdDynamicZipName) | \(try sha(path: xcframeworkdDynamicZipName)) |
    | \(xcframeworkdStaticZipName)  | \(try sha(path: xcframeworkdStaticZipName))  |
  """

try write(content: releaseMD, atPath: "release.md")