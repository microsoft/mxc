// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(any(test, feature = "microvm"))]
use std::collections::BTreeMap;
#[cfg(any(test, feature = "microvm"))]
use std::path::{Component, Path, PathBuf};
#[cfg(feature = "microvm")]
use std::process::Command;

#[cfg(any(test, feature = "microvm"))]
use sha2::{Digest, Sha256};

// Upgrade procedure: docs/backends/nvx/nvx.md#maintainers-updating-the-bundled-runtime.
#[cfg(any(test, feature = "microvm"))]
pub(crate) const OFFICIAL_BUNDLE_URL: &str =
    "https://github.com/Azure/aci-edge-sandbox/releases/download/v0.1.0-build188642429/aci-edge-sandboxes-0.1.0-build188642429.zip";
#[cfg(any(test, feature = "microvm"))]
pub(crate) const OFFICIAL_BUNDLE_ZIP_SHA256: &str =
    "cad4db7c574a73aaa1c5a07e7a740cd2b01d5b83c62c81b2196d63bad9ecc126";
const BUNDLE_DIR_ENV: &str = "ACI_EDGE_SANDBOXES_AGENT_BUNDLE_DIR";

#[cfg(any(test, feature = "microvm"))]
pub(crate) const OFFICIAL_BUNDLE_FILES: &[(&str, &str)] = &[
    (
        "NOTICE.txt",
        "a3770dc8821ade6e9d409188ebec282de9da94f4e8702a24cea84b9b50538c83",
    ),
    (
        "SHA256SUMS",
        "24d6fcbd2fc22b7618045680c6313db74de3129872c170c25316c12c20145c29",
    ),
    (
        "SOURCE-MANIFEST.json",
        "33468418005a55daa9d1c23e1663d9da54af76fbb56f4c26cbb419ab6d9c8572",
    ),
    (
        "bin/EULA.txt",
        "5126fe5a31fc3273681b824860a9fe6a625f9f581aae8fe65c1e38bb225c64c2",
    ),
    (
        "bin/aci_edge_agent.dll",
        "d30a5058ab4765728f0422f43678ad46831d17d7677a82fba0cdcd0ed4ea4343",
    ),
    (
        "bin/direct-images.exe",
        "03dfa4d44083e071e73d145724a742a023843377fe2b7da8a72a7549a091b6a3",
    ),
    (
        "bin/openvmm.exe",
        "adf2df9a147afd6cc31db74c9b98b3488845d1812cca0bd482c3020b9dd12ad9",
    ),
    (
        "bundle-manifest.json",
        "c2e35e7b750d9fbe73ba5148a7a6ec7adc5173f4336a9b0706393587a484430a",
    ),
    (
        "guest/initramfs-edge.cpio.gz",
        "f566132af956284c70ff1dc11912b7eee95bbd7414957e0126a010d7e6ea02f1",
    ),
    (
        "guest/nvx-edge-agent",
        "3ddeb6c850c1b27f4d44b8e0e1bc5df8a11da0f400d2d78260845c72e50ffd91",
    ),
    (
        "guest/vmlinux",
        "1f0d15e9667ad506e4e98ca24eaca5e6aa69266b6069fa8fd848813457bf5c62",
    ),
    (
        "guest/vmlinux.config",
        "89228d78a10ac9d8f151384b0adc5a155c8a1ee045732b17e236a0e28b49297d",
    ),
    (
        "licenses/linux/COPYING",
        "fb5a425bd3b3cd6071a3a9aff9909a859e7c1158d54d32e07658398cd67eb6a0",
    ),
    (
        "licenses/linux/LICENSES/deprecated/0BSD",
        "6b50bcee8c2f90c73558dee62e444dde54f3cea86ccfcea84aa8be60005e67b4",
    ),
    (
        "licenses/linux/LICENSES/deprecated/CC0-1.0",
        "c8a97e7369419869e2d60eab21a9f13bf293bfc33aed0de3c459644a8edd0c80",
    ),
    (
        "licenses/linux/LICENSES/deprecated/GFDL-1.1",
        "8f13a0664b7e0f30d7a9001f3ecd87d3dea7964559d08337ca1a4b129d9e0e0d",
    ),
    (
        "licenses/linux/LICENSES/deprecated/GFDL-1.2",
        "e43e6da62a83b8bf96819ff1226151da373cb87f165cd538f405978a0a8c6b7a",
    ),
    (
        "licenses/linux/LICENSES/deprecated/GPL-1.0",
        "e72efc63ce52380f374733ec7a733f5c11efa3c1f2b0cb48a9c355868ee5b09c",
    ),
    (
        "licenses/linux/LICENSES/deprecated/ISC",
        "cbdf535b99a9f4cb208c5495c6dd9a1f84104d83c03f8f0d98ee7a0c43805388",
    ),
    (
        "licenses/linux/LICENSES/deprecated/Linux-OpenIB",
        "8ae20d34c2a74c85ae2760dd0034baf18e44bee3289b9b3a4fe46768b4ea2cd6",
    ),
    (
        "licenses/linux/LICENSES/deprecated/X11",
        "21115f2385035c1ceeda8820b7f050c89a30418457a5e2a5c6091f2545d40e44",
    ),
    (
        "licenses/linux/LICENSES/deprecated/Zlib",
        "3b42160485d3d596ff8a4956958c4360dc55f1e2414c964aef0ad2d3c2a92abb",
    ),
    (
        "licenses/linux/LICENSES/dual/Apache-2.0",
        "7e4d3fba250d15e9e0afa380d4b611828fa2560cc8fdebe95bcf2f01a487de12",
    ),
    (
        "licenses/linux/LICENSES/dual/CC-BY-4.0",
        "84d5ad08940d29065d8a6f062effa4204c2235c9f2487aa53748ed0a0a6cce86",
    ),
    (
        "licenses/linux/LICENSES/dual/CDDL-1.0",
        "490abf7869e4638fbb43df99a20e5683224617a6bf9ffd06971cb02b153e53c1",
    ),
    (
        "licenses/linux/LICENSES/dual/MPL-1.1",
        "ccbda1d2f0cfef821f39e1880aae9213c7933e07713ee638ad1fb02547c0b97b",
    ),
    (
        "licenses/linux/LICENSES/dual/copyleft-next-0.3.1",
        "28386705873e5eacf16b5d34dd06e58737a2c5a3622acda380a0f236c0a6d02a",
    ),
    (
        "licenses/linux/LICENSES/exceptions/GCC-exception-2.0",
        "0dca50b78073055447d02e8f6ae4fa94c1d0e6d7fbb4c874c9db5eb960c8b3d4",
    ),
    (
        "licenses/linux/LICENSES/exceptions/Linux-syscall-note",
        "8e378ab93586eb55135d3bc119cce787f7324f48394777d00c34fa3d0be3303f",
    ),
    (
        "licenses/linux/LICENSES/preferred/BSD-2-Clause",
        "6313108c23efffa36948f8b2cff1560a5935373b527b0e1a837cc77e6ed1bacd",
    ),
    (
        "licenses/linux/LICENSES/preferred/BSD-3-Clause",
        "7a83b1aeb460458db9a4bd521d7f237c45b1650f6e60ea5ffc71e49472454de3",
    ),
    (
        "licenses/linux/LICENSES/preferred/BSD-3-Clause-Clear",
        "3f8a01d020e77c045e364c4681ee78c591041b7a38aa61972f689f4bc4cb5088",
    ),
    (
        "licenses/linux/LICENSES/preferred/GPL-2.0",
        "8780e78a1a737e127f25a65f6d95269bffd36158dc261114de7859b490bfc5aa",
    ),
    (
        "licenses/linux/LICENSES/preferred/LGPL-2.0",
        "967792c8a6a57bbbc123a69fff6c3020af80b04623916b82ba721b0347e64433",
    ),
    (
        "licenses/linux/LICENSES/preferred/LGPL-2.1",
        "b5b8b75228bc1de1cca15cf00f90229e936d9712c62df52b057fffad21ffec48",
    ),
    (
        "licenses/linux/LICENSES/preferred/MIT",
        "323c587d0ccf10e376f8bf9a7f31fb4ca6078105194b42e0b1e0ee2bc9bde71f",
    ),
    (
        "provenance/direct-images/NOTICE.txt",
        "1c2effeb20d1b4e13e4d8e5a35e7b8511a6fd2177628e04ae63100be4b7be536",
    ),
    (
        "provenance/direct-images/SHA256SUMS",
        "386f42c4a036d82c3b77d8137802b733b97af7b2af0a58021c6176c9209a4301",
    ),
    (
        "provenance/direct-images/cgmanifest.json",
        "13db463b670cd5ba2b0c1d6e43a4d3824a5ca7537601645837b6b94d2c947410",
    ),
    (
        "provenance/direct-images/dependency-inventory.json",
        "9bf5edc5f9f06b7af928aaac8c76cbb2b29a5dca97b6a4341ca76736c3e3c9bb",
    ),
    (
        "provenance/direct-images/direct-images-manifest.json",
        "ea4a2eb0a7df5af8c6c5b8042f66c97dd9c57bc32a8cd1351f0e437a24e71bc0",
    ),
    (
        "provenance/direct-images/licenses/modules/001/LICENSE",
        "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
    ),
    (
        "provenance/direct-images/licenses/modules/002/LICENSE",
        "4bbe3b885e8cd1907ab4cf9a41e862e74e24b5422297a4f2fe524e6a30ada2b4",
    ),
    (
        "provenance/direct-images/licenses/modules/003/LICENSE",
        "4bbe3b885e8cd1907ab4cf9a41e862e74e24b5422297a4f2fe524e6a30ada2b4",
    ),
    (
        "provenance/direct-images/licenses/modules/004/LICENSE.md",
        "a55959c4e3e8917bfa857359bb641115336276a6cc97408fd8197e079fb18470",
    ),
    (
        "provenance/direct-images/licenses/modules/005/AUTHORS",
        "dce0bbb894d965a798508c684f46369aed4dc5c889db1eb782b36d99d11de8ee",
    ),
    (
        "provenance/direct-images/licenses/modules/005/LICENSE",
        "2d81ea060825006fc8f3fe28aa5dc0ffeb80faf325b612c955229157b8c10dc0",
    ),
    (
        "provenance/direct-images/licenses/modules/005/NOTICE",
        "a8c869fbda819afb8d80e0ac19bac52e766bc6c19cb38cf94f52d64c4be2aab6",
    ),
    (
        "provenance/direct-images/licenses/modules/005/cli/connhelper/internal/syntax/LICENSE",
        "ce63850f77649f00d1394045e2794ffb09a5596beabac51c9548edd958845d7c",
    ),
    (
        "provenance/direct-images/licenses/modules/006/LICENSE",
        "a6c2a5fdf40879f644bdb0da9042f245e7e263237d623264aafcf2470610ad8c",
    ),
    (
        "provenance/direct-images/licenses/modules/007/LICENSE",
        "73ba74dfaa520b49a401b5d21459a8523a146f3b7518a833eea5efa85130bf68",
    ),
    (
        "provenance/direct-images/licenses/modules/008/LICENSE",
        "58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd",
    ),
    (
        "provenance/direct-images/licenses/modules/009/LICENSE",
        "0d9e582ee4bff57bf1189c9e514e6da7ce277f9cd3bc2d488b22fbb39a6d87cf",
    ),
    (
        "provenance/direct-images/licenses/modules/009/gzhttp/LICENSE",
        "2252a5b1e2b1d3663b53ea77051b8ed065cb9270a3d1174d5d6ead8a2de051b6",
    ),
    (
        "provenance/direct-images/licenses/modules/009/internal/lz4ref/LICENSE",
        "6a358d2540ca14048f02d366f23787c0a480157e58f058113f0e27168dd4e447",
    ),
    (
        "provenance/direct-images/licenses/modules/009/internal/snapref/LICENSE",
        "f69f157b0be75da373605dbc8bbf142e8924ee82d8f44f11bcaf351335bf98cf",
    ),
    (
        "provenance/direct-images/licenses/modules/009/s2/LICENSE",
        "08683b14bda8ae3538abf19e1879e853a39e3b8276a8d673363b529d15a61c1a",
    ),
    (
        "provenance/direct-images/licenses/modules/009/s2/cmd/internal/filepathx/LICENSE",
        "8582c87d9a6baa28f7827c5205b7d16c3179bc794ebd4c7cc287c49a89b7eaa1",
    ),
    (
        "provenance/direct-images/licenses/modules/009/s2/cmd/internal/readahead/LICENSE",
        "10fa24a602fde465db603cd5d546e37e33642a73cd24ddf5910be81724fec8b2",
    ),
    (
        "provenance/direct-images/licenses/modules/009/snappy/AUTHORS",
        "f6f3821e64460346c1ed1a15fb32b94ad241617276b60726c1350ca315309463",
    ),
    (
        "provenance/direct-images/licenses/modules/009/snappy/CONTRIBUTORS",
        "98d5f03af6be02487975df7fc5b7d57aca7c19c6a303188e45a1c100afd09668",
    ),
    (
        "provenance/direct-images/licenses/modules/009/snappy/LICENSE",
        "f69f157b0be75da373605dbc8bbf142e8924ee82d8f44f11bcaf351335bf98cf",
    ),
    (
        "provenance/direct-images/licenses/modules/009/snappy/xerial/LICENSE",
        "d4ff111fa30ac75e28dca3868de957a3b73ff50b76bc4b8fe5c3a1f008d26703",
    ),
    (
        "provenance/direct-images/licenses/modules/009/zstd/internal/xxhash/LICENSE.txt",
        "f566a9f97bacdaf00d9f21dd991e81dc11201c4e016c86b470799429a1c9a79c",
    ),
    (
        "provenance/direct-images/licenses/modules/010/LICENSE",
        "88a2379b3ca34bf5c57127aff9dcb802bbb60ece0805cdbda65b3bd115f971d9",
    ),
    (
        "provenance/direct-images/licenses/modules/011/LICENSE",
        "cf248820bf1178370bb4f1670a59f8748d46bc96d0f64080cd631511c6046409",
    ),
    (
        "provenance/direct-images/licenses/modules/012/LICENSE",
        "18cc155157d07d5ac0b227e5f58ae9f815ccd817487fd10c6e4f4f0ec4411ce1",
    ),
    (
        "provenance/direct-images/licenses/modules/012/cmd/runhcs/LICENSE",
        "552a739c3b25792263f731542238b92f6f8d07e9a488eae27e6c4690038a8243",
    ),
    (
        "provenance/direct-images/licenses/modules/012/cmd/runhcs/NOTICE",
        "ca8ea5330b8511a120980d043bbf9b9879ef5d01c3837eab03f0c5329eca1564",
    ),
    (
        "provenance/direct-images/licenses/modules/012/pkg/go-runhcs/LICENSE",
        "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
    ),
    (
        "provenance/direct-images/licenses/modules/012/pkg/go-runhcs/NOTICE",
        "93f53cf91ed77744bc29a861720ac516c08f4deb6caadfe1dff1cde13b02457b",
    ),
    (
        "provenance/direct-images/licenses/modules/013/LICENSE.md",
        "0583acca2b32a7e4f7bc2d98422b2f55097333273731b3ba2a16d66f9e422744",
    ),
    (
        "provenance/direct-images/licenses/modules/014/LICENSE",
        "aceb55133c41c50c2e170c5918e301fe74f592d0f28724bf2f7a7bfdcff1fc5f",
    ),
    (
        "provenance/direct-images/licenses/modules/014/LICENSE.docs",
        "a1d1adec3ba691ef6e377a78bbe9e9e2501f2f4a1723d08857da1ac6564e4fed",
    ),
    (
        "provenance/direct-images/licenses/modules/015/LICENSE",
        "b0a3f39513927db306adabea11d14c23f079d4febcea241d123a68d1a0d45418",
    ),
    (
        "provenance/direct-images/licenses/modules/016/LICENSE",
        "8d427fd87bc9579ea368fde3d49f9ca22eac857f91a9dec7e3004bdfab7dee86",
    ),
    (
        "provenance/direct-images/licenses/modules/017/LICENSE.txt",
        "75e1ca97a84a9da6051dee0114333388216f2c4a5a028296b882ff3d57274735",
    ),
    (
        "provenance/direct-images/licenses/modules/018/LICENSE",
        "51a0c9ec7f8b7634181b8d4c03e5b5d204ac21d6e72f46c313973424664b2e6b",
    ),
    (
        "provenance/direct-images/licenses/modules/019/LICENSE",
        "3e64f5c2419b8150badd1c21a143806db894a51e0ec7ffd1560ddd6819f2aa37",
    ),
    (
        "provenance/direct-images/licenses/modules/020/LICENSE",
        "1b0edc159f8b0395fc51dc72b95619404e494563b7df7d683d97e35e0a4a8650",
    ),
    (
        "provenance/direct-images/licenses/modules/021/AUTHORS",
        "627c695f80fdac6412d66e6ad4160a4acb41923ca7ee3fd7e112e105f0ff46b9",
    ),
    (
        "provenance/direct-images/licenses/modules/021/LICENSE",
        "58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd",
    ),
    (
        "provenance/direct-images/licenses/modules/022/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/modules/022/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/modules/023/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/modules/023/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/modules/024/LICENSE",
        "4835612df0098ca95f8e7d9e3bffcb02358d435dbb38057c844c99d7f725eb20",
    ),
    (
        "provenance/direct-images/licenses/modules/024/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/source/EULA.txt",
        "5126fe5a31fc3273681b824860a9fe6a625f9f581aae8fe65c1e38bb225c64c2",
    ),
    (
        "provenance/direct-images/licenses/toolchain/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/toolchain/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/compile/internal/ssa/_gen/vendor/golang.org/x/tools/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/compile/internal/ssa/_gen/vendor/golang.org/x/tools/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/github.com/google/pprof/AUTHORS",
        "8a196dfd9252ad9cb0670365e680d6b19560c688776fa76f0203854ae2c0e29c",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/github.com/google/pprof/CONTRIBUTORS",
        "2e6c7aac8aaaed781b36b1edb63cfb0692671310008d9a50afb585a686c74f1e",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/github.com/google/pprof/LICENSE",
        "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/github.com/google/pprof/third_party/svgpan/LICENSE",
        "154c946c17de61ca71d28e13673d76a5798e6e25995a7397fbae157afc8f62b4",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/github.com/ianlancetaylor/demangle/LICENSE",
        "b73277f7730993ef8e7f80aed83e5309762fed4d77eced982abb2c00657c074d",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/github.com/microsoft/go-infra/telemetry/LICENSE",
        "c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/github.com/microsoft/go-infra/telemetry/config/LICENSE",
        "c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/arch/LICENSE",
        "8cda009bd927676a95ee7ce2dae921442ac4d9584d041b56ecfcba6839032f0b",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/arch/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/build/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/build/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/mod/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/mod/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/sync/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/sync/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/sys/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/sys/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/telemetry/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/telemetry/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/term/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/term/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/text/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/text/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/tools/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/golang.org/x/tools/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/cmd/vendor/rsc.io/markdown/LICENSE",
        "2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/crypto/internal/boring/LICENSE",
        "56210f826b8f0fbac3160dfe55c97f4019eb6cdda3963b5a0eab8a8bdb62360e",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/runtime/testdata/testgoroutineleakprofile/goker/LICENSE",
        "f99df8ae6da6de047ed002d9dbe8682d9a19c88e9a7473abdadf3ac206621a85",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/vendor/github.com/microsoft/go-crypto-darwin/LICENSE",
        "c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/vendor/github.com/microsoft/go-crypto-openssl/LICENSE",
        "5562115257d56e6eb6be6ff2a11de8fbf32f2ee3aa3af90e2e4bfe923ff4d46a",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/vendor/github.com/microsoft/go-crypto-winnative/LICENSE",
        "c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/vendor/golang.org/x/crypto/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/vendor/golang.org/x/crypto/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/vendor/golang.org/x/net/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/vendor/golang.org/x/net/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/vendor/golang.org/x/sys/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/vendor/golang.org/x/sys/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/vendor/golang.org/x/text/LICENSE",
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
    ),
    (
        "provenance/direct-images/licenses/toolchain/src/vendor/golang.org/x/text/PATENTS",
        "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
    ),
    (
        "provenance/edge-guest.json",
        "ecc5a57d759d753483f96ab63810787e34528cef8a6d5d1fd5c7f225247cd4c3",
    ),
    (
        "provenance/edge-windows.json",
        "d48571e0e33d5aa246b4035f7c15319e669d69dd2652f6044ca8217ac50fd8c1",
    ),
    (
        "provenance/licenses/linux/COPYING-LINUX",
        "4fc360c08586ee232e17eaf34e97feae0065dc3daacb2210b754921dc587a5c5",
    ),
    (
        "provenance/licenses/nvx/LICENSE",
        "7df20dcdf9197e9945c14858d41c60f11b52b93e5b69e2b63416b874d598d322",
    ),
    (
        "provenance/licenses/nvx/THIRD_PARTY_NOTICES.md",
        "5b5c66e898c8df31ee5d4e427e23a39cc3c2609e8670457822ae0022789cb3ff",
    ),
    (
        "provenance/licenses/openvmm/LICENSE",
        "c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383",
    ),
    (
        "provenance/openvmm.provenance.json",
        "c3d4f53e4fafa3644027bc572478c7ebaf26d98a6845fb48417b1e345d89aabd",
    ),
    (
        "provenance/vmlinux.provenance.json",
        "f49f66ea98efeb7f1a5de9b4a11b60d45b9b80904edcff478c7a5635b47aa42c",
    ),
    (
        "source/linux/BUILD-ENVIRONMENT.txt",
        "d855844d44fb6fc776e14b2d3c8d9eadcff862be48fb56bda43d28ddf0111723",
    ),
    (
        "source/linux/SOURCE-MANIFEST.json",
        "2bdbd08c2a760548c7167f91d0394c0ae065ef13e0411360439954c5a643e212",
    ),
    (
        "source/linux/SOURCE.md",
        "5b196b1f6e4e3dad274d9ac4ecd1d67c78c6ad0d8e755d696e0232bb38cd81ca",
    ),
    (
        "source/linux/config-microvm",
        "963797f9f0a78ca0b1dfbf46f6e29508479004f1726233be2da380ac4defc9bd",
    ),
    (
        "source/linux/patches/0001-microvm-xe9-earlycon.patch",
        "af6ce084f92162cdf82fa24e4ac3d519bf04c8657863219b1edaf848ccaebd29",
    ),
    (
        "source/linux/patches/0002-microvm-hvc-xe9.patch",
        "704a3f5048cc42db0740eb47352ca1fb36f47d0281fe43fe7ebe727fcafc8ee0",
    ),
    (
        "source/linux/patches/0003-microvm-virtio-mmio-shared-status.patch",
        "ecca885480441528a8ef0007a8c147daa10ab84acb0c17044b2772f460325231",
    ),
];

pub(crate) fn run() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_MICROVM");
    println!("cargo:rerun-if-env-changed={BUNDLE_DIR_ENV}");
    #[cfg(feature = "microvm")]
    if std::env::var_os("CARGO_FEATURE_MICROVM").is_some()
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
    {
        stage_official_bundle();
    }
}

#[cfg(feature = "microvm")]
fn stage_official_bundle() {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    let bundle_dir = std::env::var_os(BUNDLE_DIR_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    stage_bundle_against(
        &out_dir,
        bundle_dir.as_deref(),
        OFFICIAL_BUNDLE_ZIP_SHA256,
        OFFICIAL_BUNDLE_FILES,
    );
}

#[cfg(feature = "microvm")]
pub(crate) fn stage_bundle_against(
    out_dir: &Path,
    bundle_dir: Option<&Path>,
    expected_archive_sha256: &str,
    expected_files: &[(&str, &str)],
) {
    // A linked build directory must not redirect the executable's staging directory.
    let profile = out_dir
        .ancestors()
        .nth(3)
        .expect("OUT_DIR has target/profile ancestors");
    let profile = profile.canonicalize().unwrap_or_else(|error| {
        panic!(
            "cannot resolve Cargo profile directory {}: {error}",
            profile.display()
        )
    });
    // Cargo owns these roots; caller-supplied bundle paths remain unresolved.
    let out_dir = out_dir.canonicalize().unwrap_or_else(|error| {
        panic!(
            "cannot resolve Cargo OUT_DIR {}: {error}",
            out_dir.display()
        )
    });
    let source = match bundle_dir {
        Some(directory) => {
            let archive = directory.join("aci-edge-sandboxes.zip");
            if archive.is_file() && !directory.join("SOURCE-MANIFEST.json").is_file() {
                println!("cargo:rerun-if-changed={}", archive.display());
                let extracted = out_dir.join("aci-edge-sandboxes");
                if !is_verified_bundle(&extracted, expected_files) {
                    extract_verified_archive_against(
                        &archive,
                        &extracted,
                        expected_archive_sha256,
                        expected_files,
                    );
                }
                extracted
            } else {
                directory.to_path_buf()
            }
        }
        None => acquire_cached_bundle(&out_dir, expected_archive_sha256, expected_files),
    };
    verify_bundle_against(&source, expected_files);

    let target = profile.join("aci-edge-sandboxes");
    copy_bundle(&source, &target);
    verify_bundle_against(&target, expected_files);
}

#[cfg(feature = "microvm")]
fn acquire_cached_bundle(
    out_dir: &Path,
    expected_archive_sha256: &str,
    expected_files: &[(&str, &str)],
) -> PathBuf {
    let extracted = out_dir.join("aci-edge-sandboxes");
    if is_verified_bundle(&extracted, expected_files) {
        return extracted;
    }

    let archive = out_dir.join("aci-edge-sandboxes.zip");
    let archive_ok =
        archive.is_file() && sha256(&archive).eq_ignore_ascii_case(expected_archive_sha256);
    if !archive_ok {
        let _ = std::fs::remove_file(&archive);
        download_archive(OFFICIAL_BUNDLE_URL, &archive);
    }
    extract_verified_archive_against(
        &archive,
        &extracted,
        expected_archive_sha256,
        expected_files,
    );
    extracted
}

#[cfg(feature = "microvm")]
fn download_archive(url: &str, destination: &Path) {
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
    }
    let partial = destination.with_extension("zip.part");
    let _ = std::fs::remove_file(&partial);
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--retry",
            "5",
            "--retry-delay",
            "5",
            "--retry-all-errors",
            "--output",
        ])
        .arg(&partial)
        .arg(url)
        .output()
        .unwrap_or_else(|error| {
            let _ = std::fs::remove_file(&partial);
            panic!(
                "cannot invoke curl to download signed NVX bundle from {url}: {error}; \
                 set {BUNDLE_DIR_ENV} to a pre-fetched bundle directory for offline builds"
            )
        });
    if !output.status.success() {
        let _ = std::fs::remove_file(&partial);
        panic!(
            "curl failed to download signed NVX bundle from {url} ({}): {}; \
             set {BUNDLE_DIR_ENV} to a pre-fetched bundle directory for offline builds",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    std::fs::rename(&partial, destination).unwrap_or_else(|error| {
        let _ = std::fs::remove_file(&partial);
        panic!(
            "cannot finalize downloaded NVX bundle ({} -> {}): {error}",
            partial.display(),
            destination.display()
        )
    });
}

#[cfg(any(test, feature = "microvm"))]
pub(crate) fn extract_verified_archive_against(
    archive_path: &Path,
    destination: &Path,
    expected_archive_sha256: &str,
    expected_files: &[(&str, &str)],
) {
    let actual_archive_sha256 = sha256(archive_path);
    if !actual_archive_sha256.eq_ignore_ascii_case(expected_archive_sha256) {
        let _ = std::fs::remove_file(archive_path);
        panic!(
            "microvm requires the signed v0.1.0-build188642429 archive {}: \
             expected SHA-256 {expected_archive_sha256}, got {actual_archive_sha256}",
            archive_path.display()
        );
    }

    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
    }
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("aci-edge-sandboxes");
    let staging = destination.with_file_name(format!("{name}.tmp.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", staging.display()));

    let unpack_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unpack_zip_strict(archive_path, &staging);
        verify_bundle_against(&staging, expected_files);
    }));
    if let Err(payload) = unpack_result {
        let _ = std::fs::remove_dir_all(&staging);
        std::panic::resume_unwind(payload);
    }

    let _ = std::fs::remove_dir_all(destination);
    std::fs::rename(&staging, destination).unwrap_or_else(|error| {
        let _ = std::fs::remove_dir_all(&staging);
        panic!(
            "cannot publish extracted NVX bundle to {}: {error}",
            destination.display()
        )
    });
}

#[cfg(any(test, feature = "microvm"))]
fn unpack_zip_strict(archive_path: &Path, destination: &Path) {
    let file = std::fs::File::open(archive_path)
        .unwrap_or_else(|error| panic!("cannot open {}: {error}", archive_path.display()));
    let mut archive = zip::ZipArchive::new(file).unwrap_or_else(|error| {
        panic!(
            "cannot read NVX bundle archive {}: {error}",
            archive_path.display()
        )
    });

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .unwrap_or_else(|error| panic!("cannot read NVX zip entry {index}: {error}"));
        let name = entry
            .name()
            .unwrap_or_else(|error| panic!("cannot decode NVX zip entry {index} name: {error}"))
            .into_owned();
        assert!(
            !entry.is_symlink(),
            "NVX bundle archive must not contain links: {}",
            name
        );
        let relative = entry
            .enclosed_name()
            .unwrap_or_else(|| panic!("NVX bundle archive entry path is not safe: {}", name));
        assert!(
            !relative.as_os_str().is_empty()
                && relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
            "NVX bundle archive entry path is not safe: {}",
            name
        );
        let out_path = destination.join(&relative);
        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", out_path.display()));
        } else {
            assert!(
                entry.is_file(),
                "NVX bundle archive must contain only regular files and directories: {}",
                name
            );
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
            }
            assert!(
                !out_path.exists(),
                "duplicate NVX bundle archive entry: {}",
                relative.display()
            );
            let mut output = std::fs::File::create(&out_path)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", out_path.display()));
            std::io::copy(&mut entry, &mut output)
                .unwrap_or_else(|error| panic!("cannot write {}: {error}", out_path.display()));
        }
    }
}

#[cfg(feature = "microvm")]
fn is_verified_bundle(source: &Path, expected_files: &[(&str, &str)]) -> bool {
    source.is_dir()
        && std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_bundle_against(source, expected_files);
        }))
        .is_ok()
}

#[cfg(any(test, feature = "microvm"))]
fn sha256(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|error| {
        panic!(
            "cannot read signed NVX artifact {}: {error}",
            path.display()
        )
    });
    Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(any(test, feature = "microvm"))]
pub(crate) fn verify_bundle_against(source: &Path, expected_files: &[(&str, &str)]) {
    assert_safe_directory(source, "NVX bundle source");
    let expected: BTreeMap<&str, &str> = expected_files.iter().copied().collect();
    assert_eq!(
        expected.len(),
        expected_files.len(),
        "official NVX bundle file list contains duplicate paths"
    );

    let mut actual = BTreeMap::new();
    collect_bundle_files(source, source, &mut actual);
    let actual_paths: Vec<&str> = actual.keys().map(String::as_str).collect();
    let expected_paths: Vec<&str> = expected.keys().copied().collect();
    assert_eq!(
        actual_paths, expected_paths,
        "microvm requires the complete signed v0.1.0-build188642429 bundle"
    );

    for (relative, path) in actual {
        let expected_sha256 = expected[relative.as_str()];
        assert_eq!(
            sha256(&path),
            expected_sha256,
            "microvm requires the signed v0.1.0-build188642429 artifact {relative}"
        );
    }
}

#[cfg(any(test, feature = "microvm"))]
fn collect_bundle_files(source: &Path, directory: &Path, files: &mut BTreeMap<String, PathBuf>) {
    for entry in std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot list {}: {error}", directory.display()))
    {
        let entry = entry.unwrap_or_else(|error| panic!("cannot read bundle entry: {error}"));
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", path.display()));
        let kind = metadata.file_type();
        assert!(
            !kind.is_symlink() && !is_reparse_point(&metadata),
            "NVX bundle must not contain links or reparse points"
        );
        if kind.is_dir() {
            collect_bundle_files(source, &path, files);
            continue;
        }
        assert!(kind.is_file(), "NVX bundle must contain only regular files");
        let relative = path
            .strip_prefix(source)
            .expect("bundle entry remains under its source");
        assert!(
            relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
            "NVX bundle path is not safe: {}",
            relative.display()
        );
        let relative = relative
            .to_str()
            .unwrap_or_else(|| panic!("NVX bundle path is not UTF-8: {}", relative.display()))
            .replace('\\', "/");
        assert!(
            files.insert(relative.clone(), path).is_none(),
            "duplicate NVX bundle path: {relative}"
        );
    }
}

#[cfg(any(test, feature = "microvm"))]
fn copy_bundle(source: &Path, target: &Path) {
    assert_safe_directory(source, "NVX bundle source");
    assert_safe_destination(target);
    std::fs::create_dir_all(target)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", target.display()));
    for entry in std::fs::read_dir(source)
        .unwrap_or_else(|error| panic!("cannot list {}: {error}", source.display()))
    {
        let entry = entry.unwrap_or_else(|error| panic!("cannot read bundle entry: {error}"));
        let from = entry.path();
        let to = target.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&from)
            .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", from.display()));
        let kind = metadata.file_type();
        assert!(
            !kind.is_symlink() && !is_reparse_point(&metadata),
            "NVX bundle must not contain links or reparse points"
        );
        if kind.is_dir() {
            copy_bundle(&from, &to);
        } else {
            assert!(kind.is_file(), "NVX bundle must contain only regular files");
            println!("cargo:rerun-if-changed={}", from.display());
            let contents = std::fs::read(&from)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", from.display()));
            assert_safe_destination(&to);
            if std::fs::read(&to).is_ok_and(|existing| existing == contents) {
                continue;
            }
            std::fs::copy(&from, &to).unwrap_or_else(|error| {
                panic!(
                    "cannot stage signed NVX artifact {} to {}: {error}",
                    from.display(),
                    to.display()
                )
            });
        }
    }
}

#[cfg(any(test, feature = "microvm"))]
fn assert_safe_directory(path: &Path, description: &str) {
    assert_safe_ancestors(path, description, false);
    let metadata = std::fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("cannot inspect {description} {}: {error}", path.display()));
    assert!(
        metadata.is_dir(),
        "{description} must be a directory: {}",
        path.display()
    );
}

#[cfg(any(test, feature = "microvm"))]
fn assert_safe_destination(target: &Path) {
    assert_safe_ancestors(target, "NVX bundle destination", true);
}

#[cfg(any(test, feature = "microvm"))]
fn assert_safe_ancestors(target: &Path, description: &str, allow_missing: bool) {
    let absolute = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|error| panic!("cannot resolve {description}: {error}"))
            .join(target)
    };
    // Inspect parents first, without resolving links in the untrusted path.
    let ancestors: Vec<_> = absolute.ancestors().collect();
    for path in ancestors.into_iter().rev() {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(error) => panic!("cannot inspect {description} {}: {error}", path.display()),
        };
        assert!(
            !metadata.file_type().is_symlink() && !is_reparse_point(&metadata),
            "{description} must not traverse a link or reparse point: {}",
            path.display()
        );
    }
}

#[cfg(all(any(test, feature = "microvm"), target_os = "windows"))]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(all(any(test, feature = "microvm"), not(target_os = "windows")))]
fn is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    fn create_directory_link(original: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_dir(original, link)
    }

    #[cfg(unix)]
    fn create_directory_link(original: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(original, link)
    }

    #[cfg(windows)]
    fn create_file_link(original: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(original, link)
    }

    #[cfg(unix)]
    fn create_file_link(original: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(original, link)
    }

    fn link_created_or_skipped(result: std::io::Result<()>, description: &str) -> bool {
        match result {
            Ok(()) => {
                eprintln!("executing {description}: link creation succeeded");
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping {description}: link creation is not permitted: {error}");
                false
            }
            Err(error) => panic!("cannot create link for {description}: {error}"),
        }
    }

    fn assert_source_link_rejected(action: impl FnOnce() + std::panic::UnwindSafe, link: &Path) {
        let error = std::panic::catch_unwind(action).expect_err("source link must be rejected");
        let message = error
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| error.downcast_ref::<&str>().copied())
            .expect("source rejection message");
        assert!(
            message.contains("NVX bundle source must not traverse a link or reparse point"),
            "{message}"
        );
        assert!(message.contains(&link.display().to_string()), "{message}");
    }

    fn check_linked_source_parent(create_link: impl FnOnce(&Path, &Path) -> std::io::Result<()>) {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let parent = root.join("parent");
        let source = parent.join("bundle");
        let linked_parent = root.join("linked-parent");
        let destination = root.join("destination");
        std::fs::create_dir_all(&source).expect("source directory");
        std::fs::create_dir(&destination).expect("destination directory");
        std::fs::write(source.join("file"), b"approved contents").expect("source file");
        let sentinel = destination.join("sentinel");
        std::fs::write(&sentinel, b"owned sentinel").expect("destination sentinel");
        let expected_digest = sha256(&source.join("file"));
        let expected = [("file", expected_digest.as_str())];
        verify_bundle_against(&source, &expected);
        let positive_destination = root.join("positive-destination");
        copy_bundle(&source, &positive_destination);
        verify_bundle_against(&positive_destination, &expected);

        if !link_created_or_skipped(
            create_link(&parent, &linked_parent),
            "linked source ancestor rejection",
        ) {
            return;
        }
        let linked_source = linked_parent.join("bundle");
        assert!(!std::fs::symlink_metadata(&linked_source)
            .expect("ordinary bundle under linked parent")
            .file_type()
            .is_symlink());
        assert_source_link_rejected(
            || verify_bundle_against(&linked_source, &expected),
            &linked_parent,
        );
        assert_source_link_rejected(|| copy_bundle(&linked_source, &destination), &linked_parent);
        assert_eq!(
            std::fs::read(&sentinel).expect("unchanged sentinel"),
            b"owned sentinel"
        );
        let entries: Vec<_> = std::fs::read_dir(&destination)
            .expect("destination tree")
            .map(|entry| entry.expect("destination entry").file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("sentinel")]);
        verify_bundle_against(&source, &expected);
    }

    #[test]
    fn rejects_linked_source_ancestor_before_reading_or_writing() {
        check_linked_source_parent(create_directory_link);
    }

    #[cfg(windows)]
    #[test]
    fn rejects_junction_source_ancestor_before_reading_or_writing() {
        check_linked_source_parent(|original, link| {
            let output = std::process::Command::new("cmd.exe")
                .args(["/d", "/c", "mklink", "/J"])
                .arg(link)
                .arg(original)
                .output()?;
            assert!(
                output.status.success(),
                "junction creation failed: {output:?}"
            );
            Ok(())
        });
    }

    #[test]
    fn rejects_linked_source_root_when_supported() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let source = root.join("source");
        let linked_source = root.join("linked-source");
        std::fs::create_dir(&source).expect("source directory");
        std::fs::write(source.join("file"), b"contents").expect("source file");
        let expected_digest = sha256(&source.join("file"));
        let expected = [("file", expected_digest.as_str())];
        verify_bundle_against(&source, &expected);

        if !link_created_or_skipped(
            create_directory_link(&source, &linked_source),
            "linked source root rejection",
        ) {
            return;
        }

        assert_source_link_rejected(
            || verify_bundle_against(&linked_source, &expected),
            &linked_source,
        );
        let destination = root.join("destination");
        assert_source_link_rejected(|| copy_bundle(&linked_source, &destination), &linked_source);
        assert!(
            !destination.exists(),
            "source rejection precedes destination creation"
        );
    }

    #[test]
    fn rejects_linked_destination_before_writing_when_supported() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let source = root.join("source");
        let redirected = root.join("redirected");
        let destination = root.join("destination");
        std::fs::create_dir(&source).expect("source directory");
        std::fs::create_dir(&redirected).expect("redirected directory");
        std::fs::write(source.join("file"), b"contents").expect("source file");
        if !link_created_or_skipped(
            create_directory_link(&redirected, &destination),
            "linked destination directory rejection",
        ) {
            return;
        }

        assert!(std::panic::catch_unwind(|| copy_bundle(&source, &destination)).is_err());
        assert!(
            !redirected.join("file").exists(),
            "destination rejection must happen before the first write"
        );
    }

    #[test]
    fn rejects_linked_destination_file_before_reading_or_writing() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonical temporary root");
        let source = root.join("source");
        let positive_destination = root.join("positive-destination");
        let destination = root.join("destination");
        let sentinel = root.join("sentinel");
        std::fs::create_dir(&source).expect("source directory");
        std::fs::create_dir(&destination).expect("destination directory");
        std::fs::write(source.join("file"), b"approved contents").expect("source file");
        std::fs::write(&sentinel, b"owned sentinel").expect("sentinel file");

        let expected_digest = sha256(&source.join("file"));
        let expected = [("file", expected_digest.as_str())];
        verify_bundle_against(&source, &expected);
        copy_bundle(&source, &positive_destination);
        assert_eq!(
            std::fs::read(positive_destination.join("file")).expect("positive staged file"),
            b"approved contents"
        );

        let destination_file = destination.join("file");
        if !link_created_or_skipped(
            create_file_link(&sentinel, &destination_file),
            "linked destination file rejection",
        ) {
            return;
        }
        let sentinel_digest = sha256(&sentinel);
        let tree_before: Vec<_> = std::fs::read_dir(&destination)
            .expect("destination tree")
            .map(|entry| entry.expect("destination entry").file_name())
            .collect();

        assert!(
            std::panic::catch_unwind(|| copy_bundle(&source, &destination)).is_err(),
            "linked destination file must be rejected"
        );
        assert_eq!(
            sha256(&sentinel),
            sentinel_digest,
            "sentinel must be unchanged"
        );
        let tree_after: Vec<_> = std::fs::read_dir(&destination)
            .expect("destination tree after rejection")
            .map(|entry| {
                entry
                    .expect("destination entry after rejection")
                    .file_name()
            })
            .collect();
        assert_eq!(
            tree_after, tree_before,
            "destination tree must be unchanged"
        );
        assert!(
            std::fs::symlink_metadata(&destination_file)
                .expect("destination link after rejection")
                .file_type()
                .is_symlink(),
            "destination file link must remain in place"
        );
    }
}
