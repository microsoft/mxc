{
  "variables": {
    "mxc_ffi_include_dir%": "../../../src/target/diplomat-bindings/c"
  },
  "targets": [
    {
      "target_name": "mxc_node_ffi",
      "sources": [
        "native/addon.cc",
        "native/runtime.cc",
        "native/generated/operations.cc"
      ],
      "include_dirs": [
        "<(mxc_ffi_include_dir)",
        "native"
      ],
      "defines": [
        "NAPI_VERSION=8"
      ],
      "conditions": [
        [
          "OS=='win'",
          {
            "defines": [
              "WIN32_LEAN_AND_MEAN",
              "NOMINMAX"
            ]
          }
        ],
        [
          "OS=='linux'",
          {
            "libraries": [
              "-ldl"
            ]
          }
        ]
      ]
    }
  ]
}
