{
    "targets": [
        {
            "target_name": "multihashing",
            "sources": [
                "multihashing.cc",
                "cryptonight_common.c",
                "cryptonight.c",
                "crypto/c_blake256.c",
                "crypto/c_groestl.c",
                "crypto/c_jh.c",
                "crypto/c_keccak.c",
                "crypto/c_skein.c",
                "crypto/hash.c",
                "crypto/oaes_lib.c",
                "crypto/soft_aes.c",
                "sha3/sph_keccak.c",
            ],
            "include_dirs": [
                "crypto",
                "<!(node -e \"require('nan')\")",
            ],
			"cflags_c": [
				"-std=gnu11 -march=native -fPIC -m64"
			],
            "cflags_cc": [
                "-std=gnu++11 -fPIC -m64"
            ],
        }
    ]
}
