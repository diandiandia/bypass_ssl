function hook_native(){
    // Hook EVP_parse_public_key
    var EVP_parse_public_key = Module.getGlobalExportByName("EVP_parse_public_key");
    if (EVP_parse_public_key) {
        Interceptor.attach(EVP_parse_public_key, {
            onEnter: function(args) {
                console.log("=== EVP_parse_public_key called ===");
                console.log("参数1: " + args[0]); // 通常是CBS*
                console.log("参数2: " + args[1]); // 通常是EVP_PKEY**
                
                // 保存参数供退出时使用
                this.evpPkeyPtr = args[1];
            },
            onLeave: function(retval) {
                console.log("EVP_parse_public_key 返回: " + retval);
                if (retval > 0 && this.evpPkeyPtr) {
                    var evpPkey = this.evpPkeyPtr.readPointer();
                    console.log("解析的EVP_PKEY: " + evpPkey);
                    dumpEVP_PKEY(evpPkey, "public");
                }
            }
        });
    }
    
    // Hook EVP_marshal_public_key
    var EVP_marshal_public_key = Module.getGlobalExportByName("EVP_marshal_public_key");
    if (EVP_marshal_public_key) {
        Interceptor.attach(EVP_marshal_public_key, {
            onEnter: function(args) {
                console.log("=== EVP_marshal_public_key called ===");
                console.log("参数1: " + args[0]); // 通常是CBB*
                console.log("参数2: " + args[1]); // 通常是EVP_PKEY*
                
                this.evpPkey = args[1];
                dumpEVP_PKEY(this.evpPkey, "public-marshal");
            },
            onLeave: function(retval) {
                console.log("EVP_marshal_public_key 返回: " + retval);
            }
        });
    }
    
    // Hook EVP_parse_private_key
    var EVP_parse_private_key = Module.getGlobalExportByName("EVP_parse_private_key");
    if (EVP_parse_private_key) {
        Interceptor.attach(EVP_parse_private_key, {
            onEnter: function(args) {
                console.log("=== EVP_parse_private_key called ===");
                console.log("参数1: " + args[0]); // CBS*
                console.log("参数2: " + args[1]); // EVP_PKEY**
                
                this.evpPkeyPtr = args[1];
            },
            onLeave: function(retval) {
                console.log("EVP_parse_private_key 返回: " + retval);
                if (retval > 0 && this.evpPkeyPtr) {
                    var evpPkey = this.evpPkeyPtr.readPointer();
                    console.log("解析的私钥EVP_PKEY: " + evpPkey);
                    dumpEVP_PKEY(evpPkey, "private");
                }
            }
        });
    }
    
    // Hook EVP_marshal_private_key
    var EVP_marshal_private_key = Module.getGlobalExportByName("EVP_marshal_private_key");
    if (EVP_marshal_private_key) {
        Interceptor.attach(EVP_marshal_private_key, {
            onEnter: function(args) {
                console.log("=== EVP_marshal_private_key called ===");
                console.log("参数1: " + args[0]); // CBB*
                console.log("参数2: " + args[1]); // EVP_PKEY*
                
                this.evpPkey = args[1];
                dumpEVP_PKEY(this.evpPkey, "private-marshal");
            },
            onLeave: function(retval) {
                console.log("EVP_marshal_private_key 返回: " + retval);
            }
        });
    }
    
    // 辅助函数：尝试导出EVP_PKEY内容
    function dumpEVP_PKEY(evpPkey, type) {
        try {
            console.log("🔐 处理 " + type + " 密钥: " + evpPkey);
            
            // 尝试调用EVP_PKEY_get0_RSA, EVP_PKEY_get0_EC_KEY等函数
            var EVP_PKEY_get0_RSA = Module.getGlobalExportByName("EVP_PKEY_get0_RSA");
            var EVP_PKEY_get0_EC_KEY = Module.getGlobalExportByName("EVP_PKEY_get0_EC_KEY");
            
            if (EVP_PKEY_get0_RSA) {
                var rsaKey = new NativeFunction(EVP_PKEY_get0_RSA, 'pointer', ['pointer'])(evpPkey);
                if (rsaKey && !rsaKey.isNull()) {
                    console.log("🔑 RSA密钥: " + rsaKey);
                    dumpRSAKey(rsaKey);
                }
            }
            
            if (EVP_PKEY_get0_EC_KEY) {
                var ecKey = new NativeFunction(EVP_PKEY_get0_EC_KEY, 'pointer', ['pointer'])(evpPkey);
                if (ecKey && !ecKey.isNull()) {
                    console.log("🔑 EC密钥: " + ecKey);
                    dumpECKey(ecKey);
                }
            }
            
            // 尝试获取密钥类型
            var EVP_PKEY_id = Module.findExportByName(null, "EVP_PKEY_id");
            if (EVP_PKEY_id) {
                var keyType = new NativeFunction(EVP_PKEY_id, 'int', ['pointer'])(evpPkey);
                console.log("密钥类型: " + keyType + " (" + getKeyTypeName(keyType) + ")");
            }
            
        } catch (e) {
            console.log("导出密钥失败: " + e.message);
        }
    }
    
    // 辅助函数：获取密钥类型名称
    function getKeyTypeName(keyType) {
        var types = {
            6: "RSA",
            408: "EC",
            116: "DSA",
            28: "X25519",
            1034: "ED25519"
        };
        return types[keyType] || "未知类型(" + keyType + ")";
    }
    
    // 辅助函数：导出RSA密钥信息
    function dumpRSAKey(rsaKey) {
        try {
            var RSA_get0_key = Module.getGlobalExportByName("RSA_get0_key");
            if (RSA_get0_key) {
                var nPtr = Memory.alloc(Process.pointerSize);
                var ePtr = Memory.alloc(Process.pointerSize);
                var dPtr = Memory.alloc(Process.pointerSize);
                
                new NativeFunction(RSA_get0_key, 'void', ['pointer', 'pointer', 'pointer', 'pointer'])(
                    rsaKey, nPtr, ePtr, dPtr
                );
                
                var n = nPtr.readPointer();
                var e = ePtr.readPointer();
                var d = dPtr.readPointer();
                
                console.log("RSA模数(n): " + n);
                console.log("RSA指数(e): " + e);
                console.log("RSA私钥指数(d): " + d);
                
                // 尝试读取BIGNUM值
                if (!n.isNull()) dumpBIGNUM(n, "n");
                if (!e.isNull()) dumpBIGNUM(e, "e");
                if (!d.isNull()) dumpBIGNUM(d, "d");
            }
        } catch (e) {
            console.log("导出RSA密钥失败: " + e.message);
        }
    }
    
    // 辅助函数：导出EC密钥信息
    function dumpECKey(ecKey) {
        try {
            var EC_KEY_get0_private_key = Module.getGlobalExportByName("EC_KEY_get0_private_key");
            var EC_KEY_get0_public_key = Module.getGlobalExportByName("EC_KEY_get0_public_key");
            
            if (EC_KEY_get0_private_key) {
                var privKey = new NativeFunction(EC_KEY_get0_private_key, 'pointer', ['pointer'])(ecKey);
                if (privKey && !privKey.isNull()) {
                    console.log("EC私钥: " + privKey);
                    dumpBIGNUM(privKey, "EC私钥");
                }
            }
            
            if (EC_KEY_get0_public_key) {
                var pubKey = new NativeFunction(EC_KEY_get0_public_key, 'pointer', ['pointer'])(ecKey);
                if (pubKey && !pubKey.isNull()) {
                    console.log("EC公钥: " + pubKey);
                    // EC公钥是EC_POINT结构，比较复杂
                }
            }
            
        } catch (e) {
            console.log("导出EC密钥失败: " + e.message);
        }
    }
    
    // 辅助函数：导出BIGNUM值
    function dumpBIGNUM(bn, name) {
        try {
            var BN_num_bytes = Module.getGlobalExportByName("BN_num_bytes");
            var BN_bn2hex = Module.getGlobalExportByName("BN_bn2hex");
            
            if (BN_num_bytes && BN_bn2hex) {
                var numBytes = new NativeFunction(BN_num_bytes, 'int', ['pointer'])(bn);
                var hexPtr = new NativeFunction(BN_bn2hex, 'pointer', ['pointer'])(bn);
                
                if (hexPtr && !hexPtr.isNull()) {
                    var hexStr = hexPtr.readCString();
                    console.log(name + " (hex): " + hexStr);
                    
                    // 释放内存
                    var CRYPTO_free = Module.getGlobalExportByName("CRYPTO_free");
                    if (CRYPTO_free) {
                        new NativeFunction(CRYPTO_free, 'void', ['pointer'])(hexPtr);
                    }
                }
                
                console.log(name + " 长度: " + numBytes + " 字节");
            }
        } catch (e) {
            console.log("导出BIGNUM失败: " + e.message);
        }
    }
}


setTimeout(hook_native, 0);