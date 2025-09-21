const CONFIG = {
  debug: true,
  certificatePath: '/data/local/tmp/cert-der.crt',
  certificatePaths: ['/data/local/tmp/cert-der.crt', '/data/local/tmp/burp-ca.crt'],
  maxMemoryScanSize: 1024 * 1024 * 10,
  stopAfterFirstMatch: true,
  nativeHook: {
    enabled: true,
    targetLibrary: 'libflutter.so',
    pattern: 'FF C3 01 D1 FD 7B 01 A9 FC 6F 02 A9 FA 67 03 A9 F8 5F 04 A9 F6 57 05 A9 F4 4F 06 A9 08 0A 80 52 48 00 00 39'
  }
};

// 工具函数模块
// 工具函数模块
const Utils = {
  log: function(level, message) {
    const prefixes = {
      info: '[.]',
      success: '[+]',
      warning: '[-]',
      error: '[!]',
      debug: '[o]'
    };
    if (level === 'debug' && !CONFIG.debug) return;
    console.log(`${prefixes[level] || '[?]'} ${message}`);
  },
  
  sleep: function(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  },
  
  checkModule: function(name) {
    try {
      return Process.findModuleByName(name) !== null;
    } catch (e) {
      return false;
    }
  },
  
  bytesToHex: function(byteArray) {
    return Array.from(byteArray, byte => ('0' + (byte & 0xFF).toString(16)).slice(-2)).join('');
  }
};

// SSL绕过管理器
const SSLBypassManager = {
  applyHook: function(className, methodName, overloads, implementation, description) {
    try {
      const targetClass = Java.use(className);
      const method = targetClass[methodName];
      
      if (!method) {
        Utils.log('warning', `Method ${methodName} not found in ${className}`);
        return false;
      }
      
      if (overloads) {
        if (Array.isArray(overloads)) {
          overloads.forEach(overload => {
            try {
              method.overload.apply(method, overload).implementation = implementation;
              Utils.log('success', `${description || className}.${methodName} (overload: ${overload.join(', ')})`);
            } catch (err) {
              Utils.log('warning', `Failed to hook overload ${overload.join(', ')} for ${className}.${methodName}: ${err.message}`);
            }
          });
        } else {
          method.overload.apply(method, overloads).implementation = implementation;
          Utils.log('success', `${description || className}.${methodName} (overload: ${overloads.join(', ')})`);
        }
      } else {
        method.implementation = implementation;
        Utils.log('success', `${description || className}.${methodName} (all overloads)`);
      }
      
      return true;
    } catch (err) {
      Utils.log('error', `${description || className}.${methodName}: ${err.message}`);
      return false;
    }
  },
  
  hookSSLContext: function() {
    try {
      const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
      const SSLContext = Java.use('javax.net.ssl.SSLContext');
      
      const TrustManager = Java.registerClass({
        name: 'dev.sslpinning.bypass.TrustManager',
        implements: [X509TrustManager],
        methods: {
          checkClientTrusted: function (chain, authType) { },
          checkServerTrusted: function (chain, authType) { },
          getAcceptedIssuers: function () { return []; }
        }
      });
      
      const TrustManagers = [TrustManager.$new()];
      
      const SSLContext_init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', 
        '[Ljavax.net.ssl.TrustManager;', 
        'java.security.SecureRandom'
      );
      
      SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
        Utils.log('debug', 'Bypassing Trustmanager initialization');
        SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
      };
      
      Utils.log('success', 'SSLContext Hook');
      return true;
    } catch (err) {
      Utils.log('error', `SSLContext Hook: ${err.message}`);
      return false;
    }
  },
  
  loadCustomCertificate: function() {
    try {
      const CertificateFactory = Java.use('java.security.cert.CertificateFactory');
      const FileInputStream = Java.use('java.io.FileInputStream');
      const BufferedInputStream = Java.use('java.io.BufferedInputStream');
      const X509Certificate = Java.use('java.security.cert.X509Certificate');
      const KeyStore = Java.use('java.security.KeyStore');
      const TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
      const SSLContext = Java.use('javax.net.ssl.SSLContext');
      
      let ca = null;
      let certPath = null;
      
      for (let path of CONFIG.certificatePaths) {
        try {
          certPath = path;
          const fileInputStream = FileInputStream.$new(path);
          const bufferedInputStream = BufferedInputStream.$new(fileInputStream);
          const cf = CertificateFactory.getInstance('X.509');
          ca = cf.generateCertificate(bufferedInputStream);
          bufferedInputStream.close();
          break;
        } catch (e) {
          Utils.log('warning', `Failed to load certificate from ${path}: ${e.message}`);
        }
      }
      
      if (!ca) {
        Utils.log('error', 'Failed to load any certificate');
        return null;
      }
      
      const certInfo = Java.cast(ca, X509Certificate);
      Utils.log('info', `Loaded CA: ${certInfo.getSubjectDN()} from ${certPath}`);
      
      const keyStoreType = KeyStore.getDefaultType();
      const keyStore = KeyStore.getInstance(keyStoreType);
      keyStore.load(null, null);
      keyStore.setCertificateEntry('ca', ca);
      
      const tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
      const tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
      tmf.init(keyStore);
      
      Utils.log('success', 'Custom TrustManager created with injected certificate');
      
      SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', 
        '[Ljavax.net.ssl.TrustManager;', 
        'java.security.SecureRandom'
      ).implementation = function(a, b, c) {
        Utils.log('debug', 'App invoked SSLContext.init, using our TrustManager');
        SSLContext.init.overload(
          '[Ljavax.net.ssl.KeyManager;', 
          '[Ljavax.net.ssl.TrustManager;', 
          'java.security.SecureRandom'
        ).call(this, a, tmf.getTrustManagers(), c);
        Utils.log('success', 'SSLContext initialized with custom TrustManager!');
      };
      
      return tmf;
    } catch (err) {
      Utils.log('error', `Certificate loading failed: ${err.message}`);
      return null;
    }
  },
  
  setupExceptionAutoPatcher: function() {
    try {
      const UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
      
      UnverifiedCertError.$init.implementation = function(str) {
        Utils.log('debug', 'Unexpected SSL verification failure, attempting dynamic patch');
        
        try {
          const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
          const exceptionStackIndex = stackTrace.findIndex(stack =>
            stack.getClassName() === 'javax.net.ssl.SSLPeerUnverifiedException'
          );
          
          if (exceptionStackIndex >= 0 && stackTrace.length > exceptionStackIndex + 1) {
            const callingFunctionStack = stackTrace[exceptionStackIndex + 1];
            const className = callingFunctionStack.getClassName();
            const methodName = callingFunctionStack.getMethodName();
            
            Utils.log('debug', `Thrown by ${className}->${methodName}`);
            
            try {
              const callingClass = Java.use(className);
              const callingMethod = callingClass[methodName];
              
              if (!callingMethod || callingMethod.implementation) {
                return this.$init(str);
              }
              
              Utils.log('debug', `Attempting to patch ${className}->${methodName} automatically`);
              const returnTypeName = callingMethod.returnType.type;
              
              callingMethod.implementation = function() {
                Utils.log('debug', `Bypassing ${className}->${methodName} (automatic exception patch)`);
                
                if (returnTypeName === 'void') {
                  return;
                } else if (returnTypeName === 'boolean') {
                  return true;
                } else if (returnTypeName === 'int' || returnTypeName === 'long') {
                  return 0;
                } else {
                  return null;
                }
              };
              
              Utils.log('success', `Automatically patched ${className}->${methodName}`);
            } catch (e) {
              Utils.log('error', `Failed to patch ${className}->${methodName}: ${e.message}`);
            }
          }
        } catch (e) {
          Utils.log('error', `Exception auto-patching failed: ${e.message}`);
        }
        
        return this.$init(str);
      };
      
      Utils.log('success', 'SSLPeerUnverifiedException auto-patcher');
      return true;
    } catch (err) {
      Utils.log('error', `SSLPeerUnverifiedException auto-patcher: ${err.message}`);
      return false;
    }
  }
};

// 原生代码Hook管理器
const NativeHookManager = {
  scanMemoryForPattern: function(moduleName, pattern, callback) {
    try {
      const module = Process.findModuleByName(moduleName);
      if (!module) {
        Utils.log('error', `Module not found: ${moduleName}`);
        return false;
      }
      
      Utils.log('info', `Scanning module: ${module.name} (${module.base}-${module.base.add(module.size)})`);
      
      const ranges = module.enumerateRanges('r-x');
      let found = false;
      
      for (let range of ranges) {
        const scanSize = Math.min(range.size, CONFIG.maxMemoryScanSize);
        Utils.log('debug', `Scanning range: ${range.base} - ${range.base.add(scanSize)}`);
        
        try {
          const matches = Memory.scanSync(range.base, scanSize, pattern);
          
          for (let match of matches) {
            Utils.log('success', `Found pattern match at address: ${match.address}`);
            callback(match.address);
            found = true;
            
            if (CONFIG.stopAfterFirstMatch) {
              return true;
            }
          }
        } catch (e) {
          Utils.log('error', `Memory scan error: ${e.message}`);
          continue;
        }
        
        if (found && CONFIG.stopAfterFirstMatch) {
          break;
        }
      }
      
      return found;
    } catch (err) {
      Utils.log('error', `Memory scanning failed: ${err.message}`);
      return false;
    }
  },
  
  hookSslVerifyResult: function(address) {
    try {
      Interceptor.attach(address, {
        onEnter: function(args) {
          Utils.log('debug', 'Intercepted SSL verification');
        },
        onLeave: function(retval) {
          Utils.log('debug', `ssl_verify_result at ${address}, original result: ${retval}`);
          retval.replace(0x1);
        }
      });
      
      Utils.log('success', `Hooked ssl_verify_result at address: ${address}`);
      return true;
    } catch (err) {
      Utils.log('error', `Failed to hook ssl_verify_result at ${address}: ${err.message}`);
      return false;
    }
  },
  
  monitorLibraryLoading: function(libraryName) {
    try {
      Interceptor.attach(Module.getGlobalExportByName('android_dlopen_ext'), {
        onEnter: function(args) {
          try {
            const loadedSoName = args[0].readCString();
            if (loadedSoName && loadedSoName.indexOf(libraryName) >= 0) {
              Utils.log('info', `Detected loading of target library: ${loadedSoName}`);
              this.isTargetLibrary = true;
            }
          } catch (e) {
            Utils.log('error', `Error reading library name: ${e.message}`);
          }
        },
        onLeave: function(retval) {
          if (this.isTargetLibrary) {
            Utils.log('info', `Library ${libraryName} has been loaded, attempting to hook`);
            this.hookLibrary(libraryName);
          }
        }
      });
      
      Utils.log('success', `Monitoring library loading for: ${libraryName}`);
      return true;
    } catch (err) {
      Utils.log('error', `Failed to set up library loading monitor: ${err.message}`);
      return false;
    }
  },
  
  hookLibrary: function(libraryName) {
    Utils.log('info', `Starting native hooks for ${libraryName}`);
    
    return this.scanMemoryForPattern(libraryName, CONFIG.nativeHook.pattern, (address) => {
      if (address && !address.isNull()) {
        this.hookSslVerifyResult(address);
      }
    });
  }
};

// 主要的Java Hook配置
const SSL_BYPASS_CONFIG = [
  {
    className: 'com.android.org.conscrypt.TrustManagerImpl',
    methodName: 'checkTrustedRecursive',
    description: 'TrustManagerImpl checkTrustedRecursive',
    implementation: function() {
      Utils.log('debug', 'Bypassing TrustManagerImpl checkTrustedRecursive');
      return Java.use('java.util.ArrayList').$new();
    }
  },
  {
    className: 'com.android.org.conscrypt.TrustManagerImpl',
    methodName: 'verifyChain',
    description: 'TrustManagerImpl verifyChain',
    implementation: function(untrustedChain) {
      Utils.log('debug', 'Bypassing TrustManagerImpl verifyChain');
      return untrustedChain;
    }
  },
  {
    className: 'javax.net.ssl.HttpsURLConnection',
    methodName: 'setDefaultHostnameVerifier',
    description: 'HttpsURLConnection setDefaultHostnameVerifier',
    implementation: function() {
      Utils.log('debug', 'Bypassing HttpsURLConnection setDefaultHostnameVerifier');
    }
  },
  {
    className: 'javax.net.ssl.HttpsURLConnection',
    methodName: 'setSSLSocketFactory',
    description: 'HttpsURLConnection setSSLSocketFactory',
    implementation: function() {
      Utils.log('debug', 'Bypassing HttpsURLConnection setSSLSocketFactory');
    }
  },
  {
    className: 'javax.net.ssl.HttpsURLConnection',
    methodName: 'setHostnameVerifier',
    description: 'HttpsURLConnection setHostnameVerifier',
    implementation: function() {
      Utils.log('debug', 'Bypassing HttpsURLConnection setHostnameVerifier');
    }
  }
];

// 高级SSL Bypass配置
const ADVANCED_SSL_BYPASS_CONFIG = [
  {
    className: 'okhttp3.CertificatePinner',
    methodName: 'check',
    overloads: [
      ['java.lang.String', 'java.util.List'],
      ['java.lang.String', '[Ljava.security.cert.Certificate;']
    ],
    description: 'OkHTTPv3 CertificatePinner.check',
    implementation: function(host) {
      Utils.log('debug', `Bypassing OkHTTPv3 CertificatePinner.check for: ${host}`);
    }
  },
  {
    className: 'okhttp3.CertificatePinner',
    methodName: 'check$okhttp',
    overloads: null,
    description: 'OkHTTPv3 CertificatePinner check$okhttp',
    implementation: function(host) {
      Utils.log('debug', `Bypassing OkHTTPv3 CertificatePinner check$okhttp for: ${host}`);
    }
  },
  {
    className: 'com.datatheorem.android.trustkit.pinning.OkHostnameVerifier',
    methodName: 'verify',
    overloads: [
      ['java.lang.String', 'javax.net.ssl.SSLSession'],
      ['java.lang.String', 'java.security.cert.X509Certificate']
    ],
    description: 'Trustkit OkHostnameVerifier',
    implementation: function(host) {
      Utils.log('debug', `Bypassing Trustkit OkHostnameVerifier for: ${host}`);
      return true;
    }
  },
  {
    className: 'com.datatheorem.android.trustkit.pinning.PinningTrustManager',
    methodName: 'checkServerTrusted',
    overloads: null,
    description: 'Trustkit PinningTrustManager',
    implementation: function() {
      Utils.log('debug', 'Bypassing Trustkit PinningTrustManager');
    }
  },
  {
    className: 'com.android.org.conscrypt.OpenSSLSocketImpl',
    methodName: 'verifyCertificateChain',
    overloads: [['[J', 'java.lang.String']],
    description: 'OpenSSLSocketImpl verifyCertificateChain',
    implementation: function(certRefs, authMethod) {
      Utils.log('debug', `Bypassing OpenSSLSocketImpl verifyCertificateChain: ${authMethod}`);
    }
  },
  {
    className: 'com.android.org.conscrypt.OpenSSLEngineSocketImpl',
    methodName: 'verifyCertificateChain',
    overloads: [['[Ljava.lang.Long;', 'java.lang.String']],
    description: 'OpenSSLEngineSocketImpl verifyCertificateChain',
    implementation: function(certRefs, authMethod) {
      Utils.log('debug', `Bypassing OpenSSLEngineSocketImpl verifyCertificateChain: ${authMethod}`);
    }
  },
  {
    className: 'android.webkit.WebViewClient',
    methodName: 'onReceivedSslError',
    overloads: [['android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError']],
    description: 'Android WebViewClient.onReceivedSslError',
    implementation: function(view, handler, error) {
      Utils.log('debug', 'Bypassing Android WebViewClient SSL error handling');
      if (handler && handler.proceed) {
        handler.proceed();
      }
    }
  },
  {
    className: 'org.apache.cordova.CordovaWebViewClient',
    methodName: 'onReceivedSslError',
    overloads: [['android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError']],
    description: 'Apache Cordova WebViewClient',
    implementation: function(webView, handler) {
      Utils.log('debug', 'Bypassing Apache Cordova WebViewClient');
      if (handler && handler.proceed) {
        handler.proceed();
      }
    }
  }
];

// KeyStore.load Hook
function hookKeyStore() {
  try {
    const KeyStore = Java.use('java.security.KeyStore');
    const StringClass = Java.use('java.lang.String');
    const ByteString = Java.use('com.android.okhttp.okio.ByteString');
    
    // 创建缓冲区
    var myArray = new Array(1024);
    for (var i = 0; i < myArray.length; i++) {
      myArray[i] = 0x0;
    }
    var buffer = Java.array('byte', myArray);
    
    // Hook KeyStore.load(java.security.KeyStore$LoadStoreParameter)
    KeyStore.load.overload('java.security.KeyStore$LoadStoreParameter').implementation = function(arg0) {
      Utils.log('debug', 'KeyStore.load(LoadStoreParameter) called');
      Utils.log('debug', Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()));
      Utils.log('debug', `KeyStore.load1: ${arg0}`);
      
      // 提取密码（如果存在）
      if (arg0) {
        try {
          const PasswordProtection = Java.use('java.security.KeyStore$PasswordProtection');
          if (Java.cast(arg0, PasswordProtection)) {
            const password = arg0.getPassword();
            if (password) {
              const passwordStr = StringClass.$new(password);
              Utils.log('debug', `KeyStore.load1 password: ${passwordStr}`);
            } else {
              Utils.log('debug', 'KeyStore.load1 password: null');
            }
          }
        } catch (e) {
          Utils.log('warning', `Failed to extract password from LoadStoreParameter: ${e.message}`);
        }
      }
      
      this.load(arg0);
    };
    
    // Hook KeyStore.load(java.io.InputStream, [C)
    KeyStore.load.overload('java.io.InputStream', '[C').implementation = function(arg0, arg1) {
      Utils.log('debug', 'KeyStore.load(InputStream, char[]) called');
      Utils.log('debug', Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()));
      
      // 打印密码
      const password = arg1 ? StringClass.$new(arg1) : null;
      Utils.log('debug', `KeyStore.load2 password: ${password || 'null'}`);
      
      // 读取并打印证书（hex 编码）
      if (arg0) {
        try {
          let data = [];
          let r;
          while ((r = arg0.read(buffer)) > 0) {
            let chunk = buffer.slice(0, r);
            data = data.concat(Array.from(chunk));
          }
          const hexData = Utils.bytesToHex(data);
          Utils.log('debug', `KeyStore.load2 certificate (hex): ${hexData}`);
        } catch (e) {
          Utils.log('error', `Failed to read InputStream: ${e.message}`);
        }
      } else {
        Utils.log('debug', 'KeyStore.load2 InputStream: null');
      }
      
      this.load(arg0, arg1);
    };
    
    Utils.log('success', 'hook_KeyStore_load');
  } catch (err) {
    Utils.log('error', `hook_KeyStore_load failed: ${err.message}`);
  }
}


// 应用所有的bypass配置
function applyBypassConfig(configArray) {
  let successCount = 0;
  let failCount = 0;
  
  for (let config of configArray) {
    const result = SSLBypassManager.applyHook(
      config.className,
      config.methodName,
      config.overloads,
      config.implementation,
      config.description
    );
    
    if (result) {
      successCount++;
    } else {
      failCount++;
    }
  }
  
  return { successCount, failCount };
}

// Java Hook主函数
function hook_java() {
  if (!Java.available) {
    Utils.log('error', 'Java is not available');
    return;
  }
  
  Utils.log('info', 'Starting Java SSL bypass hooks');
  
  Java.perform(function() {
    try {
      SSLBypassManager.setupExceptionAutoPatcher();
      SSLBypassManager.hookSSLContext();
      const basicResults = applyBypassConfig(SSL_BYPASS_CONFIG);
      Utils.log('info', `Basic SSL bypass: ${basicResults.successCount} successful, ${basicResults.failCount} failed`);
      const advancedResults = applyBypassConfig(ADVANCED_SSL_BYPASS_CONFIG);
      Utils.log('info', `Advanced SSL bypass: ${advancedResults.successCount} successful, ${advancedResults.failCount} failed`);
      // SSLBypassManager.loadCustomCertificate();
      hookKeyStore(); // 添加 KeyStore hook
      Utils.log('success', 'SSL unpinning setup completed');
    } catch (err) {
      Utils.log('error', `Java hook initialization failed: ${err.message}`);
    }
  });
}

// 原生Hook主函数
function hook_native() {
  if (!CONFIG.nativeHook.enabled) {
    Utils.log('info', 'Native hooking is disabled in configuration');
    return;
  }
  
  if (Process.arch !== 'arm64') {
    Utils.log('warning', `This script is optimized for arm64 architecture, but running on ${Process.arch}`);
  }
  
  Utils.log('info', 'Starting native SSL bypass hooks');
  
  try {
    NativeHookManager.monitorLibraryLoading(CONFIG.nativeHook.targetLibrary);
    if (Utils.checkModule(CONFIG.nativeHook.targetLibrary)) {
      NativeHookManager.hookLibrary(CONFIG.nativeHook.targetLibrary);
    }
  } catch (err) {
    Utils.log('error', `Native hook initialization failed: ${err.message}`);
  }
}

// 主入口函数
function hook_all() {
  Utils.log('info', 'Starting comprehensive SSL unpinning');
  Utils.log('info', `Running on architecture: ${Process.arch}`);
  
  try {
    hook_java();
    setTimeout(hook_native, 100);
  } catch (err) {
    Utils.log('error', `Global hook initialization failed: ${err.message}`);
  }
}

// 启动所有Hook
setTimeout(hook_all, 0);