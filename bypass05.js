// Native SSL 绕过脚本
// 用于 Hook Android 应用的原生 SSL 验证函数

// 配置选项
const CONFIG = {
  debug: true,
  maxMemoryScanSize: 1024 * 1024 * 10, // 最大扫描内存 (10MB)
  stopAfterFirstMatch: true, // 找到第一个匹配后停止
  nativeHook: {
    enabled: true,
    targetLibrary: 'libflutter.so',
    pattern: 'FF C3 01 D1 FD 7B 01 A9 FC 6F 02 A9 FA 67 03 A9 F8 5F 04 A9 F6 57 05 A9 F4 4F 06 A9 08 0A 80 52 48 00 00 39'
  }
};

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
  
  checkModule: function(name) {
    try {
      return Process.findModuleByName(name) !== null;
    } catch (e) {
      return false;
    }
  }
};

// 原生代码 Hook 管理器
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
            NativeHookManager.hookLibrary(libraryName);
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

// 主入口函数
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

// 启动 Native Hook
setTimeout(hook_native, 0);