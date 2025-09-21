function hook_dlopen() {
    var android_dlopen_ext_ptr = Module.getGlobalExportByName("android_dlopen_ext");
    if (android_dlopen_ext_ptr) {
        // Now you can use android_dlopen_ext_ptr
        console.log("android_dlopen_ext found at: " + android_dlopen_ext_ptr);
        Interceptor.attach(android_dlopen_ext_ptr, {
            onEnter: function (args) {
                var so_name = args[0].readCString();
                if (so_name.indexOf("libflutter.so") >= 0) this.call_hook = true;
            }   , onLeave: function (retval) {
                if (this.call_hook) hookFlutter();
            }
        });
    } else {
        console.error("android_dlopen_ext not found in libdl.so");
    }
}

function hook_ssl_verify_result(address) {
    Interceptor.attach(address, {
            onEnter: function(args) {
                console.log("Disabling SSL validation")
            },
            onLeave: function(retval) {
                console.log("ssl_verify_result: " + address);
                console.log("Retval: " + retval);
                retval.replace(0x1);
            }
        });
    }
function hookFlutter() {
    var m = Process.findModuleByName("libflutter.so");
    if (!m) {
        console.error("libflutter.so not found");
        return;
    }
    console.log("libflutter.so base: " + m.base + ", size: " + m.size);

    var pattern = "FF C3 01 D1 FD 7B 01 A9 FC 6F 02 A9 FA 67 03 A9 F8 5F 04 A9 F6 57 05 A9 F4 4F 06 A9 08 0A 80 52 48 00 00 39";
    var pageSize = Process.pageSize;
    var scanSize = m.size - (m.size % pageSize); // Align to page size

    // Grant permissions page by page
    for (var addr = m.base; addr < m.base.add(m.size); addr = addr.add(pageSize)) {
        try {
            Memory.protect(addr, pageSize, 'rwx');
        } catch (e) {
            console.log("Failed to set permissions for page at: " + addr + ", error: " + e);
        }
    }

    Memory.scan(m.base, scanSize, pattern, {
        onMatch: function(address, size) {
            console.log('[+] ssl_verify_result found at: ' + address.toString());
            hook_ssl_verify_result(address);
        },
        onError: function(reason) {
            console.log('[!] Memory scan error: ' + reason);
        },
        onComplete: function() {
            console.log("Memory scan completed");
        }
    });
}

setTimeout(hook_dlopen, 0);


