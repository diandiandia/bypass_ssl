function hook_dlopen() {
    var android_dlopen_ext = Module.getGlobalExportByName("android_dlopen_ext");
    console.log("android_dlopen_ext: " + android_dlopen_ext);
    Interceptor.attach(android_dlopen_ext, {
        onEnter: function (args) {
            var so_name = args[0].readCString();
            if (so_name.indexOf("libflutter.so") >= 0) this.call_hook = true;
        }, onLeave: function (retval) {
            if (this.call_hook) hookFlutter();
        }
    });
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
    //利用函数前10字节定位
    var pattern = "FF C3 01 D1 FD 7B 01 A9 FC 6F 02 A9FA 67 03 A9 F8 5F 04 A9 F6 57 05 A9 F4 4F 06 A9 08 0A 80 52 48 00 00 39";
    Memory.protect(m.base, m.size, 'rwx');
    var res = Memory.scan(m.base, m.size, pattern, {
        onMatch: function(address, size){
            console.log('[+] ssl_verify_result found at: ' + address.toString());
        // Add 0x01 because it's a THUMB function
        // Otherwise, we would get 'Error: unable to intercept function at 0x9906f8ac; please file a bug'
            hook_ssl_verify_result(address);
        },
        onError: function(reason){
            console.log('[!] There was an error scanning memory');
        },
        onComplete: function() {
            console.log("All done")
        }
    });
}

setTimeout(hook_dlopen, 0);