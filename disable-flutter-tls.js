function hook_java() {
    if (Java.available) {
        Java.perform(function () {
            console.log("Java available");

        });
    }
}

function hook_ssl_verify_result(address) {
    Interceptor.attach(address, {
        onEnter: function (args) {
            console.log("Disabling SSL validation")
        },
        onLeave: function (retval) {
            console.log("ssl_verify_result: " + address);
            console.log("Retval: " + retval);
            retval.replace(0x1);
        }
    });
}

function hook_flutter() {
    if (Process.arch == "arm64") {
        var pattern = "FF C3 01 D1 FD 7B 01 A9 FC 6F 02 A9 FA 67 03 A9 F8 5F 04 A9 F6 57 05 A9 F4 4F 06 A9 08 0A 80 52 48 00 00 39";
    } else {
        var pattern = "2D E9 F0 4F 85 B0 06 46 50 20 10 70";
    }

    var m = Process.findModuleByName("libflutter.so");
    if (!m) {
        console.error("libflutter.so not found");
        return;
    }
    console.log("libflutter.so base: " + m.base + ", size: " + m.size);
    var ranges = m.enumerateRanges('r-x');
    var found = false;
    for (let range of ranges) {
        console.log("Range: " + range.base + ", size: " + range.size + ", protection: " + range.protection);
        var matches = Memory.scanSync(range.base, range.size, pattern);
        matches.forEach(function (match) {
            found = true;
            if (Process.arch == 'arm64') {
                var match_address = match.address
                console.log("Match found at: " + match_address.toString());
            } else {
                match_address = match.address.add(0x1);
                console.log("Match found at: " + match_address.toString());
            }

            hook_ssl_verify_result(match_address);
        });
        if (found) {
            console.log("Match found in range: " + range.base + " - " + range.end);
            break;
        }
    }
    if (!found) {
        console.log("Match not found");
    }

}

function hook_native() {
    hook_flutter();
}


function hook_all() {
    hook_java();
    hook_native();
}

setTimeout(hook_all, 0);