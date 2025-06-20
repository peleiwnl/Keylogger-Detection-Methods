// check if a hook is keyboard-related
function isKeyboardHook(idHook) {
    // WH_KEYBOARD = 2, WH_KEYBOARD_LL = 13
    return idHook === 2 || idHook === 13;
}

// find the export of SetWindowsHookExA in user32.dll
var hookAddress = Module.findExportByName("user32.dll", "SetWindowsHookExA");
if (hookAddress) {
    Interceptor.attach(hookAddress, {
        onEnter: function (args) {
            var idHook = args[0].toInt32();
            var message = "SetWindowsHookExA called with parameters:\n" +
                 " idHook: " + idHook + "\n" +
                 " lpfn: " + args[1] + "\n" +
                 " hMod: " + args[2] + "\n" +
                 " dwThreadId: " + args[3].toInt32() + "\n" +
                 " ProcessID: " + Process.id;
                 
            if (isKeyboardHook(idHook)) {
                message += "\n\nWARNING: This process could be malicious! It uses Keyboard Windows API functions for keystroke logging!";
            }
            
            send(message);
        },
        onLeave: function (retval) {
            send("SetWindowsHookExA returned: " + retval);
        }
    });
} else {
    send("SetWindowsHookExA not found");
}

// unicode version
var hookAddressW = Module.findExportByName("user32.dll", "SetWindowsHookExW");
if (hookAddressW) {
    Interceptor.attach(hookAddressW, {
        onEnter: function (args) {
            var idHook = args[0].toInt32();
            var message = "SetWindowsHookExW called with parameters:\n" +
                 " idHook: " + idHook + "\n" +
                 " lpfn: " + args[1] + "\n" +
                 " hMod: " + args[2] + "\n" +
                 " dwThreadId: " + args[3].toInt32() + "\n" +
                 " ProcessID: " + Process.id;
                 
            if (isKeyboardHook(idHook)) {
                message += "\n\nWARNING: This process could be malicious! It uses Keyboard Windows API functions for keystroke logging!";
            }
            
            send(message);
        },
        onLeave: function (retval) {
            send("SetWindowsHookExW returned: " + retval);
        }
    });
} else {
    send("SetWindowsHookExW not found!");
}

// hook GetAsyncKeyState in user32.dll
var gasAddress = Module.findExportByName("user32.dll", "GetAsyncKeyState");
if (gasAddress) {
    Interceptor.attach(gasAddress, {
        onEnter: function (args) {
            send("GetAsyncKeyState called: key code " + args[0].toInt32() + " in process " + Process.id + 
                 "\n\nWARNING: This process could be malicious! It uses Keyboard Windows API functions for keystroke logging!");
        }
    });
} else {
    send("GetAsyncKeyState not found!");
}

// hook GetKeyState
var gksAddress = Module.findExportByName("user32.dll", "GetKeyState");
if (gksAddress) {
    Interceptor.attach(gksAddress, {
        onEnter: function (args) {
            send("GetKeyState called: key code " + args[0].toInt32() + " in process " + Process.id + 
                 "\n\nWARNING: This process could be malicious! It uses Keyboard Windows API functions for keystroke logging!");
        }
    });
} else {
    send("GetKeyState not found!");
}

// hook GetKeyboardState
var gkbsAddress = Module.findExportByName("user32.dll", "GetKeyboardState");
if (gkbsAddress) {
    Interceptor.attach(gkbsAddress, {
        onEnter: function (args) {
            send("GetKeyboardState called in process " + Process.id + 
                 "\n\nWARNING: This process could be malicious! It uses Keyboard Windows API functions for keystroke logging!");
        }
    });
} else {
    send("GetKeyboardState not found!");
}