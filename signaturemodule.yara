rule Keylogger {
    meta:
        description = "detects keyloggers using  using different techniques"
        author = "Pele"
        date = "2025-04-04"
        threat_level = "High"
        reference = "Kkeyloggers leveraging imports and hooks for keyboard monitoring"
    
    strings:
      
        $import_pynput = "import pynput" nocase wide ascii
        $from_pynput = "from pynput" nocase wide ascii
        $keyboard_listener = "keyboard.Listener" nocase wide ascii
        $on_press = "on_press" nocase wide ascii
        $on_release = "on_release" nocase wide ascii
        
        $write_to_file = /open\(.{1,100}, ['"]w['"]/ nocase wide ascii
        $append_to_file = /open\(.{1,100}, ['"]a['"]/ nocase wide ascii
        $key_log_var = /key.{0,20}log/ nocase wide ascii
        
        $get_async_key = "GetAsyncKeyState" wide ascii
        $user32_dll = "user32.dll" wide ascii
        $keyboard_hook = "SetWindowsHookEx" wide ascii
        $wh_keyboard = "WH_KEYBOARD" wide ascii
        $keybd_event = "keybd_event" wide ascii
        
        $base64_pynput = "cHlucHV0" wide ascii // Base64 of "pynput"
        $hidden_import = /__import__\(['"]pynput['"]/ nocase wide ascii
        
    condition:
        (
            ($import_pynput or $from_pynput) and
            (
                $keyboard_listener or
                $on_press or
                $on_release
            ) and
            (
                $write_to_file or
                $append_to_file or
                $key_log_var
            )
        ) or
        (
            (
                $import_pynput or
                $from_pynput or
                $base64_pynput or
                $hidden_import
            ) and
            (
                $get_async_key or
                ($user32_dll and ($keyboard_hook or $wh_keyboard or $keybd_event))
            )
        )
}