#RequireAdmin
#include <Array.au3>

; ============================================
; PWI 64-bit Base Address Finder
; ============================================
; 1. Log into a character on elementclient_64.exe
; 2. Run this script
; 3. It will find and display the base address
; ============================================

; Known offsets from the 32-bit bot
Global $PLAYER_OFFSET = 52        ; 0x34
Global $PLAYERNAME_OFFSET = 2960  ; 0xB90
Global $PLAYERID_OFFSET = 2056   ; 0x808

; Step 1: Find the process
Local $PID = ProcessExists("elementclient_64.exe")
If $PID = 0 Then
    MsgBox(16, "Error", "elementclient_64.exe is not running!" & @CRLF & @CRLF & "Please log into a character first, then run this script again.")
    Exit
EndIf

MsgBox(64, "Process Found", "Found elementclient_64.exe (PID: " & $PID & ")" & @CRLF & @CRLF & "Click OK to start scanning. This may take 1-5 minutes." & @CRLF & "A message will pop up when done.")

; Step 2: Open the process with correct 64-bit types
Local $hKernel32 = DllOpen("kernel32.dll")
Local $aOpenProc = DllCall($hKernel32, "handle", "OpenProcess", "dword", 0x1F0FFF, "bool", 0, "dword", $PID)
If $aOpenProc[0] = 0 Then
    MsgBox(16, "Error", "Failed to open process. Try running as Administrator.")
    DllClose($hKernel32)
    Exit
EndIf
Local $hProcess = $aOpenProc[0]

; Step 3: Get the base address of elementclient_64.exe module
Local $sModuleName = "elementclient_64.exe"
Local $hModuleBase = _GetModuleBaseAddress($PID, $sModuleName)
If $hModuleBase = 0 Then
    MsgBox(16, "Error", "Could not find module base address for " & $sModuleName)
    DllCall($hKernel32, "bool", "CloseHandle", "handle", $hProcess)
    DllClose($hKernel32)
    Exit
EndIf

; Step 4: Ask user for character name
Local $charName = InputBox("Character Name", "Type your character's name EXACTLY as it appears in-game:" & @CRLF & "(This is case-sensitive)", "", "", 400, 200)
If $charName = "" Then
    MsgBox(16, "Error", "You must enter a character name.")
    DllCall($hKernel32, "bool", "CloseHandle", "handle", $hProcess)
    DllClose($hKernel32)
    Exit
EndIf

; Step 5: Try the known 32-bit ADDRESS_BASE first (unlikely to work but fast check)
Local $oldBase = 22982616
ConsoleWrite("Trying old 32-bit ADDRESS_BASE (0x" & Hex($oldBase) & ")..." & @CRLF)
Local $testName = _TryReadName($hProcess, $hKernel32, $oldBase)
If $testName = $charName Then
    MsgBox(64, "SUCCESS - Same Address!", "The 32-bit ADDRESS_BASE works for 64-bit too!" & @CRLF & @CRLF & "$ADDRESS_BASE = " & $oldBase & "  (0x" & Hex($oldBase) & ")" & @CRLF & @CRLF & "Character name: " & $testName)
    DllCall($hKernel32, "bool", "CloseHandle", "handle", $hProcess)
    DllClose($hKernel32)
    Exit
EndIf

; Step 6: Scan memory for the character name (UTF-16)
ConsoleWrite("Scanning memory for character name: " & $charName & @CRLF)
Local $nameBytes = StringToBinary($charName, 2) ; UTF-16 LE
Local $nameHex = StringTrimLeft(String($nameBytes), 2) ; Remove "0x" prefix

; Scan regions of memory
Local $foundAddresses = _ScanForString($hProcess, $hKernel32, $charName)

If UBound($foundAddresses) = 0 Then
    MsgBox(16, "Not Found", "Could not find character name in memory." & @CRLF & @CRLF & "Make sure:" & @CRLF & "- You typed the name exactly right (case-sensitive)" & @CRLF & "- You are logged in on the character" & @CRLF & "- The game is not minimized")
    DllCall($hKernel32, "bool", "CloseHandle", "handle", $hProcess)
    DllClose($hKernel32)
    Exit
EndIf

ConsoleWrite("Found " & UBound($foundAddresses) & " matches for character name in memory." & @CRLF)

; Step 7: For each name address, work backwards through pointer chain
; Name is at: [[[BASE] + 0x1C] + 0x34] + 0xB90 -> pointer to name string
; So name string pointer is at: player + 0xB90
; Player is at: [[BASE] + 0x1C] + 0x34
; We need to find what points to (nameAddr) -> that's the name string pointer location = player + 0xB90
; So player = nameStringPointerAddr - 0xB90

Local $results = ""
Local $resultCount = 0

For $i = 0 To UBound($foundAddresses) - 1
    Local $nameAddr = $foundAddresses[$i]
    ConsoleWrite("Checking name address: 0x" & Hex($nameAddr) & @CRLF)

    ; Find what pointer points to this name address
    ; Scan for pointers to this address
    Local $ptrToName = _ScanForPointer($hProcess, $hKernel32, $nameAddr)

    For $p = 0 To UBound($ptrToName) - 1
        Local $namePointerAddr = $ptrToName[$p]
        ; namePointerAddr should be player + PLAYERNAME_OFFSET
        Local $playerAddr = $namePointerAddr - $PLAYERNAME_OFFSET

        ; Verify: read player ID at player + PLAYERID_OFFSET, should be non-zero
        Local $testID = _ReadDword($hProcess, $hKernel32, $playerAddr + $PLAYERID_OFFSET)
        If $testID = 0 Then ContinueLoop

        ; Verify: re-read name from this player address
        Local $testName2 = _ReadNameFromPlayer($hProcess, $hKernel32, $playerAddr)
        If $testName2 <> $charName Then ContinueLoop

        ConsoleWrite("Valid player object at: 0x" & Hex($playerAddr) & " (ID: " & $testID & ")" & @CRLF)

        ; Now find what points to playerAddr at offset 0x34
        ; [[BASE] + 0x1C] + 0x34 = playerAddr
        ; So [BASE] + 0x1C points to (playerAddr - 0x34) ... no
        ; Actually: read value at [[BASE]+0x1C] + 0x34 = playerAddr
        ; So we need address where value at addr+0x34 = playerAddr
        ; Scan for (playerAddr) at offset 0x34 from some pointer

        Local $playerListAddr = 0
        ; Scan for pointer to playerAddr, but the pointer is at someAddr + 0x34
        ; So we scan for the value playerAddr, and check if the address is someAddr + 0x34
        Local $ptrToPlayer = _ScanForPointer($hProcess, $hKernel32, $playerAddr)

        For $q = 0 To UBound($ptrToPlayer) - 1
            ; ptrToPlayer[$q] has value = playerAddr
            ; This should be at [BASE]+0x1C + 0x34
            ; So [BASE]+0x1C = ptrToPlayer[$q] - 0x34
            Local $level2Addr = $ptrToPlayer[$q] - $PLAYER_OFFSET

            ; Now find what pointer + 0x1C = level2Addr
            ; [BASE] + 0x1C should point to level2Addr... no
            ; [BASE] value + 0x1C -> read -> should give level2Addr
            ; Actually: read([BASE]) = someVal, then read(someVal + 0x1C) = level2Addr
            ; So someVal + 0x1C is at an address that has value level2Addr
            ; We need to find someVal where read(someVal+0x1C) = level2Addr

            ; Check if level2Addr - 0x1C is a valid read that gives us something useful
            Local $ptrToLevel2 = _ScanForPointer($hProcess, $hKernel32, $level2Addr)

            For $r = 0 To UBound($ptrToLevel2) - 1
                ; ptrToLevel2[$r] has value = level2Addr
                ; This should be at someAddr + 0x1C
                Local $gameObjMgrPtr = $ptrToLevel2[$r] - 0x1C

                ; Now find what static address points to gameObjMgrPtr value
                ; [BASE] = gameObjMgrPtr... no, BASE is the address, and read(BASE) = gameObjMgrPtr
                ; We need to find BASE where read(BASE) = gameObjMgrPtr
                ; Actually gameObjMgrPtr IS the value we read from BASE
                ; So we scan for the value gameObjMgrPtr as a pointer

                Local $ptrToGameObj = _ScanForPointerInModule($hProcess, $hKernel32, $gameObjMgrPtr, $hModuleBase)

                For $s = 0 To UBound($ptrToGameObj) - 1
                    Local $baseAddr = $ptrToGameObj[$s]
                    ; VERIFY the full chain
                    Local $verifyName = _TryReadName($hProcess, $hKernel32, $baseAddr)
                    If $verifyName = $charName Then
                        $resultCount += 1
                        $results &= "ADDRESS_BASE = " & $baseAddr & "  (0x" & Hex($baseAddr) & ")" & @CRLF
                        $results &= "  Module offset: 0x" & Hex($baseAddr - $hModuleBase) & @CRLF
                        $results &= "  Character: " & $verifyName & @CRLF
                        $results &= "  Player ID: " & $testID & @CRLF
                        $results &= @CRLF
                        ConsoleWrite("*** FOUND BASE: " & $baseAddr & " (0x" & Hex($baseAddr) & ") ***" & @CRLF)
                    EndIf
                Next
            Next
        Next
    Next
Next

; Step 8: Show results
If $resultCount > 0 Then
    MsgBox(64, "SUCCESS! Found " & $resultCount & " result(s)", "Results:" & @CRLF & @CRLF & $results & @CRLF & "Copy the ADDRESS_BASE value and give it to Claude!")
    ClipPut($results)
    MsgBox(64, "Copied!", "Results have been copied to your clipboard.")
Else
    ; Fallback: just report found name addresses and try common base patterns
    ConsoleWrite("Full chain scan failed. Trying brute force on module..." & @CRLF)

    Local $bruteResults = ""
    Local $bruteCount = 0

    ; Scan every dword in the .data/.rdata sections of the module (first 32MB)
    Local $scanSize = 0x2000000 ; 32MB
    Local $chunkSize = 4096
    For $offset = 0 To $scanSize - 1 Step $chunkSize
        Local $addr = $hModuleBase + $offset
        Local $chunk = _ReadBytes($hProcess, $hKernel32, $addr, $chunkSize)
        If @error Then ContinueLoop

        For $bytePos = 0 To $chunkSize - 4 Step 4
            Local $val = _BytesToDword($chunk, $bytePos)
            If $val < 0x10000 Or $val > 0x7FFFFFFFFFFF Then ContinueLoop

            Local $testName3 = _TryReadName($hProcess, $hKernel32, $addr + $bytePos)
            If $testName3 = $charName Then
                $bruteCount += 1
                $bruteResults &= "ADDRESS_BASE = " & ($addr + $bytePos) & "  (0x" & Hex($addr + $bytePos) & ")" & @CRLF
                $bruteResults &= "  Module offset: elementclient_64.exe+0x" & Hex($offset + $bytePos) & @CRLF
                $bruteResults &= @CRLF
                ConsoleWrite("*** BRUTE FORCE FOUND: 0x" & Hex($addr + $bytePos) & " ***" & @CRLF)
            EndIf
        Next

        ; Progress every 4MB
        If Mod($offset, 0x400000) = 0 Then
            ConsoleWrite("Scanning module... " & Round($offset / $scanSize * 100) & "%" & @CRLF)
        EndIf
    Next

    If $bruteCount > 0 Then
        MsgBox(64, "SUCCESS (brute force)! Found " & $bruteCount & " result(s)", $bruteResults & @CRLF & "Copy the ADDRESS_BASE value and give it to Claude!")
        ClipPut($bruteResults)
    Else
        Local $nameAddrList = ""
        For $i = 0 To UBound($foundAddresses) - 1
            $nameAddrList &= "0x" & Hex($foundAddresses[$i]) & @CRLF
        Next
        MsgBox(48, "Partial Results", "Could not find the full pointer chain automatically." & @CRLF & @CRLF & "Found character name at these addresses:" & @CRLF & $nameAddrList & @CRLF & "Please share these addresses with Claude for further analysis.")
        ClipPut($nameAddrList)
    EndIf
EndIf

DllCall($hKernel32, "bool", "CloseHandle", "handle", $hProcess)
DllClose($hKernel32)
MsgBox(64, "Done", "Scan complete. Results copied to clipboard.")

; ============================================
; HELPER FUNCTIONS
; ============================================

Func _ReadDword($hProc, $hK32, $addr)
    Local $buf = DllStructCreate("dword")
    DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $addr, "ptr", DllStructGetPtr($buf), "ulong_ptr", 4, "ulong_ptr*", 0)
    If @error Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

Func _ReadPtr($hProc, $hK32, $addr)
    Local $buf = DllStructCreate("ptr")
    DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $addr, "ptr", DllStructGetPtr($buf), "ulong_ptr", DllStructGetSize($buf), "ulong_ptr*", 0)
    If @error Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

Func _ReadBytes($hProc, $hK32, $addr, $size)
    Local $buf = DllStructCreate("byte[" & $size & "]")
    Local $ret = DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $addr, "ptr", DllStructGetPtr($buf), "ulong_ptr", $size, "ulong_ptr*", 0)
    If @error Or $ret[0] = 0 Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

Func _BytesToDword($bytes, $offset)
    Local $buf = DllStructCreate("byte[4]")
    DllStructSetData($buf, 1, BinaryMid($bytes, $offset + 1, 4))
    Local $buf2 = DllStructCreate("dword", DllStructGetPtr($buf))
    Return DllStructGetData($buf2, 1)
EndFunc

Func _TryReadName($hProc, $hK32, $baseAddr)
    ; Follow: [[[baseAddr] + 0x1C] + 0x34] + 0xB90 -> pointer -> name string
    Local $val1 = _ReadDword($hProc, $hK32, $baseAddr)
    If $val1 = 0 Then Return ""
    Local $val2 = _ReadDword($hProc, $hK32, $val1 + 0x1C)
    If $val2 = 0 Then Return ""
    Local $player = _ReadDword($hProc, $hK32, $val2 + 0x34)
    If $player = 0 Then Return ""
    Local $namePtr = _ReadDword($hProc, $hK32, $player + 2960)
    If $namePtr = 0 Then Return ""
    Local $nameBuf = DllStructCreate("wchar[50]")
    DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $namePtr, "ptr", DllStructGetPtr($nameBuf), "ulong_ptr", 100, "ulong_ptr*", 0)
    Return DllStructGetData($nameBuf, 1)
EndFunc

Func _ReadNameFromPlayer($hProc, $hK32, $playerAddr)
    Local $namePtr = _ReadDword($hProc, $hK32, $playerAddr + 2960)
    If $namePtr = 0 Then Return ""
    Local $nameBuf = DllStructCreate("wchar[50]")
    DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $namePtr, "ptr", DllStructGetPtr($nameBuf), "ulong_ptr", 100, "ulong_ptr*", 0)
    Return DllStructGetData($nameBuf, 1)
EndFunc

Func _ScanForString($hProc, $hK32, $searchStr)
    Local $searchBytes = StringToBinary($searchStr, 2) ; UTF-16 LE
    Local $searchLen = BinaryLen($searchBytes)
    Local $results[0]

    ; Query memory regions
    Local $addr = 0
    Local $mbi = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")

    While 1
        Local $ret = DllCall($hK32, "ulong_ptr", "VirtualQueryEx", "handle", $hProc, "ptr", $addr, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
        If @error Or $ret[0] = 0 Then ExitLoop

        Local $regionBase = DllStructGetData($mbi, "BaseAddress")
        Local $regionSize = DllStructGetData($mbi, "RegionSize")
        Local $state = DllStructGetData($mbi, "State")
        Local $protect = DllStructGetData($mbi, "Protect")

        ; Only scan committed, readable memory
        If $state = 0x1000 And BitAND($protect, 0x100) = 0 And $regionSize < 0x10000000 Then
            ; Read in chunks
            Local $chunkSize = 65536
            If $regionSize < $chunkSize Then $chunkSize = $regionSize
            For $offset = 0 To $regionSize - $searchLen Step $chunkSize
                Local $readSize = $chunkSize
                If $offset + $readSize > $regionSize Then $readSize = $regionSize - $offset
                Local $data = _ReadBytes($hProc, $hK32, $regionBase + $offset, $readSize)
                If @error Then ContinueLoop
                Local $pos = 1
                While 1
                    Local $found = StringInStr(BinaryToString($data, 2), $searchStr, 1, 1, $pos)
                    If $found = 0 Then ExitLoop
                    Local $foundAddr = $regionBase + $offset + ($found - 1) * 2
                    ReDim $results[UBound($results) + 1]
                    $results[UBound($results) - 1] = $foundAddr
                    $pos = $found + 1
                    If UBound($results) >= 50 Then ExitLoop 2
                WEnd
            Next
        EndIf

        $addr = $regionBase + $regionSize
        If $addr = 0 Then ExitLoop
    WEnd

    Return $results
EndFunc

Func _ScanForPointer($hProc, $hK32, $targetVal)
    Local $searchBytes = DllStructCreate("dword")
    DllStructSetData($searchBytes, 1, $targetVal)
    Local $results[0]

    Local $addr = 0
    Local $mbi = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")

    While 1
        Local $ret = DllCall($hK32, "ulong_ptr", "VirtualQueryEx", "handle", $hProc, "ptr", $addr, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
        If @error Or $ret[0] = 0 Then ExitLoop

        Local $regionBase = DllStructGetData($mbi, "BaseAddress")
        Local $regionSize = DllStructGetData($mbi, "RegionSize")
        Local $state = DllStructGetData($mbi, "State")
        Local $protect = DllStructGetData($mbi, "Protect")

        If $state = 0x1000 And BitAND($protect, 0x100) = 0 And $regionSize < 0x10000000 Then
            Local $chunkSize = 65536
            If $regionSize < $chunkSize Then $chunkSize = $regionSize
            For $offset = 0 To $regionSize - 4 Step $chunkSize
                Local $readSize = $chunkSize
                If $offset + $readSize > $regionSize Then $readSize = $regionSize - $offset
                Local $data = _ReadBytes($hProc, $hK32, $regionBase + $offset, $readSize)
                If @error Then ContinueLoop
                For $bytePos = 0 To BinaryLen($data) - 4 Step 4
                    If _BytesToDword($data, $bytePos) = $targetVal Then
                        ReDim $results[UBound($results) + 1]
                        $results[UBound($results) - 1] = $regionBase + $offset + $bytePos
                        If UBound($results) >= 20 Then ExitLoop 3
                    EndIf
                Next
            Next
        EndIf

        $addr = $regionBase + $regionSize
        If $addr = 0 Then ExitLoop
    WEnd

    Return $results
EndFunc

Func _ScanForPointerInModule($hProc, $hK32, $targetVal, $moduleBase)
    Local $results[0]
    Local $scanSize = 0x2000000 ; 32MB from module base
    Local $chunkSize = 65536

    For $offset = 0 To $scanSize - 4 Step $chunkSize
        Local $data = _ReadBytes($hProc, $hK32, $moduleBase + $offset, $chunkSize)
        If @error Then ContinueLoop
        For $bytePos = 0 To BinaryLen($data) - 4 Step 4
            If _BytesToDword($data, $bytePos) = $targetVal Then
                ReDim $results[UBound($results) + 1]
                $results[UBound($results) - 1] = $moduleBase + $offset + $bytePos
                If UBound($results) >= 10 Then ExitLoop 2
            EndIf
        Next
    Next

    Return $results
EndFunc

Func _GetModuleBaseAddress($pid, $moduleName)
    Local $hSnapshot = DllCall("kernel32.dll", "handle", "CreateToolhelp32Snapshot", "dword", 0x8, "dword", $pid)
    If @error Or $hSnapshot[0] = -1 Then Return 0
    $hSnapshot = $hSnapshot[0]

    Local $MODULEENTRY32 = DllStructCreate("dword dwSize; dword th32ModuleID; dword th32ProcessID; dword GlblcntUsage; dword ProccntUsage; ptr modBaseAddr; dword modBaseSize; handle hModule; wchar szModule[256]; wchar szExePath[260]")
    DllStructSetData($MODULEENTRY32, "dwSize", DllStructGetSize($MODULEENTRY32))

    Local $ret = DllCall("kernel32.dll", "bool", "Module32FirstW", "handle", $hSnapshot, "ptr", DllStructGetPtr($MODULEENTRY32))
    If @error Or $ret[0] = 0 Then
        DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $hSnapshot)
        Return 0
    EndIf

    While 1
        If StringLower(DllStructGetData($MODULEENTRY32, "szModule")) = StringLower($moduleName) Then
            Local $base = DllStructGetData($MODULEENTRY32, "modBaseAddr")
            DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $hSnapshot)
            Return $base
        EndIf
        $ret = DllCall("kernel32.dll", "bool", "Module32NextW", "handle", $hSnapshot, "ptr", DllStructGetPtr($MODULEENTRY32))
        If @error Or $ret[0] = 0 Then ExitLoop
    WEnd

    DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $hSnapshot)
    Return 0
EndFunc
