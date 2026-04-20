#RequireAdmin
#include <GUIConstantsEx.au3>

; ============================================
; PWI 64-bit Base Address Finder (v5)
; Works backwards from known name addresses
; ============================================

Local $PID = ProcessExists("elementclient_64.exe")
If $PID = 0 Then
    MsgBox(16, "Error", "elementclient_64.exe is not running!")
    Exit
EndIf

Local $hK32 = DllOpen("kernel32.dll")
Local $aOpen = DllCall($hK32, "handle", "OpenProcess", "dword", 0x1F0FFF, "bool", 0, "dword", $PID)
If $aOpen[0] = 0 Then
    MsgBox(16, "Error", "Failed to open process. Run as Administrator.")
    Exit
EndIf
Local $hProc = $aOpen[0]

Local $moduleBase = _GetModuleBase64($hProc, $hK32, "elementclient_64.exe")

Local $charName = InputBox("Character Name", "Type your character name EXACTLY (case-sensitive):", "", "", 400, 200)
If $charName = "" Then Exit

Global $hGUI = GUICreate("Finding ADDRESS_BASE...", 600, 250, -1, -1)
Global $lblStatus = GUICtrlCreateLabel("Starting...", 20, 15, 560, 25)
Global $lblDetail = GUICtrlCreateLabel("", 20, 45, 560, 25)
Global $lblTimer = GUICtrlCreateLabel("", 20, 75, 560, 25)
Global $lblResults = GUICtrlCreateLabel("", 20, 110, 560, 120)
GUISetState(@SW_SHOW, $hGUI)
Global $gStart = TimerInit()
Global $gLastUpdate = 0

Global $outputFile = @ScriptDir & "\FindBaseAddress_Results.txt"
Global $fullOutput = ""

_AppendOutput("PWI 64-bit Base Address Finder v5")
_AppendOutput("==================================")
_AppendOutput("PID: " & $PID)
_AppendOutput("Module base: 0x" & Hex($moduleBase))
_AppendOutput("Character: " & $charName)
_AppendOutput("")

; ==========================================
; STEP 1: Find character name in memory
; ==========================================
_Status("Step 1: Finding character name in memory...")

Local $nameAddrs[0]
Local $addr = 0
Local $mbi = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")

While 1
    Local $ret = DllCall($hK32, "ulong_ptr", "VirtualQueryEx", "handle", $hProc, "ptr", $addr, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
    If @error Or $ret[0] = 0 Then ExitLoop
    Local $rBase = DllStructGetData($mbi, "BaseAddress")
    Local $rSize = DllStructGetData($mbi, "RegionSize")
    Local $rState = DllStructGetData($mbi, "State")
    Local $rProt = DllStructGetData($mbi, "Protect")
    If $rState = 0x1000 And BitAND($rProt, 0x100) = 0 And $rSize < 0x10000000 Then
        Local $chunk = 65536
        If $rSize < $chunk Then $chunk = $rSize
        For $off = 0 To $rSize - 2 Step $chunk
            Local $rdSz = $chunk
            If $off + $rdSz > $rSize Then $rdSz = $rSize - $off
            Local $data = _ReadBytes($hProc, $hK32, $rBase + $off, $rdSz)
            If @error Then ContinueLoop
            Local $dataStr = BinaryToString($data, 2)
            Local $pos = 1
            While 1
                Local $f = StringInStr($dataStr, $charName, 1, 1, $pos)
                If $f = 0 Then ExitLoop
                ReDim $nameAddrs[UBound($nameAddrs) + 1]
                $nameAddrs[UBound($nameAddrs) - 1] = $rBase + $off + ($f - 1) * 2
                $pos = $f + 1
                If UBound($nameAddrs) >= 500 Then ExitLoop 2
            WEnd
        Next
    EndIf
    $addr = $rBase + $rSize
    If $addr = 0 Then ExitLoop
WEnd

_AppendOutput("Step 1: Found " & UBound($nameAddrs) & " name occurrences")
_AppendOutput("")
_SaveOutput()

If UBound($nameAddrs) = 0 Then
    GUIDelete($hGUI)
    MsgBox(16, "Error", "Could not find name in memory.")
    Exit
EndIf

; ==========================================
; STEP 2: Find 8-byte pointers TO each name address
; Also try 4-byte pointers (game might use 32-bit ptrs internally)
; ==========================================
_Status("Step 2: Finding pointers to name addresses...")

Local $ptrToName[0][2]
Local $maxNames = UBound($nameAddrs) - 1
If $maxNames > 49 Then $maxNames = 49

For $ni = 0 To $maxNames
    Local $targetAddr = $nameAddrs[$ni]

    ; Search for 8-byte pointer
    Local $search8 = _QwordToSearchBytes($targetAddr)
    ; Search for 4-byte pointer (lower 32 bits only)
    Local $search4 = _DwordToSearchBytes(BitAND($targetAddr, 0xFFFFFFFF))

    Local $scanAddr = 0
    While 1
        Local $sRet = DllCall($hK32, "ulong_ptr", "VirtualQueryEx", "handle", $hProc, "ptr", $scanAddr, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
        If @error Or $sRet[0] = 0 Then ExitLoop
        Local $sBase = DllStructGetData($mbi, "BaseAddress")
        Local $sSize = DllStructGetData($mbi, "RegionSize")
        Local $sState = DllStructGetData($mbi, "State")
        Local $sProt = DllStructGetData($mbi, "Protect")
        If $sState = 0x1000 And BitAND($sProt, 0x100) = 0 And $sSize < 0x10000000 Then
            Local $sChunk = 65536
            If $sSize < $sChunk Then $sChunk = $sSize
            For $sOff = 0 To $sSize - 4 Step $sChunk
                Local $sRead = $sChunk
                If $sOff + $sRead > $sSize Then $sRead = $sSize - $sOff
                If $sRead < 4 Then ContinueLoop
                Local $sData = _ReadBytes($hProc, $hK32, $sBase + $sOff, $sRead)
                If @error Then ContinueLoop
                Local $sBin = BinaryToString($sData, 1)

                ; Search for 8-byte matches (no alignment restriction)
                Local $sPos = 1
                While 1
                    Local $sFound = StringInStr($sBin, $search8, 1, 1, $sPos)
                    If $sFound = 0 Then ExitLoop
                    Local $ptrLoc = $sBase + $sOff + ($sFound - 1)
                    If $ptrLoc <> $targetAddr Then
                        ReDim $ptrToName[UBound($ptrToName, 1) + 1][2]
                        $ptrToName[UBound($ptrToName, 1) - 1][0] = $ptrLoc
                        $ptrToName[UBound($ptrToName, 1) - 1][1] = $targetAddr
                    EndIf
                    $sPos = $sFound + 1
                    If UBound($ptrToName, 1) >= 500 Then ExitLoop 3
                WEnd

                ; Search for 4-byte matches too
                $sPos = 1
                While 1
                    $sFound = StringInStr($sBin, $search4, 1, 1, $sPos)
                    If $sFound = 0 Then ExitLoop
                    $ptrLoc = $sBase + $sOff + ($sFound - 1)
                    If $ptrLoc <> $targetAddr Then
                        ; Verify the upper 4 bytes are 0 (valid 32-bit ptr in 64-bit space)
                        If Mod($sFound - 1, 4) = 0 Then
                            ReDim $ptrToName[UBound($ptrToName, 1) + 1][2]
                            $ptrToName[UBound($ptrToName, 1) - 1][0] = $ptrLoc
                            $ptrToName[UBound($ptrToName, 1) - 1][1] = $targetAddr
                        EndIf
                    EndIf
                    $sPos = $sFound + 1
                    If UBound($ptrToName, 1) >= 500 Then ExitLoop 3
                WEnd
            Next
        EndIf
        $scanAddr = $sBase + $sSize
        If $scanAddr = 0 Then ExitLoop
    WEnd

    _TickProgress("Step 2: Name " & ($ni + 1) & "/" & ($maxNames + 1), UBound($ptrToName, 1) & " pointers found")
    If UBound($ptrToName, 1) >= 500 Then ExitLoop
Next

_AppendOutput("Step 2: Found " & UBound($ptrToName, 1) & " pointers to name")
For $i = 0 To UBound($ptrToName, 1) - 1
    If $i > 29 Then
        _AppendOutput("  ... and " & (UBound($ptrToName, 1) - 30) & " more")
        ExitLoop
    EndIf
    _AppendOutput("  PTR at 0x" & Hex($ptrToName[$i][0]) & " -> name at 0x" & Hex($ptrToName[$i][1]))
Next
_AppendOutput("")
_SaveOutput()

If UBound($ptrToName, 1) = 0 Then
    GUIDelete($hGUI)
    _AppendOutput("ERROR: No pointers to name found.")
    _AppendOutput("The name may be stored inline (not via pointer) in the 64-bit client.")
    _SaveOutput()
    ClipPut($fullOutput)
    MsgBox(48, "No pointers found", "Could not find any pointers to the name." & @CRLF & @CRLF & "Results saved to " & $outputFile)
    Exit
EndIf

; ==========================================
; STEP 3: For each pointer-to-name, try it as
; player+offset, then trace back to ADDRESS_BASE
; Try WIDE range of name offsets
; ==========================================
_Status("Step 3: Tracing chains back to ADDRESS_BASE...")

Local $results = ""
Local $resultCount = 0

; Wide range of possible name offsets
Local $nameOffMin = 0x0100
Local $nameOffMax = 0x3000
Local $nameOffStep = 4

_AppendOutput("=== STEP 3: CHAIN TRACING ===")
_AppendOutput("Testing name offsets from 0x" & Hex($nameOffMin) & " to 0x" & Hex($nameOffMax))
_AppendOutput("")

For $pi = 0 To UBound($ptrToName, 1) - 1
    If $pi > 29 Then ExitLoop
    Local $namePtrLoc = $ptrToName[$pi][0]

    _TickProgress("Step 3: Pointer " & ($pi + 1) & "/" & UBound($ptrToName, 1), "Testing offsets... Found: " & $resultCount)

    For $nameOff = $nameOffMin To $nameOffMax Step $nameOffStep
        Local $playerBase = $namePtrLoc - $nameOff

        ; Quick sanity: does reading name through this player base work?
        Local $testNamePtr = _ReadQword($hProc, $hK32, $playerBase + $nameOff)
        If $testNamePtr = 0 Then ContinueLoop
        ; Also try as dword
        If $testNamePtr < 0x10000 Then
            $testNamePtr = _ReadDword($hProc, $hK32, $playerBase + $nameOff)
            If $testNamePtr = 0 Or $testNamePtr < 0x10000 Then ContinueLoop
        EndIf
        Local $testName = _ReadWString($hProc, $hK32, $testNamePtr)
        If $testName <> $charName Then ContinueLoop

        ; Player base looks valid. Now find what points to playerBase.
        ; Try player offsets from 0x00 to 0x200
        For $playerOff = 0x00 To 0x200 Step 4
            ; Scan for a qword/dword in memory whose value = playerBase
            ; But full scan is too slow, so check the STATIC data in the module
            If $moduleBase = 0 Then ContinueLoop

            ; The chain is: [ADDRESS_BASE] -> +l1Off -> +playerOff = playerBase
            ; So we need: some addr where [addr + playerOff] = playerBase
            ; And [ADDRESS_BASE] -> +l1Off = addr
            ; And ADDRESS_BASE is static (in the module)

            ; Scan module data for a qword that, when we follow +l1Off -> +playerOff, gives playerBase
            ; But that's 3 levels. Let's do it in steps.

            ; First, try: is there any readable memory location at (playerBase - playerOff)?
            ; That would be the level2 struct
            Local $level2 = $playerBase ; wait, no
            ; [level2 + playerOff] = playerBase means we need to find level2 addr
            ; Actually: level2 is a struct, and at level2+playerOff there's a pointer to playerBase
            ; So we need to find where in memory the value playerBase is stored

            ; Brute force: scan module static data for chains
            ; This is what we were doing before. Let's be smarter.
            ; Just scan module .data for qwords, follow 2 levels, see if we hit playerBase
        Next

        ; SIMPLER APPROACH: just record this as a valid player struct
        _AppendOutput("Valid player at 0x" & Hex($playerBase) & " (name ptr at +" & Hex($nameOff) & ")")
        _AppendOutput("  Name ptr loc: 0x" & Hex($namePtrLoc))

        ; Now scan MODULE static data for any chain that reaches this player
        ; Scan every qword in module data sections
        Local $scanStart = $moduleBase
        Local $scanEnd = $moduleBase + 0x0C000000
        Local $scanChunk = 8192

        For $mAddr = $scanStart To $scanEnd - 8 Step $scanChunk
            Local $mData = _ReadBytes($hProc, $hK32, $mAddr, $scanChunk)
            If @error Then ContinueLoop

            For $bp = 0 To $scanChunk - 8 Step 8
                Local $v0 = _BytesToQword($mData, $bp)
                If $v0 = 0 Or $v0 < 0x10000 Then ContinueLoop
                If $v0 >= $moduleBase And $v0 < $scanEnd Then ContinueLoop

                ; Try: [v0 + l1Off] -> +playerOff = playerBase
                For $l1 = 0x00 To 0xF0 Step 8
                    Local $v1 = _ReadQword($hProc, $hK32, $v0 + $l1)
                    If $v1 = 0 Or $v1 < 0x10000 Then ContinueLoop

                    For $pOff = 0x00 To 0x200 Step 8
                        Local $v2 = _ReadQword($hProc, $hK32, $v1 + $pOff)
                        If $v2 = $playerBase Then
                            ; VERIFY full chain
                            Local $vName = _ReadQword($hProc, $hK32, $v2 + $nameOff)
                            If $vName = 0 Then ContinueLoop
                            Local $vn = _ReadWString($hProc, $hK32, $vName)
                            If $vn <> $charName Then ContinueLoop

                            $resultCount += 1
                            Local $candAddr = $mAddr + $bp
                            Local $relOff = $candAddr - $moduleBase
                            Local $rLine = "ADDRESS_BASE = " & $candAddr & " (0x" & Hex($candAddr) & ")"
                            $results &= "=== RESULT " & $resultCount & " ===" & @CRLF
                            $results &= $rLine & @CRLF
                            $results &= "Module + 0x" & Hex($relOff) & @CRLF
                            $results &= "Chain: [0x" & Hex($candAddr) & "] -> +0x" & Hex($l1) & " -> +0x" & Hex($pOff) & " -> +0x" & Hex($nameOff) & " -> ptr -> name" & @CRLF
                            $results &= "PLAYER_OFFSET = " & $pOff & " (0x" & Hex($pOff) & ")" & @CRLF
                            $results &= "PLAYERNAME_OFFSET = " & $nameOff & " (0x" & Hex($nameOff) & ")" & @CRLF
                            $results &= @CRLF

                            _AppendOutput("*** FOUND ADDRESS_BASE! ***")
                            _AppendOutput("  " & $rLine)
                            _AppendOutput("  Module + 0x" & Hex($relOff))
                            _AppendOutput("  Chain: +0x" & Hex($l1) & " -> +0x" & Hex($pOff) & " -> +0x" & Hex($nameOff) & " -> name")
                            _AppendOutput("")
                            _SaveOutput()
                            GUICtrlSetData($lblResults, "FOUND #" & $resultCount & ": " & $rLine & @CRLF & _
                                "+0x" & Hex($l1) & " -> +0x" & Hex($pOff) & " -> +0x" & Hex($nameOff))
                        EndIf
                    Next

                    ; Also try 4-byte read for player offset (mixed 32/64 bit struct)
                    For $pOff = 0x00 To 0x200 Step 4
                        Local $v2d = _ReadDword($hProc, $hK32, $v1 + $pOff)
                        If $v2d = 0 Or $v2d < 0x10000 Then ContinueLoop
                        If $v2d = $playerBase Then
                            Local $vName2 = _ReadQword($hProc, $hK32, $v2d + $nameOff)
                            If $vName2 = 0 Then ContinueLoop
                            Local $vn2 = _ReadWString($hProc, $hK32, $vName2)
                            If $vn2 <> $charName Then ContinueLoop

                            $resultCount += 1
                            Local $candAddr2 = $mAddr + $bp
                            Local $relOff2 = $candAddr2 - $moduleBase
                            $results &= "=== RESULT " & $resultCount & " (32-bit player ptr) ===" & @CRLF
                            $results &= "ADDRESS_BASE = " & $candAddr2 & " (0x" & Hex($candAddr2) & ")" & @CRLF
                            $results &= "Chain: +0x" & Hex($l1) & " -> +0x" & Hex($pOff) & "(dword) -> +0x" & Hex($nameOff) & " -> name" & @CRLF
                            $results &= @CRLF
                            _AppendOutput("*** FOUND (32-bit player ptr)! 0x" & Hex($candAddr2) & " ***")
                            _AppendOutput("  Chain: +0x" & Hex($l1) & " -> +0x" & Hex($pOff) & "(dword) -> +0x" & Hex($nameOff))
                            _AppendOutput("")
                            _SaveOutput()
                        EndIf
                    Next
                Next
            Next
        Next

        ; Only try a few valid player bases per pointer (performance)
        If $resultCount > 0 Then ExitLoop 2
    Next
Next

; ==========================================
; DONE
; ==========================================
GUIDelete($hGUI)

_AppendOutput("==================================")
_AppendOutput("TOTAL RESULTS: " & $resultCount)
_AppendOutput("==================================")
_SaveOutput()

If $resultCount > 0 Then
    ClipPut($results)
    MsgBox(64, "Found " & $resultCount & " result(s)", $results & @CRLF & "Saved to " & $outputFile & @CRLF & "Copied to clipboard!")
Else
    ClipPut($fullOutput)
    MsgBox(48, "No results", "Could not find ADDRESS_BASE." & @CRLF & @CRLF & "Results saved to " & $outputFile & @CRLF & "Paste to Claude for analysis.")
EndIf

DllCall($hK32, "bool", "CloseHandle", "handle", $hProc)
DllClose($hK32)

; ============================================
; HELPER FUNCTIONS
; ============================================

Func _Status($msg, $detail = "")
    GUICtrlSetData($lblStatus, $msg)
    If $detail <> "" Then GUICtrlSetData($lblDetail, $detail)
    Local $el = Round(TimerDiff($gStart) / 1000)
    GUICtrlSetData($lblTimer, "Elapsed: " & $el & "s")
    $gLastUpdate = TimerInit()
EndFunc

Func _TickProgress($msg, $detail = "")
    If TimerDiff($gLastUpdate) > 500 Then _Status($msg, $detail)
EndFunc

Func _AppendOutput($line)
    $fullOutput &= $line & @CRLF
EndFunc

Func _SaveOutput()
    Local $hFile = FileOpen($outputFile, 2)
    FileWrite($hFile, $fullOutput)
    FileClose($hFile)
EndFunc

Func _ReadBytes($hP, $hK, $iA, $iS)
    Local $buf = DllStructCreate("byte[" & $iS & "]")
    Local $r = DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $iA, "ptr", DllStructGetPtr($buf), "ulong_ptr", $iS, "ulong_ptr*", 0)
    If @error Or $r[0] = 0 Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

Func _ReadQword($hP, $hK, $iA)
    Local $buf = DllStructCreate("uint64")
    Local $r = DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $iA, "ptr", DllStructGetPtr($buf), "ulong_ptr", 8, "ulong_ptr*", 0)
    If @error Or $r[0] = 0 Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

Func _ReadDword($hP, $hK, $iA)
    Local $buf = DllStructCreate("dword")
    Local $r = DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $iA, "ptr", DllStructGetPtr($buf), "ulong_ptr", 4, "ulong_ptr*", 0)
    If @error Or $r[0] = 0 Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

Func _ReadWString($hP, $hK, $iA)
    Local $buf = DllStructCreate("wchar[100]")
    DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $iA, "ptr", DllStructGetPtr($buf), "ulong_ptr", 200, "ulong_ptr*", 0)
    If @error Then Return ""
    Return DllStructGetData($buf, 1)
EndFunc

Func _BytesToQword($bytes, $iOff)
    Local $b1 = DllStructCreate("byte[8]")
    DllStructSetData($b1, 1, BinaryMid($bytes, $iOff + 1, 8))
    Local $b2 = DllStructCreate("uint64", DllStructGetPtr($b1))
    Return DllStructGetData($b2, 1)
EndFunc

Func _QwordToSearchBytes($val)
    Local $buf = DllStructCreate("uint64")
    DllStructSetData($buf, 1, $val)
    Local $bytes = DllStructCreate("byte[8]", DllStructGetPtr($buf))
    Local $r = ""
    For $i = 1 To 8
        $r &= Chr(DllStructGetData($bytes, 1, $i))
    Next
    Return $r
EndFunc

Func _DwordToSearchBytes($val)
    Local $buf = DllStructCreate("dword")
    DllStructSetData($buf, 1, $val)
    Local $bytes = DllStructCreate("byte[4]", DllStructGetPtr($buf))
    Local $r = ""
    For $i = 1 To 4
        $r &= Chr(DllStructGetData($bytes, 1, $i))
    Next
    Return $r
EndFunc

Func _GetModuleBase64($hProc, $hK32, $moduleName)
    Local $hPsapi = DllOpen("psapi.dll")
    If $hPsapi = -1 Then Return 0
    Local $modArray = DllStructCreate("ptr[1024]")
    Local $cbNeeded = DllStructCreate("dword")
    Local $ret = DllCall($hPsapi, "bool", "EnumProcessModulesEx", _
        "handle", $hProc, "ptr", DllStructGetPtr($modArray), _
        "dword", DllStructGetSize($modArray), "ptr", DllStructGetPtr($cbNeeded), "dword", 0x03)
    If @error Or $ret[0] = 0 Then
        DllClose($hPsapi)
        Return 0
    EndIf
    Local $numMod = DllStructGetData($cbNeeded, 1) / 8
    If $numMod > 1024 Then $numMod = 1024
    For $i = 1 To $numMod
        Local $hMod = DllStructGetData($modArray, 1, $i)
        Local $nameBuf = DllStructCreate("wchar[260]")
        DllCall($hPsapi, "dword", "GetModuleBaseNameW", _
            "handle", $hProc, "handle", $hMod, _
            "ptr", DllStructGetPtr($nameBuf), "dword", 260)
        If StringInStr(DllStructGetData($nameBuf, 1), $moduleName) Then
            DllClose($hPsapi)
            Return $hMod
        EndIf
    Next
    DllClose($hPsapi)
    Return 0
EndFunc
