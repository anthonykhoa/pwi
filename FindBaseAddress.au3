#RequireAdmin

; ============================================
; PWI 64-bit Base Address Finder (v7)
; Focused: explores around known static pointer
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
If $moduleBase = 0 Then
    MsgBox(16, "Error", "Could not find module base.")
    Exit
EndIf

Local $charName = InputBox("Character Name", "Type your character name EXACTLY (case-sensitive):", "", "", 400, 200)
If $charName = "" Then Exit

Global $outputFile = @ScriptDir & "\FindBaseAddress_Results.txt"
Global $fullOutput = ""

_Out("PWI 64-bit Base Address Finder v7")
_Out("==================================")
_Out("PID: " & $PID)
_Out("Module base: 0x" & Hex($moduleBase))
_Out("Character: " & $charName)
_Out("")

; ==========================================
; STRATEGY: Scan the module's static data
; for ANY qword that chains to the player name.
; We scan only module memory (static addresses).
; For each qword, try 2, 3, and 4-level chains.
; ==========================================

Local $resultCount = 0
Local $results = ""

; Get module size
Local $hPsapi = DllOpen("psapi.dll")
Local $modInfo = DllStructCreate("ptr BaseAddr; dword SizeOfImage; ptr EntryPoint")
DllCall($hPsapi, "bool", "GetModuleInformation", "handle", $hProc, "handle", $moduleBase, _
    "ptr", DllStructGetPtr($modInfo), "dword", DllStructGetSize($modInfo))
Local $moduleSize = DllStructGetData($modInfo, "SizeOfImage")
DllClose($hPsapi)
If $moduleSize = 0 Then $moduleSize = 0x0C000000

_Out("Module size: 0x" & Hex($moduleSize))
_Out("")

; First: quick check of known offset from v5 (0x1A21470)
Local $knownOffset = 0x1A21470
Local $knownAddr = $moduleBase + $knownOffset
Local $knownVal = _ReadQword($hProc, $hK32, $knownAddr)
_Out("Known static ptr at Module+0x" & Hex($knownOffset) & " = 0x" & Hex($knownVal))
If $knownVal <> 0 Then
    Local $knownName = _ReadWString($hProc, $hK32, $knownVal)
    _Out("  Direct read as string: '" & $knownName & "'")
EndIf
_Out("")
_Save()

; ==========================================
; SCAN 1: Check ±0x200000 around known static ptr
; Try 1-level chain: [addr] -> name directly
; ==========================================
_Out("=== SCAN 1: Direct name pointers (1-level) near Module+0x1A21470 ===")
Local $scanStart = $knownAddr - 0x200000
Local $scanEnd = $knownAddr + 0x200000
If $scanStart < $moduleBase Then $scanStart = $moduleBase
If $scanEnd > $moduleBase + $moduleSize Then $scanEnd = $moduleBase + $moduleSize

For $a = $scanStart To $scanEnd - 8 Step 8
    Local $v = _ReadQword($hProc, $hK32, $a)
    If $v = 0 Or $v < 0x10000 Then ContinueLoop
    If $v >= $moduleBase And $v < ($moduleBase + $moduleSize) Then ContinueLoop
    Local $nm = _ReadWString($hProc, $hK32, $v)
    If $nm = $charName Then
        _Out("1-LEVEL: Module+0x" & Hex($a - $moduleBase) & " -> name directly")
        _Out("  [0x" & Hex($a) & "] = 0x" & Hex($v) & " -> '" & $nm & "'")
        _Out("")
    EndIf
Next
_Save()

; ==========================================
; SCAN 2: 2-level chains near known ptr
; [addr] -> +off -> name ptr -> name
; ==========================================
_Out("=== SCAN 2: 2-level chains ===")
For $a = $scanStart To $scanEnd - 8 Step 8
    Local $v0 = _ReadQword($hProc, $hK32, $a)
    If $v0 = 0 Or $v0 < 0x10000 Then ContinueLoop
    If $v0 >= $moduleBase And $v0 < ($moduleBase + $moduleSize) Then ContinueLoop

    For $off1 = 0x000 To 0x3000 Step 8
        Local $np = _ReadQword($hProc, $hK32, $v0 + $off1)
        If $np = 0 Or $np < 0x10000 Then ContinueLoop
        Local $nm2 = _ReadWString($hProc, $hK32, $np)
        If $nm2 = $charName Then
            _Out("2-LEVEL: Module+0x" & Hex($a - $moduleBase) & " -> +0x" & Hex($off1) & " -> name")
            _Out("")
        EndIf
    Next
Next
_Save()

; ==========================================
; SCAN 3: 3-level chains (the expected pattern)
; [addr] -> +off1 -> +off2 -> name ptr -> name
; Scan entire module data section (skip first 30%)
; ==========================================
_Out("=== SCAN 3: 3-level chains (full module scan) ===")
_Out("This is the main scan - may take a few minutes...")
_Save()

Local $dataStart = $moduleBase + Int($moduleSize * 0.3)
Local $dataEnd = $moduleBase + $moduleSize
Local $totalBytes = $dataEnd - $dataStart
Local $scanned = 0

For $a = $dataStart To $dataEnd - 8 Step 8
    Local $v0b = _ReadQword($hProc, $hK32, $a)
    If $v0b = 0 Or $v0b < 0x10000 Then
        $scanned += 8
        ContinueLoop
    EndIf
    If $v0b >= $moduleBase And $v0b < ($moduleBase + $moduleSize) Then
        $scanned += 8
        ContinueLoop
    EndIf

    For $off1 = 0x00 To 0xF0 Step 8
        Local $v1b = _ReadQword($hProc, $hK32, $v0b + $off1)
        If $v1b = 0 Or $v1b < 0x10000 Then ContinueLoop

        For $off2 = 0x000 To 0x3000 Step 8
            Local $npb = _ReadQword($hProc, $hK32, $v1b + $off2)
            If $npb = 0 Or $npb < 0x10000 Then ContinueLoop
            Local $nm3 = _ReadWString($hProc, $hK32, $npb)
            If $nm3 = $charName Then
                $resultCount += 1
                Local $relOff = $a - $moduleBase
                $results &= "=== RESULT " & $resultCount & " ===" & @CRLF
                $results &= "ADDRESS_BASE = 0x" & Hex($a) & " (Module+0x" & Hex($relOff) & ")" & @CRLF
                $results &= "Chain: [0x" & Hex($a) & "] -> +0x" & Hex($off1) & " -> +0x" & Hex($off2) & " -> ptr -> name" & @CRLF
                $results &= "Level1 offset = 0x" & Hex($off1) & @CRLF
                $results &= "PLAYERNAME_OFFSET = 0x" & Hex($off2) & @CRLF
                $results &= @CRLF
                _Out("*** FOUND! ADDRESS_BASE = 0x" & Hex($a) & " ***")
                _Out("  Module+0x" & Hex($relOff))
                _Out("  Chain: +0x" & Hex($off1) & " -> +0x" & Hex($off2) & " -> name")
                _Out("")
                _Save()
            EndIf
        Next
    Next

    $scanned += 8
    If Mod($scanned, 0x100000) < 8 Then
        Local $pct = Round($scanned / $totalBytes * 100)
        _Out("  Progress: " & $pct & "% (" & Round(TimerDiff($gStart) / 1000) & "s)")
        _Save()
    EndIf
Next

; ==========================================
; SCAN 4: 4-level chains
; [addr] -> +off1 -> +off2 -> +off3 -> name ptr -> name
; Only scan near known static ptr area
; ==========================================
_Out("")
_Out("=== SCAN 4: 4-level chains (near known static ptr) ===")
_Save()

For $a = $scanStart To $scanEnd - 8 Step 8
    Local $v0c = _ReadQword($hProc, $hK32, $a)
    If $v0c = 0 Or $v0c < 0x10000 Then ContinueLoop
    If $v0c >= $moduleBase And $v0c < ($moduleBase + $moduleSize) Then ContinueLoop

    For $off1 = 0x00 To 0x80 Step 8
        Local $v1c = _ReadQword($hProc, $hK32, $v0c + $off1)
        If $v1c = 0 Or $v1c < 0x10000 Then ContinueLoop

        For $off2 = 0x00 To 0x100 Step 8
            Local $v2c = _ReadQword($hProc, $hK32, $v1c + $off2)
            If $v2c = 0 Or $v2c < 0x10000 Then ContinueLoop

            For $off3 = 0x000 To 0x3000 Step 8
                Local $npc = _ReadQword($hProc, $hK32, $v2c + $off3)
                If $npc = 0 Or $npc < 0x10000 Then ContinueLoop
                Local $nm4 = _ReadWString($hProc, $hK32, $npc)
                If $nm4 = $charName Then
                    $resultCount += 1
                    Local $relOff4 = $a - $moduleBase
                    $results &= "=== RESULT " & $resultCount & " ===" & @CRLF
                    $results &= "ADDRESS_BASE = 0x" & Hex($a) & " (Module+0x" & Hex($relOff4) & ")" & @CRLF
                    $results &= "Chain: [0x" & Hex($a) & "] -> +0x" & Hex($off1) & " -> +0x" & Hex($off2) & " -> +0x" & Hex($off3) & " -> ptr -> name" & @CRLF
                    $results &= @CRLF
                    _Out("*** FOUND (4-level)! ADDRESS_BASE = 0x" & Hex($a) & " ***")
                    _Out("  Module+0x" & Hex($relOff4))
                    _Out("  Chain: +0x" & Hex($off1) & " -> +0x" & Hex($off2) & " -> +0x" & Hex($off3) & " -> name")
                    _Out("")
                    _Save()
                EndIf
            Next
        Next
    Next
Next

; ==========================================
; DONE
; ==========================================
_Out("==================================")
_Out("TOTAL RESULTS: " & $resultCount)
_Out("Time: " & Round(TimerDiff($gStart) / 1000) & "s")
_Out("==================================")
_Save()

If $resultCount > 0 Then
    ClipPut($results)
    MsgBox(64, "Found " & $resultCount & " result(s)", $results & @CRLF & "Saved & copied to clipboard!")
Else
    ClipPut($fullOutput)
    MsgBox(48, "No results", "Results saved to " & $outputFile & @CRLF & "Paste to Claude.")
EndIf

DllCall($hK32, "bool", "CloseHandle", "handle", $hProc)
DllClose($hK32)

; ============================================
; HELPERS
; ============================================
Global $gStart = TimerInit()

Func _Out($line)
    $fullOutput &= $line & @CRLF
    ConsoleWrite($line & @CRLF)
EndFunc

Func _Save()
    Local $hFile = FileOpen($outputFile, 2)
    FileWrite($hFile, $fullOutput)
    FileClose($hFile)
EndFunc

Func _ReadQword($hP, $hK, $iA)
    Local $buf = DllStructCreate("uint64")
    DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $iA, "ptr", DllStructGetPtr($buf), "ulong_ptr", 8, "ulong_ptr*", 0)
    If @error Then Return 0
    Return DllStructGetData($buf, 1)
EndFunc

Func _ReadWString($hP, $hK, $iA)
    Local $buf = DllStructCreate("wchar[100]")
    DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $iA, "ptr", DllStructGetPtr($buf), "ulong_ptr", 200, "ulong_ptr*", 0)
    If @error Then Return ""
    Return DllStructGetData($buf, 1)
EndFunc

Func _GetModuleBase64($hProc, $hK32, $moduleName)
    Local $hPsapi = DllOpen("psapi.dll")
    If $hPsapi = -1 Then Return 0
    Local $modArray = DllStructCreate("ptr[1024]")
    Local $cbNeeded = DllStructCreate("dword")
    DllCall($hPsapi, "bool", "EnumProcessModulesEx", _
        "handle", $hProc, "ptr", DllStructGetPtr($modArray), _
        "dword", DllStructGetSize($modArray), "ptr", DllStructGetPtr($cbNeeded), "dword", 0x03)
    If @error Then
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
