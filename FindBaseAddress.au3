#RequireAdmin
#include <GUIConstantsEx.au3>

; ============================================
; PWI 64-bit Base Address Finder (v6)
; Focused: works backwards level-by-level
; from known name pointers
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

Global $hGUI = GUICreate("Finding ADDRESS_BASE v6...", 600, 300, -1, -1)
Global $lblStatus = GUICtrlCreateLabel("Starting...", 20, 15, 560, 25)
Global $lblDetail = GUICtrlCreateLabel("", 20, 45, 560, 25)
Global $lblTimer = GUICtrlCreateLabel("", 20, 75, 560, 25)
Global $lblResults = GUICtrlCreateLabel("", 20, 110, 560, 170)
GUISetState(@SW_SHOW, $hGUI)
Global $gStart = TimerInit()
Global $gLastUpdate = 0

Global $outputFile = @ScriptDir & "\FindBaseAddress_Results.txt"
Global $fullOutput = ""

_AppendOutput("PWI 64-bit Base Address Finder v6")
_AppendOutput("==================================")
_AppendOutput("PID: " & $PID)
_AppendOutput("Module base: 0x" & Hex($moduleBase))
_AppendOutput("Character: " & $charName)
_AppendOutput("")

; ==========================================
; STEP 1: Find character name in memory
; ==========================================
_Status("Step 1: Finding character name...")

Local $nameAddrs[0]
Local $mbi = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")
_ScanForString($hProc, $hK32, $charName, $nameAddrs, 300)

_AppendOutput("Step 1: Found " & UBound($nameAddrs) & " name occurrences")
_AppendOutput("")
_SaveOutput()

If UBound($nameAddrs) = 0 Then
    GUIDelete($hGUI)
    MsgBox(16, "Error", "Name not found in memory.")
    Exit
EndIf

; ==========================================
; STEP 2: Find pointers to name (LEVEL 1 back)
; These are at player_struct + PLAYERNAME_OFFSET
; ==========================================
_Status("Step 2: Finding pointers to name (Level 1)...")

Local $level1[0] ; addresses where a pointer-to-name lives
_FindPointersToAddresses($hProc, $hK32, $nameAddrs, $level1, 300)

_AppendOutput("Step 2 (Level 1): Found " & UBound($level1) & " pointers to name")
Local $showMax = UBound($level1) - 1
If $showMax > 19 Then $showMax = 19
For $i = 0 To $showMax
    Local $isStatic = ""
    If $level1[$i] >= $moduleBase And $level1[$i] < ($moduleBase + 0x10000000) Then $isStatic = " [STATIC MODULE ADDR]"
    _AppendOutput("  0x" & Hex($level1[$i]) & $isStatic)
Next
_AppendOutput("")
_SaveOutput()

; ==========================================
; STEP 3: For each Level 1 address, try to
; determine the struct base by checking if
; reading name works at various offsets back
; Then find pointers TO the struct (LEVEL 2)
; ==========================================
_Status("Step 3: Finding struct bases and Level 2 pointers...")

Local $level2[0]
Local $level2Info[0][3] ; [n][0]=level2 addr, [n][1]=struct addr, [n][2]=name offset used

_AppendOutput("=== STEP 3: STRUCT BASE + LEVEL 2 POINTERS ===")

; Deduplicate level1
Local $uniqueL1[0]
For $i = 0 To UBound($level1) - 1
    Local $isDup = False
    For $j = 0 To UBound($uniqueL1) - 1
        If $level1[$i] = $uniqueL1[$j] Then
            $isDup = True
            ExitLoop
        EndIf
    Next
    If Not $isDup Then
        ReDim $uniqueL1[UBound($uniqueL1) + 1]
        $uniqueL1[UBound($uniqueL1) - 1] = $level1[$i]
    EndIf
Next

_AppendOutput("Unique Level 1 pointers: " & UBound($uniqueL1))

For $i = 0 To UBound($uniqueL1) - 1
    If $i > 19 Then ExitLoop
    Local $namePtrLoc = $uniqueL1[$i]

    _TickProgress("Step 3: Testing L1 pointer " & ($i + 1) & "/" & UBound($uniqueL1), "")

    ; Try name offsets to find struct base
    ; Wider range, step by 4 for 32-bit fields, 8 for 64-bit
    For $nameOff = 0x100 To 0x3000 Step 4
        Local $structBase = $namePtrLoc - $nameOff

        ; Quick validate: read name ptr from structBase + nameOff
        Local $np = _ReadQword($hProc, $hK32, $structBase + $nameOff)
        If $np = 0 Or $np < 0x10000 Then ContinueLoop
        Local $tn = _ReadWString($hProc, $hK32, $np)
        If $tn <> $charName Then ContinueLoop

        ; Valid struct base found! Now search for pointers TO structBase
        _AppendOutput("  Valid struct at 0x" & Hex($structBase) & " (name at +" & Hex($nameOff) & ")")

        Local $ptrsToStruct[0]
        Local $searchAddrs[1] = [$structBase]
        _FindPointersToAddresses($hProc, $hK32, $searchAddrs, $ptrsToStruct, 50)

        _AppendOutput("    Found " & UBound($ptrsToStruct) & " pointers to struct")

        For $k = 0 To UBound($ptrsToStruct) - 1
            Local $isStatic2 = ""
            If $ptrsToStruct[$k] >= $moduleBase And $ptrsToStruct[$k] < ($moduleBase + 0x10000000) Then $isStatic2 = " [STATIC]"
            _AppendOutput("    L2: 0x" & Hex($ptrsToStruct[$k]) & $isStatic2)

            ReDim $level2[UBound($level2) + 1]
            $level2[UBound($level2) - 1] = $ptrsToStruct[$k]
            ReDim $level2Info[UBound($level2Info, 1) + 1][3]
            $level2Info[UBound($level2Info, 1) - 1][0] = $ptrsToStruct[$k]
            $level2Info[UBound($level2Info, 1) - 1][1] = $structBase
            $level2Info[UBound($level2Info, 1) - 1][2] = $nameOff
        Next
        _SaveOutput()

        ; Only use first valid name offset per L1 pointer
        ExitLoop
    Next
Next

_AppendOutput("")
_AppendOutput("Level 2 total: " & UBound($level2) & " pointers")
_AppendOutput("")
_SaveOutput()

; ==========================================
; STEP 4: For each Level 2, figure out what
; offset it's at in its parent struct, then
; find pointers TO that parent (LEVEL 3)
; ==========================================
_Status("Step 4: Finding Level 3 pointers (should find ADDRESS_BASE)...")

_AppendOutput("=== STEP 4: LEVEL 3 (ADDRESS_BASE candidates) ===")

Local $resultCount = 0
Local $results = ""

; Deduplicate level2
Local $uniqueL2[0]
For $i = 0 To UBound($level2) - 1
    Local $isDup2 = False
    For $j = 0 To UBound($uniqueL2) - 1
        If $level2[$i] = $uniqueL2[$j] Then
            $isDup2 = True
            ExitLoop
        EndIf
    Next
    If Not $isDup2 Then
        ReDim $uniqueL2[UBound($uniqueL2) + 1]
        $uniqueL2[UBound($uniqueL2) - 1] = $level2[$i]
    EndIf
Next

For $i = 0 To UBound($uniqueL2) - 1
    If $i > 19 Then ExitLoop
    Local $l2Addr = $uniqueL2[$i]

    _TickProgress("Step 4: L2 pointer " & ($i + 1) & "/" & UBound($uniqueL2), "Found " & $resultCount & " ADDRESS_BASE candidates")

    ; The L2 pointer is at some_struct + some_offset, and [some_struct + some_offset] = player/entity struct
    ; We need to find the parent struct. Try offsets.
    For $l2Off = 0x00 To 0x200 Step 4
        Local $parentStruct = $l2Addr - $l2Off

        ; Search for pointers to parentStruct
        Local $ptrsToParent[0]
        Local $searchParent[1] = [$parentStruct]
        _FindPointersToAddresses($hProc, $hK32, $searchParent, $ptrsToParent, 20)

        For $k = 0 To UBound($ptrsToParent) - 1
            Local $l3Addr = $ptrsToParent[$k]

            ; Check if this is a static module address
            If $l3Addr >= $moduleBase And $l3Addr < ($moduleBase + 0x10000000) Then
                ; POTENTIAL ADDRESS_BASE! Verify the full chain.
                ; Find what nameOff was used for this chain
                Local $nameOff3 = 0
                Local $structAddr3 = 0
                For $m = 0 To UBound($level2Info, 1) - 1
                    If $level2Info[$m][0] = $l2Addr Then
                        $structAddr3 = $level2Info[$m][1]
                        $nameOff3 = $level2Info[$m][2]
                        ExitLoop
                    EndIf
                Next

                ; Verify: [l3Addr] -> +l2Off -> player offset back -> +nameOff -> name
                Local $check0 = _ReadQword($hProc, $hK32, $l3Addr)
                If $check0 = 0 Then ContinueLoop
                Local $check1 = _ReadQword($hProc, $hK32, $check0 + $l2Off)
                If $check1 = 0 Then ContinueLoop

                ; check1 should point to the entity struct area
                ; Try to find the player offset
                For $pOff = 0x00 To 0x200 Step 4
                    Local $check2 = _ReadQword($hProc, $hK32, $check1 + $pOff)
                    If $check2 = 0 Or $check2 < 0x10000 Then ContinueLoop
                    Local $checkNP = _ReadQword($hProc, $hK32, $check2 + $nameOff3)
                    If $checkNP = 0 Then ContinueLoop
                    Local $checkName = _ReadWString($hProc, $hK32, $checkNP)
                    If $checkName = $charName Then
                        $resultCount += 1
                        Local $relOff = $l3Addr - $moduleBase
                        $results &= "=== RESULT " & $resultCount & " ===" & @CRLF
                        $results &= "ADDRESS_BASE = " & $l3Addr & " (0x" & Hex($l3Addr) & ")" & @CRLF
                        $results &= "Module + 0x" & Hex($relOff) & @CRLF
                        $results &= "Chain: [0x" & Hex($l3Addr) & "] -> +0x" & Hex($l2Off) & " -> +0x" & Hex($pOff) & " -> +0x" & Hex($nameOff3) & " -> ptr -> name" & @CRLF
                        $results &= "Level1 offset = 0x" & Hex($l2Off) & " (was 0x1C in 32-bit)" & @CRLF
                        $results &= "PLAYER_OFFSET = 0x" & Hex($pOff) & " (was 0x34 in 32-bit)" & @CRLF
                        $results &= "PLAYERNAME_OFFSET = 0x" & Hex($nameOff3) & " (was 0xB90 in 32-bit)" & @CRLF
                        $results &= @CRLF

                        _AppendOutput("*** FOUND ADDRESS_BASE! ***")
                        _AppendOutput("  ADDRESS_BASE = 0x" & Hex($l3Addr))
                        _AppendOutput("  Module + 0x" & Hex($relOff))
                        _AppendOutput("  Chain: +0x" & Hex($l2Off) & " -> +0x" & Hex($pOff) & " -> +0x" & Hex($nameOff3) & " -> name")
                        _AppendOutput("")
                        _SaveOutput()

                        GUICtrlSetData($lblResults, "FOUND! ADDRESS_BASE = 0x" & Hex($l3Addr) & @CRLF & _
                            "Module + 0x" & Hex($relOff) & @CRLF & _
                            "Chain: +0x" & Hex($l2Off) & " -> +0x" & Hex($pOff) & " -> +0x" & Hex($nameOff3))
                    EndIf
                Next
            EndIf
        Next
    Next
Next

; ==========================================
; STEP 5: Also check the static pointer we
; found at 0x141A21470 and explore around it
; ==========================================
_Status("Step 5: Exploring static module pointers...")
_AppendOutput("=== STEP 5: STATIC POINTER EXPLORATION ===")

; Check all static (module) addresses found at any level
Local $staticAddrs[0]
For $i = 0 To UBound($uniqueL1) - 1
    If $uniqueL1[$i] >= $moduleBase And $uniqueL1[$i] < ($moduleBase + 0x10000000) Then
        ReDim $staticAddrs[UBound($staticAddrs) + 1]
        $staticAddrs[UBound($staticAddrs) - 1] = $uniqueL1[$i]
    EndIf
Next

_AppendOutput("Static pointers found at Level 1: " & UBound($staticAddrs))

For $i = 0 To UBound($staticAddrs) - 1
    Local $staticPtr = $staticAddrs[$i]
    Local $relOff5 = $staticPtr - $moduleBase
    _AppendOutput("")
    _AppendOutput("Exploring static ptr at 0x" & Hex($staticPtr) & " (Module + 0x" & Hex($relOff5) & ")")

    ; Read surrounding ±0x200 bytes and dump as qwords
    For $scanOff = -0x200 To 0x200 Step 8
        Local $scanAddr = $staticPtr + $scanOff
        Local $val = _ReadQword($hProc, $hK32, $scanAddr)
        If $val = 0 Then ContinueLoop

        ; Try following this as a pointer chain
        ; 2-level: [val] -> +off -> name
        For $off1 = 0x100 To 0x3000 Step 8
            Local $np5 = _ReadQword($hProc, $hK32, $val + $off1)
            If $np5 = 0 Or $np5 < 0x10000 Then ContinueLoop
            Local $nm5 = _ReadWString($hProc, $hK32, $np5)
            If $nm5 = $charName Then
                _AppendOutput("  2-LEVEL HIT at Module+0x" & Hex($scanAddr - $moduleBase) & ": [ptr] -> +0x" & Hex($off1) & " -> name")
            EndIf
        Next

        ; 3-level: [val] -> +off1 -> +off2 -> name ptr -> name
        For $off1a = 0x00 To 0x100 Step 8
            Local $v1 = _ReadQword($hProc, $hK32, $val + $off1a)
            If $v1 = 0 Or $v1 < 0x10000 Then ContinueLoop
            For $off2a = 0x100 To 0x3000 Step 8
                Local $np5b = _ReadQword($hProc, $hK32, $v1 + $off2a)
                If $np5b = 0 Or $np5b < 0x10000 Then ContinueLoop
                Local $nm5b = _ReadWString($hProc, $hK32, $np5b)
                If $nm5b = $charName Then
                    _AppendOutput("  3-LEVEL HIT at Module+0x" & Hex($scanAddr - $moduleBase) & ": [ptr] -> +0x" & Hex($off1a) & " -> +0x" & Hex($off2a) & " -> name")
                EndIf
            Next
        Next

        ; 4-level: [val] -> +off1 -> +off2 -> +off3 -> name ptr -> name
        For $off1b = 0x00 To 0x80 Step 8
            Local $v1b = _ReadQword($hProc, $hK32, $val + $off1b)
            If $v1b = 0 Or $v1b < 0x10000 Then ContinueLoop
            For $off2b = 0x00 To 0x100 Step 8
                Local $v2b = _ReadQword($hProc, $hK32, $v1b + $off2b)
                If $v2b = 0 Or $v2b < 0x10000 Then ContinueLoop
                For $off3b = 0x100 To 0x3000 Step 0x20
                    Local $np5c = _ReadQword($hProc, $hK32, $v2b + $off3b)
                    If $np5c = 0 Or $np5c < 0x10000 Then ContinueLoop
                    Local $nm5c = _ReadWString($hProc, $hK32, $np5c)
                    If $nm5c = $charName Then
                        ; Refine: try nearby offsets
                        For $fine = $off3b - 0x18 To $off3b + 0x18 Step 4
                            Local $npF = _ReadQword($hProc, $hK32, $v2b + $fine)
                            If $npF = 0 Then ContinueLoop
                            Local $nmF = _ReadWString($hProc, $hK32, $npF)
                            If $nmF = $charName Then
                                $resultCount += 1
                                $results &= "=== RESULT " & $resultCount & " (via static exploration) ===" & @CRLF
                                $results &= "ADDRESS_BASE = " & $scanAddr & " (0x" & Hex($scanAddr) & ")" & @CRLF
                                $results &= "Module + 0x" & Hex($scanAddr - $moduleBase) & @CRLF
                                $results &= "Chain: [0x" & Hex($scanAddr) & "] -> +0x" & Hex($off1b) & " -> +0x" & Hex($off2b) & " -> +0x" & Hex($fine) & " -> ptr -> name" & @CRLF
                                $results &= @CRLF
                                _AppendOutput("  *** ADDRESS_BASE CANDIDATE: 0x" & Hex($scanAddr) & " ***")
                                _AppendOutput("    Chain: +0x" & Hex($off1b) & " -> +0x" & Hex($off2b) & " -> +0x" & Hex($fine) & " -> name")
                                _SaveOutput()
                                GUICtrlSetData($lblResults, "FOUND: 0x" & Hex($scanAddr) & @CRLF & _
                                    "Chain: +0x" & Hex($off1b) & " -> +0x" & Hex($off2b) & " -> +0x" & Hex($fine))
                                ExitLoop 3
                            EndIf
                        Next
                    EndIf
                Next
            Next
        Next
    Next
    _SaveOutput()
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
    MsgBox(48, "No ADDRESS_BASE found", "But we found useful chain data!" & @CRLF & @CRLF & "Results saved to " & $outputFile & @CRLF & "Paste to Claude for analysis.")
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

; Scan all memory for a UTF-16 string
Func _ScanForString(ByRef $hP, ByRef $hK, $str, ByRef $outArr, $maxResults)
    Local $addr = 0
    Local $lmbi = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")
    While 1
        Local $r = DllCall($hK, "ulong_ptr", "VirtualQueryEx", "handle", $hP, "ptr", $addr, "ptr", DllStructGetPtr($lmbi), "ulong_ptr", DllStructGetSize($lmbi))
        If @error Or $r[0] = 0 Then ExitLoop
        Local $b = DllStructGetData($lmbi, "BaseAddress")
        Local $s = DllStructGetData($lmbi, "RegionSize")
        If DllStructGetData($lmbi, "State") = 0x1000 And BitAND(DllStructGetData($lmbi, "Protect"), 0x100) = 0 And $s < 0x10000000 Then
            Local $chunk = 65536
            If $s < $chunk Then $chunk = $s
            For $off = 0 To $s - 2 Step $chunk
                Local $rdSz = $chunk
                If $off + $rdSz > $s Then $rdSz = $s - $off
                Local $data = _ReadBytes($hP, $hK, $b + $off, $rdSz)
                If @error Then ContinueLoop
                Local $ds = BinaryToString($data, 2)
                Local $p = 1
                While 1
                    Local $f = StringInStr($ds, $str, 1, 1, $p)
                    If $f = 0 Then ExitLoop
                    ReDim $outArr[UBound($outArr) + 1]
                    $outArr[UBound($outArr) - 1] = $b + $off + ($f - 1) * 2
                    $p = $f + 1
                    If UBound($outArr) >= $maxResults Then Return
                WEnd
            Next
        EndIf
        $addr = $b + $s
        If $addr = 0 Then ExitLoop
    WEnd
EndFunc

; Find all memory locations containing 8-byte pointers to any of the target addresses
Func _FindPointersToAddresses(ByRef $hP, ByRef $hK, ByRef $targets, ByRef $outArr, $maxResults)
    Local $addr = 0
    Local $lmbi = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")

    ; Build search patterns for all targets
    Local $patterns[UBound($targets)]
    For $t = 0 To UBound($targets) - 1
        $patterns[$t] = _QwordToSearchBytes($targets[$t])
    Next

    While 1
        Local $r = DllCall($hK, "ulong_ptr", "VirtualQueryEx", "handle", $hP, "ptr", $addr, "ptr", DllStructGetPtr($lmbi), "ulong_ptr", DllStructGetSize($lmbi))
        If @error Or $r[0] = 0 Then ExitLoop
        Local $b = DllStructGetData($lmbi, "BaseAddress")
        Local $s = DllStructGetData($lmbi, "RegionSize")
        If DllStructGetData($lmbi, "State") = 0x1000 And BitAND(DllStructGetData($lmbi, "Protect"), 0x100) = 0 And $s < 0x10000000 Then
            Local $chunk = 65536
            If $s < $chunk Then $chunk = $s
            For $off = 0 To $s - 8 Step $chunk
                Local $rdSz = $chunk
                If $off + $rdSz > $s Then $rdSz = $s - $off
                If $rdSz < 8 Then ContinueLoop
                Local $data = _ReadBytes($hP, $hK, $b + $off, $rdSz)
                If @error Then ContinueLoop
                Local $bin = BinaryToString($data, 1)

                For $t = 0 To UBound($targets) - 1
                    Local $p = 1
                    While 1
                        Local $f = StringInStr($bin, $patterns[$t], 1, 1, $p)
                        If $f = 0 Then ExitLoop
                        Local $loc = $b + $off + ($f - 1)
                        If $loc <> $targets[$t] Then
                            ReDim $outArr[UBound($outArr) + 1]
                            $outArr[UBound($outArr) - 1] = $loc
                        EndIf
                        $p = $f + 1
                        If UBound($outArr) >= $maxResults Then Return
                    WEnd
                Next
            Next
        EndIf
        $addr = $b + $s
        If $addr = 0 Then ExitLoop
    WEnd
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

Func _ReadWString($hP, $hK, $iA)
    Local $buf = DllStructCreate("wchar[100]")
    DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $iA, "ptr", DllStructGetPtr($buf), "ulong_ptr", 200, "ulong_ptr*", 0)
    If @error Then Return ""
    Return DllStructGetData($buf, 1)
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
