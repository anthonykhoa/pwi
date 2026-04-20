#RequireAdmin
#include <GUIConstantsEx.au3>

; ============================================
; PWI 64-bit Offset Finder v3
; ============================================
; Handles both pointer-to-name and inline name
; ============================================

Dim $PID = ProcessExists("elementclient_64.exe")
If $PID = 0 Then
    MsgBox(16, "Error", "elementclient_64.exe is not running!" & @CRLF & "Log into a character first.")
    Exit
EndIf

Dim $hK32 = DllOpen("kernel32.dll")
Dim $aOpen = DllCall($hK32, "handle", "OpenProcess", "dword", 0x1F0FFF, "bool", 0, "dword", $PID)
If $aOpen[0] = 0 Then
    MsgBox(16, "Error", "Failed to open process. Run as Administrator.")
    DllClose($hK32)
    Exit
EndIf
Dim $hProc = $aOpen[0]

Dim $charName = InputBox("Character Name", "Type your character name EXACTLY (case-sensitive):", "", "", 400, 200)
If $charName = "" Then Exit

Global $hGUI = GUICreate("Finding Offsets...", 550, 250, -1, -1)
Global $lblStatus = GUICtrlCreateLabel("Starting...", 20, 15, 510, 25)
Global $lblDetail = GUICtrlCreateLabel("", 20, 45, 510, 25)
Global $lblTimer = GUICtrlCreateLabel("", 20, 75, 510, 25)
Global $lblResults = GUICtrlCreateLabel("", 20, 110, 510, 120)
GUISetState(@SW_SHOW, $hGUI)
Global $gStart = TimerInit()
Global $gLastUpdate = 0

Dim $ret, $rBase, $rSize, $rState, $rProtect
Dim $chunkSize, $readSize, $data, $dataStr, $pos, $found, $foundAddr
Dim $rdSz, $chunk, $bp, $off, $offset
Dim $addr, $regionCount
Dim $mbi = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")

; ==========================================
; PHASE 1: Find character name in memory
; ==========================================
_Status("Phase 1: Searching for '" & $charName & "' in memory...")

Dim $nameAddresses[0]
$addr = 0
$regionCount = 0

While 1
    $ret = DllCall($hK32, "ulong_ptr", "VirtualQueryEx", "handle", $hProc, "ptr", $addr, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
    If @error Or $ret[0] = 0 Then ExitLoop
    $rBase = DllStructGetData($mbi, "BaseAddress")
    $rSize = DllStructGetData($mbi, "RegionSize")
    $rState = DllStructGetData($mbi, "State")
    $rProtect = DllStructGetData($mbi, "Protect")

    If $rState = 0x1000 And BitAND($rProtect, 0x100) = 0 And $rSize < 0x10000000 Then
        $chunkSize = 65536
        If $rSize < $chunkSize Then $chunkSize = $rSize
        For $offset = 0 To $rSize - 2 Step $chunkSize
            $readSize = $chunkSize
            If $offset + $readSize > $rSize Then $readSize = $rSize - $offset
            $data = _ReadBytes($hProc, $hK32, $rBase + $offset, $readSize)
            If @error Then ContinueLoop
            $dataStr = BinaryToString($data, 2)
            $pos = 1
            While 1
                $found = StringInStr($dataStr, $charName, 1, 1, $pos)
                If $found = 0 Then ExitLoop
                $foundAddr = $rBase + $offset + ($found - 1) * 2
                ReDim $nameAddresses[UBound($nameAddresses) + 1]
                $nameAddresses[UBound($nameAddresses) - 1] = $foundAddr
                $pos = $found + 1
                If UBound($nameAddresses) >= 200 Then ExitLoop 2
            WEnd
        Next
        $regionCount += 1
        _TickProgress("Phase 1: Scanning... (" & $regionCount & " regions)", UBound($nameAddresses) & " name matches")
    EndIf

    $addr = $rBase + $rSize
    If $addr = 0 Then ExitLoop
WEnd

If UBound($nameAddresses) = 0 Then
    GUIDelete($hGUI)
    MsgBox(16, "Error", "Could not find '" & $charName & "' in memory.")
    Exit
EndIf

_Status("Phase 1 done: " & UBound($nameAddresses) & " name matches found.")
Sleep(500)

; ==========================================
; PHASE 2: Dump info about each name location
; For each name address, read surrounding
; memory and look for structure patterns.
; Also check if a pointer or inline name.
; ==========================================
_Status("Phase 2: Analyzing each name location...")

Dim $output = ""
Dim $candidates = 0
Dim $nameAddr, $surroundStart, $surroundData, $hexDump

; For each name address, dump 256 bytes before it and the address itself
; This helps us understand the structure
For $i = 0 To UBound($nameAddresses) - 1
    $nameAddr = $nameAddresses[$i]
    _TickProgress("Phase 2: Analyzing name " & ($i + 1) & "/" & UBound($nameAddresses), "Address: 0x" & Hex($nameAddr))

    ; Read 4KB before the name to look for structure start
    $surroundStart = $nameAddr - 0x1000
    $surroundData = _ReadBytes($hProc, $hK32, $surroundStart, 0x1000)
    If @error Then ContinueLoop

    ; Check: is there a pointer TO this name address stored somewhere nearby?
    ; (would indicate pointer-based name, not inline)
    Dim $isPointerBased = False
    Dim $pointerLoc = 0
    For $scanOff = 0 To 0x1000 - 8 Step 8
        Dim $ptrVal = _BytesToPtr($surroundData, $scanOff)
        If $ptrVal = $nameAddr Then
            $isPointerBased = True
            $pointerLoc = $surroundStart + $scanOff
            ExitLoop
        EndIf
    Next

    ; Also check memory AFTER the name
    Dim $afterData = _ReadBytes($hProc, $hK32, $nameAddr, 0x1000)
    If Not @error Then
        For $scanOff = 0x100 To 0x1000 - 8 Step 8
            Dim $ptrVal2 = _BytesToPtr($afterData, $scanOff)
            If $ptrVal2 = $nameAddr Then
                $isPointerBased = True
                $pointerLoc = $nameAddr + $scanOff
                ExitLoop
            EndIf
        Next
    EndIf

    ; Check for nearby non-zero dwords that could be player IDs
    ; (a number between 1000 and 100000000)
    Dim $nearbyID = 0
    Dim $nearbyIDOffset = 0
    For $idOff = 0 To 0x1000 - 4 Step 4
        Dim $idCheck = _BytesToDword($surroundData, $idOff)
        If $idCheck > 1000 And $idCheck < 100000000 Then
            $nearbyID = $idCheck
            $nearbyIDOffset = $idOff - 0x1000 ; offset relative to name
            ExitLoop
        EndIf
    Next

    $candidates += 1
    $output &= "=== Name Location " & $candidates & " ===" & @CRLF
    $output &= "Name string at: 0x" & Hex($nameAddr) & @CRLF
    If $isPointerBased Then
        $output &= "TYPE: Pointer-based (pointer at 0x" & Hex($pointerLoc) & ", offset from name ptr: " & ($pointerLoc - $nameAddr) & ")" & @CRLF
    Else
        $output &= "TYPE: Inline (no pointer found nearby)" & @CRLF
    EndIf
    If $nearbyID > 0 Then
        $output &= "Nearby ID-like value: " & $nearbyID & " at offset " & $nearbyIDOffset & " from name" & @CRLF
    EndIf

    ; Dump first 128 bytes before name as hex for analysis
    Dim $hexBefore = ""
    For $hb = 0x0F00 To 0x0FFF
        $hexBefore &= Hex(BinaryMid($surroundData, $hb + 1, 1), 2)
        If Mod($hb + 1, 4) = 0 Then $hexBefore &= " "
    Next
    $output &= "256 bytes before name: " & $hexBefore & @CRLF
    $output &= @CRLF

    If $candidates >= 10 Then ExitLoop
Next

_Status("Phase 2 done: " & $candidates & " locations analyzed.")

Dim $chainResults = ""
Dim $chainCount = 0

; ==========================================
; PHASE 3: Dump pointer data for Claude
; ==========================================

; Final approach: for each name address, read the surrounding 4KB
; and output the raw pointer-sized values near it
_Status("Phase 3b: Extracting pointer chain data...")

Dim $ptrDump = ""
Dim $dumpCount = 0

For $i = 0 To UBound($nameAddresses) - 1
    If $dumpCount >= 5 Then ExitLoop
    $nameAddr = $nameAddresses[$i]
    _TickProgress("Phase 3b: Dumping " & ($i + 1) & "/" & UBound($nameAddresses), "")

    ; Read 2KB before and 512 bytes after
    Dim $beforeSize = 0x800
    Dim $beforeData = _ReadBytes($hProc, $hK32, $nameAddr - $beforeSize, $beforeSize + 0x200)
    If @error Then ContinueLoop

    ; Look for 8-byte values that look like valid pointers (> 0x10000)
    Dim $ptrs = ""
    For $po = 0 To $beforeSize + 0x200 - 8 Step 8
        Dim $ptrV = _BytesToPtr($beforeData, $po)
        If $ptrV > 0x10000 And $ptrV < 0x7FFFFFFFFFFF Then
            Dim $relOff = $po - $beforeSize
            $ptrs &= "  offset " & $relOff & " (0x" & Hex($relOff) & "): ptr = 0x" & Hex($ptrV) & @CRLF
        EndIf
    Next

    If $ptrs <> "" Then
        $dumpCount += 1
        $ptrDump &= "=== Name at 0x" & Hex($nameAddr) & " ===" & @CRLF
        $ptrDump &= "Pointers within 2KB before and 512B after:" & @CRLF
        $ptrDump &= $ptrs & @CRLF
    EndIf
Next

; ==========================================
; FINAL OUTPUT
; ==========================================
GUIDelete($hGUI)

Dim $fullOutput = "PWI 64-bit Offset Finder Results" & @CRLF
$fullOutput &= "================================" & @CRLF
$fullOutput &= "Process: elementclient_64.exe (PID " & $PID & ")" & @CRLF
$fullOutput &= "Character: " & $charName & @CRLF
$fullOutput &= "Name matches found: " & UBound($nameAddresses) & @CRLF
$fullOutput &= @CRLF

; Add first 20 name addresses
$fullOutput &= "Name addresses:" & @CRLF
Dim $showMax = UBound($nameAddresses) - 1
If $showMax > 19 Then $showMax = 19
For $i = 0 To $showMax
    $fullOutput &= "  0x" & Hex($nameAddresses[$i]) & @CRLF
Next
If UBound($nameAddresses) > 20 Then $fullOutput &= "  ... and " & (UBound($nameAddresses) - 20) & " more" & @CRLF
$fullOutput &= @CRLF

$fullOutput &= $output & @CRLF
$fullOutput &= "=== POINTER DUMPS ===" & @CRLF
$fullOutput &= $ptrDump

If $chainCount > 0 Then
    MsgBox(64, "SUCCESS!", $chainResults & @CRLF & "Copied to clipboard!")
    ClipPut($chainResults)
Else
    MsgBox(48, "Analysis Complete", "Data collected and copied to clipboard." & @CRLF & @CRLF & "Paste the results to Claude - he can analyze" & @CRLF & "the pointer structure and find the offsets." & @CRLF & @CRLF & "Collected:" & @CRLF & "- " & UBound($nameAddresses) & " name addresses" & @CRLF & "- " & $candidates & " location analyses" & @CRLF & "- " & $dumpCount & " pointer dumps")
    ClipPut($fullOutput)
EndIf

DllCall($hK32, "bool", "CloseHandle", "handle", $hProc)
DllClose($hK32)

; ============================================
; HELPER FUNCTIONS
; ============================================

Func _Status($msg, $detail = "")
    GUICtrlSetData($lblStatus, $msg)
    If $detail <> "" Then GUICtrlSetData($lblDetail, $detail)
    Dim $el = Round(TimerDiff($gStart) / 1000)
    GUICtrlSetData($lblTimer, "Elapsed: " & $el & "s")
    $gLastUpdate = TimerInit()
EndFunc

Func _TickProgress($msg, $detail = "")
    If TimerDiff($gLastUpdate) > 500 Then _Status($msg, $detail)
EndFunc

Func _ReadDword($hP, $hK, $iA)
    Dim $buf = DllStructCreate("dword")
    DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $iA, "ptr", DllStructGetPtr($buf), "ulong_ptr", 4, "ulong_ptr*", 0)
    If @error Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

Func _ReadQword($hP, $hK, $iA)
    Dim $buf = DllStructCreate("ptr")
    DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $iA, "ptr", DllStructGetPtr($buf), "ulong_ptr", 8, "ulong_ptr*", 0)
    If @error Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

Func _ReadBytes($hP, $hK, $iA, $iS)
    Dim $buf = DllStructCreate("byte[" & $iS & "]")
    Dim $r = DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $iA, "ptr", DllStructGetPtr($buf), "ulong_ptr", $iS, "ulong_ptr*", 0)
    If @error Or $r[0] = 0 Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

Func _BytesToDword($bytes, $iOff)
    Dim $b1 = DllStructCreate("byte[4]")
    DllStructSetData($b1, 1, BinaryMid($bytes, $iOff + 1, 4))
    Dim $b2 = DllStructCreate("dword", DllStructGetPtr($b1))
    Return DllStructGetData($b2, 1)
EndFunc

Func _BytesToPtr($bytes, $iOff)
    Dim $b1 = DllStructCreate("byte[8]")
    DllStructSetData($b1, 1, BinaryMid($bytes, $iOff + 1, 8))
    Dim $b2 = DllStructCreate("ptr", DllStructGetPtr($b1))
    Return DllStructGetData($b2, 1)
EndFunc
