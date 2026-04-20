#RequireAdmin
#include <GUIConstantsEx.au3>

; ============================================
; PWI 64-bit Offset Finder v4
; ============================================
; Uses Cheat Engine offsets from module base
; to systematically find the pointer chain.
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

; ==========================================
; STEP 1: Get module base address
; ==========================================
Global $hGUI = GUICreate("Finding Offsets...", 600, 350, -1, -1)
Global $lblStatus = GUICtrlCreateLabel("Starting...", 20, 15, 560, 25)
Global $lblDetail = GUICtrlCreateLabel("", 20, 45, 560, 25)
Global $lblTimer = GUICtrlCreateLabel("", 20, 75, 560, 25)
Global $lblResults = GUICtrlCreateLabel("", 20, 110, 560, 220)
GUISetState(@SW_SHOW, $hGUI)
Global $gStart = TimerInit()
Global $gLastUpdate = 0

_Status("Step 1: Finding module base address...")

Dim $moduleBase = 0
Dim $hSnap, $me

For $attempt = 1 To 5
    $hSnap = DllCall($hK32, "handle", "CreateToolhelp32Snapshot", "dword", 0x18, "dword", $PID)
    If Not @error And $hSnap[0] <> -1 Then
        $me = DllStructCreate("dword dwSize; dword th32ModuleID; dword th32ProcessID; dword GlcntUsage; ptr modBaseAddr; dword modBaseSize; handle hModule; char szModule[256]; char szExePath[260]")
        DllStructSetData($me, "dwSize", DllStructGetSize($me))
        Dim $mRet = DllCall($hK32, "bool", "Module32First", "handle", $hSnap[0], "ptr", DllStructGetPtr($me))
        If Not @error And $mRet[0] Then
            While 1
                If StringInStr(DllStructGetData($me, "szModule"), "elementclient_64") Then
                    $moduleBase = DllStructGetData($me, "modBaseAddr")
                    ExitLoop
                EndIf
                DllStructSetData($me, "dwSize", DllStructGetSize($me))
                Dim $nRet = DllCall($hK32, "bool", "Module32Next", "handle", $hSnap[0], "ptr", DllStructGetPtr($me))
                If @error Or $nRet[0] = 0 Then ExitLoop
            WEnd
        EndIf
        DllCall($hK32, "bool", "CloseHandle", "handle", $hSnap[0])
    EndIf
    If $moduleBase <> 0 Then ExitLoop
    Sleep(500)
Next

If $moduleBase = 0 Then
    _Status("Warning: Could not find module base. Will try without it.")
    Sleep(1000)
EndIf

_Status("Module base: 0x" & Hex($moduleBase))
Sleep(500)

; ==========================================
; STEP 2: Find character name in memory
; ==========================================
_Status("Step 2: Finding character name in memory...")

Dim $nameAddresses[0]
Dim $addr = 0
Dim $regionCount = 0
Dim $mbi = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")

While 1
    Dim $ret = DllCall($hK32, "ulong_ptr", "VirtualQueryEx", "handle", $hProc, "ptr", $addr, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
    If @error Or $ret[0] = 0 Then ExitLoop
    Dim $rBase = DllStructGetData($mbi, "BaseAddress")
    Dim $rSize = DllStructGetData($mbi, "RegionSize")
    Dim $rState = DllStructGetData($mbi, "State")
    Dim $rProtect = DllStructGetData($mbi, "Protect")

    If $rState = 0x1000 And BitAND($rProtect, 0x100) = 0 And $rSize < 0x10000000 Then
        Dim $chunkSize = 65536
        If $rSize < $chunkSize Then $chunkSize = $rSize
        For $offset = 0 To $rSize - 2 Step $chunkSize
            Dim $readSize = $chunkSize
            If $offset + $readSize > $rSize Then $readSize = $rSize - $offset
            Dim $data = _ReadBytes($hProc, $hK32, $rBase + $offset, $readSize)
            If @error Then ContinueLoop
            Dim $dataStr = BinaryToString($data, 2)
            Dim $pos = 1
            While 1
                Dim $found = StringInStr($dataStr, $charName, 1, 1, $pos)
                If $found = 0 Then ExitLoop
                Dim $foundAddr = $rBase + $offset + ($found - 1) * 2
                ReDim $nameAddresses[UBound($nameAddresses) + 1]
                $nameAddresses[UBound($nameAddresses) - 1] = $foundAddr
                $pos = $found + 1
                If UBound($nameAddresses) >= 300 Then ExitLoop 2
            WEnd
        Next
        $regionCount += 1
        _TickProgress("Step 2: Scanning... (" & $regionCount & " regions)", UBound($nameAddresses) & " name matches")
    EndIf

    $addr = $rBase + $rSize
    If $addr = 0 Then ExitLoop
WEnd

_Status("Step 2 done: " & UBound($nameAddresses) & " name matches found.")
Sleep(500)

If UBound($nameAddresses) = 0 Then
    GUIDelete($hGUI)
    MsgBox(16, "Error", "Could not find '" & $charName & "' in memory.")
    Exit
EndIf

; ==========================================
; STEP 3: For each name address, scan ALL
; memory for pointers TO that name address.
; This finds what object contains the name.
; ==========================================
_Status("Step 3: Scanning for pointers to each name address...")

Dim $output = ""
Dim $ptrToNameResults = ""
Dim $ptrToNameCount = 0

; For efficiency, only check the first 20 unique name addresses
Dim $maxNames = UBound($nameAddresses) - 1
If $maxNames > 19 Then $maxNames = 19

For $ni = 0 To $maxNames
    Dim $targetAddr = $nameAddresses[$ni]
    _TickProgress("Step 3: Checking name " & ($ni + 1) & "/" & ($maxNames + 1), "Looking for pointers to 0x" & Hex($targetAddr))

    ; Encode target address as 4 bytes (little-endian) for search
    Dim $b0 = BitAND($targetAddr, 0xFF)
    Dim $b1 = BitAND(BitShift($targetAddr, 8), 0xFF)
    Dim $b2 = BitAND(BitShift($targetAddr, 16), 0xFF)
    Dim $b3 = BitAND(BitShift($targetAddr, 24), 0xFF)
    Dim $searchBytes = Chr($b0) & Chr($b1) & Chr($b2) & Chr($b3)

    ; Scan all committed memory for this 4-byte pattern
    Dim $scanAddr = 0
    While 1
        Dim $sRet = DllCall($hK32, "ulong_ptr", "VirtualQueryEx", "handle", $hProc, "ptr", $scanAddr, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
        If @error Or $sRet[0] = 0 Then ExitLoop
        Dim $sBase = DllStructGetData($mbi, "BaseAddress")
        Dim $sSize = DllStructGetData($mbi, "RegionSize")
        Dim $sState = DllStructGetData($mbi, "State")
        Dim $sProtect = DllStructGetData($mbi, "Protect")

        If $sState = 0x1000 And BitAND($sProtect, 0x100) = 0 And $sSize < 0x10000000 Then
            Dim $sChunk = 65536
            If $sSize < $sChunk Then $sChunk = $sSize
            For $sOff = 0 To $sSize - 4 Step $sChunk
                Dim $sRead = $sChunk
                If $sOff + $sRead > $sSize Then $sRead = $sSize - $sOff
                If $sRead < 4 Then ContinueLoop
                Dim $sData = _ReadBytes($hProc, $hK32, $sBase + $sOff, $sRead)
                If @error Then ContinueLoop

                ; Search for the 4-byte address pattern in this chunk
                Dim $sBin = BinaryToString($sData, 1)
                Dim $sPos = 1
                While 1
                    Dim $sFound = StringInStr($sBin, $searchBytes, 1, 1, $sPos)
                    If $sFound = 0 Then ExitLoop
                    ; Verify it's dword-aligned
                    If Mod($sFound - 1, 4) = 0 Then
                        Dim $ptrLocation = $sBase + $sOff + ($sFound - 1)
                        ; Skip self-references (the name address itself)
                        If $ptrLocation <> $targetAddr Then
                            $ptrToNameCount += 1
                            Dim $ptrOffset = $targetAddr - $ptrLocation
                            $ptrToNameResults &= "Pointer to name 0x" & Hex($targetAddr) & " found at 0x" & Hex($ptrLocation)
                            $ptrToNameResults &= " (offset from ptr to name: " & $ptrOffset & " / 0x" & Hex($ptrOffset) & ")" & @CRLF

                            ; Read surrounding context at the pointer location
                            ; The pointer location might be inside the player object
                            ; Read 32 bytes before and after to see structure
                            Dim $ctxData = _ReadBytes($hProc, $hK32, $ptrLocation - 32, 72)
                            If Not @error Then
                                Dim $ctxHex = ""
                                For $cb = 1 To 72
                                    $ctxHex &= Hex(BinaryMid($ctxData, $cb, 1), 2)
                                    If Mod($cb, 4) = 0 Then $ctxHex &= " "
                                Next
                                $ptrToNameResults &= "  Context (32B before, 8B ptr, 32B after): " & $ctxHex & @CRLF
                            EndIf

                            ; Now try to find what points to THIS location (backtrack chain)
                            ; The player object start should be somewhere before this pointer
                            ; Try reading dwords every 4 bytes going back from ptrLocation
                            ; to see if any are valid heap addresses
                            Dim $objStart = 0
                            Dim $backData = _ReadBytes($hProc, $hK32, $ptrLocation - 0x1000, 0x1000)
                            If Not @error Then
                                ; Look for vtable pointer (first dword of object, usually > moduleBase)
                                For $bk = 0x1000 - 4 To 0 Step -4
                                    Dim $bkVal = _BytesToDword($backData, $bk)
                                    ; Check if this looks like a vtable pointer (in module range)
                                    If $moduleBase <> 0 And $bkVal > $moduleBase And $bkVal < ($moduleBase + 0x10000000) Then
                                        $objStart = $ptrLocation - 0x1000 + $bk
                                        Dim $nameOffInObj = $ptrLocation - $objStart
                                        $ptrToNameResults &= "  Possible object start at 0x" & Hex($objStart) & " (vtable-like ptr: 0x" & Hex($bkVal) & ")" & @CRLF
                                        $ptrToNameResults &= "  Name ptr offset in object: " & $nameOffInObj & " (0x" & Hex($nameOffInObj) & ")" & @CRLF
                                        ExitLoop
                                    EndIf
                                Next
                            EndIf

                            $ptrToNameResults &= @CRLF
                            If $ptrToNameCount >= 50 Then ExitLoop 3
                        EndIf
                    EndIf
                    $sPos = $sFound + 1
                WEnd
            Next
        EndIf

        $scanAddr = $sBase + $sSize
        If $scanAddr = 0 Then ExitLoop
    WEnd

    If $ptrToNameCount >= 50 Then ExitLoop
Next

_Status("Step 3 done: " & $ptrToNameCount & " pointers to name found.")
Sleep(500)

; ==========================================
; STEP 4: Try known CE offsets from module base
; ==========================================
Dim $ceResults = ""
If $moduleBase <> 0 Then
    _Status("Step 4: Testing Cheat Engine offsets...")

    ; Known CE offsets the user found
    Dim $ceOffsets[4] = [0x01ADBC30, 0x0A13BC40, 0x01A6D2A8, 0x019292E0]

    For $ci = 0 To 3
        Dim $testBase = $moduleBase + $ceOffsets[$ci]
        _TickProgress("Step 4: Testing CE offset " & ($ci + 1) & "/4", "0x" & Hex($ceOffsets[$ci]))

        ; Read the value at this address
        Dim $val0 = _ReadDword($hProc, $hK32, $testBase)
        If $val0 = 0 Then
            $ceResults &= "CE offset 0x" & Hex($ceOffsets[$ci]) & " at 0x" & Hex($testBase) & " -> value = 0 (empty)" & @CRLF
            ContinueLoop
        EndIf

        $ceResults &= "CE offset 0x" & Hex($ceOffsets[$ci]) & " at 0x" & Hex($testBase) & " -> value = 0x" & Hex($val0) & @CRLF

        ; Try various offset combinations for the pointer chain
        ; Old chain: [base] -> +0x1C -> +0x34 -> player -> +0xB90 -> namePtr -> name
        ; Try offsets 0x00 to 0x80 for first level
        For $off1 = 0x00 To 0x80 Step 4
            Dim $val1 = _ReadDword($hProc, $hK32, $val0 + $off1)
            If $val1 = 0 Or $val1 < 0x10000 Then ContinueLoop

            ; Try offsets 0x00 to 0x80 for second level
            For $off2 = 0x00 To 0x80 Step 4
                Dim $val2 = _ReadDword($hProc, $hK32, $val1 + $off2)
                If $val2 = 0 Or $val2 < 0x10000 Then ContinueLoop

                ; Now val2 should be the player object
                ; Try to read name at various offsets from 0x000 to 0x1200
                For $nameOff = 0x000 To 0x1200 Step 4
                    Dim $namePtr = _ReadDword($hProc, $hK32, $val2 + $nameOff)
                    If $namePtr = 0 Or $namePtr < 0x10000 Then ContinueLoop

                    ; Try to read a string at namePtr
                    Dim $nameBuf = DllStructCreate("wchar[50]")
                    DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $namePtr, "ptr", DllStructGetPtr($nameBuf), "ulong_ptr", 100, "ulong_ptr*", 0)
                    Dim $testName = DllStructGetData($nameBuf, 1)

                    If $testName = $charName Then
                        $ceResults &= "  *** MATCH FOUND! ***" & @CRLF
                        $ceResults &= "  Chain: [0x" & Hex($testBase) & "] -> +0x" & Hex($off1) & " -> +0x" & Hex($off2) & " -> +0x" & Hex($nameOff) & " -> name" & @CRLF
                        $ceResults &= "  ADDRESS_BASE = " & $testBase & " (0x" & Hex($testBase) & ")" & @CRLF
                        $ceResults &= "  Offset1 = " & $off1 & " (0x" & Hex($off1) & ")" & @CRLF
                        $ceResults &= "  Offset2 = " & $off2 & " (0x" & Hex($off2) & ")" & @CRLF
                        $ceResults &= "  PLAYERNAME_OFFSET = " & $nameOff & " (0x" & Hex($nameOff) & ")" & @CRLF
                        $ceResults &= @CRLF
                    EndIf
                Next
            Next
        Next

        ; Also try: the value at testBase might directly point to a structure
        ; containing the name (2-level chain instead of 3-level)
        For $off1 = 0x00 To 0x100 Step 4
            Dim $val1b = _ReadDword($hProc, $hK32, $val0 + $off1)
            If $val1b = 0 Or $val1b < 0x10000 Then ContinueLoop

            ; Try name directly at offset from val1b
            For $nameOff2 = 0x000 To 0x1200 Step 4
                Dim $namePtr2 = _ReadDword($hProc, $hK32, $val1b + $nameOff2)
                If $namePtr2 = 0 Or $namePtr2 < 0x10000 Then ContinueLoop

                Dim $nameBuf2 = DllStructCreate("wchar[50]")
                DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $namePtr2, "ptr", DllStructGetPtr($nameBuf2), "ulong_ptr", 100, "ulong_ptr*", 0)
                Dim $testName2 = DllStructGetData($nameBuf2, 1)

                If $testName2 = $charName Then
                    $ceResults &= "  *** MATCH (2-level) ***" & @CRLF
                    $ceResults &= "  Chain: [0x" & Hex($testBase) & "] -> +0x" & Hex($off1) & " -> +0x" & Hex($nameOff2) & " -> name" & @CRLF
                    $ceResults &= "  ADDRESS_BASE = " & $testBase & " (0x" & Hex($testBase) & ")" & @CRLF
                    $ceResults &= "  PLAYERNAME_OFFSET = " & $nameOff2 & " (0x" & Hex($nameOff2) & ")" & @CRLF
                    $ceResults &= @CRLF
                EndIf
            Next
        Next

        ; Also try: name stored inline (not via pointer)
        For $off1c = 0x00 To 0x80 Step 4
            Dim $val1c = _ReadDword($hProc, $hK32, $val0 + $off1c)
            If $val1c = 0 Or $val1c < 0x10000 Then ContinueLoop

            For $off2c = 0x00 To 0x80 Step 4
                Dim $val2c = _ReadDword($hProc, $hK32, $val1c + $off2c)
                If $val2c = 0 Or $val2c < 0x10000 Then ContinueLoop

                ; Read inline name at various offsets
                For $inOff = 0x000 To 0x1200 Step 4
                    Dim $inBuf = DllStructCreate("wchar[50]")
                    DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $val2c + $inOff, "ptr", DllStructGetPtr($inBuf), "ulong_ptr", 100, "ulong_ptr*", 0)
                    Dim $inName = DllStructGetData($inBuf, 1)

                    If $inName = $charName Then
                        $ceResults &= "  *** MATCH (inline name) ***" & @CRLF
                        $ceResults &= "  Chain: [0x" & Hex($testBase) & "] -> +0x" & Hex($off1c) & " -> +0x" & Hex($off2c) & " -> name inline at +0x" & Hex($inOff) & @CRLF
                        $ceResults &= "  ADDRESS_BASE = " & $testBase & " (0x" & Hex($testBase) & ")" & @CRLF
                        $ceResults &= "  Inline name offset = " & $inOff & " (0x" & Hex($inOff) & ")" & @CRLF
                        $ceResults &= @CRLF
                    EndIf
                Next
            Next
        Next
    Next
EndIf

; ==========================================
; STEP 5: Brute force - scan module memory
; for dwords that start a valid pointer chain
; leading to the character name
; ==========================================
_Status("Step 5: Brute-force scanning module memory for ADDRESS_BASE...")

Dim $bfResults = ""
Dim $bfCount = 0
Dim $bfAddr = 0
Dim $bfRegions = 0

While 1
    Dim $bfRet = DllCall($hK32, "ulong_ptr", "VirtualQueryEx", "handle", $hProc, "ptr", $bfAddr, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
    If @error Or $bfRet[0] = 0 Then ExitLoop
    Dim $bfBase = DllStructGetData($mbi, "BaseAddress")
    Dim $bfSize = DllStructGetData($mbi, "RegionSize")
    Dim $bfState = DllStructGetData($mbi, "State")
    Dim $bfProtect = DllStructGetData($mbi, "Protect")
    Dim $bfType = DllStructGetData($mbi, "Type")

    ; Only scan committed, readable, image-backed memory
    If $bfState = 0x1000 And BitAND($bfProtect, 0x100) = 0 And $bfType = 0x1000000 Then
        Dim $bfChunk = 4096
        For $bfOff = 0 To $bfSize - 4 Step $bfChunk
            Dim $bfRead = $bfChunk
            If $bfOff + $bfRead > $bfSize Then $bfRead = $bfSize - $bfOff
            If $bfRead < 4 Then ContinueLoop

            Dim $bfData = _ReadBytes($hProc, $hK32, $bfBase + $bfOff, $bfRead)
            If @error Then ContinueLoop

            For $bfBp = 0 To $bfRead - 4 Step 4
                Dim $bfVal = _BytesToDword($bfData, $bfBp)
                If $bfVal < 0x10000 Or $bfVal = 0 Then ContinueLoop

                ; Try the old-style 3-level chain with various offsets
                ; Level 1: try +0x1C and +0x20 and +0x28 and +0x30
                Dim $tryOffs1[4] = [0x1C, 0x20, 0x28, 0x30]
                For $t1 = 0 To 3
                    Dim $lv1 = _ReadDword($hProc, $hK32, $bfVal + $tryOffs1[$t1])
                    If $lv1 = 0 Or $lv1 < 0x10000 Then ContinueLoop

                    ; Level 2: try +0x34 and +0x38 and +0x40 and +0x48 and +0x50 and +0x68
                    Dim $tryOffs2[6] = [0x34, 0x38, 0x40, 0x48, 0x50, 0x68]
                    For $t2 = 0 To 5
                        Dim $lv2 = _ReadDword($hProc, $hK32, $lv1 + $tryOffs2[$t2])
                        If $lv2 = 0 Or $lv2 < 0x10000 Then ContinueLoop

                        ; Try name pointer at various offsets
                        Dim $tryNameOffs[8] = [0xB90, 0xB98, 0xBA0, 0xBA8, 0xBB0, 0x1170, 0x1178, 0x1180]
                        For $tn = 0 To 7
                            Dim $np = _ReadDword($hProc, $hK32, $lv2 + $tryNameOffs[$tn])
                            If $np = 0 Or $np < 0x10000 Then ContinueLoop

                            Dim $nb = DllStructCreate("wchar[50]")
                            DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $np, "ptr", DllStructGetPtr($nb), "ulong_ptr", 100, "ulong_ptr*", 0)
                            Dim $nm = DllStructGetData($nb, 1)
                            If $nm = $charName Then
                                $bfCount += 1
                                Dim $bfFoundAddr = $bfBase + $bfOff + $bfBp
                                $bfResults &= "*** FOUND (ptr-based name)! ***" & @CRLF
                                $bfResults &= "ADDRESS_BASE = " & $bfFoundAddr & " (0x" & Hex($bfFoundAddr) & ")" & @CRLF
                                $bfResults &= "Chain: [base] -> +0x" & Hex($tryOffs1[$t1]) & " -> +0x" & Hex($tryOffs2[$t2]) & " -> +0x" & Hex($tryNameOffs[$tn]) & " -> name" & @CRLF
                                $bfResults &= @CRLF
                            EndIf
                        Next

                        ; Also try inline name at common offsets
                        Dim $tryInline[8] = [0xB90, 0xB98, 0xBA0, 0xBA8, 0xBB0, 0x1170, 0x1178, 0x1180]
                        For $ti = 0 To 7
                            Dim $ib = DllStructCreate("wchar[50]")
                            DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $lv2 + $tryInline[$ti], "ptr", DllStructGetPtr($ib), "ulong_ptr", 100, "ulong_ptr*", 0)
                            Dim $im = DllStructGetData($ib, 1)
                            If $im = $charName Then
                                $bfCount += 1
                                Dim $bfFoundAddr2 = $bfBase + $bfOff + $bfBp
                                $bfResults &= "*** FOUND (inline name)! ***" & @CRLF
                                $bfResults &= "ADDRESS_BASE = " & $bfFoundAddr2 & " (0x" & Hex($bfFoundAddr2) & ")" & @CRLF
                                $bfResults &= "Chain: [base] -> +0x" & Hex($tryOffs1[$t1]) & " -> +0x" & Hex($tryOffs2[$t2]) & " -> inline name at +0x" & Hex($tryInline[$ti]) & @CRLF
                                $bfResults &= @CRLF
                            EndIf
                        Next
                    Next
                Next
            Next
        Next
        $bfRegions += 1
        If Mod($bfRegions, 5) = 0 Then
            _TickProgress("Step 5: Scanning module memory (" & $bfRegions & " regions)", $bfCount & " matches found so far")
        EndIf
    EndIf

    $bfAddr = $bfBase + $bfSize
    If $bfAddr = 0 Then ExitLoop
WEnd

_Status("Step 5 done: " & $bfCount & " matches from brute force scan.")
Sleep(500)

; ==========================================
; FINAL OUTPUT
; ==========================================
GUIDelete($hGUI)

Dim $fullOutput = "PWI 64-bit Offset Finder v4 Results" & @CRLF
$fullOutput &= "====================================" & @CRLF
$fullOutput &= "Process: elementclient_64.exe (PID " & $PID & ")" & @CRLF
$fullOutput &= "Module base: 0x" & Hex($moduleBase) & @CRLF
$fullOutput &= "Character: " & $charName & @CRLF
$fullOutput &= "Name matches in memory: " & UBound($nameAddresses) & @CRLF
$fullOutput &= @CRLF

$fullOutput &= "=== POINTER-TO-NAME SCAN RESULTS ===" & @CRLF
$fullOutput &= "Found " & $ptrToNameCount & " pointers to name addresses" & @CRLF
$fullOutput &= $ptrToNameResults & @CRLF

If $ceResults <> "" Then
    $fullOutput &= "=== CHEAT ENGINE OFFSET RESULTS ===" & @CRLF
    $fullOutput &= $ceResults & @CRLF
EndIf

$fullOutput &= "=== BRUTE FORCE SCAN RESULTS ===" & @CRLF
$fullOutput &= "Found " & $bfCount & " matches" & @CRLF
$fullOutput &= $bfResults & @CRLF

; Show first 20 name addresses for reference
$fullOutput &= "=== NAME ADDRESSES (first 20) ===" & @CRLF
Dim $showMax = UBound($nameAddresses) - 1
If $showMax > 19 Then $showMax = 19
For $i = 0 To $showMax
    $fullOutput &= "  0x" & Hex($nameAddresses[$i]) & @CRLF
Next
$fullOutput &= @CRLF

ClipPut($fullOutput)

If $bfCount > 0 Or StringInStr($ceResults, "MATCH") Then
    MsgBox(64, "SUCCESS!", "Found potential ADDRESS_BASE values!" & @CRLF & @CRLF & "Results copied to clipboard." & @CRLF & "Paste them to Claude for analysis.")
Else
    MsgBox(48, "Analysis Complete", "Data collected and copied to clipboard." & @CRLF & @CRLF & "Results:" & @CRLF & "- " & UBound($nameAddresses) & " name addresses" & @CRLF & "- " & $ptrToNameCount & " pointers to name" & @CRLF & "- " & $bfCount & " brute force matches" & @CRLF & @CRLF & "Paste the results to Claude for analysis.")
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
