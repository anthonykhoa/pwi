#RequireAdmin
#include <GUIConstantsEx.au3>

; ============================================
; PWI 64-bit Offset Finder
; ============================================
; Finds the new pointer chain offsets for the
; 64-bit client by working backwards from the
; character name in memory.
; ============================================

; Step 1: Find the process
Local $PID = ProcessExists("elementclient_64.exe")
If $PID = 0 Then
    MsgBox(16, "Error", "elementclient_64.exe is not running!" & @CRLF & "Log into a character first.")
    Exit
EndIf

; Step 2: Open process
Local $hK32 = DllOpen("kernel32.dll")
Local $aOpen = DllCall($hK32, "handle", "OpenProcess", "dword", 0x1F0FFF, "bool", 0, "dword", $PID)
If $aOpen[0] = 0 Then
    MsgBox(16, "Error", "Failed to open process. Run as Administrator.")
    DllClose($hK32)
    Exit
EndIf
Local $hProc = $aOpen[0]

; Step 3: Get character name
Local $charName = InputBox("Character Name", "Type your character name EXACTLY (case-sensitive):", "", "", 400, 200)
If $charName = "" Then Exit

; Progress window
Global $hGUI = GUICreate("Finding Offsets...", 500, 200, -1, -1)
Global $lblStatus = GUICtrlCreateLabel("Starting...", 20, 15, 460, 25)
Global $lblDetail = GUICtrlCreateLabel("", 20, 45, 460, 25)
Global $lblTimer = GUICtrlCreateLabel("", 20, 75, 460, 25)
Global $lblResults = GUICtrlCreateLabel("", 20, 105, 460, 80)
GUISetState(@SW_SHOW, $hGUI)
Global $gStart = TimerInit()

; ==========================================
; PHASE 1: Find character name in memory
; ==========================================
_Status("Phase 1: Searching for '" & $charName & "' in memory...")

Local $nameAddresses[0]
Local $addr = 0
Local $mbi = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")
Local $regionCount = 0

While 1
    Local $ret = DllCall($hK32, "ulong_ptr", "VirtualQueryEx", "handle", $hProc, "ptr", $addr, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
    If @error Or $ret[0] = 0 Then ExitLoop

    Local $rBase = DllStructGetData($mbi, "BaseAddress")
    Local $rSize = DllStructGetData($mbi, "RegionSize")
    Local $rState = DllStructGetData($mbi, "State")
    Local $rProtect = DllStructGetData($mbi, "Protect")

    If $rState = 0x1000 And BitAND($rProtect, 0x100) = 0 And $rSize < 0x10000000 Then
        Local $chunkSize = 65536
        If $rSize < $chunkSize Then $chunkSize = $rSize
        For $offset = 0 To $rSize - 2 Step $chunkSize
            Local $readSize = $chunkSize
            If $offset + $readSize > $rSize Then $readSize = $rSize - $offset
            Local $data = _ReadBytes($hProc, $hK32, $rBase + $offset, $readSize)
            If @error Then ContinueLoop
            Local $dataStr = BinaryToString($data, 2)
            Local $pos = 1
            While 1
                Local $found = StringInStr($dataStr, $charName, 1, 1, $pos)
                If $found = 0 Then ExitLoop
                Local $foundAddr = $rBase + $offset + ($found - 1) * 2
                ReDim $nameAddresses[UBound($nameAddresses) + 1]
                $nameAddresses[UBound($nameAddresses) - 1] = $foundAddr
                $pos = $found + 1
                If UBound($nameAddresses) >= 200 Then ExitLoop 2
            WEnd
        Next
        $regionCount += 1
        _TickProgress("Phase 1: Scanning for name... (" & $regionCount & " regions)", UBound($nameAddresses) & " matches so far")
    EndIf

    $addr = $rBase + $rSize
    If $addr = 0 Then ExitLoop
WEnd

If UBound($nameAddresses) = 0 Then
    GUIDelete($hGUI)
    MsgBox(16, "Error", "Could not find '" & $charName & "' in memory. Check spelling/case.")
    Exit
EndIf

_Status("Phase 1 done: Found " & UBound($nameAddresses) & " name matches.")

; ==========================================
; PHASE 2: Find what points to each name address
; (looking for the name POINTER in the player object)
; ==========================================
_Status("Phase 2: Finding pointers to name strings...")

Local $namePointers[0][2] ; [n][0] = pointer location, [n][1] = name address it points to

; Build list of name addresses to search for
; Scan all memory for dwords/ptrs that match any of our name addresses
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
        Local $chunkSz = 65536
        If $rSize < $chunkSz Then $chunkSz = $rSize
        For $off = 0 To $rSize - 4 Step $chunkSz
            Local $rdSz = $chunkSz
            If $off + $rdSz > $rSize Then $rdSz = $rSize - $off
            If $rdSz < 4 Then ContinueLoop
            Local $chunk = _ReadBytes($hProc, $hK32, $rBase + $off, $rdSz)
            If @error Then ContinueLoop

            For $bp = 0 To $rdSz - 4 Step 4
                Local $val = _BytesToDword($chunk, $bp)
                If $val < 0x10000 Then ContinueLoop

                For $n = 0 To UBound($nameAddresses) - 1
                    If $val = $nameAddresses[$n] Then
                        Local $ptrAddr = $rBase + $off + $bp
                        ReDim $namePointers[UBound($namePointers, 1) + 1][2]
                        $namePointers[UBound($namePointers, 1) - 1][0] = $ptrAddr
                        $namePointers[UBound($namePointers, 1) - 1][1] = $val
                        If UBound($namePointers, 1) >= 100 Then ExitLoop 4
                    EndIf
                Next
            Next
        Next
        $regionCount += 1
        _TickProgress("Phase 2: Finding name pointers... (" & $regionCount & " regions)", UBound($namePointers, 1) & " pointers found so far")
    EndIf

    $addr = $rBase + $rSize
    If $addr = 0 Then ExitLoop
WEnd

_Status("Phase 2 done: Found " & UBound($namePointers, 1) & " name pointers.")

If UBound($namePointers, 1) = 0 Then
    GUIDelete($hGUI)
    MsgBox(48, "Partial Results", "Found name strings but no pointers to them." & @CRLF & @CRLF & "Name addresses:" & @CRLF & _FormatAddrs($nameAddresses) & @CRLF & "Share this with Claude.")
    ClipPut("Name addresses found but no pointers:" & @CRLF & _FormatAddrs($nameAddresses))
    Exit
EndIf

; ==========================================
; PHASE 3: For each name pointer, figure out
; the offset from the player object base.
; The name pointer is at playerBase + NAME_OFFSET.
; We find NAME_OFFSET by checking what other
; recognizable data is near the pointer.
; ==========================================
_Status("Phase 3: Analyzing player object structure...")

Local $output = ""
Local $validCount = 0

For $i = 0 To UBound($namePointers, 1) - 1
    Local $namePtrAddr = $namePointers[$i][0]

    ; Try various offsets for where the name pointer might be in the player struct
    ; Read a wide area around the name pointer to look for patterns
    ; The old name offset was 0xB90 (2960), so the player base would be namePtrAddr - 0xB90
    ; But we don't know the new offset, so try a range

    ; Read 16KB around the name pointer location to find the player object boundary
    Local $scanStart = $namePtrAddr - 0x2000 ; 8KB before
    Local $scanSize = 0x4000 ; 16KB total
    Local $areaData = _ReadBytes($hProc, $hK32, $scanStart, $scanSize)
    If @error Then ContinueLoop

    ; For each possible name offset (0 to 8192 in steps of 4),
    ; assume playerBase = namePtrAddr - offset
    ; Then check if playerBase + some_other_offset has a valid player ID (non-zero dword)
    ; Also try to verify by reading the name back through the pointer

    For $tryOffset = 0 To 0x1800 Step 4
        Local $tryPlayerBase = $namePtrAddr - $tryOffset

        ; Quick validation: read a few things from this candidate player base
        ; Check for player ID somewhere in the first 0x1000 bytes
        ; A valid player object should have some non-zero dwords at consistent offsets

        ; Try reading name through this offset to verify
        Local $nameCheck = _ReadDword($hProc, $hK32, $tryPlayerBase + $tryOffset)
        If $nameCheck = $namePointers[$i][1] Then
            ; This confirms the name pointer is at tryPlayerBase + tryOffset
            ; Now look for what points to tryPlayerBase (the level above in the chain)

            ; Check for a player ID - try common ID offsets around the old 0x808
            Local $possibleID = 0
            Local $idOffset = 0
            For $tryID = 0x700 To 0x1000 Step 4
                Local $idVal = _ReadDword($hProc, $hK32, $tryPlayerBase + $tryID)
                If $idVal > 1000 And $idVal < 100000000 Then
                    $possibleID = $idVal
                    $idOffset = $tryID
                    ExitLoop
                EndIf
            Next

            $validCount += 1
            $output &= "=== Candidate " & $validCount & " ===" & @CRLF
            $output &= "Name pointer at: 0x" & Hex($namePtrAddr) & @CRLF
            $output &= "Player object at: 0x" & Hex($tryPlayerBase) & @CRLF
            $output &= "NAME_OFFSET = " & $tryOffset & "  (0x" & Hex($tryOffset) & ")" & @CRLF
            If $possibleID > 0 Then
                $output &= "Possible Player ID: " & $possibleID & " at offset " & $idOffset & " (0x" & Hex($idOffset) & ")" & @CRLF
            EndIf
            $output &= @CRLF

            If $validCount >= 20 Then ExitLoop 2
            ExitLoop ; Found it for this pointer, move to next
        EndIf
    Next

    _TickProgress("Phase 3: Checking pointer " & ($i + 1) & "/" & UBound($namePointers, 1), $validCount & " player objects found so far")
Next

; ==========================================
; PHASE 4: For each player object, scan for
; pointers to it and trace up the chain to
; find PLAYER_OFFSET, level2 offset, and ADDRESS_BASE
; ==========================================
Local $playerAddrs[0]
Local $playerNameOffsets[0]
For $z = 0 To UBound($namePointers, 1) - 1
    Local $npa = $namePointers[$z][0]
    For $tryOff = 0 To 0x1800 Step 4
        Local $tpb = $npa - $tryOff
        Local $nc = _ReadDword($hProc, $hK32, $tpb + $tryOff)
        If $nc = $namePointers[$z][1] Then
            ReDim $playerAddrs[UBound($playerAddrs) + 1]
            $playerAddrs[UBound($playerAddrs) - 1] = $tpb
            ReDim $playerNameOffsets[UBound($playerNameOffsets) + 1]
            $playerNameOffsets[UBound($playerNameOffsets) - 1] = $tryOff
            ExitLoop
        EndIf
    Next
    If UBound($playerAddrs) >= 5 Then ExitLoop
Next

If UBound($playerAddrs) = 0 And $validCount = 0 Then
    GUIDelete($hGUI)
    MsgBox(48, "No Results", "Could not identify player objects." & @CRLF & "Raw data copied to clipboard - share with Claude.")
    Local $rawOut = "Name addresses:" & @CRLF & _FormatAddrs($nameAddresses) & @CRLF
    $rawOut &= "Name pointer locations:" & @CRLF
    For $i = 0 To UBound($namePointers, 1) - 1
        $rawOut &= "  0x" & Hex($namePointers[$i][0]) & " -> 0x" & Hex($namePointers[$i][1]) & @CRLF
    Next
    ClipPut($rawOut)
    DllCall($hK32, "bool", "CloseHandle", "handle", $hProc)
    DllClose($hK32)
    Exit
EndIf

_Status("Phase 4: Finding pointers to player objects...")

Local $chainResults = ""
Local $chainCount = 0

For $pi = 0 To UBound($playerAddrs) - 1
    Local $pAddr = $playerAddrs[$pi]
    Local $pNameOff = $playerNameOffsets[$pi]
    _Status("Phase 4: Tracing chain for player " & ($pi + 1) & "/" & UBound($playerAddrs) & "...")

    ; Scan all memory for dwords equal to pAddr (pointers to the player)
    Local $ptrToPlayer[0]
    $addr = 0
    While 1
        $ret = DllCall($hK32, "ulong_ptr", "VirtualQueryEx", "handle", $hProc, "ptr", $addr, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
        If @error Or $ret[0] = 0 Then ExitLoop
        $rBase = DllStructGetData($mbi, "BaseAddress")
        $rSize = DllStructGetData($mbi, "RegionSize")
        $rState = DllStructGetData($mbi, "State")
        $rProtect = DllStructGetData($mbi, "Protect")
        If $rState = 0x1000 And BitAND($rProtect, 0x100) = 0 And $rSize < 0x10000000 Then
            Local $cSz4 = 65536
            If $rSize < $cSz4 Then $cSz4 = $rSize
            For $o4 = 0 To $rSize - 4 Step $cSz4
                Local $rS4 = $cSz4
                If $o4 + $rS4 > $rSize Then $rS4 = $rSize - $o4
                If $rS4 < 4 Then ContinueLoop
                Local $c4 = _ReadBytes($hProc, $hK32, $rBase + $o4, $rS4)
                If @error Then ContinueLoop
                For $b4 = 0 To $rS4 - 4 Step 4
                    If _BytesToDword($c4, $b4) = $pAddr Then
                        ReDim $ptrToPlayer[UBound($ptrToPlayer) + 1]
                        $ptrToPlayer[UBound($ptrToPlayer) - 1] = $rBase + $o4 + $b4
                        If UBound($ptrToPlayer) >= 30 Then ExitLoop 3
                    EndIf
                Next
            Next
            _TickProgress("Phase 4a: Scanning for player pointers...", UBound($ptrToPlayer) & " pointers found")
        EndIf
        $addr = $rBase + $rSize
        If $addr = 0 Then ExitLoop
    WEnd

    If UBound($ptrToPlayer) = 0 Then ContinueLoop

    ; For each pointer to player, the PLAYER_OFFSET = ptrLocation - listBase
    ; We try each pointer location and see if we can trace further up
    For $pp = 0 To UBound($ptrToPlayer) - 1
        Local $playerPtrLoc = $ptrToPlayer[$pp]
        _TickProgress("Phase 4b: Testing player ptr " & ($pp + 1) & "/" & UBound($ptrToPlayer), "Trying offset combinations...")

        ; Try different PLAYER_OFFSETs (0x00 to 0x200)
        For $tryPO = 0 To 0x200 Step 4
            Local $listBase = $playerPtrLoc - $tryPO

            ; Now scan for pointers to listBase (level 2)
            ; But that's another full scan - too slow for all combos
            ; Instead, for each tryPO, scan for what points to listBase
            ; Only do this for small number of candidates

            ; Quick check: is there something at listBase - some_offset that looks like a valid pointer?
            ; The old chain was: [BASE] -> val, val+0x1C -> listBase
            ; So we need to find val where val + someOffset = listBase
            ; Try offsets 0x00 to 0x100
            For $tryL2Off = 0 To 0x100 Step 4
                Local $level1Val = $listBase - $tryL2Off
                _TickProgress("Phase 4c: PlayerOff=0x" & Hex($tryPO) & " L2Off=0x" & Hex($tryL2Off), "Scanning exe/dll for base address...")

                ; Now find ADDRESS_BASE: scan image memory for dword = level1Val
                ; Only scan exe/dll sections (MEM_IMAGE) for the static base
                Local $scanAddr = 0
                Local $mbi2 = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")
                While 1
                    Local $ret2 = DllCall($hK32, "ulong_ptr", "VirtualQueryEx", "handle", $hProc, "ptr", $scanAddr, "ptr", DllStructGetPtr($mbi2), "ulong_ptr", DllStructGetSize($mbi2))
                    If @error Or $ret2[0] = 0 Then ExitLoop
                    Local $sBase = DllStructGetData($mbi2, "BaseAddress")
                    Local $sSize = DllStructGetData($mbi2, "RegionSize")
                    Local $sState = DllStructGetData($mbi2, "State")
                    Local $sProtect = DllStructGetData($mbi2, "Protect")
                    Local $sType = DllStructGetData($mbi2, "Type")

                    If $sState = 0x1000 And BitAND($sProtect, 0x100) = 0 And $sType = 0x1000000 Then
                        Local $cSz5 = 65536
                        If $sSize < $cSz5 Then $cSz5 = $sSize
                        For $o5 = 0 To $sSize - 4 Step $cSz5
                            Local $rS5 = $cSz5
                            If $o5 + $rS5 > $sSize Then $rS5 = $sSize - $o5
                            If $rS5 < 4 Then ContinueLoop
                            Local $c5 = _ReadBytes($hProc, $hK32, $sBase + $o5, $rS5)
                            If @error Then ContinueLoop
                            For $b5 = 0 To $rS5 - 4 Step 4
                                If _BytesToDword($c5, $b5) = $level1Val Then
                                    Local $candidateBase = $sBase + $o5 + $b5
                                    ; VERIFY: read the full chain with these offsets
                                    Local $vName = _TryReadNameWithOffsets($hProc, $hK32, $candidateBase, $tryL2Off, $tryPO, $pNameOff)
                                    If $vName = $charName Then
                                        $chainCount += 1
                                        $chainResults &= "=== FOUND COMPLETE CHAIN " & $chainCount & " ===" & @CRLF
                                        $chainResults &= "ADDRESS_BASE = " & $candidateBase & "  (0x" & Hex($candidateBase) & ")" & @CRLF
                                        $chainResults &= "Level 2 offset = " & $tryL2Off & "  (0x" & Hex($tryL2Off) & ")  [old: 0x1C]" & @CRLF
                                        $chainResults &= "PLAYER_OFFSET = " & $tryPO & "  (0x" & Hex($tryPO) & ")  [old: 0x34]" & @CRLF
                                        $chainResults &= "PLAYERNAME_OFFSET = " & $pNameOff & "  (0x" & Hex($pNameOff) & ")  [old: 0xB90]" & @CRLF
                                        $chainResults &= "Character: " & $vName & @CRLF
                                        $chainResults &= @CRLF
                                        GUICtrlSetData($lblResults, "FOUND! Base=0x" & Hex($candidateBase) & " Offsets=" & $tryL2Off & "/" & $tryPO & "/" & $pNameOff)
                                    EndIf
                                EndIf
                            Next
                        Next
                    EndIf
                    $scanAddr = $sBase + $sSize
                    If $scanAddr = 0 Then ExitLoop
                WEnd

                If $chainCount > 0 Then ExitLoop
            Next
            If $chainCount > 0 Then ExitLoop
        Next
        If $chainCount > 0 Then ExitLoop
    Next
    If $chainCount > 0 Then ExitLoop
Next

; ==========================================
; FINAL OUTPUT
; ==========================================
GUIDelete($hGUI)

If $chainCount > 0 Then
    MsgBox(64, "SUCCESS! Found ADDRESS_BASE + offsets!", "Complete pointer chain found!" & @CRLF & @CRLF & $chainResults & @CRLF & "Results copied to clipboard - paste to Claude!")
    ClipPut($chainResults)
ElseIf $validCount > 0 Then
    MsgBox(48, "Partial Results", "Found player objects but couldn't trace full chain." & @CRLF & @CRLF & $output & @CRLF & "Results copied to clipboard - paste to Claude!")
    ClipPut($output)
Else
    MsgBox(48, "No Results", "Could not identify player object structure." & @CRLF & @CRLF & "Found " & UBound($nameAddresses) & " name strings and " & UBound($namePointers, 1) & " name pointers." & @CRLF & @CRLF & "Raw data copied to clipboard - share with Claude.")
    Local $rawOut = "Name addresses:" & @CRLF & _FormatAddrs($nameAddresses) & @CRLF
    $rawOut &= "Name pointer locations:" & @CRLF
    For $i = 0 To UBound($namePointers, 1) - 1
        $rawOut &= "  0x" & Hex($namePointers[$i][0]) & " -> 0x" & Hex($namePointers[$i][1]) & @CRLF
    Next
    ClipPut($rawOut)
EndIf

DllCall($hK32, "bool", "CloseHandle", "handle", $hProc)
DllClose($hK32)

; ============================================
; HELPER FUNCTIONS
; ============================================

Global $gLastUpdate = 0
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

Func _ReadDword($hP, $hK, $iA)
    Local $buf = DllStructCreate("dword")
    DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $iA, "ptr", DllStructGetPtr($buf), "ulong_ptr", 4, "ulong_ptr*", 0)
    If @error Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

Func _ReadBytes($hP, $hK, $iA, $iS)
    Local $buf = DllStructCreate("byte[" & $iS & "]")
    Local $r = DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $iA, "ptr", DllStructGetPtr($buf), "ulong_ptr", $iS, "ulong_ptr*", 0)
    If @error Or $r[0] = 0 Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

Func _BytesToDword($bytes, $iOff)
    Local $buf = DllStructCreate("byte[4]")
    DllStructSetData($buf, 1, BinaryMid($bytes, $iOff + 1, 4))
    Local $buf2 = DllStructCreate("dword", DllStructGetPtr($buf))
    Return DllStructGetData($buf2, 1)
EndFunc

Func _TryReadNameWithOffsets($hP, $hK, $base, $off1, $off2, $nameOff)
    Local $v1 = _ReadDword($hP, $hK, $base)
    If $v1 = 0 Then Return ""
    Local $v2 = _ReadDword($hP, $hK, $v1 + $off1)
    If $v2 = 0 Then Return ""
    Local $pl = _ReadDword($hP, $hK, $v2 + $off2)
    If $pl = 0 Then Return ""
    Local $np = _ReadDword($hP, $hK, $pl + $nameOff)
    If $np = 0 Then Return ""
    Local $nb = DllStructCreate("wchar[50]")
    DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $np, "ptr", DllStructGetPtr($nb), "ulong_ptr", 100, "ulong_ptr*", 0)
    Return DllStructGetData($nb, 1)
EndFunc

Func _FormatAddrs($arr)
    Local $s = ""
    Local $max = UBound($arr) - 1
    If $max > 19 Then $max = 19
    For $i = 0 To $max
        $s &= "  0x" & Hex($arr[$i]) & @CRLF
    Next
    If UBound($arr) > 20 Then $s &= "  ... and " & (UBound($arr) - 20) & " more" & @CRLF
    Return $s
EndFunc
