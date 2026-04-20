#RequireAdmin
#include <GUIConstantsEx.au3>

; ============================================
; PWI 64-bit Offset Finder
; ============================================

; Step 1: Find the process
Dim $PID = ProcessExists("elementclient_64.exe")
If $PID = 0 Then
    MsgBox(16, "Error", "elementclient_64.exe is not running!" & @CRLF & "Log into a character first.")
    Exit
EndIf

; Step 2: Open process
Dim $hK32 = DllOpen("kernel32.dll")
Dim $aOpen = DllCall($hK32, "handle", "OpenProcess", "dword", 0x1F0FFF, "bool", 0, "dword", $PID)
If $aOpen[0] = 0 Then
    MsgBox(16, "Error", "Failed to open process. Run as Administrator.")
    DllClose($hK32)
    Exit
EndIf
Dim $hProc = $aOpen[0]

; Step 3: Get character name
Dim $charName = InputBox("Character Name", "Type your character name EXACTLY (case-sensitive):", "", "", 400, 200)
If $charName = "" Then Exit

; Progress window
Global $hGUI = GUICreate("Finding Offsets...", 500, 200, -1, -1)
Global $lblStatus = GUICtrlCreateLabel("Starting...", 20, 15, 460, 25)
Global $lblDetail = GUICtrlCreateLabel("", 20, 45, 460, 25)
Global $lblTimer = GUICtrlCreateLabel("", 20, 75, 460, 25)
Global $lblResults = GUICtrlCreateLabel("", 20, 105, 460, 80)
GUISetState(@SW_SHOW, $hGUI)
Global $gStart = TimerInit()
Global $gLastUpdate = 0

; Shared variables for loops
Dim $ret, $rBase, $rSize, $rState, $rProtect, $rType
Dim $chunkSize, $readSize, $data, $dataStr, $pos, $found, $foundAddr
Dim $rdSz, $chunk, $val, $ptrAddr, $bp, $off, $offset
Dim $addr, $regionCount, $mbi

; ==========================================
; PHASE 1: Find character name in memory
; ==========================================
_Status("Phase 1: Searching for '" & $charName & "' in memory...")

Dim $nameAddresses[0]
$addr = 0
$mbi = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")
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
; ==========================================
_Status("Phase 2: Finding pointers to name strings...")

Dim $namePointers[0][2]
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
        For $off = 0 To $rSize - 4 Step $chunkSize
            $rdSz = $chunkSize
            If $off + $rdSz > $rSize Then $rdSz = $rSize - $off
            If $rdSz < 4 Then ContinueLoop
            $chunk = _ReadBytes($hProc, $hK32, $rBase + $off, $rdSz)
            If @error Then ContinueLoop

            For $bp = 0 To $rdSz - 4 Step 4
                $val = _BytesToDword($chunk, $bp)
                If $val < 0x10000 Then ContinueLoop

                For $n = 0 To UBound($nameAddresses) - 1
                    If $val = $nameAddresses[$n] Then
                        $ptrAddr = $rBase + $off + $bp
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
; PHASE 3: Find player object + NAME_OFFSET
; ==========================================
_Status("Phase 3: Analyzing player object structure...")

Dim $output = ""
Dim $validCount = 0
Dim $namePtrAddr, $tryPlayerBase, $nameCheck, $possibleID, $idOffset, $idVal, $tryOffset

For $i = 0 To UBound($namePointers, 1) - 1
    $namePtrAddr = $namePointers[$i][0]

    For $tryOffset = 0 To 0x1800 Step 4
        $tryPlayerBase = $namePtrAddr - $tryOffset
        $nameCheck = _ReadDword($hProc, $hK32, $tryPlayerBase + $tryOffset)
        If $nameCheck = $namePointers[$i][1] Then
            $possibleID = 0
            $idOffset = 0
            For $tryID = 0x700 To 0x1000 Step 4
                $idVal = _ReadDword($hProc, $hK32, $tryPlayerBase + $tryID)
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
            ExitLoop
        EndIf
    Next

    _TickProgress("Phase 3: Checking pointer " & ($i + 1) & "/" & UBound($namePointers, 1), $validCount & " player objects found so far")
Next

; ==========================================
; PHASE 4: Trace chain upwards to find ADDRESS_BASE
; ==========================================
Dim $playerAddrs[0]
Dim $playerNameOffsets[0]
Dim $npa, $tpb, $nc

For $z = 0 To UBound($namePointers, 1) - 1
    $npa = $namePointers[$z][0]
    For $tryOff = 0 To 0x1800 Step 4
        $tpb = $npa - $tryOff
        $nc = _ReadDword($hProc, $hK32, $tpb + $tryOff)
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
    Dim $rawOut = "Name addresses:" & @CRLF & _FormatAddrs($nameAddresses) & @CRLF
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

Dim $chainResults = ""
Dim $chainCount = 0
Dim $pAddr, $pNameOff, $ptrToPlayer, $playerPtrLoc
Dim $listBase, $level1Val, $scanAddr
Dim $sBase, $sSize, $sState, $sProtect, $sType
Dim $candidateBase, $vName
Dim $mbi2 = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")

For $pi = 0 To UBound($playerAddrs) - 1
    $pAddr = $playerAddrs[$pi]
    $pNameOff = $playerNameOffsets[$pi]
    _Status("Phase 4: Tracing chain for player " & ($pi + 1) & "/" & UBound($playerAddrs) & "...")

    ; Scan all memory for dwords equal to pAddr
    Dim $ptrToPlayer[0]
    $addr = 0
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
            For $off = 0 To $rSize - 4 Step $chunkSize
                $rdSz = $chunkSize
                If $off + $rdSz > $rSize Then $rdSz = $rSize - $off
                If $rdSz < 4 Then ContinueLoop
                $chunk = _ReadBytes($hProc, $hK32, $rBase + $off, $rdSz)
                If @error Then ContinueLoop
                For $bp = 0 To $rdSz - 4 Step 4
                    If _BytesToDword($chunk, $bp) = $pAddr Then
                        ReDim $ptrToPlayer[UBound($ptrToPlayer) + 1]
                        $ptrToPlayer[UBound($ptrToPlayer) - 1] = $rBase + $off + $bp
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

    For $pp = 0 To UBound($ptrToPlayer) - 1
        $playerPtrLoc = $ptrToPlayer[$pp]
        _TickProgress("Phase 4b: Testing player ptr " & ($pp + 1) & "/" & UBound($ptrToPlayer), "Trying offset combinations...")

        For $tryPO = 0 To 0x200 Step 4
            $listBase = $playerPtrLoc - $tryPO

            For $tryL2Off = 0 To 0x100 Step 4
                $level1Val = $listBase - $tryL2Off
                _TickProgress("Phase 4c: PO=0x" & Hex($tryPO) & " L2=0x" & Hex($tryL2Off), "Scanning exe/dll for base...")

                $scanAddr = 0
                While 1
                    $ret = DllCall($hK32, "ulong_ptr", "VirtualQueryEx", "handle", $hProc, "ptr", $scanAddr, "ptr", DllStructGetPtr($mbi2), "ulong_ptr", DllStructGetSize($mbi2))
                    If @error Or $ret[0] = 0 Then ExitLoop
                    $sBase = DllStructGetData($mbi2, "BaseAddress")
                    $sSize = DllStructGetData($mbi2, "RegionSize")
                    $sState = DllStructGetData($mbi2, "State")
                    $sProtect = DllStructGetData($mbi2, "Protect")
                    $sType = DllStructGetData($mbi2, "Type")

                    If $sState = 0x1000 And BitAND($sProtect, 0x100) = 0 And $sType = 0x1000000 Then
                        $chunkSize = 65536
                        If $sSize < $chunkSize Then $chunkSize = $sSize
                        For $off = 0 To $sSize - 4 Step $chunkSize
                            $rdSz = $chunkSize
                            If $off + $rdSz > $sSize Then $rdSz = $sSize - $off
                            If $rdSz < 4 Then ContinueLoop
                            $chunk = _ReadBytes($hProc, $hK32, $sBase + $off, $rdSz)
                            If @error Then ContinueLoop
                            For $bp = 0 To $rdSz - 4 Step 4
                                If _BytesToDword($chunk, $bp) = $level1Val Then
                                    $candidateBase = $sBase + $off + $bp
                                    $vName = _TryReadNameWithOffsets($hProc, $hK32, $candidateBase, $tryL2Off, $tryPO, $pNameOff)
                                    If $vName = $charName Then
                                        $chainCount += 1
                                        $chainResults &= "=== FOUND COMPLETE CHAIN " & $chainCount & " ===" & @CRLF
                                        $chainResults &= "ADDRESS_BASE = " & $candidateBase & "  (0x" & Hex($candidateBase) & ")" & @CRLF
                                        $chainResults &= "Level 2 offset = " & $tryL2Off & "  (0x" & Hex($tryL2Off) & ")  [old: 0x1C]" & @CRLF
                                        $chainResults &= "PLAYER_OFFSET = " & $tryPO & "  (0x" & Hex($tryPO) & ")  [old: 0x34]" & @CRLF
                                        $chainResults &= "PLAYERNAME_OFFSET = " & $pNameOff & "  (0x" & Hex($pNameOff) & ")  [old: 0xB90]" & @CRLF
                                        $chainResults &= "Character: " & $vName & @CRLF
                                        $chainResults &= @CRLF
                                        GUICtrlSetData($lblResults, "FOUND! Base=0x" & Hex($candidateBase))
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
    MsgBox(48, "Partial Results", "Found player objects but couldn't trace full chain." & @CRLF & @CRLF & StringLeft($output, 1500) & @CRLF & "Results copied to clipboard - paste to Claude!")
    ClipPut($output)
Else
    MsgBox(48, "No Results", "Could not identify player object structure." & @CRLF & @CRLF & "Found " & UBound($nameAddresses) & " name strings and " & UBound($namePointers, 1) & " name pointers." & @CRLF & @CRLF & "Raw data copied to clipboard - share with Claude.")
    Dim $rawOut2 = "Name addresses:" & @CRLF & _FormatAddrs($nameAddresses) & @CRLF
    $rawOut2 &= "Name pointer locations:" & @CRLF
    For $i = 0 To UBound($namePointers, 1) - 1
        $rawOut2 &= "  0x" & Hex($namePointers[$i][0]) & " -> 0x" & Hex($namePointers[$i][1]) & @CRLF
    Next
    ClipPut($rawOut2)
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
    Dim $buf2 = DllStructCreate("byte[" & $iS & "]")
    Dim $r = DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $iA, "ptr", DllStructGetPtr($buf2), "ulong_ptr", $iS, "ulong_ptr*", 0)
    If @error Or $r[0] = 0 Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf2, 1)
EndFunc

Func _BytesToDword($bytes, $iOff)
    Dim $b1 = DllStructCreate("byte[4]")
    DllStructSetData($b1, 1, BinaryMid($bytes, $iOff + 1, 4))
    Dim $b2 = DllStructCreate("dword", DllStructGetPtr($b1))
    Return DllStructGetData($b2, 1)
EndFunc

Func _TryReadNameWithOffsets($hP, $hK, $base, $off1, $off2, $nameOff)
    Dim $v1 = _ReadDword($hP, $hK, $base)
    If $v1 = 0 Then Return ""
    Dim $v2 = _ReadDword($hP, $hK, $v1 + $off1)
    If $v2 = 0 Then Return ""
    Dim $pl = _ReadDword($hP, $hK, $v2 + $off2)
    If $pl = 0 Then Return ""
    Dim $np = _ReadDword($hP, $hK, $pl + $nameOff)
    If $np = 0 Then Return ""
    Dim $nb = DllStructCreate("wchar[50]")
    DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $np, "ptr", DllStructGetPtr($nb), "ulong_ptr", 100, "ulong_ptr*", 0)
    Return DllStructGetData($nb, 1)
EndFunc

Func _FormatAddrs($arr)
    Dim $s = ""
    Dim $max = UBound($arr) - 1
    If $max > 19 Then $max = 19
    For $i = 0 To $max
        $s &= "  0x" & Hex($arr[$i]) & @CRLF
    Next
    If UBound($arr) > 20 Then $s &= "  ... and " & (UBound($arr) - 20) & " more" & @CRLF
    Return $s
EndFunc
