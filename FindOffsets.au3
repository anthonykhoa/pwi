#RequireAdmin
#include <GUIConstantsEx.au3>

; ============================================
; PWI 64-bit Offset Finder v4b
; ============================================
; Saves results to file after each step.
; Also removed slow Step 5 brute force.
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

Global $outputFile = @ScriptDir & "\FindOffsets_Results.txt"
Global $fullOutput = ""

Global $hGUI = GUICreate("Finding Offsets...", 600, 350, -1, -1)
Global $lblStatus = GUICtrlCreateLabel("Starting...", 20, 15, 560, 25)
Global $lblDetail = GUICtrlCreateLabel("", 20, 45, 560, 25)
Global $lblTimer = GUICtrlCreateLabel("", 20, 75, 560, 25)
Global $lblResults = GUICtrlCreateLabel("", 20, 110, 560, 220)
GUISetState(@SW_SHOW, $hGUI)
Global $gStart = TimerInit()
Global $gLastUpdate = 0

_AppendOutput("PWI 64-bit Offset Finder v4b Results")
_AppendOutput("====================================")
_AppendOutput("Process: elementclient_64.exe (PID " & $PID & ")")
_AppendOutput("Character: " & $charName)
_AppendOutput("")

; ==========================================
; STEP 1: Get module base address
; ==========================================
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

_AppendOutput("Module base: 0x" & Hex($moduleBase))
_AppendOutput("")
_SaveOutput()

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

_AppendOutput("=== STEP 2: NAME SEARCH ===")
_AppendOutput("Name matches found: " & UBound($nameAddresses))
Dim $showMax = UBound($nameAddresses) - 1
If $showMax > 29 Then $showMax = 29
For $i = 0 To $showMax
    _AppendOutput("  0x" & Hex($nameAddresses[$i]))
Next
If UBound($nameAddresses) > 30 Then _AppendOutput("  ... and " & (UBound($nameAddresses) - 30) & " more")
_AppendOutput("")
_SaveOutput()

_Status("Step 2 done: " & UBound($nameAddresses) & " name matches. Results saved.")
Sleep(500)

If UBound($nameAddresses) = 0 Then
    GUIDelete($hGUI)
    MsgBox(16, "Error", "Could not find '" & $charName & "' in memory.")
    Exit
EndIf

; ==========================================
; STEP 3: For each name address, scan ALL
; memory for pointers TO that name address.
; ==========================================
_Status("Step 3: Scanning for pointers to each name address...")

_AppendOutput("=== STEP 3: POINTER-TO-NAME SCAN ===")

Dim $ptrToNameCount = 0

Dim $maxNames = UBound($nameAddresses) - 1
If $maxNames > 19 Then $maxNames = 19

For $ni = 0 To $maxNames
    Dim $targetAddr = $nameAddresses[$ni]
    _TickProgress("Step 3: Checking name " & ($ni + 1) & "/" & ($maxNames + 1), "Looking for pointers to 0x" & Hex($targetAddr) & " | Found: " & $ptrToNameCount)

    Dim $b0 = BitAND($targetAddr, 0xFF)
    Dim $b1 = BitAND(BitShift($targetAddr, 8), 0xFF)
    Dim $b2 = BitAND(BitShift($targetAddr, 16), 0xFF)
    Dim $b3 = BitAND(BitShift($targetAddr, 24), 0xFF)
    Dim $searchBytes = Chr($b0) & Chr($b1) & Chr($b2) & Chr($b3)

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

                Dim $sBin = BinaryToString($sData, 1)
                Dim $sPos = 1
                While 1
                    Dim $sFound = StringInStr($sBin, $searchBytes, 1, 1, $sPos)
                    If $sFound = 0 Then ExitLoop
                    If Mod($sFound - 1, 4) = 0 Then
                        Dim $ptrLocation = $sBase + $sOff + ($sFound - 1)
                        If $ptrLocation <> $targetAddr Then
                            $ptrToNameCount += 1
                            _AppendOutput("PTR to name 0x" & Hex($targetAddr) & " found at 0x" & Hex($ptrLocation))

                            ; Read surrounding context
                            Dim $ctxData = _ReadBytes($hProc, $hK32, $ptrLocation - 32, 72)
                            If Not @error Then
                                Dim $ctxHex = ""
                                For $cb = 1 To 72
                                    $ctxHex &= Hex(BinaryMid($ctxData, $cb, 1), 2)
                                    If Mod($cb, 4) = 0 Then $ctxHex &= " "
                                Next
                                _AppendOutput("  Context: " & $ctxHex)
                            EndIf

                            ; Check for vtable near this pointer (object start)
                            If $moduleBase <> 0 Then
                                Dim $backData = _ReadBytes($hProc, $hK32, $ptrLocation - 0x1000, 0x1000)
                                If Not @error Then
                                    For $bk = 0x0FFC To 0 Step -4
                                        Dim $bkVal = _BytesToDword($backData, $bk)
                                        If $bkVal > $moduleBase And $bkVal < ($moduleBase + 0x10000000) Then
                                            Dim $objStart = $ptrLocation - 0x1000 + $bk
                                            Dim $nameOffInObj = $ptrLocation - $objStart
                                            _AppendOutput("  Possible object at 0x" & Hex($objStart) & " (vtable: 0x" & Hex($bkVal) & ", name ptr offset: 0x" & Hex($nameOffInObj) & ")")
                                            ExitLoop
                                        EndIf
                                    Next
                                EndIf
                            EndIf

                            _AppendOutput("")
                            _SaveOutput()
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

_AppendOutput("Step 3 total: " & $ptrToNameCount & " pointers to name found")
_AppendOutput("")
_SaveOutput()

_Status("Step 3 done: " & $ptrToNameCount & " pointers found. Results saved.")
Sleep(500)

; ==========================================
; STEP 4: Try known CE offsets from module base
; ==========================================
If $moduleBase <> 0 Then
    _Status("Step 4: Testing Cheat Engine offsets...")
    _AppendOutput("=== STEP 4: CHEAT ENGINE OFFSETS ===")

    Dim $ceOffsets[4] = [0x01ADBC30, 0x0A13BC40, 0x01A6D2A8, 0x019292E0]

    For $ci = 0 To 3
        Dim $testBase = $moduleBase + $ceOffsets[$ci]
        _TickProgress("Step 4: Testing CE offset " & ($ci + 1) & "/4", "0x" & Hex($ceOffsets[$ci]))

        Dim $val0 = _ReadDword($hProc, $hK32, $testBase)
        _AppendOutput("CE offset 0x" & Hex($ceOffsets[$ci]) & " at 0x" & Hex($testBase) & " -> 0x" & Hex($val0))

        If $val0 = 0 Then
            _AppendOutput("  (empty, skipping)")
            ContinueLoop
        EndIf

        ; Try 3-level chain: [base] -> +off1 -> +off2 -> player -> +nameOff -> namePtr -> name
        For $off1 = 0x00 To 0x80 Step 4
            Dim $val1 = _ReadDword($hProc, $hK32, $val0 + $off1)
            If $val1 = 0 Or $val1 < 0x10000 Then ContinueLoop

            For $off2 = 0x00 To 0x80 Step 4
                Dim $val2 = _ReadDword($hProc, $hK32, $val1 + $off2)
                If $val2 = 0 Or $val2 < 0x10000 Then ContinueLoop

                ; Try name via pointer
                For $nameOff = 0x000 To 0x1200 Step 4
                    Dim $namePtr = _ReadDword($hProc, $hK32, $val2 + $nameOff)
                    If $namePtr = 0 Or $namePtr < 0x10000 Then ContinueLoop
                    Dim $nameBuf = DllStructCreate("wchar[50]")
                    DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $namePtr, "ptr", DllStructGetPtr($nameBuf), "ulong_ptr", 100, "ulong_ptr*", 0)
                    Dim $testName = DllStructGetData($nameBuf, 1)
                    If $testName = $charName Then
                        _AppendOutput("  *** MATCH (3-level, ptr name)! ***")
                        _AppendOutput("  Chain: [0x" & Hex($testBase) & "] -> +0x" & Hex($off1) & " -> +0x" & Hex($off2) & " -> +0x" & Hex($nameOff) & " -> name")
                        _AppendOutput("  ADDRESS_BASE = " & $testBase)
                        _SaveOutput()
                    EndIf
                Next

                ; Try name inline
                For $inOff = 0x000 To 0x1200 Step 4
                    Dim $inBuf = DllStructCreate("wchar[50]")
                    DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $val2 + $inOff, "ptr", DllStructGetPtr($inBuf), "ulong_ptr", 100, "ulong_ptr*", 0)
                    Dim $inName = DllStructGetData($inBuf, 1)
                    If $inName = $charName Then
                        _AppendOutput("  *** MATCH (3-level, inline name)! ***")
                        _AppendOutput("  Chain: [0x" & Hex($testBase) & "] -> +0x" & Hex($off1) & " -> +0x" & Hex($off2) & " -> inline at +0x" & Hex($inOff))
                        _AppendOutput("  ADDRESS_BASE = " & $testBase)
                        _SaveOutput()
                    EndIf
                Next
            Next
        Next

        ; Try 2-level chain: [base] -> +off1 -> player -> +nameOff -> name
        For $off1b = 0x00 To 0x100 Step 4
            Dim $val1b = _ReadDword($hProc, $hK32, $val0 + $off1b)
            If $val1b = 0 Or $val1b < 0x10000 Then ContinueLoop

            For $nameOff2 = 0x000 To 0x1200 Step 4
                Dim $namePtr2 = _ReadDword($hProc, $hK32, $val1b + $nameOff2)
                If $namePtr2 = 0 Or $namePtr2 < 0x10000 Then ContinueLoop
                Dim $nameBuf2 = DllStructCreate("wchar[50]")
                DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $namePtr2, "ptr", DllStructGetPtr($nameBuf2), "ulong_ptr", 100, "ulong_ptr*", 0)
                Dim $testName2 = DllStructGetData($nameBuf2, 1)
                If $testName2 = $charName Then
                    _AppendOutput("  *** MATCH (2-level, ptr name)! ***")
                    _AppendOutput("  Chain: [0x" & Hex($testBase) & "] -> +0x" & Hex($off1b) & " -> +0x" & Hex($nameOff2) & " -> name")
                    _AppendOutput("  ADDRESS_BASE = " & $testBase)
                    _SaveOutput()
                EndIf
            Next

            ; Try 2-level inline
            For $inOff2 = 0x000 To 0x1200 Step 4
                Dim $inBuf2 = DllStructCreate("wchar[50]")
                DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $val1b + $inOff2, "ptr", DllStructGetPtr($inBuf2), "ulong_ptr", 100, "ulong_ptr*", 0)
                Dim $inName2 = DllStructGetData($inBuf2, 1)
                If $inName2 = $charName Then
                    _AppendOutput("  *** MATCH (2-level, inline name)! ***")
                    _AppendOutput("  Chain: [0x" & Hex($testBase) & "] -> +0x" & Hex($off1b) & " -> inline at +0x" & Hex($inOff2))
                    _AppendOutput("  ADDRESS_BASE = " & $testBase)
                    _SaveOutput()
                EndIf
            Next
        Next

        _AppendOutput("")
        _SaveOutput()
    Next

    _AppendOutput("Step 4 complete.")
    _AppendOutput("")
    _SaveOutput()
EndIf

; ==========================================
; DONE
; ==========================================
GUIDelete($hGUI)

_SaveOutput()
ClipPut($fullOutput)

MsgBox(64, "Done", "Analysis complete!" & @CRLF & @CRLF & "Results saved to:" & @CRLF & $outputFile & @CRLF & @CRLF & "Also copied to clipboard." & @CRLF & "Paste the results to Claude for analysis.")

DllCall($hK32, "bool", "CloseHandle", "handle", $hProc)
DllClose($hK32)

; ============================================
; HELPER FUNCTIONS
; ============================================

Func _AppendOutput($line)
    $fullOutput &= $line & @CRLF
EndFunc

Func _SaveOutput()
    Dim $hFile = FileOpen($outputFile, 2)
    FileWrite($hFile, $fullOutput)
    FileClose($hFile)
EndFunc

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
