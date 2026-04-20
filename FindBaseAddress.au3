#RequireAdmin
#include <GUIConstantsEx.au3>

; ============================================
; PWI 64-bit Base Address Finder (v3 - 64-bit fixed)
; ============================================
; 1. Log into a character on elementclient_64.exe
; 2. Run this script as Administrator
; 3. It will find and display the base address
; ============================================

; 64-bit pointer chain offsets (may need adjustment)
; Chain: [ADDRESS_BASE] -> +0x1C -> +0x34 -> player struct -> +0xB90 (name ptr) -> name
; For 64-bit, offsets likely change: pointers are 8 bytes, struct layouts shift
Global $PLAYER_OFFSET = 52       ; 0x34
Global $PLAYERNAME_OFFSET = 2960 ; 0xB90

; Step 1: Find the process
Local $PID = ProcessExists("elementclient_64.exe")
If $PID = 0 Then
    MsgBox(16, "Error", "elementclient_64.exe is not running!" & @CRLF & @CRLF & "Please log into a character first, then run this script again.")
    Exit
EndIf

MsgBox(64, "Process Found", "Found elementclient_64.exe (PID: " & $PID & ")" & @CRLF & @CRLF & "Click OK to start scanning.")

; Step 2: Open process with full access
Local $hKernel32 = DllOpen("kernel32.dll")
Local $aOpenProc = DllCall($hKernel32, "handle", "OpenProcess", "dword", 0x1F0FFF, "bool", 0, "dword", $PID)
If $aOpenProc[0] = 0 Then
    MsgBox(16, "Error", "Failed to open process. Try running as Administrator.")
    DllClose($hKernel32)
    Exit
EndIf
Local $hProcess = $aOpenProc[0]

; Step 3: Get module base address using NtQueryInformationProcess + PEB
; Module32First/Next fails for 64-bit processes from 32-bit AutoIt,
; so we use EnumProcessModulesEx instead
Local $moduleBase = _GetModuleBase64($hProcess, $hKernel32, "elementclient_64.exe")

; Step 4: Ask for character name
Local $charName = InputBox("Character Name", "Type your character's name EXACTLY as it appears in-game:" & @CRLF & "(This is case-sensitive)", "", "", 400, 200)
If $charName = "" Then
    MsgBox(16, "Error", "You must enter a character name.")
    DllCall($hKernel32, "bool", "CloseHandle", "handle", $hProcess)
    DllClose($hKernel32)
    Exit
EndIf

; Create progress window
Global $hProgressGUI = GUICreate("Scanning...", 500, 180, -1, -1)
Global $hProgressLabel = GUICtrlCreateLabel("Starting scan...", 20, 15, 460, 25)
Global $hProgressDetail = GUICtrlCreateLabel("", 20, 45, 460, 25)
Global $hProgressTimer = GUICtrlCreateLabel("", 20, 75, 460, 25)
Global $hProgressResults = GUICtrlCreateLabel("", 20, 105, 460, 60)
GUISetState(@SW_SHOW, $hProgressGUI)
Global $gStartTime = TimerInit()

Global $outputFile = @ScriptDir & "\FindBaseAddress_Results.txt"
Global $fullOutput = ""

_AppendOutput("PWI 64-bit Base Address Finder v3 Results")
_AppendOutput("==========================================")
_AppendOutput("Process: elementclient_64.exe (PID " & $PID & ")")
_AppendOutput("Module base: 0x" & Hex($moduleBase))
_AppendOutput("Character: " & $charName)
_AppendOutput("")

; Step 5: First, find ALL occurrences of the character name in memory (as UTF-16)
_UpdateProgress("Step 1: Finding character name in memory...", "Scanning for '" & $charName & "'...")

Local $nameAddresses[0]
Local $addr = 0
Local $mbi = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")
Local $regionCount = 0

While 1
    Local $ret = DllCall($hKernel32, "ulong_ptr", "VirtualQueryEx", "handle", $hProcess, "ptr", $addr, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
    If @error Or $ret[0] = 0 Then ExitLoop

    Local $regionBase = DllStructGetData($mbi, "BaseAddress")
    Local $regionSize = DllStructGetData($mbi, "RegionSize")
    Local $state = DllStructGetData($mbi, "State")
    Local $protect = DllStructGetData($mbi, "Protect")

    If $state = 0x1000 And BitAND($protect, 0x100) = 0 And $regionSize < 0x10000000 Then
        Local $chunkSize = 65536
        If $regionSize < $chunkSize Then $chunkSize = $regionSize
        For $offset = 0 To $regionSize - 2 Step $chunkSize
            Local $readSize = $chunkSize
            If $offset + $readSize > $regionSize Then $readSize = $regionSize - $offset
            Local $data = _ReadBytes($hProcess, $hKernel32, $regionBase + $offset, $readSize)
            If @error Then ContinueLoop
            Local $dataStr = BinaryToString($data, 2) ; UTF-16
            Local $pos = 1
            While 1
                Local $found = StringInStr($dataStr, $charName, 1, 1, $pos)
                If $found = 0 Then ExitLoop
                Local $foundAddr = $regionBase + $offset + ($found - 1) * 2
                ReDim $nameAddresses[UBound($nameAddresses) + 1]
                $nameAddresses[UBound($nameAddresses) - 1] = $foundAddr
                $pos = $found + 1
                If UBound($nameAddresses) >= 500 Then ExitLoop 2
            WEnd
        Next
        $regionCount += 1
        If Mod($regionCount, 20) = 0 Then
            _UpdateProgress("Step 1: Scanning... (" & $regionCount & " regions)", UBound($nameAddresses) & " name matches found")
        EndIf
    EndIf

    $addr = $regionBase + $regionSize
    If $addr = 0 Then ExitLoop
WEnd

_AppendOutput("Step 1: Found " & UBound($nameAddresses) & " name occurrences in memory")
_AppendOutput("")

If UBound($nameAddresses) = 0 Then
    GUIDelete($hProgressGUI)
    _AppendOutput("ERROR: Could not find character name in memory!")
    _SaveOutput()
    MsgBox(16, "Error", "Could not find '" & $charName & "' in memory." & @CRLF & @CRLF & "Make sure you typed the name exactly right (case-sensitive).")
    Exit
EndIf

; Step 6: For each name address, find 64-bit pointers pointing TO it
_UpdateProgress("Step 2: Finding pointers to name addresses...", "This may take a few minutes...")

Local $ptrToName[0][2] ; [n][0] = pointer location, [n][1] = name address it points to

For $ni = 0 To UBound($nameAddresses) - 1
    If $ni > 29 Then ExitLoop ; limit to first 30 name addresses

    Local $targetAddr = $nameAddresses[$ni]
    ; Build the 8-byte little-endian search pattern for this 64-bit pointer
    Local $searchBytes = _PtrToBytes($targetAddr)

    Local $scanAddr = 0
    While 1
        Local $sRet = DllCall($hKernel32, "ulong_ptr", "VirtualQueryEx", "handle", $hProcess, "ptr", $scanAddr, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
        If @error Or $sRet[0] = 0 Then ExitLoop
        Local $sBase = DllStructGetData($mbi, "BaseAddress")
        Local $sSize = DllStructGetData($mbi, "RegionSize")
        Local $sState = DllStructGetData($mbi, "State")
        Local $sProtect = DllStructGetData($mbi, "Protect")

        If $sState = 0x1000 And BitAND($sProtect, 0x100) = 0 And $sSize < 0x10000000 Then
            Local $sChunk = 65536
            If $sSize < $sChunk Then $sChunk = $sSize
            For $sOff = 0 To $sSize - 8 Step $sChunk
                Local $sRead = $sChunk
                If $sOff + $sRead > $sSize Then $sRead = $sSize - $sOff
                If $sRead < 8 Then ContinueLoop
                Local $sData = _ReadBytes($hProcess, $hKernel32, $sBase + $sOff, $sRead)
                If @error Then ContinueLoop

                Local $sBin = BinaryToString($sData, 1) ; raw bytes
                Local $sPos = 1
                While 1
                    Local $sFound = StringInStr($sBin, $searchBytes, 1, 1, $sPos)
                    If $sFound = 0 Then ExitLoop
                    If Mod($sFound - 1, 8) = 0 Then ; aligned to 8 bytes (64-bit pointer alignment)
                        Local $ptrLocation = $sBase + $sOff + ($sFound - 1)
                        If $ptrLocation <> $targetAddr Then
                            ReDim $ptrToName[UBound($ptrToName, 1) + 1][2]
                            $ptrToName[UBound($ptrToName, 1) - 1][0] = $ptrLocation
                            $ptrToName[UBound($ptrToName, 1) - 1][1] = $targetAddr
                        EndIf
                    EndIf
                    $sPos = $sFound + 1
                    If UBound($ptrToName, 1) >= 200 Then ExitLoop 3
                WEnd
            Next
        EndIf

        $scanAddr = $sBase + $sSize
        If $scanAddr = 0 Then ExitLoop
    WEnd

    If Mod($ni, 3) = 0 Then
        _UpdateProgress("Step 2: Checking name " & ($ni + 1) & "/30", "Found " & UBound($ptrToName, 1) & " pointers to name so far")
    EndIf
    If UBound($ptrToName, 1) >= 200 Then ExitLoop
Next

_AppendOutput("Step 2: Found " & UBound($ptrToName, 1) & " pointers to name addresses")
_AppendOutput("")

; Step 7: For each pointer-to-name location, try to work backwards to find ADDRESS_BASE
; The 32-bit chain is: [ADDRESS_BASE] -> +0x1C -> +0x34 -> player -> +0xB90 -> namePtr -> name
; For 64-bit, we try various offset combinations
_UpdateProgress("Step 3: Tracing pointer chains back to ADDRESS_BASE...", "Testing offset combinations...")

Local $results = ""
Local $resultCount = 0

_AppendOutput("=== STEP 3: CHAIN TRACING ===")

For $pi = 0 To UBound($ptrToName, 1) - 1
    Local $namePtrLoc = $ptrToName[$pi][0]  ; address where the pointer-to-name lives
    ; namePtrLoc is at player + PLAYERNAME_OFFSET
    ; So player struct base = namePtrLoc - PLAYERNAME_OFFSET

    ; Try various name offsets (the 64-bit offset might differ from 0xB90)
    Local $nameOffsets[7] = [0xB90, 0xB98, 0xBA0, 0xBA8, 0xBB0, 0x1720, 0x1730]

    For $noi = 0 To UBound($nameOffsets) - 1
        Local $nameOff = $nameOffsets[$noi]
        Local $playerBase = $namePtrLoc - $nameOff

        ; Verify: read namePtr from playerBase + nameOff, should give us a name address
        Local $verifyNamePtr = _ReadQword($hProcess, $hKernel32, $playerBase + $nameOff)
        If $verifyNamePtr = 0 Then ContinueLoop
        Local $verifyName = _ReadWString($hProcess, $hKernel32, $verifyNamePtr)
        If $verifyName <> $charName Then ContinueLoop

        _AppendOutput("Valid player struct candidate at 0x" & Hex($playerBase) & " (name at +" & Hex($nameOff) & ")")

        ; Now trace back: player was reached via [something] + PLAYER_OFFSET
        ; Try various player offsets for the 64-bit version
        Local $playerOffsets[10] = [0x34, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78]

        For $poi = 0 To UBound($playerOffsets) - 1
            Local $pOff = $playerOffsets[$poi]
            ; Scan memory for a qword that points to (playerBase - is there a ptr at some addr + pOff that = playerBase?)
            ; That is: we need addr2 such that [addr2 + pOff] = playerBase
            Local $scanTarget = $playerBase
            Local $addr2Candidate = _FindPointerTo($hProcess, $hKernel32, $scanTarget, $pOff)
            If $addr2Candidate = 0 Then ContinueLoop

            _AppendOutput("  Level 2 struct at 0x" & Hex($addr2Candidate) & " (player at +" & Hex($pOff) & ")")

            ; Now trace back one more level: [ADDRESS_BASE] -> +off1 -> addr2
            ; The 32-bit offset was 0x1C (28)
            Local $level1Offsets[10] = [0x1C, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60]

            For $l1i = 0 To UBound($level1Offsets) - 1
                Local $l1Off = $level1Offsets[$l1i]
                Local $baseCandidate = _FindPointerTo($hProcess, $hKernel32, $addr2Candidate, $l1Off)
                If $baseCandidate = 0 Then ContinueLoop

                ; Final verification: follow the full chain from baseCandidate
                Local $v1 = _ReadQword($hProcess, $hKernel32, $baseCandidate)
                If $v1 = 0 Then ContinueLoop
                Local $v2 = _ReadQword($hProcess, $hKernel32, $v1 + $l1Off)
                If $v2 <> $addr2Candidate Then ContinueLoop
                Local $v3 = _ReadQword($hProcess, $hKernel32, $v2 + $pOff)
                If $v3 <> $playerBase Then ContinueLoop
                Local $v4 = _ReadQword($hProcess, $hKernel32, $v3 + $nameOff)
                If $v4 = 0 Then ContinueLoop
                Local $finalName = _ReadWString($hProcess, $hKernel32, $v4)
                If $finalName <> $charName Then ContinueLoop

                $resultCount += 1
                Local $rLine = "ADDRESS_BASE = " & $baseCandidate & "  (0x" & Hex($baseCandidate) & ")"
                $results &= $rLine & @CRLF
                $results &= "  Chain: [0x" & Hex($baseCandidate) & "] -> +0x" & Hex($l1Off) & " -> +0x" & Hex($pOff) & " -> +0x" & Hex($nameOff) & " -> name" & @CRLF
                $results &= "  PLAYER_OFFSET = " & $pOff & "  (0x" & Hex($pOff) & ")" & @CRLF
                $results &= "  PLAYERNAME_OFFSET = " & $nameOff & "  (0x" & Hex($nameOff) & ")" & @CRLF
                $results &= @CRLF

                _AppendOutput("  *** FOUND ADDRESS_BASE! ***")
                _AppendOutput("  " & $rLine)
                _AppendOutput("  Chain: [0x" & Hex($baseCandidate) & "] -> +0x" & Hex($l1Off) & " -> +0x" & Hex($pOff) & " -> +0x" & Hex($nameOff) & " -> name")
                _AppendOutput("  PLAYER_OFFSET = " & $pOff)
                _AppendOutput("  PLAYERNAME_OFFSET = " & $nameOff)
                _AppendOutput("")
                _SaveOutput()

                GUICtrlSetData($hProgressResults, "FOUND: " & $rLine)
            Next
        Next
    Next

    If Mod($pi, 5) = 0 Then
        _UpdateProgress("Step 3: Testing chain " & ($pi + 1) & "/" & UBound($ptrToName, 1), "Found " & $resultCount & " valid chain(s)")
    EndIf
Next

; Step 8: If module base was found, also try known static offsets
If $moduleBase <> 0 Then
    _UpdateProgress("Step 4: Testing static offsets from module base...", "Module: 0x" & Hex($moduleBase))
    _AppendOutput("=== STEP 4: STATIC OFFSET SCAN ===")
    _AppendOutput("Module base: 0x" & Hex($moduleBase))

    ; Scan the .data/.rdata sections of the module for pointers that lead to the player name
    ; Typical range for static data in a 64-bit exe
    Local $staticStart = $moduleBase + 0x01000000
    Local $staticEnd = $moduleBase + 0x0B000000
    Local $chunkSz = 8192

    For $sAddr = $staticStart To $staticEnd Step $chunkSz
        Local $chunk = _ReadBytes($hProcess, $hKernel32, $sAddr, $chunkSz)
        If @error Then ContinueLoop

        For $bPos = 0 To $chunkSz - 8 Step 8
            Local $candidateBase = $sAddr + $bPos

            ; Try to follow the chain with various offsets
            Local $val0 = _ReadQword($hProcess, $hKernel32, $candidateBase)
            If $val0 = 0 Or $val0 < 0x10000 Then ContinueLoop

            ; Try offset combos for level 1
            Local $l1Offs[5] = [0x1C, 0x20, 0x28, 0x30, 0x38]
            For $a = 0 To 4
                Local $val1 = _ReadQword($hProcess, $hKernel32, $val0 + $l1Offs[$a])
                If $val1 = 0 Or $val1 < 0x10000 Then ContinueLoop

                ; Try offset combos for player
                Local $pOffs[5] = [0x34, 0x38, 0x48, 0x50, 0x68]
                For $b = 0 To 4
                    Local $val2 = _ReadQword($hProcess, $hKernel32, $val1 + $pOffs[$b])
                    If $val2 = 0 Or $val2 < 0x10000 Then ContinueLoop

                    ; Try name offset
                    Local $nOffs[4] = [0xB90, 0xB98, 0x1720, 0x1730]
                    For $c = 0 To 3
                        Local $nameP = _ReadQword($hProcess, $hKernel32, $val2 + $nOffs[$c])
                        If $nameP = 0 Or $nameP < 0x10000 Then ContinueLoop
                        Local $nm = _ReadWString($hProcess, $hKernel32, $nameP)
                        If $nm = $charName Then
                            $resultCount += 1
                            Local $rL = "ADDRESS_BASE = " & $candidateBase & "  (0x" & Hex($candidateBase) & ")"
                            Local $relOff = $candidateBase - $moduleBase
                            $results &= $rL & @CRLF
                            $results &= "  Module+0x" & Hex($relOff) & @CRLF
                            $results &= "  Chain: [0x" & Hex($candidateBase) & "] -> +0x" & Hex($l1Offs[$a]) & " -> +0x" & Hex($pOffs[$b]) & " -> +0x" & Hex($nOffs[$c]) & " -> name" & @CRLF
                            $results &= @CRLF
                            _AppendOutput("*** FOUND via static offset! ***")
                            _AppendOutput("  " & $rL)
                            _AppendOutput("  Module+0x" & Hex($relOff))
                            _AppendOutput("  Chain: -> +0x" & Hex($l1Offs[$a]) & " -> +0x" & Hex($pOffs[$b]) & " -> +0x" & Hex($nOffs[$c]) & " -> name")
                            _AppendOutput("")
                            _SaveOutput()
                            GUICtrlSetData($hProgressResults, "FOUND: " & $rL)
                        EndIf
                    Next
                Next
            Next
        Next

        If Mod(($sAddr - $staticStart), 0x1000000) < $chunkSz Then
            Local $pct = Round(($sAddr - $staticStart) / ($staticEnd - $staticStart) * 100)
            _UpdateProgress("Step 4: Scanning static data... " & $pct & "%", "Found " & $resultCount & " result(s)")
        EndIf
    Next

    _AppendOutput("Step 4 complete.")
    _AppendOutput("")
    _SaveOutput()
EndIf

; Show results
GUIDelete($hProgressGUI)

_AppendOutput("==========================================")
_AppendOutput("TOTAL RESULTS: " & $resultCount)
_AppendOutput("==========================================")
_SaveOutput()

If $resultCount > 0 Then
    ClipPut($results)
    MsgBox(64, "SUCCESS! Found " & $resultCount & " result(s)", _
        "Results:" & @CRLF & @CRLF & $results & @CRLF & _
        "Results saved to:" & @CRLF & $outputFile & @CRLF & @CRLF & _
        "Also copied to clipboard! Paste to Claude for next steps.")
Else
    MsgBox(48, "No results", _
        "Could not find ADDRESS_BASE with known offset patterns." & @CRLF & @CRLF & _
        "Results saved to:" & @CRLF & $outputFile & @CRLF & @CRLF & _
        "Please paste the results file to Claude for analysis." & @CRLF & _
        "The 64-bit client may use different pointer chain offsets.")
EndIf

DllCall($hKernel32, "bool", "CloseHandle", "handle", $hProcess)
DllClose($hKernel32)

; ============================================
; HELPER FUNCTIONS
; ============================================

Func _UpdateProgress($msg, $detail)
    GUICtrlSetData($hProgressLabel, $msg)
    GUICtrlSetData($hProgressDetail, $detail)
    Local $elapsed = Round(TimerDiff($gStartTime) / 1000)
    GUICtrlSetData($hProgressTimer, "Running... " & $elapsed & "s elapsed")
EndFunc

Func _AppendOutput($line)
    $fullOutput &= $line & @CRLF
EndFunc

Func _SaveOutput()
    Local $hFile = FileOpen($outputFile, 2)
    FileWrite($hFile, $fullOutput)
    FileClose($hFile)
EndFunc

Func _ReadBytes($hProc, $hK32, $iAddr, $iSize)
    Local $buf = DllStructCreate("byte[" & $iSize & "]")
    Local $ret2 = DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $iAddr, "ptr", DllStructGetPtr($buf), "ulong_ptr", $iSize, "ulong_ptr*", 0)
    If @error Or $ret2[0] = 0 Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

; Read a 64-bit pointer (qword) from process memory
Func _ReadQword($hProc, $hK32, $iAddr)
    Local $buf = DllStructCreate("uint64")
    Local $ret = DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $iAddr, "ptr", DllStructGetPtr($buf), "ulong_ptr", 8, "ulong_ptr*", 0)
    If @error Or $ret[0] = 0 Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

Func _ReadWString($hProc, $hK32, $iAddr)
    Local $buf = DllStructCreate("wchar[100]")
    DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $iAddr, "ptr", DllStructGetPtr($buf), "ulong_ptr", 200, "ulong_ptr*", 0)
    If @error Then Return ""
    Return DllStructGetData($buf, 1)
EndFunc

; Convert a pointer value to its 8-byte little-endian string representation for searching
Func _PtrToBytes($ptr)
    Local $buf = DllStructCreate("uint64")
    DllStructSetData($buf, 1, $ptr)
    Local $bytes = DllStructCreate("byte[8]", DllStructGetPtr($buf))
    Local $result = ""
    For $i = 1 To 8
        $result &= Chr(DllStructGetData($bytes, 1, $i))
    Next
    Return $result
EndFunc

; Find a qword pointer in memory: looks for an address where [addr + offset] = targetValue
; Scans all readable memory for targetValue as a qword, then checks if it's at the right offset
Func _FindPointerTo($hProc, $hK32, $targetValue, $offset)
    Local $searchBytes = _PtrToBytes($targetValue)
    Local $scanAddr = 0
    Local $mbiLocal = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")

    While 1
        Local $r = DllCall($hK32, "ulong_ptr", "VirtualQueryEx", "handle", $hProc, "ptr", $scanAddr, "ptr", DllStructGetPtr($mbiLocal), "ulong_ptr", DllStructGetSize($mbiLocal))
        If @error Or $r[0] = 0 Then ExitLoop
        Local $b = DllStructGetData($mbiLocal, "BaseAddress")
        Local $s = DllStructGetData($mbiLocal, "RegionSize")
        Local $st = DllStructGetData($mbiLocal, "State")
        Local $pr = DllStructGetData($mbiLocal, "Protect")

        If $st = 0x1000 And BitAND($pr, 0x100) = 0 And $s < 0x10000000 Then
            Local $chunk = 65536
            If $s < $chunk Then $chunk = $s
            For $off = 0 To $s - 8 Step $chunk
                Local $rd = $chunk
                If $off + $rd > $s Then $rd = $s - $off
                If $rd < 8 Then ContinueLoop
                Local $d = _ReadBytes($hProc, $hK32, $b + $off, $rd)
                If @error Then ContinueLoop

                Local $bin = BinaryToString($d, 1)
                Local $p = 1
                While 1
                    Local $f = StringInStr($bin, $searchBytes, 1, 1, $p)
                    If $f = 0 Then ExitLoop
                    ; The pointer was found at (b + off + f - 1)
                    ; That means [structBase + offset] = targetValue
                    ; So structBase = (b + off + f - 1) - offset
                    Local $ptrLoc = $b + $off + ($f - 1)
                    Local $structBase = $ptrLoc - $offset
                    If $structBase > 0 Then
                        Return $structBase
                    EndIf
                    $p = $f + 1
                WEnd
            Next
        EndIf

        $scanAddr = $b + $s
        If $scanAddr = 0 Then ExitLoop
    WEnd

    Return 0
EndFunc

; Get the base address of a module in a 64-bit process using EnumProcessModulesEx
Func _GetModuleBase64($hProc, $hK32, $moduleName)
    Local $hPsapi = DllOpen("psapi.dll")
    If $hPsapi = -1 Then Return 0

    ; Allocate array for up to 1024 module handles
    Local $modArray = DllStructCreate("ptr[1024]")
    Local $cbNeeded = DllStructCreate("dword")

    ; LIST_MODULES_ALL = 0x03
    Local $ret = DllCall($hPsapi, "bool", "EnumProcessModulesEx", _
        "handle", $hProc, _
        "ptr", DllStructGetPtr($modArray), _
        "dword", DllStructGetSize($modArray), _
        "ptr", DllStructGetPtr($cbNeeded), _
        "dword", 0x03)

    If @error Or $ret[0] = 0 Then
        DllClose($hPsapi)
        Return 0
    EndIf

    Local $numModules = DllStructGetData($cbNeeded, 1) / 8 ; ptr is 8 bytes on 64-bit
    If $numModules > 1024 Then $numModules = 1024

    For $i = 1 To $numModules
        Local $hMod = DllStructGetData($modArray, 1, $i)
        Local $nameBuf = DllStructCreate("wchar[260]")
        DllCall($hPsapi, "dword", "GetModuleBaseNameW", _
            "handle", $hProc, _
            "handle", $hMod, _
            "ptr", DllStructGetPtr($nameBuf), _
            "dword", 260)
        Local $name = DllStructGetData($nameBuf, 1)
        If StringInStr($name, $moduleName) Then
            DllClose($hPsapi)
            Return $hMod
        EndIf
    Next

    DllClose($hPsapi)
    Return 0
EndFunc
