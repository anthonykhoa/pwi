#RequireAdmin
#include <GUIConstantsEx.au3>

; ============================================
; PWI 64-bit Base Address Finder (v4)
; ============================================
; 1. Log into a character on elementclient_64.exe
; 2. Run this script as Administrator
; 3. It will find and display the base address
; ============================================

; Step 1: Find the process
Local $PID = ProcessExists("elementclient_64.exe")
If $PID = 0 Then
    MsgBox(16, "Error", "elementclient_64.exe is not running!" & @CRLF & @CRLF & "Please log into a character first, then run this script again.")
    Exit
EndIf

; Step 2: Open process
Local $hKernel32 = DllOpen("kernel32.dll")
Local $aOpenProc = DllCall($hKernel32, "handle", "OpenProcess", "dword", 0x1F0FFF, "bool", 0, "dword", $PID)
If $aOpenProc[0] = 0 Then
    MsgBox(16, "Error", "Failed to open process. Try running as Administrator.")
    DllClose($hKernel32)
    Exit
EndIf
Local $hProcess = $aOpenProc[0]

; Step 3: Get module base
Local $moduleBase = _GetModuleBase64($hProcess, $hKernel32, "elementclient_64.exe")
If $moduleBase = 0 Then
    MsgBox(16, "Error", "Could not find module base address.")
    Exit
EndIf

; Step 4: Ask for character name
Local $charName = InputBox("Character Name", "Type your character's name EXACTLY as it appears in-game:" & @CRLF & "(Case-sensitive)", "", "", 400, 200)
If $charName = "" Then
    MsgBox(16, "Error", "You must enter a character name.")
    DllCall($hKernel32, "bool", "CloseHandle", "handle", $hProcess)
    DllClose($hKernel32)
    Exit
EndIf

; Progress window
Global $hProgressGUI = GUICreate("Scanning...", 550, 200, -1, -1)
Global $hProgressLabel = GUICtrlCreateLabel("Starting...", 20, 15, 510, 25)
Global $hProgressDetail = GUICtrlCreateLabel("", 20, 45, 510, 25)
Global $hProgressTimer = GUICtrlCreateLabel("", 20, 75, 510, 25)
Global $hProgressResults = GUICtrlCreateLabel("", 20, 105, 510, 80)
GUISetState(@SW_SHOW, $hProgressGUI)
Global $gStartTime = TimerInit()

Global $outputFile = @ScriptDir & "\FindBaseAddress_Results.txt"
Global $fullOutput = ""

_AppendOutput("PWI 64-bit Base Address Finder v4 Results")
_AppendOutput("==========================================")
_AppendOutput("Process: elementclient_64.exe (PID " & $PID & ")")
_AppendOutput("Module base: 0x" & Hex($moduleBase))
_AppendOutput("Character: " & $charName)
_AppendOutput("")

; ==========================================
; STRATEGY: Scan all static data in the module for addresses
; that lead to the player name through a pointer chain.
;
; 32-bit chain was: [ADDRESS_BASE] -> +0x1C -> +0x34 -> player -> +0xB90 -> namePtr -> name
; For 64-bit we try many offset combos at each level.
; ==========================================

; Level 1 offsets (was 0x1C = 28 in 32-bit)
Local $l1Offsets[12] = [0x1C, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70]

; Level 2 / player offsets (was 0x34 = 52 in 32-bit)
Local $l2Offsets[14] = [0x34, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98]

; Name pointer offsets (was 0xB90 = 2960 in 32-bit)
; In 64-bit structs are bigger, so name could be much further
Local $nameOffsets[20] = [0xB90, 0xB98, 0xBA0, 0xBA8, 0xBB0, 0xBB8, 0xBC0, 0xBC8, _
    0x1000, 0x1100, 0x1200, 0x1300, 0x1400, 0x1500, 0x1600, 0x1700, 0x1720, 0x1730, 0x1740, 0x1800]

Local $resultCount = 0
Local $results = ""

; Get module size for scan range
Local $modInfo = DllStructCreate("ptr BaseAddr; dword SizeOfImage; ptr EntryPoint")
Local $hPsapi = DllOpen("psapi.dll")
DllCall($hPsapi, "bool", "GetModuleInformation", "handle", $hProcess, "handle", $moduleBase, _
    "ptr", DllStructGetPtr($modInfo), "dword", DllStructGetSize($modInfo))
Local $moduleSize = DllStructGetData($modInfo, "SizeOfImage")
If $moduleSize = 0 Then $moduleSize = 0x0C000000
DllClose($hPsapi)

_AppendOutput("Module size: 0x" & Hex($moduleSize))
_AppendOutput("")
_AppendOutput("=== SCANNING STATIC DATA SECTION ===")
_SaveOutput()

; Scan the data sections of the module (typically after code, in the upper half)
; Start from about 60% into the module to skip code sections
Local $dataStart = $moduleBase + Int($moduleSize * 0.4)
Local $dataEnd = $moduleBase + $moduleSize
Local $chunkSize = 4096
Local $totalScanned = 0
Local $totalToScan = $dataEnd - $dataStart

_UpdateProgress("Scanning module data sections...", "Module: 0x" & Hex($moduleBase) & " Size: 0x" & Hex($moduleSize))

For $scanAddr = $dataStart To $dataEnd - 8 Step $chunkSize
    Local $chunk = _ReadBytes($hProcess, $hKernel32, $scanAddr, $chunkSize)
    If @error Then
        $totalScanned += $chunkSize
        ContinueLoop
    EndIf

    ; Check every 8-byte aligned qword in this chunk as a potential ADDRESS_BASE
    For $bPos = 0 To $chunkSize - 8 Step 8
        Local $candidateAddr = $scanAddr + $bPos

        ; Read the qword value at this candidate address
        Local $val0 = _BytesToQword($chunk, $bPos)
        If $val0 = 0 Or $val0 < 0x10000 Then ContinueLoop
        ; Skip if value looks like it's inside the module code (probably not a heap pointer)
        If $val0 >= $moduleBase And $val0 < $moduleBase + $moduleSize Then ContinueLoop

        ; Try each level 1 offset
        For $a = 0 To UBound($l1Offsets) - 1
            Local $val1 = _ReadQword($hProcess, $hKernel32, $val0 + $l1Offsets[$a])
            If $val1 = 0 Or $val1 < 0x10000 Then ContinueLoop

            ; Try each level 2 (player) offset
            For $b = 0 To UBound($l2Offsets) - 1
                Local $val2 = _ReadQword($hProcess, $hKernel32, $val1 + $l2Offsets[$b])
                If $val2 = 0 Or $val2 < 0x10000 Then ContinueLoop

                ; Try each name offset
                For $c = 0 To UBound($nameOffsets) - 1
                    ; Try pointer-to-name (name stored as a pointer to string)
                    Local $namePtr = _ReadQword($hProcess, $hKernel32, $val2 + $nameOffsets[$c])
                    If $namePtr = 0 Or $namePtr < 0x10000 Then ContinueLoop
                    Local $testName = _ReadWString($hProcess, $hKernel32, $namePtr)
                    If $testName = $charName Then
                        $resultCount += 1
                        Local $relOffset = $candidateAddr - $moduleBase
                        Local $rLine = "ADDRESS_BASE = " & $candidateAddr & "  (0x" & Hex($candidateAddr) & ")"
                        $results &= "=== RESULT " & $resultCount & " ===" & @CRLF
                        $results &= $rLine & @CRLF
                        $results &= "Module + 0x" & Hex($relOffset) & @CRLF
                        $results &= "Chain: [base] -> +0x" & Hex($l1Offsets[$a]) & " -> +0x" & Hex($l2Offsets[$b]) & " -> +0x" & Hex($nameOffsets[$c]) & " -> ptr -> name" & @CRLF
                        $results &= "New PLAYER_OFFSET = " & $l2Offsets[$b] & " (0x" & Hex($l2Offsets[$b]) & ")" & @CRLF
                        $results &= "New PLAYERNAME_OFFSET = " & $nameOffsets[$c] & " (0x" & Hex($nameOffsets[$c]) & ")" & @CRLF
                        $results &= @CRLF

                        _AppendOutput("*** FOUND! " & $rLine & " ***")
                        _AppendOutput("  Module + 0x" & Hex($relOffset))
                        _AppendOutput("  Chain: [base] -> +0x" & Hex($l1Offsets[$a]) & " -> +0x" & Hex($l2Offsets[$b]) & " -> +0x" & Hex($nameOffsets[$c]) & " -> ptr -> name")
                        _AppendOutput("  PLAYER_OFFSET = " & $l2Offsets[$b])
                        _AppendOutput("  PLAYERNAME_OFFSET = " & $nameOffsets[$c])
                        _AppendOutput("")
                        _SaveOutput()

                        GUICtrlSetData($hProgressResults, "FOUND #" & $resultCount & ": " & $rLine & @CRLF & _
                            "Chain: +0x" & Hex($l1Offsets[$a]) & " -> +0x" & Hex($l2Offsets[$b]) & " -> +0x" & Hex($nameOffsets[$c]))
                    EndIf
                Next

                ; Also try inline name (name stored directly in struct, not via pointer)
                For $c = 0 To UBound($nameOffsets) - 1
                    Local $inlineName = _ReadWString($hProcess, $hKernel32, $val2 + $nameOffsets[$c])
                    If $inlineName = $charName Then
                        $resultCount += 1
                        Local $relOffset2 = $candidateAddr - $moduleBase
                        Local $rLine2 = "ADDRESS_BASE = " & $candidateAddr & "  (0x" & Hex($candidateAddr) & ")"
                        $results &= "=== RESULT " & $resultCount & " (INLINE NAME) ===" & @CRLF
                        $results &= $rLine2 & @CRLF
                        $results &= "Module + 0x" & Hex($relOffset2) & @CRLF
                        $results &= "Chain: [base] -> +0x" & Hex($l1Offsets[$a]) & " -> +0x" & Hex($l2Offsets[$b]) & " -> inline name at +0x" & Hex($nameOffsets[$c]) & @CRLF
                        $results &= @CRLF

                        _AppendOutput("*** FOUND (INLINE)! " & $rLine2 & " ***")
                        _AppendOutput("  Chain: [base] -> +0x" & Hex($l1Offsets[$a]) & " -> +0x" & Hex($l2Offsets[$b]) & " -> inline at +0x" & Hex($nameOffsets[$c]))
                        _AppendOutput("")
                        _SaveOutput()
                    EndIf
                Next
            Next
        Next
    Next

    $totalScanned += $chunkSize
    If Mod($totalScanned, 0x100000) < $chunkSize Then
        Local $pct = Round($totalScanned / $totalToScan * 100)
        Local $elapsed = Round(TimerDiff($gStartTime) / 1000)
        _UpdateProgress("Scanning... " & $pct & "% (" & $elapsed & "s)", _
            "Checked 0x" & Hex($scanAddr) & " | Found: " & $resultCount & " result(s)")
    EndIf
Next

; ==========================================
; ALSO: scan ALL readable memory (not just module)
; for the chain, in case ADDRESS_BASE is a heap address
; that gets stored somewhere we missed
; ==========================================
If $resultCount = 0 Then
    _UpdateProgress("No results in module. Scanning all memory...", "This may take several minutes.")
    _AppendOutput("")
    _AppendOutput("=== FULL MEMORY SCAN (no results in module) ===")
    _SaveOutput()

    Local $scanAddr2 = 0
    Local $mbi = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")
    Local $regionsScanned = 0

    While 1
        Local $ret = DllCall($hKernel32, "ulong_ptr", "VirtualQueryEx", "handle", $hProcess, "ptr", $scanAddr2, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
        If @error Or $ret[0] = 0 Then ExitLoop

        Local $regionBase = DllStructGetData($mbi, "BaseAddress")
        Local $regionSize = DllStructGetData($mbi, "RegionSize")
        Local $state = DllStructGetData($mbi, "State")
        Local $protect = DllStructGetData($mbi, "Protect")
        Local $type = DllStructGetData($mbi, "Type")

        ; Only scan image-backed memory (exe/dll data sections)
        If $state = 0x1000 And BitAND($protect, 0x100) = 0 And $type = 0x1000000 And $regionSize < 0x10000000 Then
            For $offset = 0 To $regionSize - 8 Step $chunkSize
                Local $readSize = $chunkSize
                If $offset + $readSize > $regionSize Then $readSize = $regionSize - $offset
                If $readSize < 8 Then ContinueLoop

                Local $chunkData = _ReadBytes($hProcess, $hKernel32, $regionBase + $offset, $readSize)
                If @error Then ContinueLoop

                For $bPos2 = 0 To $readSize - 8 Step 8
                    Local $candAddr = $regionBase + $offset + $bPos2
                    Local $v0 = _BytesToQword($chunkData, $bPos2)
                    If $v0 = 0 Or $v0 < 0x10000 Then ContinueLoop

                    For $a2 = 0 To UBound($l1Offsets) - 1
                        Local $v1 = _ReadQword($hProcess, $hKernel32, $v0 + $l1Offsets[$a2])
                        If $v1 = 0 Or $v1 < 0x10000 Then ContinueLoop

                        For $b2 = 0 To UBound($l2Offsets) - 1
                            Local $v2 = _ReadQword($hProcess, $hKernel32, $v1 + $l2Offsets[$b2])
                            If $v2 = 0 Or $v2 < 0x10000 Then ContinueLoop

                            For $c2 = 0 To UBound($nameOffsets) - 1
                                Local $np = _ReadQword($hProcess, $hKernel32, $v2 + $nameOffsets[$c2])
                                If $np = 0 Or $np < 0x10000 Then ContinueLoop
                                Local $tn = _ReadWString($hProcess, $hKernel32, $np)
                                If $tn = $charName Then
                                    $resultCount += 1
                                    $results &= "=== RESULT " & $resultCount & " (FULL SCAN) ===" & @CRLF
                                    $results &= "ADDRESS_BASE = " & $candAddr & "  (0x" & Hex($candAddr) & ")" & @CRLF
                                    $results &= "Chain: +0x" & Hex($l1Offsets[$a2]) & " -> +0x" & Hex($l2Offsets[$b2]) & " -> +0x" & Hex($nameOffsets[$c2]) & " -> ptr -> name" & @CRLF
                                    $results &= @CRLF
                                    _AppendOutput("*** FOUND (full scan)! 0x" & Hex($candAddr) & " ***")
                                    _AppendOutput("  Chain: +0x" & Hex($l1Offsets[$a2]) & " -> +0x" & Hex($l2Offsets[$b2]) & " -> +0x" & Hex($nameOffsets[$c2]))
                                    _AppendOutput("")
                                    _SaveOutput()
                                    GUICtrlSetData($hProgressResults, "FOUND: 0x" & Hex($candAddr))
                                EndIf
                            Next
                        Next
                    Next
                Next
            Next
            $regionsScanned += 1
            If Mod($regionsScanned, 10) = 0 Then
                Local $el = Round(TimerDiff($gStartTime) / 1000)
                _UpdateProgress("Full scan... (" & $regionsScanned & " regions, " & $el & "s)", "Found " & $resultCount & " result(s)")
            EndIf
        EndIf

        $scanAddr2 = $regionBase + $regionSize
        If $scanAddr2 = 0 Then ExitLoop
    WEnd
EndIf

; ==========================================
; DONE
; ==========================================
GUIDelete($hProgressGUI)

_AppendOutput("==========================================")
_AppendOutput("TOTAL RESULTS: " & $resultCount)
_AppendOutput("==========================================")
_SaveOutput()

If $resultCount > 0 Then
    ClipPut($results)
    MsgBox(64, "SUCCESS! Found " & $resultCount & " result(s)", _
        "Results:" & @CRLF & @CRLF & $results & @CRLF & _
        "Saved to: " & $outputFile & @CRLF & @CRLF & _
        "Copied to clipboard! Paste to Claude.")
Else
    _AppendOutput("")
    _AppendOutput("TROUBLESHOOTING: No results found with known offset patterns.")
    _AppendOutput("The 64-bit client may use a completely different pointer chain.")
    _AppendOutput("Next step: use Cheat Engine to find the chain manually.")
    _SaveOutput()
    ClipPut($fullOutput)
    MsgBox(48, "No results", _
        "Could not find ADDRESS_BASE." & @CRLF & @CRLF & _
        "The 64-bit pointer chain offsets may be very different." & @CRLF & _
        "Results saved to: " & $outputFile & @CRLF & @CRLF & _
        "Paste the results to Claude for next steps.")
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
    Local $ret = DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $iAddr, "ptr", DllStructGetPtr($buf), "ulong_ptr", $iSize, "ulong_ptr*", 0)
    If @error Or $ret[0] = 0 Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

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

; Extract a uint64 from a binary blob at a given byte offset
Func _BytesToQword($bytes, $iOffset)
    Local $b1 = DllStructCreate("byte[8]")
    DllStructSetData($b1, 1, BinaryMid($bytes, $iOffset + 1, 8))
    Local $b2 = DllStructCreate("uint64", DllStructGetPtr($b1))
    Return DllStructGetData($b2, 1)
EndFunc

Func _GetModuleBase64($hProc, $hK32, $moduleName)
    Local $hPsapi = DllOpen("psapi.dll")
    If $hPsapi = -1 Then Return 0

    Local $modArray = DllStructCreate("ptr[1024]")
    Local $cbNeeded = DllStructCreate("dword")

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

    Local $numModules = DllStructGetData($cbNeeded, 1) / 8
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
