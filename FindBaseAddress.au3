#RequireAdmin
#include <GUIConstantsEx.au3>

; ============================================
; PWI 64-bit Base Address Finder (v2 - Fast)
; ============================================
; 1. Log into a character on elementclient_64.exe
; 2. Run this script as Administrator
; 3. It will find and display the base address
; ============================================

Global $PLAYER_OFFSET = 52
Global $PLAYERNAME_OFFSET = 2960
Global $PLAYERID_OFFSET = 2056

; Step 1: Find the process
Local $PID = ProcessExists("elementclient_64.exe")
If $PID = 0 Then
    MsgBox(16, "Error", "elementclient_64.exe is not running!" & @CRLF & @CRLF & "Please log into a character first, then run this script again.")
    Exit
EndIf

MsgBox(64, "Process Found", "Found elementclient_64.exe (PID: " & $PID & ")" & @CRLF & @CRLF & "Click OK to start scanning.")

; Step 2: Open process
Local $hKernel32 = DllOpen("kernel32.dll")
Local $aOpenProc = DllCall($hKernel32, "handle", "OpenProcess", "dword", 0x1F0FFF, "bool", 0, "dword", $PID)
If $aOpenProc[0] = 0 Then
    MsgBox(16, "Error", "Failed to open process. Try running as Administrator.")
    DllClose($hKernel32)
    Exit
EndIf
Local $hProcess = $aOpenProc[0]

; Step 3: Ask for character name
Local $charName = InputBox("Character Name", "Type your character's name EXACTLY as it appears in-game:" & @CRLF & "(This is case-sensitive)", "", "", 400, 200)
If $charName = "" Then
    MsgBox(16, "Error", "You must enter a character name.")
    DllCall($hKernel32, "bool", "CloseHandle", "handle", $hProcess)
    DllClose($hKernel32)
    Exit
EndIf

; Create progress window
Global $hProgressGUI = GUICreate("Scanning...", 450, 120, -1, -1)
Global $hProgressLabel = GUICtrlCreateLabel("Starting scan...", 20, 15, 410, 25)
Global $hProgressDetail = GUICtrlCreateLabel("", 20, 45, 410, 25)
Global $hProgressTimer = GUICtrlCreateLabel("", 20, 80, 410, 25)
GUISetState(@SW_SHOW, $hProgressGUI)
Global $gStartTime = TimerInit()

; Step 4: Quick check - does the old 32-bit address work?
_UpdateProgress("Checking old 32-bit address...", "")
Local $oldBase = 22982616
Local $testName = _TryReadName($hProcess, $hKernel32, $oldBase)
If $testName = $charName Then
    GUIDelete($hProgressGUI)
    MsgBox(64, "SUCCESS!", "The old ADDRESS_BASE works!" & @CRLF & @CRLF & "$ADDRESS_BASE = " & $oldBase & "  (0x" & Hex($oldBase) & ")" & @CRLF & "Character: " & $testName)
    ClipPut("ADDRESS_BASE = " & $oldBase & "  (0x" & Hex($oldBase) & ")")
    DllCall($hKernel32, "bool", "CloseHandle", "handle", $hProcess)
    DllClose($hKernel32)
    Exit
EndIf

; Step 5: Scan ALL readable memory regions, trying every dword as a potential ADDRESS_BASE
_UpdateProgress("Scanning all memory for ADDRESS_BASE...", "This will take a few minutes. Progress shown below.")

Local $results = ""
Local $resultCount = 0
Local $addr = 0
Local $regionsScanned = 0
Local $totalDwordsTested = 0
Local $mbi = DllStructCreate("ptr BaseAddress; ptr AllocationBase; dword AllocationProtect; ptr RegionSize; dword State; dword Protect; dword Type")

While 1
    Local $ret = DllCall($hKernel32, "ulong_ptr", "VirtualQueryEx", "handle", $hProcess, "ptr", $addr, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
    If @error Or $ret[0] = 0 Then ExitLoop

    Local $regionBase = DllStructGetData($mbi, "BaseAddress")
    Local $regionSize = DllStructGetData($mbi, "RegionSize")
    Local $state = DllStructGetData($mbi, "State")
    Local $protect = DllStructGetData($mbi, "Protect")
    Local $type = DllStructGetData($mbi, "Type")

    ; Only scan committed, readable, image-backed memory (exe/dll sections)
    ; Type 0x1000000 = MEM_IMAGE (loaded from exe/dll)
    If $state = 0x1000 And BitAND($protect, 0x100) = 0 And $type = 0x1000000 Then
        Local $chunkSize = 4096
        For $offset = 0 To $regionSize - 4 Step $chunkSize
            Local $readSize = $chunkSize
            If $offset + $readSize > $regionSize Then $readSize = $regionSize - $offset
            If $readSize < 4 Then ContinueLoop

            Local $chunk = _ReadBytes($hProcess, $hKernel32, $regionBase + $offset, $readSize)
            If @error Then ContinueLoop

            For $bytePos = 0 To $readSize - 4 Step 4
                Local $val = _BytesToDword($chunk, $bytePos)
                If $val < 0x10000 Or $val = 0 Then ContinueLoop

                Local $tryName = _TryReadName($hProcess, $hKernel32, $regionBase + $offset + $bytePos)
                $totalDwordsTested += 1
                If $tryName = $charName Then
                    $resultCount += 1
                    Local $foundAddr = $regionBase + $offset + $bytePos
                    $results &= "ADDRESS_BASE = " & $foundAddr & "  (0x" & Hex($foundAddr) & ")" & @CRLF
                    $results &= @CRLF
                EndIf
            Next
        Next
        $regionsScanned += 1

        ; Update progress every few regions
        If Mod($regionsScanned, 5) = 0 Then
            Local $elapsed = Round(TimerDiff($gStartTime) / 1000)
            _UpdateProgress("Scanning memory regions... (" & $regionsScanned & " regions scanned)", "Found " & $resultCount & " result(s) so far. Elapsed: " & $elapsed & "s")
        EndIf
    EndIf

    $addr = $regionBase + $regionSize
    If $addr = 0 Then ExitLoop
WEnd

; Show results
GUIDelete($hProgressGUI)

If $resultCount > 0 Then
    MsgBox(64, "SUCCESS! Found " & $resultCount & " result(s)", "Results:" & @CRLF & @CRLF & $results & @CRLF & "Results copied to clipboard! Paste them to Claude.")
    ClipPut($results)
Else
    ; Try again with ALL memory types, not just image-backed
    Local $retry = MsgBox(4, "Not found in modules", "ADDRESS_BASE not found in exe/dll memory." & @CRLF & @CRLF & "Want to try scanning ALL memory? (slower, 5-15 min)")
    If $retry = 6 Then
        GUISetState(@SW_SHOW, GUICreate("Scanning ALL memory...", 450, 120, -1, -1))
        $hProgressLabel = GUICtrlCreateLabel("", 20, 15, 410, 25)
        $hProgressDetail = GUICtrlCreateLabel("", 20, 45, 410, 25)
        $hProgressTimer = GUICtrlCreateLabel("", 20, 80, 410, 25)
        $gStartTime = TimerInit()
        $regionsScanned = 0
        $addr = 0

        While 1
            $ret = DllCall($hKernel32, "ulong_ptr", "VirtualQueryEx", "handle", $hProcess, "ptr", $addr, "ptr", DllStructGetPtr($mbi), "ulong_ptr", DllStructGetSize($mbi))
            If @error Or $ret[0] = 0 Then ExitLoop

            $regionBase = DllStructGetData($mbi, "BaseAddress")
            $regionSize = DllStructGetData($mbi, "RegionSize")
            $state = DllStructGetData($mbi, "State")
            $protect = DllStructGetData($mbi, "Protect")

            If $state = 0x1000 And BitAND($protect, 0x100) = 0 And $regionSize < 0x10000000 Then
                Local $chunkSz = 4096
                For $off2 = 0 To $regionSize - 4 Step $chunkSz
                    Local $rdSz = $chunkSz
                    If $off2 + $rdSz > $regionSize Then $rdSz = $regionSize - $off2
                    If $rdSz < 4 Then ContinueLoop

                    Local $chk = _ReadBytes($hProcess, $hKernel32, $regionBase + $off2, $rdSz)
                    If @error Then ContinueLoop

                    For $bp = 0 To $rdSz - 4 Step 4
                        Local $v = _BytesToDword($chk, $bp)
                        If $v < 0x10000 Or $v = 0 Then ContinueLoop

                        Local $tn = _TryReadName($hProcess, $hKernel32, $regionBase + $off2 + $bp)
                        If $tn = $charName Then
                            $resultCount += 1
                            Local $fa = $regionBase + $off2 + $bp
                            $results &= "ADDRESS_BASE = " & $fa & "  (0x" & Hex($fa) & ")" & @CRLF & @CRLF
                        EndIf
                    Next
                Next
                $regionsScanned += 1
                If Mod($regionsScanned, 10) = 0 Then
                    Local $el = Round(TimerDiff($gStartTime) / 1000)
                    _UpdateProgress("Full scan... (" & $regionsScanned & " regions)", "Found " & $resultCount & " result(s). Elapsed: " & $el & "s")
                EndIf
            EndIf

            $addr = $regionBase + $regionSize
            If $addr = 0 Then ExitLoop
        WEnd

        GUIDelete()
        If $resultCount > 0 Then
            MsgBox(64, "SUCCESS! Found " & $resultCount & " result(s)", "Results:" & @CRLF & @CRLF & $results & @CRLF & "Results copied to clipboard!")
            ClipPut($results)
        Else
            MsgBox(48, "No results", "Could not find ADDRESS_BASE." & @CRLF & @CRLF & "The pointer chain offsets (0x1C, 0x34, 0xB90) may be" & @CRLF & "different in the 64-bit client." & @CRLF & @CRLF & "Please tell Claude this result.")
        EndIf
    EndIf
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

Func _ReadDword($hProc, $hK32, $iAddr)
    Local $buf = DllStructCreate("dword")
    DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $iAddr, "ptr", DllStructGetPtr($buf), "ulong_ptr", 4, "ulong_ptr*", 0)
    If @error Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

Func _ReadBytes($hProc, $hK32, $iAddr, $iSize)
    Local $buf = DllStructCreate("byte[" & $iSize & "]")
    Local $ret2 = DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $iAddr, "ptr", DllStructGetPtr($buf), "ulong_ptr", $iSize, "ulong_ptr*", 0)
    If @error Or $ret2[0] = 0 Then Return SetError(1, 0, 0)
    Return DllStructGetData($buf, 1)
EndFunc

Func _BytesToDword($bytes, $iOffset)
    Local $buf = DllStructCreate("byte[4]")
    DllStructSetData($buf, 1, BinaryMid($bytes, $iOffset + 1, 4))
    Local $buf2 = DllStructCreate("dword", DllStructGetPtr($buf))
    Return DllStructGetData($buf2, 1)
EndFunc

Func _TryReadName($hProc, $hK32, $baseAddr)
    Local $val1 = _ReadDword($hProc, $hK32, $baseAddr)
    If $val1 = 0 Then Return ""
    Local $val2 = _ReadDword($hProc, $hK32, $val1 + 0x1C)
    If $val2 = 0 Then Return ""
    Local $player = _ReadDword($hProc, $hK32, $val2 + 0x34)
    If $player = 0 Then Return ""
    Local $namePtr = _ReadDword($hProc, $hK32, $player + 2960)
    If $namePtr = 0 Then Return ""
    Local $nameBuf = DllStructCreate("wchar[50]")
    DllCall($hK32, "bool", "ReadProcessMemory", "handle", $hProc, "ptr", $namePtr, "ptr", DllStructGetPtr($nameBuf), "ulong_ptr", 100, "ulong_ptr*", 0)
    Return DllStructGetData($nameBuf, 1)
EndFunc
