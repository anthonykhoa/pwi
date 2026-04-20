#AutoIt3Wrapper_UseX64=y

; ============================================
; PWI 64-bit Full Offset & Address Scanner
; Finds player struct offsets, function addresses,
; and global data addresses for 64-bit client.
; ============================================

; Must run with 64-bit AutoIt
If @AutoItX64 = 0 Then
	MsgBox(16, "Error", "This script must be run with 64-bit AutoIt." & @CRLF & @CRLF & _
		"Right-click the .au3 file and choose 'Run Script (x64)'" & @CRLF & _
		"Or drag it onto AutoIt3_x64.exe")
	Exit
EndIf

; Enable SeDebugPrivilege so we can open the game process
_EnableDebugPrivilege()

Local $PID = ProcessExists("elementclient_64.exe")
If $PID = 0 Then
	MsgBox(16, "Error", "elementclient_64.exe is not running!" & @CRLF & "Log into a character first.")
	Exit
EndIf

Local $hK32 = DllOpen("kernel32.dll")
Local $aOpen = DllCall($hK32, "handle", "OpenProcess", "dword", 0x1F0FFF, "bool", 0, "dword", $PID)
If @error Or $aOpen[0] = 0 Then
	MsgBox(16, "Error", "Cannot open game process (PID " & $PID & ")." & @CRLF & @CRLF & _
		"Try one of these:" & @CRLF & _
		"1. Right-click AutoIt3_x64.exe -> Run as Administrator" & @CRLF & _
		"2. Or right-click this .au3 -> Run Script (x64) as Admin")
	Exit
EndIf
Local $hProc = $aOpen[0]

Local $moduleBase = _GetModuleBase64($hProc, $hK32, "elementclient_64.exe")
If $moduleBase = 0 Then
	; Fallback: try CreateToolhelp32Snapshot
	$moduleBase = _GetModuleBaseSnapshot($hK32, $PID, "elementclient_64.exe")
EndIf
If $moduleBase = 0 Then
	; Last resort: try the default 64-bit exe base
	Local $testPtr = _ReadQword($hProc, $hK32, 0x140000000 + 0x1A213E8)
	If $testPtr <> 0 Then
		$moduleBase = 0x140000000
		MsgBox(64, "Info", "Using default module base 0x140000000 (verified via ADDRESS_BASE)")
	EndIf
EndIf
If $moduleBase = 0 Then
	MsgBox(16, "Error", "Could not find module base." & @CRLF & "All 3 methods failed.")
	Exit
EndIf

; Get module size
Local $hPsapi = DllOpen("psapi.dll")
Local $modInfo = DllStructCreate("ptr BaseAddr; dword SizeOfImage; ptr EntryPoint")
DllCall($hPsapi, "bool", "GetModuleInformation", "handle", $hProc, "handle", $moduleBase, _
	"ptr", DllStructGetPtr($modInfo), "dword", DllStructGetSize($modInfo))
Local $moduleSize = DllStructGetData($modInfo, "SizeOfImage")
DllClose($hPsapi)
If $moduleSize = 0 Then $moduleSize = 0x10000000

Global $outputFile = @ScriptDir & "\FindAllOffsets64_Results.txt"
Global $fullOutput = ""
Global $gStart = TimerInit()

_Out("PWI 64-bit Full Offset & Address Scanner")
_Out("==========================================")
_Out("PID: " & $PID)
_Out("Module base: 0x" & Hex($moduleBase))
_Out("Module size: 0x" & Hex($moduleSize))
_Out("")

; ==========================================
; STEP 1: Get player pointer using known chain
; ==========================================
Local $ADDRESS_BASE_OFFSET = 0x1A213E8
Local $addrBase = $moduleBase + $ADDRESS_BASE_OFFSET

_Out("=== STEP 1: PLAYER POINTER CHAIN ===")
_Out("ADDRESS_BASE at: 0x" & Hex($addrBase))

Local $level0 = _ReadQword($hProc, $hK32, $addrBase)
_Out("  [ADDRESS_BASE] = 0x" & Hex($level0))

If $level0 = 0 Then
	_Out("ERROR: ADDRESS_BASE points to null. Make sure you're logged into a character.")
	_Save()
	MsgBox(16, "Error", "ADDRESS_BASE is null. Log into a character first.")
	Exit
EndIf

Local $level1 = _ReadQword($hProc, $hK32, $level0 + 0x38)
_Out("  [level0 + 0x38] = 0x" & Hex($level1))

Local $player = _ReadQword($hProc, $hK32, $level1 + 0x68)
_Out("  [level1 + 0x68] = Player at 0x" & Hex($player))

Local $namePtr = _ReadQword($hProc, $hK32, $player + 0xDF8)
Local $charName = _ReadWString($hProc, $hK32, $namePtr)
_Out("  Player name: " & $charName)
_Out("")
_Save()

If $charName = "" Then
	_Out("ERROR: Could not read player name. Chain may be wrong.")
	_Save()
	MsgBox(16, "Error", "Could not read player name.")
	Exit
EndIf

; Ask user for current stats to help match offsets
Local $inputHP = InputBox("Current HP", "What is your character's CURRENT HP?" & @CRLF & "(Check in-game, enter the number)", "", "", 400, 200)
Local $inputMaxHP = InputBox("Max HP", "What is your character's MAX HP?", "", "", 400, 200)
Local $inputMP = InputBox("Current MP", "What is your character's CURRENT MP?", "", "", 400, 200)
Local $inputMaxMP = InputBox("Max MP", "What is your character's MAX MP?", "", "", 400, 200)
Local $inputClass = InputBox("Class Number", "What class number? (0=BM, 1=Wiz, 2=Barb, 3=Veno, 4=Archer, 5=Sin, 6=Cleric/EP, 7=Cleric/HA, 8=Seeker, 9=Mystic, 10=Dusk, 11=Storm, 12=Tech)", "", "", 400, 200)

Local $hp = Int($inputHP)
Local $maxhp = Int($inputMaxHP)
Local $mp = Int($inputMP)
Local $maxmp = Int($inputMaxMP)
Local $class = Int($inputClass)

_Out("User-provided stats: HP=" & $hp & " MaxHP=" & $maxhp & " MP=" & $mp & " MaxMP=" & $maxmp & " Class=" & $class)
_Out("")

; ==========================================
; STEP 2: DUMP & SCAN PLAYER STRUCT
; ==========================================
_Out("=== STEP 2: PLAYER STRUCT OFFSET SCAN ===")
_Out("Reading 16KB from player address 0x" & Hex($player) & "...")
_Save()

; 32-bit offsets for reference (and their approximate 64-bit scaled values)
; We know NAME went from 2960 (32-bit) to 0xDF8=3576 (64-bit), ratio ~1.208
; But this varies per field, so we scan broadly

Local $scanSize = 16384 ; 16KB
Local $playerData = _ReadBytes($hProc, $hK32, $player, $scanSize)

If @error Then
	_Out("ERROR: Could not read player struct data.")
	_Save()
	MsgBox(16, "Error", "Could not read player struct.")
	Exit
EndIf

; Search for HP value (as dword) in the struct
_Out("--- Searching for HP=" & $hp & " ---")
Local $hpMatches = ""
For $off = 0 To $scanSize - 4 Step 4
	Local $val = _BytesToDword($playerData, $off)
	If $val = $hp And $hp > 0 Then
		$hpMatches &= "  Offset 0x" & Hex($off, 4) & " (" & $off & ") = " & $val
		; Check if HP+4 = MP (common pattern)
		Local $nextVal = _BytesToDword($playerData, $off + 4)
		If $nextVal = $mp Then
			$hpMatches &= "  ** HP+4 = MP! Very likely HP_OFFSET **"
		EndIf
		$hpMatches &= @CRLF
	EndIf
Next
_Out($hpMatches)

_Out("--- Searching for MaxHP=" & $maxhp & " ---")
Local $maxhpMatches = ""
For $off = 0 To $scanSize - 4 Step 4
	Local $val2 = _BytesToDword($playerData, $off)
	If $val2 = $maxhp And $maxhp > 0 Then
		$maxhpMatches &= "  Offset 0x" & Hex($off, 4) & " (" & $off & ") = " & $val2
		Local $nextVal2 = _BytesToDword($playerData, $off + 4)
		If $nextVal2 = $maxmp Then
			$maxhpMatches &= "  ** MaxHP+4 = MaxMP! Very likely MAXHP_OFFSET **"
		EndIf
		$maxhpMatches &= @CRLF
	EndIf
Next
_Out($maxhpMatches)

_Out("--- Searching for MP=" & $mp & " ---")
Local $mpMatches = ""
For $off = 0 To $scanSize - 4 Step 4
	Local $val3 = _BytesToDword($playerData, $off)
	If $val3 = $mp And $mp > 0 Then
		$mpMatches &= "  Offset 0x" & Hex($off, 4) & " (" & $off & ")" & @CRLF
	EndIf
Next
_Out($mpMatches)

_Out("--- Searching for Class=" & $class & " ---")
Local $classMatches = ""
; Class is likely a dword near the name offset area
For $off = Int(0xD00) To Int(0x1200) Step 4
	If $off + 4 > $scanSize Then ExitLoop
	Local $val4 = _BytesToDword($playerData, $off)
	If $val4 = $class Then
		$classMatches &= "  Offset 0x" & Hex($off, 4) & " (" & $off & ")" & @CRLF
	EndIf
Next
_Out($classMatches)

; Search for name pointer in struct (should be at PLAYERNAME_OFFSET = 0xDF8)
_Out("--- Verifying known offsets ---")
Local $nameAtKnown = _ReadQword($hProc, $hK32, $player + 0xDF8)
Local $nameCheck = _ReadWString($hProc, $hK32, $nameAtKnown)
_Out("  PLAYERNAME at 0xDF8: ptr=0x" & Hex($nameAtKnown) & " -> '" & $nameCheck & "' " & ($nameCheck = $charName ? "CONFIRMED" : "MISMATCH"))

; Also check where the character name string appears in struct as pointer
_Out("--- Searching for name pointer in struct ---")
For $off = 0 To $scanSize - 8 Step 8
	Local $ptrVal = _BytesToQword($playerData, $off)
	If $ptrVal = $namePtr Then
		_Out("  Name pointer found at offset 0x" & Hex($off, 4) & " (" & $off & ")")
	EndIf
Next

_Out("")
_Save()

; ==========================================
; STEP 3: DETAILED STRUCT DUMP (key regions)
; ==========================================
_Out("=== STEP 3: STRUCT DUMP AT KEY REGIONS ===")
_Out("(32-bit offsets scaled ~1.2x for reference)")
_Out("")

; Dump regions around expected 64-bit offsets for manual inspection
; 32-bit HP_OFFSET=2076, scaled ~2500. But let's dump broadly.
Local $regions[6][3] = [ _
	[0x800, 0xA00, "Vehicle/Buff region (32-bit: 1236-1664)"], _
	[0xA00, 0xC00, "ID/Speed/HP/MP region (32-bit: 2056-2184)"], _
	[0xC00, 0xE00, "Target/Equip/Name region (32-bit: 2452-2968)"], _
	[0xE00, 0x1000, "Class/Transport/Position region (32-bit: 2948-3200)"], _
	[0x1000, 0x1400, "Combat/Party/Skill region (32-bit: 3128-3619)"], _
	[0x1400, 0x1C00, "Camera/Cooldown/NPC region (32-bit: 4104-5972)"] _
]

For $r = 0 To 5
	Local $rStart = $regions[$r][0]
	Local $rEnd = $regions[$r][1]
	_Out("--- " & $regions[$r][2] & " ---")
	_Out("Offset    | Hex (dword)  | Decimal     | As Float    | As Ptr (qword)")
	For $off = $rStart To $rEnd - 4 Step 4
		If $off + 8 > $scanSize Then ExitLoop
		Local $dw = _BytesToDword($playerData, $off)
		Local $flt = _BytesToFloat($playerData, $off)
		Local $qw = _BytesToQword($playerData, $off)
		Local $marker = ""
		If $dw = $hp And $hp > 0 Then $marker &= " <<< HP?"
		If $dw = $mp And $mp > 0 Then $marker &= " <<< MP?"
		If $dw = $maxhp And $maxhp > 0 Then $marker &= " <<< MaxHP?"
		If $dw = $maxmp And $maxmp > 0 Then $marker &= " <<< MaxMP?"
		If $dw = $class And $off >= 0xD00 And $off <= 0x1200 Then $marker &= " <<< Class?"
		_Out("0x" & Hex($off, 4) & "    | 0x" & Hex($dw, 8) & "   | " & StringFormat("%-11s", $dw) & " | " & StringFormat("%-11s", StringFormat("%.2f", $flt)) & " | 0x" & Hex($qw) & $marker)
	Next
	_Out("")
Next
_Save()

; ==========================================
; STEP 4: SCAN FOR FUNCTION ADDRESSES
; ==========================================
_Out("=== STEP 4: FUNCTION ADDRESS SCAN ===")
_Out("Searching for 64-bit function addresses...")
_Out("")
_Save()

; 32-bit function offsets (from module base 0x400000)
; We'll search the 64-bit module code section for function prologues near scaled offsets
Local $funcs32[11][2] = [ _
	["ADDRESS_SENDPACKET",        14737984], _
	["ADDRESS_POSTMESSAGE",       11167168], _
	["ADDRESS_ACTION1",           12347264], _
	["ADDRESS_ACTION2",           12373712], _
	["ADDRESS_ACTION3",           12350832], _
	["ADDRESS_GATHER",            12285824], _
	["ADDRESS_CASTSKILL",         12208176], _
	["ADDRESS_SKILLCASTCONDITION", 12233776], _
	["ADDRESS_REGATTACK",         12278640], _
	["ADDRESS_GET_WORK",          12349424], _
	["ADDRESS_ISQUESTAVAILABLE",  15558544] _
]

Local $base32 = 0x400000

For $f = 0 To 10
	Local $funcName = $funcs32[$f][0]
	Local $funcAddr32 = $funcs32[$f][1]
	Local $offset32 = $funcAddr32 - $base32

	; Estimate 64-bit offset using ratio from ADDRESS_BASE
	; 32-bit ADDRESS_BASE offset = 0x15F0BE8 - 0x400000 = 0x11F0BE8
	; 64-bit ADDRESS_BASE offset = 0x1A213E8
	; Ratio ≈ 1.39
	Local $estimatedOffset64 = Int($offset32 * 1.39)
	Local $searchStart = $estimatedOffset64 - 0x100000
	Local $searchEnd = $estimatedOffset64 + 0x100000
	If $searchStart < 0 Then $searchStart = 0
	If $searchEnd > $moduleSize Then $searchEnd = $moduleSize

	_Out("--- " & $funcName & " ---")
	_Out("  32-bit: 0x" & Hex($funcAddr32) & " (offset 0x" & Hex($offset32) & ")")
	_Out("  Estimated 64-bit offset: 0x" & Hex($estimatedOffset64))
	_Out("  Searching 0x" & Hex($searchStart) & " to 0x" & Hex($searchEnd) & " for function prologues...")

	; Read the search region in chunks and look for common x64 function prologues
	Local $chunkSize = 0x10000
	Local $found = 0
	Local $candidates = ""

	For $chunkOff = $searchStart To $searchEnd Step $chunkSize
		Local $readAmt = $chunkSize
		If $chunkOff + $readAmt > $searchEnd Then $readAmt = $searchEnd - $chunkOff
		If $readAmt < 16 Then ContinueLoop

		Local $chunk = _ReadBytes($hProc, $hK32, $moduleBase + $chunkOff, $readAmt)
		If @error Then ContinueLoop

		; Search for function prologues
		For $i = 0 To $readAmt - 8
			Local $b0 = _ByteAt($chunk, $i)
			Local $b1 = _ByteAt($chunk, $i + 1)
			Local $b2 = _ByteAt($chunk, $i + 2)
			Local $b3 = _ByteAt($chunk, $i + 3)

			Local $isPrologue = False

			; Pattern 1: 48 89 5C 24 xx (mov [rsp+xx], rbx)
			If $b0 = 0x48 And $b1 = 0x89 And $b2 = 0x5C And $b3 = 0x24 Then $isPrologue = True

			; Pattern 2: 48 89 4C 24 xx (mov [rsp+xx], rcx)
			If $b0 = 0x48 And $b1 = 0x89 And $b2 = 0x4C And $b3 = 0x24 Then $isPrologue = True

			; Pattern 3: 40 53 48 83 EC (push rbx; sub rsp, xx)
			If $b0 = 0x40 And $b1 = 0x53 And $b2 = 0x48 And $b3 = 0x83 Then $isPrologue = True

			; Pattern 4: 48 83 EC xx (sub rsp, xx) - common function start
			If $b0 = 0x48 And $b1 = 0x83 And $b2 = 0xEC Then $isPrologue = True

			; Pattern 5: 55 48 8B EC (push rbp; mov rbp, rsp)
			If $b0 = 0x55 And $b1 = 0x48 And $b2 = 0x8B And $b3 = 0xEC Then $isPrologue = True

			; Only log first few near estimated offset
			If $isPrologue Then
				Local $absOffset = $chunkOff + $i
				Local $dist = Abs($absOffset - $estimatedOffset64)
				If $dist < 0x20000 And $found < 5 Then
					$found += 1
					; Read 16 bytes for signature display
					Local $sigBytes = ""
					For $sb = 0 To 15
						If $i + $sb < $readAmt Then
							$sigBytes &= Hex(_ByteAt($chunk, $i + $sb), 2) & " "
						EndIf
					Next
					$candidates &= "  Module+0x" & Hex($absOffset) & " (dist " & StringFormat("%+d", $absOffset - $estimatedOffset64) & "): " & $sigBytes & @CRLF
				EndIf
			EndIf
		Next
	Next

	If $found > 0 Then
		_Out("  Candidates (nearest to estimated offset):")
		_Out($candidates)
	Else
		_Out("  No prologues found near estimated offset.")
		_Out("")
	EndIf
	_Save()
Next

; ==========================================
; STEP 5: SCAN FOR GLOBAL DATA ADDRESSES
; ==========================================
_Out("=== STEP 5: GLOBAL DATA ADDRESSES ===")
_Out("Scanning module data section for known static pointers...")
_Out("")

; These are absolute 32-bit addresses. In 64-bit, they'll be at different module offsets.
; Strategy: scan the data section (last 30% of module) for qwords that look like valid heap pointers
; and try to identify them by their data.

Local $globals32[7][2] = [ _
	["PARTYINV_ADDRESS",      22897280], _
	["ADDRESS_CHAT_BASE",     22843288], _
	["ADDRESS_TIMESTAMP",     23111384], _
	["ADDRESS_TOWER_POINTS",  23078204], _
	["MINION_DATA_ADDRESS",   22984560], _
	["ADDRESS_NR_POINTS",     22972256], _
	["ADDRESS_WARSOUL_REPOSITORY", 22543460] _
]

; Check if ADDRESS_BASE offset area has other interesting pointers nearby
; We found ADDRESS_BASE at module+0x1A213E8. Scan nearby for other globals.
Local $dataSearchStart = $ADDRESS_BASE_OFFSET - 0x10000
Local $dataSearchEnd = $ADDRESS_BASE_OFFSET + 0x10000
If $dataSearchStart < 0 Then $dataSearchStart = 0

_Out("Scanning module data near ADDRESS_BASE (0x" & Hex($dataSearchStart) & " to 0x" & Hex($dataSearchEnd) & ")...")
_Out("Looking for qwords that point to valid heap memory...")
_Out("")

Local $dataChunk = _ReadBytes($hProc, $hK32, $moduleBase + $dataSearchStart, $dataSearchEnd - $dataSearchStart)
If Not @error Then
	Local $globalCount = 0
	For $off = 0 To ($dataSearchEnd - $dataSearchStart) - 8 Step 8
		Local $qval = _BytesToQword($dataChunk, $off)
		; Skip null, small values, and values inside the module
		If $qval = 0 Or $qval < 0x10000 Then ContinueLoop
		If $qval >= $moduleBase And $qval < ($moduleBase + $moduleSize) Then ContinueLoop

		; Try to read a few bytes from the pointer target to verify it's valid
		Local $testRead = _ReadQword($hProc, $hK32, $qval)
		If $testRead <> 0 Then
			Local $modOff = $dataSearchStart + $off
			; Check if it's near a known 32-bit global (by offset ratio)
			Local $matchName = ""
			For $g = 0 To 6
				Local $g32Off = $globals32[$g][1] - $base32
				Local $g64Est = Int($g32Off * 1.39)
				If Abs($modOff - $g64Est) < 0x50000 Then
					$matchName &= " (near est. " & $globals32[$g][0] & ")"
				EndIf
			Next

			; Try reading as string to see if it points to chat data
			Local $testStr = _ReadWString($hProc, $hK32, $qval)
			Local $strInfo = ""
			If StringLen($testStr) > 2 And StringLen($testStr) < 100 Then
				$strInfo = " str='" & StringLeft($testStr, 30) & "'"
			EndIf

			If $globalCount < 200 Then
				_Out("  Module+0x" & Hex($modOff) & " -> 0x" & Hex($qval) & $matchName & $strInfo)
				$globalCount += 1
			EndIf
		EndIf
	Next
	_Out("")
	_Out("Found " & $globalCount & " valid pointers in data section near ADDRESS_BASE.")
EndIf
_Out("")
_Save()

; ==========================================
; STEP 6: SCAN FOR PATCH BYTE PATTERNS
; ==========================================
_Out("=== STEP 6: PATCH ADDRESS SCAN ===")
_Out("Searching for known patch byte values in code section...")
_Out("")

; FAST_FLY_PATCH: original value 886 (0x0376) as "short"
; SKIP_FLY_ANIMATION1: original 420 (0x01A4) as "dword"
; SKIP_FLY_ANIMATION2: original 1400 (0x0578) as "dword"
; BUILTIN_AUTOPOT: original 49202 (0xC032) as "short"

Local $patches[4][3] = [ _
	["ADDRESS_FAST_FLY_PATCH",       12107787, 886], _
	["ADDRESS_SKIP_FLY_ANIM1_PATCH", 12359795, 420], _
	["ADDRESS_SKIP_FLY_ANIM2_PATCH", 12359944, 1400], _
	["ADDRESS_BUILTIN_AUTOPOT",      12261100, 49202] _
]

For $p = 0 To 3
	Local $pName = $patches[$p][0]
	Local $pAddr32 = $patches[$p][1]
	Local $pOrigVal = $patches[$p][2]
	Local $pOff32 = $pAddr32 - $base32
	Local $pEstOff64 = Int($pOff32 * 1.39)

	_Out("--- " & $pName & " (original value: " & $pOrigVal & " / 0x" & Hex($pOrigVal) & ") ---")
	_Out("  32-bit offset: 0x" & Hex($pOff32) & ", estimated 64-bit: 0x" & Hex($pEstOff64))

	; Search ±0x200000 around estimated offset
	Local $pSearchStart = $pEstOff64 - 0x200000
	Local $pSearchEnd = $pEstOff64 + 0x200000
	If $pSearchStart < 0 Then $pSearchStart = 0
	If $pSearchEnd > $moduleSize Then $pSearchEnd = $moduleSize

	Local $pFound = 0
	Local $pChunkSz = 0x10000
	For $pChunkOff = $pSearchStart To $pSearchEnd Step $pChunkSz
		Local $pReadAmt = $pChunkSz
		If $pChunkOff + $pReadAmt > $pSearchEnd Then $pReadAmt = $pSearchEnd - $pChunkOff
		If $pReadAmt < 4 Then ContinueLoop

		Local $pChunkData = _ReadBytes($hProc, $hK32, $moduleBase + $pChunkOff, $pReadAmt)
		If @error Then ContinueLoop

		For $pi = 0 To $pReadAmt - 4 Step 2
			Local $pVal
			If $pOrigVal < 65536 Then
				$pVal = _BytesToWord($pChunkData, $pi)
			Else
				$pVal = _BytesToDword($pChunkData, $pi)
			EndIf
			If $pVal = $pOrigVal Then
				$pFound += 1
				Local $pAbsOff = $pChunkOff + $pi
				If $pFound <= 10 Then
					_Out("  Match at Module+0x" & Hex($pAbsOff) & " (dist from est: " & ($pAbsOff - $pEstOff64) & ")")
				EndIf
			EndIf
		Next
	Next
	_Out("  Total matches: " & $pFound)
	_Out("")
	_Save()
Next

; ==========================================
; STEP 7: CHECK STRUCT OFFSETS VIA LEVEL1 POINTER
; ==========================================
_Out("=== STEP 7: GAME MANAGER STRUCT EXPLORATION ===")
_Out("Exploring the level1 struct (game manager) for sub-pointers...")
_Out("")

; level1 = [ADDRESS_BASE] + 0x38
; In 32-bit, level1 had sub-pointers at offsets like +0x1C (28), +0x34 (52=PLAYER_OFFSET)
; In 64-bit, we know +0x38 and +0x68
; Let's dump the level1 struct to find other sub-pointers

_Out("Level1 (game manager) at 0x" & Hex($level1))
For $off = 0x00 To 0x200 Step 8
	Local $subPtr = _ReadQword($hProc, $hK32, $level1 + $off)
	If $subPtr <> 0 And $subPtr > 0x10000 Then
		Local $marker2 = ""
		If $off = 0x38 Then $marker2 = " <<< chain offset (leads to player)"
		If $off = 0x68 Then $marker2 = " <<< PLAYER_OFFSET"

		; Try to identify what this pointer leads to
		Local $subCheck = _ReadQword($hProc, $hK32, $subPtr)
		Local $subStr = _ReadWString($hProc, $hK32, $subPtr)
		Local $info = ""
		If StringLen($subStr) > 2 And StringLen($subStr) < 50 Then
			$info = " (str: '" & $subStr & "')"
		EndIf

		_Out("  +0x" & Hex($off, 4) & " = 0x" & Hex($subPtr) & $info & $marker2)
	EndIf
Next
_Out("")
_Save()

; ==========================================
; DONE
; ==========================================
_Out("==========================================")
_Out("SCAN COMPLETE")
_Out("Time: " & Round(TimerDiff($gStart) / 1000) & "s")
_Out("Results saved to: " & $outputFile)
_Out("==========================================")
_Save()

ClipPut($fullOutput)
MsgBox(64, "Done", "Scan complete!" & @CRLF & @CRLF & "Results saved to:" & @CRLF & $outputFile & @CRLF & @CRLF & "Also copied to clipboard." & @CRLF & "Paste the results to Claude for analysis.")

DllCall($hK32, "bool", "CloseHandle", "handle", $hProc)
DllClose($hK32)

; ============================================
; HELPER FUNCTIONS
; ============================================

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

Func _ReadBytes($hP, $hK, $iA, $iS)
	Local $buf = DllStructCreate("byte[" & $iS & "]")
	Local $r = DllCall($hK, "bool", "ReadProcessMemory", "handle", $hP, "ptr", $iA, "ptr", DllStructGetPtr($buf), "ulong_ptr", $iS, "ulong_ptr*", 0)
	If @error Or $r[0] = 0 Then Return SetError(1, 0, 0)
	Return DllStructGetData($buf, 1)
EndFunc

Func _ByteAt($bytes, $off)
	Return Number(BinaryMid($bytes, $off + 1, 1))
EndFunc

Func _BytesToDword($bytes, $iOff)
	Local $b1 = DllStructCreate("byte[4]")
	DllStructSetData($b1, 1, BinaryMid($bytes, $iOff + 1, 4))
	Local $b2 = DllStructCreate("dword", DllStructGetPtr($b1))
	Return DllStructGetData($b2, 1)
EndFunc

Func _BytesToWord($bytes, $iOff)
	Local $b1 = DllStructCreate("byte[2]")
	DllStructSetData($b1, 1, BinaryMid($bytes, $iOff + 1, 2))
	Local $b2 = DllStructCreate("word", DllStructGetPtr($b1))
	Return DllStructGetData($b2, 1)
EndFunc

Func _BytesToQword($bytes, $iOff)
	Local $b1 = DllStructCreate("byte[8]")
	DllStructSetData($b1, 1, BinaryMid($bytes, $iOff + 1, 8))
	Local $b2 = DllStructCreate("uint64", DllStructGetPtr($b1))
	Return DllStructGetData($b2, 1)
EndFunc

Func _BytesToFloat($bytes, $iOff)
	Local $b1 = DllStructCreate("byte[4]")
	DllStructSetData($b1, 1, BinaryMid($bytes, $iOff + 1, 4))
	Local $b2 = DllStructCreate("float", DllStructGetPtr($b1))
	Return DllStructGetData($b2, 1)
EndFunc

Func _GetModuleBase64($hProc, $hK32, $moduleName)
	Local $hPsapi2 = DllOpen("psapi.dll")
	If $hPsapi2 = -1 Then
		MsgBox(16, "Debug", "Failed to open psapi.dll")
		Return 0
	EndIf
	Local $modArray2 = DllStructCreate("ptr[1024]")
	Local $cbNeeded2 = DllStructCreate("dword")
	Local $enumResult = DllCall($hPsapi2, "bool", "EnumProcessModulesEx", _
		"handle", $hProc, "ptr", DllStructGetPtr($modArray2), _
		"dword", DllStructGetSize($modArray2), "ptr", DllStructGetPtr($cbNeeded2), "dword", 0x03)
	If @error Then
		MsgBox(16, "Debug", "EnumProcessModulesEx DllCall @error=" & @error)
		DllClose($hPsapi2)
		Return 0
	EndIf
	If $enumResult[0] = 0 Then
		Local $lastErr2 = DllCall("kernel32.dll", "dword", "GetLastError")
		MsgBox(16, "Debug", "EnumProcessModulesEx returned False. GetLastError=" & $lastErr2[0])
		DllClose($hPsapi2)
		Return 0
	EndIf
	Local $cbVal = DllStructGetData($cbNeeded2, 1)
	Local $ptrSize = DllStructGetSize(DllStructCreate("ptr"))
	Local $numMod2 = $cbVal / $ptrSize
	If $numMod2 > 1024 Then $numMod2 = 1024

	Local $moduleNames = "Modules found (" & $numMod2 & "):" & @CRLF
	For $i = 1 To $numMod2
		Local $hMod2 = DllStructGetData($modArray2, 1, $i)
		Local $nameBuf2 = DllStructCreate("wchar[260]")
		DllCall($hPsapi2, "dword", "GetModuleBaseNameW", _
			"handle", $hProc, "handle", $hMod2, _
			"ptr", DllStructGetPtr($nameBuf2), "dword", 260)
		Local $modName = DllStructGetData($nameBuf2, 1)
		If $i <= 10 Then $moduleNames &= "  " & $i & ": " & $modName & " (0x" & Hex($hMod2) & ")" & @CRLF
		If StringInStr($modName, $moduleName) Then
			MsgBox(64, "Debug", "Found module '" & $modName & "' at 0x" & Hex($hMod2))
			DllClose($hPsapi2)
			Return $hMod2
		EndIf
	Next
	MsgBox(16, "Debug", $moduleNames & @CRLF & "Did NOT find '" & $moduleName & "' in list!")
	DllClose($hPsapi2)
	Return 0
EndFunc

Func _EnableDebugPrivilege()
	Local $hAdvapi = DllOpen("advapi32.dll")
	Local $hToken = DllStructCreate("handle")
	DllCall($hAdvapi, "bool", "OpenProcessToken", "handle", DllCall("kernel32.dll", "handle", "GetCurrentProcess")[0], _
		"dword", 0x0028, "ptr", DllStructGetPtr($hToken))
	If @error Then
		DllClose($hAdvapi)
		Return
	EndIf
	Local $luid = DllStructCreate("dword LowPart; long HighPart")
	DllCall($hAdvapi, "bool", "LookupPrivilegeValueW", "ptr", 0, "wstr", "SeDebugPrivilege", "ptr", DllStructGetPtr($luid))
	Local $tp = DllStructCreate("dword Count; dword LowPart; long HighPart; dword Attributes")
	DllStructSetData($tp, "Count", 1)
	DllStructSetData($tp, "LowPart", DllStructGetData($luid, "LowPart"))
	DllStructSetData($tp, "HighPart", DllStructGetData($luid, "HighPart"))
	DllStructSetData($tp, "Attributes", 0x02)
	DllCall($hAdvapi, "bool", "AdjustTokenPrivileges", "handle", DllStructGetData($hToken, 1), _
		"bool", 0, "ptr", DllStructGetPtr($tp), "dword", 0, "ptr", 0, "ptr", 0)
	DllCall("kernel32.dll", "bool", "CloseHandle", "handle", DllStructGetData($hToken, 1))
	DllClose($hAdvapi)
EndFunc

Func _GetModuleBaseSnapshot($hK32, $PID, $moduleName)
	Local $hSnap = DllCall($hK32, "handle", "CreateToolhelp32Snapshot", "dword", 0x08, "dword", $PID)
	If @error Or $hSnap[0] = Ptr(-1) Then Return 0

	; MODULEENTRY32W struct for 64-bit
	Local $sStruct = "dword dwSize; dword th32ModuleID; dword th32ProcessID; dword GlcntUsage; " & _
		"ptr modBaseAddr; dword modBaseSize; handle hModule; wchar szModule[256]; wchar szExePath[260]"
	Local $me = DllStructCreate($sStruct)
	DllStructSetData($me, "dwSize", DllStructGetSize($me))

	Local $ret = DllCall($hK32, "bool", "Module32FirstW", "handle", $hSnap[0], "ptr", DllStructGetPtr($me))
	If @error Or $ret[0] = 0 Then
		DllCall($hK32, "bool", "CloseHandle", "handle", $hSnap[0])
		Return 0
	EndIf

	While 1
		Local $name = DllStructGetData($me, "szModule")
		If StringInStr($name, $moduleName) Then
			Local $base = DllStructGetData($me, "modBaseAddr")
			DllCall($hK32, "bool", "CloseHandle", "handle", $hSnap[0])
			Return $base
		EndIf
		DllStructSetData($me, "dwSize", DllStructGetSize($me))
		Local $next = DllCall($hK32, "bool", "Module32NextW", "handle", $hSnap[0], "ptr", DllStructGetPtr($me))
		If @error Or $next[0] = 0 Then ExitLoop
	WEnd

	DllCall($hK32, "bool", "CloseHandle", "handle", $hSnap[0])
	Return 0
EndFunc
