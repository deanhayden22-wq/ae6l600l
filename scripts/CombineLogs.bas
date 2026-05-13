' ============================================================================
' CombineLogs.bas - LibreOffice Basic macro
' Combines multiple log CSVs into one, renumbering the sample column
' continuously. First log's starting sample is preserved; every subsequent
' data row increments by 1 regardless of source-file boundaries.
'
' Install:
'   1. LibreOffice  Tools  Macros  Edit Macros
'   2. Under "My Macros & Dialogs" right-click a library (e.g. Standard)
'      and choose New Module. Name it CombineLogs.
'   3. Paste the contents of this file into the module.
'   4. Run "CombineLogs" (F5 from inside the sub).
'
' Behavior:
'   - Multi-select file picker for input CSVs (.csv).
'   - Files sorted by basename using natural (numeric-aware) order:
'       log0001 < log0002 < log0010 (not log1, log10, log2).
'   - First log: header copied as-is, first data row keeps its original
'     sample value (so if log0001 starts at 0, output starts at 0).
'   - Subsequent logs: header skipped, sample column rewritten as
'     prev_last + 1, prev_last + 2, ...
'   - Output is plain comma-separated text written via LB Basic Print.
' ============================================================================

Option Explicit

Sub CombineLogs
    Dim oFilePicker As Object
    Dim oFileSaver As Object
    Dim aFiles() As String
    Dim sOutUrl As String
    Dim iLog As Integer
    Dim iIn As Integer
    Dim iOut As Integer
    Dim sLine As String
    Dim sHeader As String
    Dim lCounter As Long
    Dim bFirstLog As Boolean
    Dim bFirstDataInLog1 As Boolean
    Dim iCommaPos As Integer
    Dim sRest As String
    Dim sFirstField As String

    ' --- Pick input CSVs ---
    oFilePicker = createUnoService("com.sun.star.ui.dialogs.FilePicker")
    oFilePicker.initialize(Array(com.sun.star.ui.dialogs.TemplateDescription.FILEOPEN_SIMPLE))
    oFilePicker.setMultiSelectionMode(True)
    oFilePicker.appendFilter("CSV files (*.csv)", "*.csv")
    oFilePicker.setTitle("Select log CSVs to combine")
    If oFilePicker.execute() <> 1 Then Exit Sub
    aFiles = oFilePicker.getFiles()
    If UBound(aFiles) < 0 Then
        MsgBox "No files selected."
        Exit Sub
    End If

    ' --- Natural sort by basename ---
    NaturalSortFileUrls(aFiles)

    ' --- Confirm order with user ---
    Dim sPreview As String
    Dim k As Integer
    sPreview = "Files will be combined in this order:" & Chr(10) & Chr(10)
    For k = LBound(aFiles) To UBound(aFiles)
        sPreview = sPreview & (k + 1) & ". " & GetBaseName(aFiles(k)) & Chr(10)
    Next k
    sPreview = sPreview & Chr(10) & "Continue?"
    If MsgBox(sPreview, 4 + 32, "Combine Logs") <> 6 Then Exit Sub

    ' --- Pick output path ---
    oFileSaver = createUnoService("com.sun.star.ui.dialogs.FilePicker")
    oFileSaver.initialize(Array(com.sun.star.ui.dialogs.TemplateDescription.FILESAVE_SIMPLE))
    oFileSaver.appendFilter("CSV files (*.csv)", "*.csv")
    oFileSaver.setTitle("Save combined CSV as...")
    oFileSaver.setDefaultName("combined.csv")
    If oFileSaver.execute() <> 1 Then Exit Sub
    sOutUrl = oFileSaver.getFiles()(0)

    ' --- Open output ---
    iOut = FreeFile
    Open ConvertFromURL(sOutUrl) For Output As #iOut

    bFirstLog = True
    lCounter = 0
    Dim lTotalRows As Long
    lTotalRows = 0

    For iLog = LBound(aFiles) To UBound(aFiles)
        iIn = FreeFile
        Open ConvertFromURL(aFiles(iLog)) For Input As #iIn

        ' Read header
        If Not EOF(iIn) Then
            Line Input #iIn, sHeader
            If bFirstLog Then
                Print #iOut, sHeader
            End If
        End If

        bFirstDataInLog1 = bFirstLog

        ' Read data rows
        Do While Not EOF(iIn)
            Line Input #iIn, sLine
            If Len(sLine) > 0 Then
                iCommaPos = InStr(sLine, ",")
                If iCommaPos = 0 Then
                    ' Pathological row (no comma) - pass through untouched
                    Print #iOut, sLine
                Else
                    sRest = Mid(sLine, iCommaPos) ' includes leading comma
                    If bFirstDataInLog1 Then
                        ' Preserve log1's first sample value verbatim
                        sFirstField = Trim(Left(sLine, iCommaPos - 1))
                        lCounter = CLng(sFirstField)
                        Print #iOut, CStr(lCounter) & sRest
                        bFirstDataInLog1 = False
                    Else
                        lCounter = lCounter + 1
                        Print #iOut, CStr(lCounter) & sRest
                    End If
                    lTotalRows = lTotalRows + 1
                End If
            End If
        Loop

        Close #iIn
        bFirstLog = False
    Next iLog

    Close #iOut

    MsgBox "Combined " & (UBound(aFiles) + 1) & " logs." & Chr(10) & _
           "Total data rows: " & lTotalRows & Chr(10) & _
           "Final sample number: " & lCounter & Chr(10) & Chr(10) & _
           "Output: " & ConvertFromURL(sOutUrl), _
           64, "Done"
End Sub

' ----------------------------------------------------------------------------
' Natural sort helpers
' ----------------------------------------------------------------------------

Sub NaturalSortFileUrls(ByRef arr() As String)
    ' Simple insertion sort - file lists are small (dozens, not thousands).
    Dim i As Integer, j As Integer
    Dim tmp As String
    For i = LBound(arr) + 1 To UBound(arr)
        tmp = arr(i)
        j = i - 1
        Do While j >= LBound(arr)
            If NaturalCompare(GetBaseName(arr(j)), GetBaseName(tmp)) > 0 Then
                arr(j + 1) = arr(j)
                j = j - 1
            Else
                Exit Do
            End If
        Loop
        arr(j + 1) = tmp
    Next i
End Sub

Function NaturalCompare(s1 As String, s2 As String) As Integer
    ' Compare two strings with numeric-aware ordering, case-insensitive.
    Dim a As String, b As String
    a = LCase(s1)
    b = LCase(s2)

    Dim i As Long, j As Long
    i = 1
    j = 1
    Do While i <= Len(a) And j <= Len(b)
        Dim ca As String, cb As String
        ca = Mid(a, i, 1)
        cb = Mid(b, j, 1)
        If IsDigitChar(ca) And IsDigitChar(cb) Then
            Dim na As String, nb As String
            na = ""
            nb = ""
            Do While i <= Len(a)
                If IsDigitChar(Mid(a, i, 1)) Then
                    na = na & Mid(a, i, 1)
                    i = i + 1
                Else
                    Exit Do
                End If
            Loop
            Do While j <= Len(b)
                If IsDigitChar(Mid(b, j, 1)) Then
                    nb = nb & Mid(b, j, 1)
                    j = j + 1
                Else
                    Exit Do
                End If
            Loop
            ' Strip leading zeros for numeric compare but keep length tiebreak
            Dim va As Double, vb As Double
            va = CDbl(na)
            vb = CDbl(nb)
            If va < vb Then
                NaturalCompare = -1
                Exit Function
            ElseIf va > vb Then
                NaturalCompare = 1
                Exit Function
            End If
            ' Same numeric value, prefer shorter representation (less zero padding)
            If Len(na) < Len(nb) Then
                NaturalCompare = -1
                Exit Function
            ElseIf Len(na) > Len(nb) Then
                NaturalCompare = 1
                Exit Function
            End If
        Else
            If ca < cb Then
                NaturalCompare = -1
                Exit Function
            ElseIf ca > cb Then
                NaturalCompare = 1
                Exit Function
            End If
            i = i + 1
            j = j + 1
        End If
    Loop
    If Len(a) - i < Len(b) - j Then
        NaturalCompare = -1
    ElseIf Len(a) - i > Len(b) - j Then
        NaturalCompare = 1
    Else
        NaturalCompare = 0
    End If
End Function

Function IsDigitChar(c As String) As Boolean
    IsDigitChar = (c >= "0" And c <= "9")
End Function

Function GetBaseName(sUrl As String) As String
    Dim sPath As String
    sPath = ConvertFromURL(sUrl)
    Dim p As Long
    p = LastIndexOfChar(sPath, "\")
    Dim q As Long
    q = LastIndexOfChar(sPath, "/")
    If q > p Then p = q
    If p = 0 Then
        GetBaseName = sPath
    Else
        GetBaseName = Mid(sPath, p + 1)
    End If
End Function

Function LastIndexOfChar(s As String, c As String) As Long
    ' Returns the 1-based position of the last occurrence of c in s,
    ' or 0 if not found. Replacement for VBA-only InStrRev so the macro
    ' works in stock LibreOffice Basic without Option VBASupport.
    Dim i As Long
    For i = Len(s) To 1 Step -1
        If Mid(s, i, 1) = c Then
            LastIndexOfChar = i
            Exit Function
        End If
    Next i
    LastIndexOfChar = 0
End Function
