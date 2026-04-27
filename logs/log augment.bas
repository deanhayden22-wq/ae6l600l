Sub InsertColumnsAndFormulas()

    Dim oDoc   As Object
    Dim oSheet As Object
    Dim oCols  As Object

    oDoc   = ThisComponent
    oSheet = oDoc.Sheets.getByIndex(0)
    oCols  = oSheet.getColumns()

    ' Raw layout (29 cols):
    ' A sample  B time  C wbo2  D AFR  E FFB  F EGT  G AFC  H AFL  I RPM
    ' J MPH  K Timing  L IAT  M MAF  N MAF(V)  O Accelerator  P Throttle
    ' Q RQTQ  R ATM(psi)  S MAP  T Trgt_Boost  U IAM  V CL/OL  W FLKC
    ' X FBKC  Y avcs  Z wgdc  AA tdi  AB Tdp  AC IPW

    ' Step 1: Append IDC after IPW at column AD (position 29). No insert.
    oSheet.getCellByPosition(29, 0).setString("IDC")
    oSheet.getCellByPosition(29, 1).setFormula("=AC2*I2/1200")

    ' Step 2: Insert "mrp" before Trgt_Boost (position 19 = T). MAP-ATM.
    oCols.insertByIndex(19, 1)
    oSheet.getCellByPosition(19, 0).setString("mrp")
    oSheet.getCellByPosition(19, 1).setFormula("=S2-R2")

    ' Step 3: Insert "load" before MPH (position 9 = J). MAF*60/RPM.
    oCols.insertByIndex(9, 1)
    oSheet.getCellByPosition(9, 0).setString("load")
    oSheet.getCellByPosition(9, 1).setFormula("=M2*60/I2")

    ' Step 4: Insert "correction" before RPM (position 8 = I).
    ' Quoted "" must be written as """" inside a Basic string literal,
    ' otherwise the trailing empty-string fallback gets dropped.
    oCols.insertByIndex(8, 1)
    oSheet.getCellByPosition(8, 0).setString("correction")
    oSheet.getCellByPosition(8, 1).setFormula("=IF(Y2=8,G2+H2,IF(Y2=10,(1-D2/C2)*100,""""))")

End Sub
