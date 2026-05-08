Output ../../docs/demo.gif

Set FontSize 16
Set Width 1200
Set Height 600
Set Theme "Dracula"
Set Padding 12

Type "aegis snapshot save"
Enter
Sleep 1.5s

Type "aegis snapshot enrich"
Enter
Sleep 3s

Type "aegis ci --fail-on=block"
Enter
Sleep 2s
