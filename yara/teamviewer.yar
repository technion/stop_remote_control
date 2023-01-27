import "pe"

rule Teamviewer {
   meta:
      description = "sources - file Teamviewer_x64.exe"
      reference = "https://github.com/technion/"
      date = "2023-01-27"
      hash1 = "91898ba4cfcb7a91f6502fb289e9c2a2009d4ec0945941ba81f5baac191555f7"
   strings:
      $x1 = "TeamViewer Germany GmbH1" ascii
      $s1 = "http://www.teamviewer.com 0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      (pe.version_info["CompanyName"] contains "TeamViewer" or 
      pe.imphash() == "b78ecf47c0a3e24a6f4af114e2d1f5de") and
      $x1 and 2 of them
}

