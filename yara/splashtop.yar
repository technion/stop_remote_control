rule Splashtop {
   meta:
      description = "sources - file AnyDesk7.1.8.exe"
      reference = "https://github.com/technion/"
      date = "2023-01-27"
      hash1 = "c89e888c89b15256e27118db183da98dd97c134db0065596090f772ebbd15a48"
   strings:
      $x1 = "Remote Streamer for Microsoft Windows." ascii
      $s1 = "d:\\slave\\workspace\\GIT_WIN_SRS_Formal\\Source\\irisserver\\Release\\SRUnPackFile.pdb" fullword ascii
      $s2 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
      $s3 = "st-v3-internal.api.splashtop.com" fullword ascii
      $s4 = "Splashtop StreamerProductName" fullword ascii
   condition:
      uint16(0) == 0x5a4d and
      $x1 and 3 of them
}

