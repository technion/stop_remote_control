rule AnyDesk7_1_8 {
   meta:
      description = "sources - file AnyDesk7.1.8.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-01-27"
      hash1 = "fc19f3275d02764cf249dc6fe8962e06b83a4f5769cc369bc4f77b90c567df18"
   strings:
      $x1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" pu" ascii
      $x2 = "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb" fullword ascii
      $s3 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" pu" ascii
      $s4 = "<assemblyIdentity version=\"7.1.8.0\" processorArchitecture=\"x86\" name=\"AnyDesk.AnyDesk.AnyDesk\" type=\"win32\" />" fullword ascii
      $s5 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii
      $s6 = "<description>AnyDesk screen sharing and remote control software.</description>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      1 of ($x*) and 3 of them
}

