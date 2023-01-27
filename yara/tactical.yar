/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-01-27
   Identifier: sources
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule tacticalagent_v2_4_4_windows_386 {
   meta:
      description = "sources - file tacticalagent-v2.4.4-windows-386.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-01-27"
      hash1 = "6bd8e820684a2fe378088c9595757a768b03012ba3aa03166e12be96c9e6b25b"
   strings:
      $s1 = "SystemphH" fullword ascii /* base64 encoded string 'K+-zja' */
      $s2 = "SetupLdr.exe" fullword ascii
      $s3 = "FHeaderProcessed" fullword ascii
      $s4 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide
      $s5 = "SystemlQC" fullword ascii /* base64 encoded string 'K+-ziP' */
      $s6 = "SystemtNH" fullword ascii /* base64 encoded string 'K+-zkM' */
      $s7 = "TComponent.GetObservers$ActRecL" fullword ascii
      $s8 = "TSetupProcessorArchitecture" fullword ascii
      $s9 = "SetupMutex" fullword ascii
      $s10 = "TComponent.GetObservers$1$Intf" fullword ascii
      $s11 = "TSetupProcessorArchitectures" fullword ascii
      $s12 = "TComponent.GetObservers$ActRec" fullword ascii
      $s13 = "TComponent.GetObservers$0$Intf" fullword ascii
      $s14 = "BTDictionary<System.string,System.TypInfo.PTypeInfo>.TKeyEnumerator$(D" fullword ascii
      $s15 = "AppMutex" fullword ascii
      $s16 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii
      $s17 = "Causes Setup to create a log file in the user's TEMP directory." fullword wide
      $s18 = " TList<System.Integer>.TEmptyFunc" fullword ascii
      $s19 = "[TList<System.Generics.Collections.TPair<System.Pointer,System.Rtti.TRttiObject>>.TEmptyFunc" fullword ascii
      $s20 = "TPropSet<System.Comp><" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      8 of them
}

rule tacticalagent_v2_4_4_windows_amd64 {
   meta:
      description = "sources - file tacticalagent-v2.4.4-windows-amd64.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-01-27"
      hash1 = "d9957033e0c39d8b6ff8153376b097a1090e5c60a2a4e6931741dc1a66fb5c5f"
   strings:
      $s1 = "SystemphH" fullword ascii /* base64 encoded string 'K+-zja' */
      $s2 = "SetupLdr.exe" fullword ascii
      $s3 = "FHeaderProcessed" fullword ascii
      $s4 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide
      $s5 = "SystemlQC" fullword ascii /* base64 encoded string 'K+-ziP' */
      $s6 = "SystemtNH" fullword ascii /* base64 encoded string 'K+-zkM' */
      $s7 = "TComponent.GetObservers$ActRecL" fullword ascii
      $s8 = "TSetupProcessorArchitecture" fullword ascii
      $s9 = "SetupMutex" fullword ascii
      $s10 = "TComponent.GetObservers$1$Intf" fullword ascii
      $s11 = "TSetupProcessorArchitectures" fullword ascii
      $s12 = "TComponent.GetObservers$ActRec" fullword ascii
      $s13 = "TComponent.GetObservers$0$Intf" fullword ascii
      $s14 = "BTDictionary<System.string,System.TypInfo.PTypeInfo>.TKeyEnumerator$(D" fullword ascii
      $s15 = "AppMutex" fullword ascii
      $s16 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii
      $s17 = "Causes Setup to create a log file in the user's TEMP directory." fullword wide
      $s18 = " TList<System.Integer>.TEmptyFunc" fullword ascii
      $s19 = "[TList<System.Generics.Collections.TPair<System.Pointer,System.Rtti.TRttiObject>>.TEmptyFunc" fullword ascii
      $s20 = "TPropSet<System.Comp><" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _tacticalagent_v2_4_4_windows_386_tacticalagent_v2_4_4_windows_amd64_0 {
   meta:
      description = "sources - from files tacticalagent-v2.4.4-windows-386.exe, tacticalagent-v2.4.4-windows-amd64.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-01-27"
      hash1 = "6bd8e820684a2fe378088c9595757a768b03012ba3aa03166e12be96c9e6b25b"
      hash2 = "d9957033e0c39d8b6ff8153376b097a1090e5c60a2a4e6931741dc1a66fb5c5f"
   strings:
      $s1 = "SystemphH" fullword ascii /* base64 encoded string 'K+-zja' */
      $s2 = "SetupLdr.exe" fullword ascii
      $s3 = "FHeaderProcessed" fullword ascii
      $s4 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide
      $s5 = "SystemlQC" fullword ascii /* base64 encoded string 'K+-ziP' */
      $s6 = "SystemtNH" fullword ascii /* base64 encoded string 'K+-zkM' */
      $s7 = "TComponent.GetObservers$ActRecL" fullword ascii
      $s8 = "TSetupProcessorArchitecture" fullword ascii
      $s9 = "SetupMutex" fullword ascii
      $s10 = "TComponent.GetObservers$1$Intf" fullword ascii
      $s11 = "TSetupProcessorArchitectures" fullword ascii
      $s12 = "TComponent.GetObservers$ActRec" fullword ascii
      $s13 = "TComponent.GetObservers$0$Intf" fullword ascii
      $s14 = "BTDictionary<System.string,System.TypInfo.PTypeInfo>.TKeyEnumerator$(D" fullword ascii
      $s15 = "AppMutex" fullword ascii
      $s16 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii
      $s17 = "Causes Setup to create a log file in the user's TEMP directory." fullword wide
      $s18 = " TList<System.Integer>.TEmptyFunc" fullword ascii
      $s19 = "[TList<System.Generics.Collections.TPair<System.Pointer,System.Rtti.TRttiObject>>.TEmptyFunc" fullword ascii
      $s20 = "TPropSet<System.Comp><" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

