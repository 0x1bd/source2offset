package org.kvxd.source2offset.engine

internal val LINUX_GLOBAL_OFFSET_RULES = listOf(
    GlobalRule(
        "dwGlobalVars", "libclient.so",
        "8D ?? ?? ?? ?? ?? 48 89 35 ?? ?? ?? ?? 48 89 ?? ?? C3",
        "pointer_slot_rva", Extraction.RipRelative(9),
    ),
    GlobalRule(
        "dwWorldToProjectionMatrix", "libclient.so",
        "01 4C 8D 05 ?? ?? ?? ?? 4C 89 EE",
        "direct_address_rva", Extraction.RipRelative(4),
    ),
    GlobalRule(
        "dwViewMatrix", "libclient.so",
        "01 4C 8D 05 ?? ?? ?? ?? 4C 89 EE",
        "direct_address_rva", Extraction.RipRelative(4),
    ),
    GlobalRule(
        "dwViewToProjectionMatrix", "libclient.so",
        "EE 48 8D 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48",
        "direct_address_rva", Extraction.RipRelative(4),
    ),
    GlobalRule(
        "dwViewRender", "libclient.so",
        "48 8D 05 ?? ?? ?? ?? 48 89 38 48 85",
        "pointer_slot_rva", Extraction.RipRelative(3),
    ),
    GlobalRule(
        "dwLocalPlayerController", "libclient.so",
        "48 83 3D ?? ?? ?? ?? ?? 0F 95 C0 C3",
        "pointer_slot_rva", Extraction.RipRelative(3, 5),
    ),
    GlobalRule(
        "dwGameEntitySystem", "libclient.so",
        "4C 63 ?? ?? ?? ?? ?? 48 89 1D ?? ?? ?? ??",
        "pointer_slot_rva", Extraction.RipRelative(10),
    ),
    GlobalRule(
        "dwGameRules", "libclient.so",
        "FF 53 ?? 48 83 3D ?? ?? ?? ?? 00 74",
        "pointer_slot_rva", Extraction.RipRelative(6, 5),
    ),
    GlobalRule(
        "dwPlantedC4s", "libclient.so",
        "80 BF ?? ?? ?? ?? 00 0F 84 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 8B 10",
        "direct_address_rva", Extraction.RipRelative(16),
    ),
    GlobalRule(
        name = "dwCSGOInput",
        moduleName = "libclient.so",
        pattern =
            "4C 8D 3D ?? ?? ?? ?? " +        // LEA R15,[g_CCSGOInput]
                    "E8 ?? ?? ?? ?? " +       // CALL FUN_01ad5da0
                    "48 89 C7 " +             // MOV RDI,RAX
                    "48 85 C0 " +             // TEST RAX,RAX
                    "0F 84 ?? ?? ?? ?? " +    // JZ ...
                    "48 8B 00 " +             // MOV RAX,[RAX]
                    "FF 50 08 " +             // CALL [RAX + 0x8]
                    "BA 01 00 00 00 " +       // MOV EDX,1
                    "84 C0 " +                // TEST AL,AL
                    "0F 84 ?? ?? ?? ??",      // JZ ...
        access = "direct_address_rva",
        extraction = Extraction.RipRelative(3),
    ),
    GlobalRule(
        name = "sdlKeyboardFocus",
        moduleName = "libSDL3.so.0",
        pattern =
            "48 83 3D ?? ?? ?? ?? 00 " + // CMP qword ptr [video_device],0
                    "74 ?? " +
                    "53 " +
                    "89 FB " +
                    "40 84 FF " +
                    "74 ?? " +
                    "E8 ?? ?? ?? ?? " +    // CALL SDL_GetKeyboardFocus implementation
                    "48 85 C0 " +
                    "74 ?? " +
                    "88 1D ?? ?? ?? ?? " +
                    "31 FF " +
                    "5B " +
                    "E9",
        access = "pointer_slot_rva",
        extraction = Extraction.CallTargetRipRelative(
            callDisplacementOffset = 19,
            targetDisplacementOffset = 3,
        ),
    ),
)

internal val LINUX_MEMBER_OFFSET_RULES = listOf(
    MemberRule(
        "CGameEntitySystem_m_EntityList", "libclient.so",
        "4C 8D 6F ?? 41 54 53 48 89 FB 48 83 EC ?? 48 89 07 48",
        Extraction.I8(3),
    ),
    MemberRule(
        "CGameEntitySystem_m_EntityClasses", "libclient.so",
        "49 8B 8F ?? ?? ?? ?? 0F B7",
        Extraction.I32(3),
    ),
)
