rule Koh
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project."
        author = "Will Schroeder (@harmj0y)"
    strings:
        $typelibguid = "4d5350c8-7f8c-47cf-8cde-c752018af17e" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}