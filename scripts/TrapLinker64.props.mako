<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ImportGroup Label="PropertySheets" />
  <PropertyGroup Label="UserMacros">
    <MSVC_LINKER_PATH>$(VC_ExecutablePath_x64)</MSVC_LINKER_PATH>
  </PropertyGroup>
  <PropertyGroup>
    <ExecutablePath>${SolutionDir}\${Configuration};$(VC_ExecutablePath_x64);$(WindowsSDK_ExecutablePath);$(VS_ExecutablePath);$(MSBuild_ExecutablePath);$(SystemRoot)\SysWow64;$(FxCopDir);$(PATH);</ExecutablePath>
    <LinkIncremental>false</LinkIncremental>
    <LibraryPath>$(SolutionDir)$(Platform)\$(Configuration);${SolutionDir}${Platform}\${Configuration};${SolutionDir}\TrappedMSVCLibs\x64;$(VC_LibraryPath_x64);$(WindowsSDK_LibraryPath_x64);$(NETFXKitsDir)Lib\um\x64</LibraryPath>
  </PropertyGroup>
<ItemDefinitionGroup>
    <ClCompile>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <WholeProgramOptimization>false</WholeProgramOptimization>
    </ClCompile>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup>
    <Link>
      <LinkTimeCodeGeneration>Default</LinkTimeCodeGeneration>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <BuildMacro Include="MSVC_LINKER_PATH">
      <Value>$(MSVC_LINKER_PATH)</Value>
      <EnvironmentVariable>true</EnvironmentVariable>
    </BuildMacro>
  </ItemGroup>
</Project>
