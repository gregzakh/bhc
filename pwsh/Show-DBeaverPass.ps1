using namespace System.Security.Cryptography

function Show-DBeaverPass {
  <#
    .SYNOPSIS
        Retrieves forgottent passwords from DBeaver credential store.
    .Parameter Credentials
        The file where DBeaver keeps credentials.
    .EXAMPLE
        Show-DBeaverPass
  #>
  [CmdletBinding()]
  param(
    [Parameter(HelpMessage='The file where DBeaver keeps credentials')]
    [String]$Credentials
  )

  begin {
    if ([String]::IsNullOrEmpty($Credentials)) {
      [String[]]$chunks = 'DBeaverData', 'workspace6', 'General', '.dbeaver', 'credentials-config.json'
      $chunks = ,($IsWindows ? $env:appdata : "$env:HOME/.local/share") + $chunks
      $Credentials = [IO.Path]::Combine($chunks)
    }
    
    if (!(Test-Path $Credentials)) {
      throw [IO.FileNotFoundException]::new("$Credentials not been found or missed")
    }

    $aes = [Aes]::Create()
    $aes.KeySize = 128
    $aes.Key = [Convert]::FromHexString('babb4a9f774ab853c96c2d653dfe544a')
    $aes.IV = [Byte[]]::new(16)
    # $aes.Mode = [CipherMode]::CBC
    # $aes.Padding = [PaddingMode]::PKCS7
    $dec = $aes.CreateDecryptor()
  }
  end {
    try {
      $result = ([Text.Encoding]::UTF8.GetString(
        $dec.TransformFinalBlock(($$ = [IO.File]::ReadAllBytes($Credentials)), 0, $$.Length)
      ) | Select-String -Pattern '\{".+').Matches.Value | ConvertFrom-Json

      $result.PSObject.Properties.ForEach{
        "Driver: {0}`nCreds:  {1}`n" -f $_.Name, $_.Value.'#connection'
      }
    }
    catch { Write-Verbose $_ }
    finally {
      ($dec, $aes).ForEach{ if ($_) { $_.Dispose() } }
    }
  }
}
