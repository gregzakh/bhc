using namespace System.Security.Cryptography

function Show-DBeaverPass {
  <#
    .SYNOPSIS
        Retrieves forgottent passwords from DBeaver credential store.
    .DESCRIPTION
        This script (function) is generally aimed at the Windows version of DBeaver, but it can be easily
        adapted for Linux, for example, by replacing $Credentials path with
                           ~/.local/share/DBeaverData/workspace6/General/.dbeaver/credentials-config.json
    .Parameter Credentials
        The file where DBeaver keeps credentials.
    .EXAMPLE
        Show-DBeaverPass
    .NOTES
        If you are on Linux, you can decode DBeaver credentials using OpenSSL as follows:
        openssl aes-128-cbc -d -K babb4a9f774ab853c96c2d653dfe544a -iv 00000000000000000000000000000000 \
                     -in ~/.local/share/DBeaverData/workspace6/General/.dbeaver/credentials-config.json |
                     cut -c 15- | yq -p=json
  #>
  [CmdletBinding()]
  param(
    [Parameter(HelpMessage='The file where DBeaver keeps credentials')]
    [ValidateNotNullOrEmpty()]
    [String]$Credentials = "$env:appdata\dbeaverdata\workspace6\general\.dbeaver\credentials-config.json"
  )

  begin {
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