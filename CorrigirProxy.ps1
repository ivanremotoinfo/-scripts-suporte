# CorrigirProxy.ps1
# Detecta e corrige problemas de proxy e certificados de rede

$ErrorActionPreference = 'Continue'

# -------------------------------------------------------------------------
# Funcoes auxiliares
# -------------------------------------------------------------------------

function Write-Etapa { param([string]$t) Write-Host "`n>> $t" -ForegroundColor Cyan }
function Write-Ok    { param([string]$t) Write-Host '   [OK] ' -ForegroundColor Green  -NoNewline; Write-Host $t }
function Write-Aviso { param([string]$t) Write-Host '   [!]  ' -ForegroundColor Yellow -NoNewline; Write-Host $t }
function Write-Falha { param([string]$t) Write-Host '   [X]  ' -ForegroundColor Red    -NoNewline; Write-Host $t }
function Write-Info  { param([string]$t) Write-Host "   $t" -ForegroundColor Gray }
function Write-Dest  { param([string]$t) Write-Host "   $t" -ForegroundColor White }
function Write-Acao  { param([string]$t) Write-Host '   [>>] ' -ForegroundColor Magenta -NoNewline; Write-Host $t }

function Garantir-Chave {
    param([string]$Caminho)
    if (-not (Test-Path $Caminho)) {
        New-Item -Path $Caminho -Force | Out-Null
    }
}

function Definir-DWORD {
    param([string]$Caminho, [string]$Nome, [int]$Valor)
    Garantir-Chave $Caminho
    Set-ItemProperty -Path $Caminho -Name $Nome -Value $Valor -Type DWord -Force
}

# =========================================================================
# Cabecalho
# =========================================================================

Write-Host ''
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host '   Corrigir Proxy e Certificados de Rede              ' -ForegroundColor Cyan
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host ("   Iniciado em : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host ''

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Falha 'Este script requer privilegios de Administrador.'
    Write-Info  'Execute o PowerShell como Administrador e tente novamente.'
    exit 1
}
Write-Ok 'Executando como Administrador.'

# Rastrear acoes realizadas para o relatorio final
$acoesRealizadas  = [System.Collections.Generic.List[string]]::new()
$problemaEncontrado = $false

# =========================================================================
# ETAPA 1 - Verificar configuracoes de proxy atuais
# =========================================================================

Write-Etapa '1/9  Verificando configuracoes de proxy atuais...'
Write-Host ''

$regProxy = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

$proxyAtivo      = (Get-ItemProperty -Path $regProxy -Name 'ProxyEnable'    -ErrorAction SilentlyContinue).ProxyEnable
$proxyServidor   = (Get-ItemProperty -Path $regProxy -Name 'ProxyServer'    -ErrorAction SilentlyContinue).ProxyServer
$proxyExcecoes   = (Get-ItemProperty -Path $regProxy -Name 'ProxyOverride'  -ErrorAction SilentlyContinue).ProxyOverride
$proxyAutoConfig = (Get-ItemProperty -Path $regProxy -Name 'AutoConfigURL'  -ErrorAction SilentlyContinue).AutoConfigURL

$proxyHKLM       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
$proxyAtivoSist  = (Get-ItemProperty -Path $proxyHKLM -Name 'ProxyEnable'   -ErrorAction SilentlyContinue).ProxyEnable
$proxyServSist   = (Get-ItemProperty -Path $proxyHKLM -Name 'ProxyServer'   -ErrorAction SilentlyContinue).ProxyServer

Write-Dest '   --- Proxy do usuario (HKCU) ---'
if ($proxyAtivo -eq 1) {
    Write-Aviso 'Proxy do usuario: ATIVO'
    $problemaEncontrado = $true
    if ($proxyServidor) { Write-Dest ("   Servidor    : " + $proxyServidor) }
    if ($proxyExcecoes) { Write-Dest ("   Excecoes    : " + $proxyExcecoes) }
} else {
    Write-Ok 'Proxy do usuario: inativo.'
}
if ($proxyAutoConfig) {
    Write-Aviso 'Auto-config (PAC) configurado: ' + $proxyAutoConfig
    $problemaEncontrado = $true
}

Write-Host ''
Write-Dest '   --- Proxy do sistema (HKLM) ---'
if ($proxyAtivoSist -eq 1) {
    Write-Aviso 'Proxy do sistema: ATIVO'
    $problemaEncontrado = $true
    if ($proxyServSist) { Write-Dest ("   Servidor    : " + $proxyServSist) }
} else {
    Write-Ok 'Proxy do sistema: inativo.'
}

# Proxy WinHTTP
Write-Host ''
Write-Dest '   --- Proxy WinHTTP (netsh) ---'
$winHttpProxy = netsh winhttp show proxy 2>$null
if ($winHttpProxy) {
    $linhaProxy = $winHttpProxy | Where-Object { $_ -match 'Servidor Proxy|Proxy Server|Direct Access' }
    foreach ($linha in $linhaProxy) {
        $textoLinha = $linha.Trim()
        if ($textoLinha -match 'Direct Access|Acesso direto') {
            Write-Ok "WinHTTP: $textoLinha"
        } else {
            Write-Aviso "WinHTTP: $textoLinha"
            $problemaEncontrado = $true
        }
    }
    if (-not $linhaProxy) {
        $winHttpProxy | Where-Object { $_.Trim() } | ForEach-Object { Write-Info $_.Trim() }
    }
}

# =========================================================================
# ETAPA 2 - Perguntar se deseja limpar configuracoes de proxy
# =========================================================================

Write-Etapa '2/9  Limpeza das configuracoes de proxy...'
Write-Host ''

$limparProxy = $false
if ($proxyAtivo -eq 1 -or $proxyAutoConfig -or $proxyAtivoSist -eq 1) {
    Write-Aviso 'Proxy ativo detectado. Recomenda-se limpar para restaurar acesso direto.'
    Write-Host ''
    $resp = Read-Host '   Deseja limpar as configuracoes de proxy? (S/N)'
    if ($resp -match '^[Ss]') {
        $limparProxy = $true
    } else {
        Write-Info 'Limpeza de proxy ignorada pelo usuario.'
    }
} else {
    Write-Ok 'Nenhum proxy ativo. Etapa ignorada.'
    $resp2 = Read-Host '   Deseja limpar/resetar o proxy mesmo assim (preventivo)? (S/N)'
    if ($resp2 -match '^[Ss]') { $limparProxy = $true }
}

if ($limparProxy) {
    Write-Host ''
    Write-Acao 'Limpando ProxyEnable no registro do usuario (HKCU)...'
    Set-ItemProperty -Path $regProxy -Name 'ProxyEnable' -Value 0 -Type DWord -Force
    Remove-ItemProperty -Path $regProxy -Name 'ProxyServer'    -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $regProxy -Name 'ProxyOverride'  -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $regProxy -Name 'AutoConfigURL'  -ErrorAction SilentlyContinue
    Write-Ok 'Proxy do usuario (HKCU) limpo.'
    $acoesRealizadas.Add('Proxy do usuario (HKCU) desativado e limpo')

    Write-Acao 'Limpando proxy no registro do sistema (HKLM)...'
    Set-ItemProperty -Path $proxyHKLM -Name 'ProxyEnable' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $proxyHKLM -Name 'ProxyServer'   -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $proxyHKLM -Name 'AutoConfigURL' -ErrorAction SilentlyContinue
    Write-Ok 'Proxy do sistema (HKLM) limpo.'
    $acoesRealizadas.Add('Proxy do sistema (HKLM) desativado e limpo')

    Write-Acao 'Resetando proxy WinHTTP para acesso direto...'
    netsh winhttp reset proxy | Out-Null
    Write-Ok 'WinHTTP resetado para acesso direto.'
    $acoesRealizadas.Add('Proxy WinHTTP resetado para acesso direto (netsh)')

    # Notificar o sistema sobre mudanca de proxy (equivalente a clicar OK nas configuracoes de IE)
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class WinInet {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int lpdwBufferLength);
    public const int INTERNET_OPTION_SETTINGS_CHANGED   = 39;
    public const int INTERNET_OPTION_REFRESH            = 37;
}
'@ -ErrorAction SilentlyContinue
        [WinInet]::InternetSetOption([IntPtr]::Zero, [WinInet]::INTERNET_OPTION_SETTINGS_CHANGED, [IntPtr]::Zero, 0) | Out-Null
        [WinInet]::InternetSetOption([IntPtr]::Zero, [WinInet]::INTERNET_OPTION_REFRESH, [IntPtr]::Zero, 0) | Out-Null
        Write-Ok 'Notificacao de alteracao de proxy enviada ao sistema.'
    } catch {}
}

# =========================================================================
# ETAPA 3 - Habilitar TLS 1.0, TLS 1.1, TLS 1.2 e TLS 1.3
# =========================================================================

Write-Etapa '3/9  Verificando e habilitando protocolos TLS...'
Write-Host ''

$baseSchannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

$buildNum = $null
try {
    $buildNum = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).CurrentBuildNumber
} catch {}

$protocolos = @(
    @{ Nome = 'TLS 1.0'; Chave = 'TLS 1.0';  Habilitar = $true  }
    @{ Nome = 'TLS 1.1'; Chave = 'TLS 1.1';  Habilitar = $true  }
    @{ Nome = 'TLS 1.2'; Chave = 'TLS 1.2';  Habilitar = $true  }
    @{ Nome = 'TLS 1.3'; Chave = 'TLS 1.3';  Habilitar = ($buildNum -ge 18362) }
)

foreach ($proto in $protocolos) {
    $caminho    = $baseSchannel + '\' + $proto.Chave
    $caminhoCliente  = $caminho + '\Client'
    $caminhoServidor = $caminho + '\Server'

    $clienteEnabled  = (Get-ItemProperty -Path $caminhoCliente  -Name 'Enabled'          -ErrorAction SilentlyContinue).Enabled
    $clienteDisabled = (Get-ItemProperty -Path $caminhoCliente  -Name 'DisabledByDefault' -ErrorAction SilentlyContinue).DisabledByDefault
    $servidorEnabled = (Get-ItemProperty -Path $caminhoServidor -Name 'Enabled'          -ErrorAction SilentlyContinue).Enabled

    $jaAtivo = ($clienteEnabled -eq 1 -and $clienteDisabled -eq 0 -and $servidorEnabled -eq 1)

    if (-not $proto.Habilitar) {
        Write-Info "$($proto.Nome): nao aplicavel nesta versao do Windows (build $buildNum). Ignorado."
        continue
    }

    if ($jaAtivo) {
        Write-Ok "$($proto.Nome): ja habilitado."
    } else {
        Write-Acao "Habilitando $($proto.Nome)..."
        Definir-DWORD -Caminho $caminhoCliente  -Nome 'Enabled'          -Valor 1
        Definir-DWORD -Caminho $caminhoCliente  -Nome 'DisabledByDefault' -Valor 0
        Definir-DWORD -Caminho $caminhoServidor -Nome 'Enabled'          -Valor 1
        Definir-DWORD -Caminho $caminhoServidor -Nome 'DisabledByDefault' -Valor 0
        Write-Ok "$($proto.Nome): habilitado com sucesso."
        $acoesRealizadas.Add("$($proto.Nome) habilitado no SCHANNEL (cliente e servidor)")
    }
}

# .NET Framework - habilitar TLS forte para aplicacoes Java/juridicas
Write-Host ''
Write-Dest '   --- .NET Framework (SchUseStrongCrypto) ---'
$dotNetCaminhos = @(
    'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727'
)
foreach ($dotNetCaminho in $dotNetCaminhos) {
    $valor = (Get-ItemProperty -Path $dotNetCaminho -Name 'SchUseStrongCrypto' -ErrorAction SilentlyContinue).SchUseStrongCrypto
    $versao = Split-Path $dotNetCaminho -Leaf
    if ($valor -eq 1) {
        Write-Ok "SchUseStrongCrypto OK: $versao"
    } else {
        Definir-DWORD -Caminho $dotNetCaminho -Nome 'SchUseStrongCrypto' -Valor 1
        Write-Ok "SchUseStrongCrypto habilitado: $versao"
        $acoesRealizadas.Add("SchUseStrongCrypto habilitado para .NET $versao")
    }
}

# =========================================================================
# ETAPA 4 - Atualizar certificados raiz via Windows Update
# =========================================================================

Write-Etapa '4/9  Atualizando certificados raiz do Windows...'
Write-Host ''

$sstTemp = "$env:TEMP\roots_wu.sst"
if (Test-Path $sstTemp) { Remove-Item $sstTemp -Force -ErrorAction SilentlyContinue }

Write-Acao 'Baixando certificados raiz do Windows Update (certutil -generateSSTFromWU)...'
Write-Info 'Isso pode levar alguns segundos. Requer acesso a internet.'

$saida = certutil -generateSSTFromWU $sstTemp 2>&1
$sucesso = Test-Path $sstTemp

if ($sucesso) {
    Write-Ok 'Arquivo SST baixado com sucesso.'
    Write-Acao 'Importando certificados raiz para a loja do sistema...'
    $saidaImport = certutil -addstore -f root $sstTemp 2>&1
    $errosImport = $saidaImport | Where-Object { $_ -match 'Erro|Error|FAILED' }
    if ($errosImport) {
        Write-Aviso 'Alguns certificados nao puderam ser importados (normal para certificados ja existentes).'
    } else {
        Write-Ok 'Certificados raiz importados com sucesso.'
        $acoesRealizadas.Add('Certificados raiz atualizados via Windows Update (certutil)')
    }
    Remove-Item $sstTemp -Force -ErrorAction SilentlyContinue
} else {
    Write-Aviso 'Nao foi possivel baixar certificados do Windows Update.'
    Write-Info  'Verifique a conexao com a internet e tente novamente manualmente:'
    Write-Info  '  certutil -generateSSTFromWU %TEMP%\roots.sst'
    Write-Info  '  certutil -addstore -f root %TEMP%\roots.sst'
}

# Sincronizar via mecanismo automatico do Windows (authroot.stl)
Write-Acao 'Sinalizando o sistema para resincronizar a lista de certificados confiados...'
try {
    certutil -setreg chain\ChainCacheResyncFiletime '@now' 2>&1 | Out-Null
    Write-Ok 'Cache de cadeia de certificados sinalizado para resincronizacao.'
    $acoesRealizadas.Add('Cache de cadeia de certificados marcado para resincronizacao (certutil)')
} catch {
    Write-Info 'Resincronizacao de cache nao disponivel (opcional).'
}

# =========================================================================
# ETAPA 5 - Limpar cache SSL do Windows
# =========================================================================

Write-Etapa '5/9  Limpando cache SSL do Windows...'
Write-Host ''

# Limpar cache de URL do certutil (OCSP, CRL, AIA)
Write-Acao 'Limpando cache de URL do certutil (OCSP/CRL)...'
certutil -urlcache * delete 2>&1 | Out-Null
Write-Ok 'Cache de URL do certutil limpo.'
$acoesRealizadas.Add('Cache de URL do certutil (OCSP/CRL) limpo')

# Limpar cache CryptNetUrlCache
$cryptCache = "$env:LocalAppData\Microsoft\Windows\INetCache"
if (Test-Path $cryptCache) {
    $arquivosCrypt = @(Get-ChildItem -Path $cryptCache -Recurse -File -ErrorAction SilentlyContinue)
    if ($arquivosCrypt.Count -gt 0) {
        Write-Acao "Limpando $($arquivosCrypt.Count) arquivo(s) do cache INetCache..."
        Remove-Item -Path "$cryptCache\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok 'Cache INetCache limpo.'
        $acoesRealizadas.Add("Cache INetCache limpo ($($arquivosCrypt.Count) arquivos removidos)")
    } else {
        Write-Ok 'Cache INetCache ja estava vazio.'
    }
}

# Limpar estado SSL do IE/Edge (via rundll32)
Write-Acao 'Limpando estado SSL do Internet Explorer/Edge...'
try {
    $proc = Start-Process -FilePath 'rundll32.exe' -ArgumentList 'InetCpl.cpl,ClearMyTracksByProcess 8' -Wait -PassThru -WindowStyle Hidden
    Write-Ok 'Estado SSL do IE/Edge limpo.'
    $acoesRealizadas.Add('Estado SSL do Internet Explorer/Edge limpo via InetCpl')
} catch {
    Write-Aviso 'Nao foi possivel limpar estado SSL via InetCpl.'
}

# =========================================================================
# ETAPA 6 - Verificar certificados expirados ou invalidos
# =========================================================================

Write-Etapa '6/9  Verificando certificados na loja do usuario...'
Write-Host ''

$StoreName     = [System.Security.Cryptography.X509Certificates.StoreName]
$StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]
$OpenFlags     = [System.Security.Cryptography.X509Certificates.OpenFlags]

$hoje             = Get-Date
$certExpirados    = [System.Collections.Generic.List[PSObject]]::new()
$certQuaseExpir   = [System.Collections.Generic.List[PSObject]]::new()

$lojas = @(
    @{ Nome = 'Pessoal (My)';       Loja = $StoreName::My;       Local = $StoreLocation::CurrentUser  }
    @{ Nome = 'Raiz confiavel';     Loja = $StoreName::Root;     Local = $StoreLocation::CurrentUser  }
    @{ Nome = 'Autoridades interm.'; Loja = $StoreName::CertificationAuthority; Local = $StoreLocation::CurrentUser }
    @{ Nome = 'Raiz (sistema)';     Loja = $StoreName::Root;     Local = $StoreLocation::LocalMachine }
)

foreach ($entrada in $lojas) {
    $loja = [System.Security.Cryptography.X509Certificates.X509Store]::new($entrada.Loja, $entrada.Local)
    try {
        $loja.Open($OpenFlags::ReadOnly)
        $certs = $loja.Certificates

        $expiradosLoja  = @($certs | Where-Object { $_.NotAfter -lt $hoje })
        $quaseExpLoja   = @($certs | Where-Object { $_.NotAfter -ge $hoje -and $_.NotAfter -lt $hoje.AddDays(30) })

        if ($expiradosLoja.Count -gt 0 -or $quaseExpLoja.Count -gt 0) {
            Write-Aviso ("Loja '$($entrada.Nome)': $($expiradosLoja.Count) expirado(s), $($quaseExpLoja.Count) a expirar em 30 dias.")
            foreach ($c in $expiradosLoja) { $certExpirados.Add([PSCustomObject]@{ Loja = $entrada.Nome; Assunto = $c.Subject; Expirou = $c.NotAfter }) }
            foreach ($c in $quaseExpLoja)  { $certQuaseExpir.Add([PSCustomObject]@{ Loja = $entrada.Nome; Assunto = $c.Subject; Expira  = $c.NotAfter }) }
        } else {
            Write-Ok ("Loja '$($entrada.Nome)': $($certs.Count) certificado(s), nenhum expirado.")
        }
        $loja.Close()
    } catch {
        Write-Info ("Nao foi possivel abrir loja '$($entrada.Nome)': " + $_.Exception.Message)
    }
}

if ($certExpirados.Count -gt 0) {
    Write-Host ''
    Write-Aviso "Certificados EXPIRADOS encontrados ($($certExpirados.Count)):"
    foreach ($c in ($certExpirados | Select-Object -First 10)) {
        $assuntoResumido = if ($c.Assunto.Length -gt 70) { $c.Assunto.Substring(0, 67) + '...' } else { $c.Assunto }
        Write-Dest ("   [" + $c.Expirou.ToString('dd/MM/yyyy') + "]  " + $assuntoResumido)
    }
    Write-Info  'Certificados pessoais expirados podem ser removidos via: certmgr.msc'
    $problemaEncontrado = $true
}

if ($certQuaseExpir.Count -gt 0) {
    Write-Host ''
    Write-Info "Certificados proximos do vencimento ($($certQuaseExpir.Count)):"
    foreach ($c in $certQuaseExpir) {
        Write-Dest ("   [expira " + $c.Expira.ToString('dd/MM/yyyy') + "]  " + ($c.Assunto -replace 'CN=',''))
    }
}

# =========================================================================
# ETAPA 7 - Resetar configuracoes de proxy do IE/Edge no registro
# =========================================================================

Write-Etapa '7/9  Resetando configuracoes de proxy do IE/Edge (registro e WinHTTP)...'
Write-Host ''

# Limpar ConnectionSettings binario do IE (proxy por conexao)
$regConexoes = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
$defaultConn = (Get-ItemProperty -Path $regConexoes -Name 'DefaultConnectionSettings' -ErrorAction SilentlyContinue).DefaultConnectionSettings

if ($defaultConn) {
    # Byte 8 (indice 8) contem flags de proxy: bit 2 = proxy ativo (valor 2 ou 3 = proxy ativo, 1 = direto)
    # Forcar para acesso direto definindo o byte de flags como 1
    $bytesConn = [byte[]]$defaultConn
    if ($bytesConn.Count -ge 9) {
        $flagAtual = $bytesConn[8]
        if (($flagAtual -band 2) -ne 0) {
            Write-Acao 'Limpando configuracao de proxy por conexao (DefaultConnectionSettings)...'
            $bytesConn[8] = ($flagAtual -band 0xFD) -bor 1  # Desativa bit de proxy, ativa bit direto
            Set-ItemProperty -Path $regConexoes -Name 'DefaultConnectionSettings' -Value $bytesConn -Force
            Write-Ok 'DefaultConnectionSettings atualizado para acesso direto.'
            $acoesRealizadas.Add('DefaultConnectionSettings do IE/Edge resetado para acesso direto')
        } else {
            Write-Ok 'DefaultConnectionSettings ja configurado sem proxy ativo.'
        }
    }
}

# Garantir que WinHTTP esta sincronizado com as configuracoes do IE
Write-Acao 'Verificando sincronizacao WinHTTP com configuracoes do IE/Edge...'
$winHttpAtual = netsh winhttp show proxy 2>$null
$temProxyWinHttp = $winHttpAtual | Where-Object { $_ -match ':\d+' }

if ($temProxyWinHttp) {
    Write-Acao 'Importando configuracoes de proxy do IE para WinHTTP...'
    netsh winhttp import proxy source=ie 2>&1 | Out-Null
    Write-Ok 'WinHTTP sincronizado com as configuracoes do IE.'
    $acoesRealizadas.Add('WinHTTP sincronizado com configuracoes do IE/Edge')
} else {
    Write-Ok 'WinHTTP ja esta com acesso direto. Nenhuma acao necessaria.'
}

# Certificar que o servico WinHTTP Web Proxy Auto-Discovery esta funcionando
$wpadService = Get-Service -Name 'WinHttpAutoProxySvc' -ErrorAction SilentlyContinue
if ($wpadService) {
    if ($wpadService.Status -ne 'Running') {
        Write-Acao 'Iniciando servico WinHTTP Web Proxy Auto-Discovery...'
        try {
            Set-Service -Name 'WinHttpAutoProxySvc' -StartupType Manual -ErrorAction SilentlyContinue
            Start-Service -Name 'WinHttpAutoProxySvc' -ErrorAction SilentlyContinue
            Write-Ok 'Servico WinHTTP Auto-Discovery iniciado.'
            $acoesRealizadas.Add('Servico WinHTTP Web Proxy Auto-Discovery iniciado')
        } catch {
            Write-Info 'Servico WinHTTP Auto-Discovery nao pode ser iniciado (normal se proxy nao for usado).'
        }
    } else {
        Write-Ok 'Servico WinHTTP Auto-Discovery: em execucao.'
    }
}

# =========================================================================
# ETAPA 8 - Testar conectividade com sites juridicos
# =========================================================================

Write-Etapa '8/9  Testando conectividade com sistemas juridicos...'
Write-Host ''

$sitesJuridicos = @(
    @{ URL = 'https://pje.jus.br';                Nome = 'PJe Nacional'    }
    @{ URL = 'https://projudi.tjgo.jus.br';        Nome = 'PROJUDI TJGO'   }
    @{ URL = 'https://eproc.jfrs.jus.br';          Nome = 'eProc JFRS'     }
)

$resultadosConect = [System.Collections.Generic.List[PSObject]]::new()

# Garantir que o processo atual usa TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = (
    [Net.SecurityProtocolType]::Tls12 -bor
    [Net.SecurityProtocolType]::Tls11 -bor
    [Net.SecurityProtocolType]::Tls
)

foreach ($site in $sitesJuridicos) {
    $url  = $site.URL
    $nome = $site.Nome
    Write-Info "Testando $nome ($url)..."

    $status   = 'FALHA'
    $detalhe  = ''
    $corItem  = 'Red'
    $httpCode = $null

    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Timeout          = 12000
        $req.AllowAutoRedirect = $true
        $req.UserAgent        = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120'
        $resp = $req.GetResponse()
        $httpCode = [int]$resp.StatusCode
        $resp.Close()
        $status  = 'OK'
        $detalhe = "HTTP $httpCode"
        $corItem = 'Green'
    } catch [System.Net.WebException] {
        $webEx = $_.Exception
        if ($webEx.Response) {
            $httpCode = [int]$webEx.Response.StatusCode
            # Resposta HTTP recebida = servidor acessivel, mesmo com erro de autenticacao
            if ($httpCode -ge 200) {
                $status  = 'OK'
                $detalhe = "HTTP $httpCode (site acessivel)"
                $corItem = 'Green'
            } else {
                $status  = 'AVISO'
                $detalhe = "HTTP $httpCode"
                $corItem = 'Yellow'
            }
        } elseif ($webEx.Message -match 'SSL|certificate|certificado|TLS') {
            $status  = 'ERRO SSL'
            $detalhe = 'Erro de certificado/TLS - verifique certificados raiz'
            $corItem = 'Red'
        } elseif ($webEx.Message -match 'proxy|407') {
            $status  = 'ERRO PROXY'
            $detalhe = 'Bloqueado por proxy - verifique as configuracoes'
            $corItem = 'Red'
        } elseif ($webEx.Message -match 'timed out|tempo|timeout') {
            $status  = 'TIMEOUT'
            $detalhe = 'Servidor nao respondeu em 12 segundos'
            $corItem = 'Yellow'
        } else {
            $detalhe = $webEx.Message -replace '.*---> ', '' | Select-Object -First 1
            if ($detalhe.Length -gt 80) { $detalhe = $detalhe.Substring(0, 77) + '...' }
            $corItem = 'Yellow'
            $status  = 'AVISO'
        }
    } catch {
        $detalhe = $_.Exception.Message
        if ($detalhe.Length -gt 80) { $detalhe = $detalhe.Substring(0, 77) + '...' }
    }

    $resultadosConect.Add([PSCustomObject]@{
        Nome    = $nome
        URL     = $url
        Status  = $status
        Detalhe = $detalhe
        Cor     = $corItem
    })

    $prefixo = if ($status -eq 'OK') { '   [OK] ' } elseif ($status -match 'AVISO|TIMEOUT') { '   [!]  ' } else { '   [X]  ' }
    $corPref = if ($status -eq 'OK') { 'Green' } elseif ($status -match 'AVISO|TIMEOUT') { 'Yellow' } else { 'Red' }
    Write-Host $prefixo -ForegroundColor $corPref -NoNewline
    Write-Host ($nome.PadRight(20) + "  " + $status.PadRight(12) + "  " + $detalhe)
}

# =========================================================================
# ETAPA 9 - Relatorio final
# =========================================================================

Write-Etapa '9/9  Relatorio final...'
Write-Host ''

$corRelatorio = if ($acoesRealizadas.Count -eq 0 -and -not $problemaEncontrado) { 'Green' } else { 'Yellow' }

Write-Host '======================================================' -ForegroundColor $corRelatorio
Write-Host '   RELATORIO DE CORRECOES DE PROXY E CERTIFICADOS     ' -ForegroundColor $corRelatorio
Write-Host '======================================================' -ForegroundColor $corRelatorio
Write-Host ''

if ($acoesRealizadas.Count -gt 0) {
    Write-Host '   Acoes realizadas nesta execucao:' -ForegroundColor White
    $num = 1
    foreach ($acao in $acoesRealizadas) {
        Write-Host ('   ' + $num + '. ' + $acao) -ForegroundColor Green
        $num++
    }
} else {
    Write-Host '   Nenhuma alteracao necessaria. Sistema ja estava configurado corretamente.' -ForegroundColor Green
}

Write-Host ''
Write-Host '   Resultado dos testes de conectividade:' -ForegroundColor White
foreach ($r in $resultadosConect) {
    Write-Host ('   ' + $r.Status.PadRight(12) + '  ' + $r.Nome.PadRight(20) + '  ' + $r.Detalhe) -ForegroundColor $r.Cor
}

if ($certExpirados.Count -gt 0) {
    Write-Host ''
    Write-Host ('   Atencao: ' + $certExpirados.Count + ' certificado(s) expirado(s) encontrado(s). Use certmgr.msc para gerenciar.') -ForegroundColor Yellow
}

$requerReinicio = $acoesRealizadas | Where-Object { $_ -match 'TLS|SCHANNEL|SchUsStrong' }
if ($requerReinicio) {
    Write-Host ''
    Write-Host '   IMPORTANTE: As alteracoes de TLS entram em vigor apos reiniciar o computador.' -ForegroundColor Yellow
    Write-Host '   Reinicie o sistema para garantir que todos os programas usem os novos protocolos.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host ("   Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host '======================================================' -ForegroundColor $corRelatorio
Write-Host ''
