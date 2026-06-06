# ConfigurarPJe.ps1
# Configura completamente o ambiente PJe em uma maquina Windows
# Java security, exception.sites, cache, servicos Shodo/Shomei, conectividade

$ErrorActionPreference = 'Continue'

# -------------------------------------------------------------------------
# Funcoes auxiliares de saida
# -------------------------------------------------------------------------

function Write-Etapa { param([string]$t) Write-Host "`n>> $t" -ForegroundColor Cyan }
function Write-Ok    { param([string]$t) Write-Host '   [OK]   ' -ForegroundColor Green  -NoNewline; Write-Host $t }
function Write-Aviso { param([string]$t) Write-Host '   [!]    ' -ForegroundColor Yellow -NoNewline; Write-Host $t }
function Write-Falha { param([string]$t) Write-Host '   [ERRO] ' -ForegroundColor Red    -NoNewline; Write-Host $t }
function Write-Info  { param([string]$t) Write-Host "   $t"     -ForegroundColor Gray }
function Write-Dest  { param([string]$t) Write-Host "   $t"     -ForegroundColor White }
function Write-Acao  { param([string]$t) Write-Host '   [>>]   ' -ForegroundColor Magenta -NoNewline; Write-Host $t }

# -------------------------------------------------------------------------
# Funcoes de manipulacao de arquivos Java (sem BOM)
# -------------------------------------------------------------------------

$encodingUTF8SemBOM = New-Object System.Text.UTF8Encoding $false

function Ler-Linhas {
    param([string]$Caminho)
    if (Test-Path $Caminho) {
        return [System.IO.File]::ReadAllLines($Caminho)
    }
    return @()
}

function Escrever-Linhas {
    param([string]$Caminho, [string[]]$Linhas)
    [System.IO.File]::WriteAllLines($Caminho, $Linhas, $encodingUTF8SemBOM)
}

function Atualizar-Properties {
    param([string]$Caminho, [hashtable]$Propriedades)
    $linhasExistentes = Ler-Linhas $Caminho
    $linhasFinais = [System.Collections.Generic.List[string]]::new()

    foreach ($linha in $linhasExistentes) {
        $incluir = $true
        foreach ($chave in $Propriedades.Keys) {
            if ($linha -match ('^' + [regex]::Escape($chave) + '=')) {
                $incluir = $false
                break
            }
        }
        if ($incluir) { $linhasFinais.Add($linha) }
    }

    foreach ($chave in $Propriedades.Keys) {
        $linhasFinais.Add($chave + '=' + $Propriedades[$chave])
    }

    Escrever-Linhas $Caminho $linhasFinais.ToArray()
}

function Atualizar-ExceptionSites {
    param([string]$Caminho, [string[]]$UrlsNecessarias)
    $urlsExistentes = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($linha in (Ler-Linhas $Caminho)) {
        $l = $linha.Trim()
        if ($l -ne '') { $urlsExistentes.Add($l) | Out-Null }
    }
    $adicionadas = 0
    foreach ($url in $UrlsNecessarias) {
        if ($urlsExistentes.Add($url)) { $adicionadas++ }
    }
    Escrever-Linhas $Caminho ([string[]]$urlsExistentes)
    return $adicionadas
}

# -------------------------------------------------------------------------
# Relatorio de etapas
# -------------------------------------------------------------------------

$relatorio = [System.Collections.Generic.List[PSObject]]::new()

function Add-Rel {
    param([string]$Etapa, [string]$Status, [string]$Msg)
    $relatorio.Add([PSCustomObject]@{ Etapa = $Etapa; Status = $Status; Msg = $Msg })
}

# =========================================================================
# URLs de excecao obrigatorias para o PJe
# =========================================================================

$urlsExcecao = @(
    'https://127.0.0.1:9000'            # Shodo
    'https://127.0.0.1:9003'            # Shomei
    'http://127.0.0.1'                  # PJe local
    'https://pje.jus.br'
    # PJe - instancias especificas
    'https://pje1g.tjba.jus.br'
    'https://pje2g.tjba.jus.br'
    'https://pje.trt5.jus.br'
    'https://pje.trf1.jus.br'
    'https://pje.trf2.jus.br'
    'https://pje.trf3.jus.br'
    'https://pje.trf4.jus.br'
    'https://pje.trf5.jus.br'
    'https://pje.tst.jus.br'
    'https://pje.csjt.jus.br'
    # PROJUDI - formato estado.projudi.tjestado.jus.br (todos os 27 estados)
    'https://ac.projudi.tjac.jus.br'
    'https://al.projudi.tjal.jus.br'
    'https://am.projudi.tjam.jus.br'
    'https://ap.projudi.tjap.jus.br'
    'https://ba.projudi.tjba.jus.br'
    'https://ce.projudi.tjce.jus.br'
    'https://df.projudi.tjdft.jus.br'
    'https://es.projudi.tjes.jus.br'
    'https://go.projudi.tjgo.jus.br'
    'https://ma.projudi.tjma.jus.br'
    'https://mg.projudi.tjmg.jus.br'
    'https://ms.projudi.tjms.jus.br'
    'https://mt.projudi.tjmt.jus.br'
    'https://pa.projudi.tjpa.jus.br'
    'https://pb.projudi.tjpb.jus.br'
    'https://pe.projudi.tjpe.jus.br'
    'https://pi.projudi.tjpi.jus.br'
    'https://pr.projudi.tjpr.jus.br'
    'https://rj.projudi.tjrj.jus.br'
    'https://rn.projudi.tjrn.jus.br'
    'https://ro.projudi.tjro.jus.br'
    'https://rr.projudi.tjrr.jus.br'
    'https://rs.projudi.tjrs.jus.br'
    'https://sc.projudi.tjsc.jus.br'
    'https://se.projudi.tjse.jus.br'
    'https://sp.projudi.tjsp.jus.br'
    'https://to.projudi.tjto.jus.br'
)

# =========================================================================
# Cabecalho
# =========================================================================

Write-Host ''
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host '   Configuracao do Ambiente PJe                       ' -ForegroundColor Cyan
Write-Host '   Java  |  exception.sites  |  Shodo  |  Shomei     ' -ForegroundColor Cyan
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host ("   Iniciado em : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host ''

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if ($isAdmin) {
    Write-Ok 'Executando como Administrador (acesso a todos os perfis).'
} else {
    Write-Aviso 'Sem privilegios de Administrador. Apenas o usuario atual sera configurado.'
    Write-Info  'Execute como Administrador para configurar todos os usuarios.'
}

# =========================================================================
# ETAPA 1 - Verificar Java 8
# =========================================================================

Write-Etapa '1/9  Verificando instalacao do Java 8...'
Write-Host ''

$java8Encontrado = $false
$java8Versao     = ''
$java8Path       = ''

$regCaminhos = @(
    'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment',
    'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment'
)

foreach ($regBase in $regCaminhos) {
    $jreKey = Get-ItemProperty "$regBase\1.8" -ErrorAction SilentlyContinue
    if ($jreKey) {
        $javaHome = $jreKey.JavaHome
        $javaExe  = Join-Path $javaHome 'bin\java.exe'
        if (Test-Path $javaExe) {
            $java8Encontrado = $true
            $java8Path       = $javaExe
            $java8Versao     = if ($jreKey.FullVersion) { $jreKey.FullVersion } else { '1.8.x' }
            break
        }
    }
}

if (-not $java8Encontrado) {
    $buscaFS = @('C:\Program Files\Java', 'C:\Program Files (x86)\Java')
    foreach ($dir in $buscaFS) {
        if (Test-Path $dir) {
            $jre8 = Get-ChildItem $dir -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^jre1\.8' } |
                Sort-Object Name -Descending | Select-Object -First 1
            if ($jre8) {
                $javaExe = Join-Path $jre8.FullName 'bin\java.exe'
                if (Test-Path $javaExe) {
                    $java8Encontrado = $true
                    $java8Path       = $javaExe
                    $java8Versao     = $jre8.Name
                    break
                }
            }
        }
    }
}

if ($java8Encontrado) {
    Write-Ok "Java 8 encontrado: $java8Versao"
    Write-Info "Caminho: $java8Path"
    Add-Rel '1. Java 8' 'OK' "Versao $java8Versao encontrada em $java8Path"
} else {
    Write-Falha 'Java 8 NAO encontrado neste computador.'
    Write-Info  'O PJe requer Java 8 (JRE 1.8). Instale e execute este script novamente.'
    Write-Info  'Download: https://www.java.com/pt-BR/download/'
    Add-Rel '1. Java 8' 'ERRO' 'Java 8 nao encontrado. Instale e execute novamente.'
    Write-Host ''
    Write-Host '   Configuracao encerrada: Java 8 e obrigatorio para o PJe.' -ForegroundColor Red
    Write-Host ''
    exit 1
}

# =========================================================================
# ETAPA 2-5 - Configurar Java para cada usuario do sistema
# =========================================================================

$nomesIgnorados  = '^(Public|All Users|Default|Default User|defaultuser0|desktop\.ini)$'
$usuarios        = @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch $nomesIgnorados })

$usuariosConfig  = 0
$usuariosSemDir  = 0
$totalBackups    = 0
$totalCacheLimpo = 0

Write-Etapa '2-5/9  Configurando Java para todos os usuarios do sistema...'
Write-Host ''
Write-Info ("$($usuarios.Count) perfil(is) de usuario encontrado(s) em C:\Users.")
Write-Host ''

foreach ($usuario in $usuarios) {
    $deployDir   = Join-Path $usuario.FullName 'AppData\LocalLow\Sun\Java\Deployment'
    $deployProps = Join-Path $deployDir 'deployment.properties'
    $excepSites  = Join-Path $deployDir 'exception.sites'
    $cacheDir    = Join-Path $deployDir 'cache'

    Write-Dest ("   --- Usuario: $($usuario.Name) ---")

    # Garantir que a pasta Deployment existe
    if (-not (Test-Path $deployDir)) {
        try {
            New-Item -Path $deployDir -ItemType Directory -Force | Out-Null
            Write-Info 'Pasta Deployment criada.'
        } catch {
            Write-Aviso ("Sem acesso a pasta do usuario $($usuario.Name). Ignorando.")
            $usuariosSemDir++
            Write-Host ''
            continue
        }
    }

    # ETAPA 2 - Backup do deployment.properties
    if (Test-Path $deployProps) {
        $ts     = Get-Date -Format 'yyyyMMdd_HHmmss'
        $backup = $deployProps + '.bak_' + $ts
        try {
            Copy-Item $deployProps $backup -Force
            Write-Ok "Backup criado: deployment.properties.bak_$ts"
            $totalBackups++
        } catch {
            Write-Aviso 'Nao foi possivel criar backup do deployment.properties.'
        }
    } else {
        Write-Info 'deployment.properties nao existia. Sera criado.'
    }

    # ETAPA 3 - Configurar nivel de seguranca MEDIUM e apontar exception.sites
    $excepSitesPath = $usuario.FullName.Replace('\', '/') + '/AppData/LocalLow/Sun/Java/Deployment/exception.sites'

    $props = @{
        'deployment.security.level'              = 'MEDIUM'
        'deployment.security.level.locked'       = ''
        'deployment.user.security.exception.sites' = $excepSitesPath
    }

    try {
        Atualizar-Properties $deployProps $props
        Write-Ok 'deployment.properties: security.level=MEDIUM configurado.'
    } catch {
        Write-Aviso ('Erro ao atualizar deployment.properties: ' + $_.Exception.Message)
    }

    # ETAPA 4 - Adicionar excecoes de sites no exception.sites
    try {
        $adicionadas = Atualizar-ExceptionSites $excepSites $urlsExcecao
        if ($adicionadas -gt 0) {
            Write-Ok "exception.sites: $adicionadas URL(s) nova(s) adicionada(s) ($($urlsExcecao.Count) total configuradas)."
        } else {
            Write-Ok "exception.sites: todas as $($urlsExcecao.Count) URLs ja estavam presentes."
        }
    } catch {
        Write-Aviso ('Erro ao atualizar exception.sites: ' + $_.Exception.Message)
    }

    # ETAPA 5 - Limpar cache do Java
    if (Test-Path $cacheDir) {
        try {
            $itensCache = @(Get-ChildItem $cacheDir -Recurse -Force -ErrorAction SilentlyContinue)
            Remove-Item $cacheDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Ok ("Cache do Java removido ($($itensCache.Count) item(ns) eliminados).")
            $totalCacheLimpo++
        } catch {
            Write-Aviso ('Erro ao limpar cache Java: ' + $_.Exception.Message)
        }
    } else {
        Write-Info 'Cache do Java ja estava vazio.'
    }

    $usuariosConfig++
    Write-Host ''
}

Add-Rel '2. Backup props' 'OK' "$totalBackups backup(s) criado(s) com timestamp"
Add-Rel '3. Security MEDIUM' 'OK' "deployment.properties atualizado em $usuariosConfig usuario(s)"
Add-Rel '4. exception.sites' 'OK' "$($urlsExcecao.Count) URLs configuradas em $usuariosConfig usuario(s)"
Add-Rel '5. Cache Java' 'OK' "Cache limpo em $totalCacheLimpo usuario(s)"

if ($usuariosSemDir -gt 0) {
    Write-Aviso "$usuariosSemDir usuario(s) ignorado(s) por falta de permissao de acesso."
}

# =========================================================================
# ETAPA 6 - Verificar servico Shodo
# =========================================================================

Write-Etapa '6/9  Verificando servico Shodo...'
Write-Host ''

$servicoShodo = Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'shodo' -or $_.DisplayName -match 'shodo' } |
    Select-Object -First 1

if ($servicoShodo) {
    Write-Info ("Servico encontrado: '$($servicoShodo.Name)' - Status: $($servicoShodo.Status)")
    if ($servicoShodo.Status -eq 'Running') {
        Write-Ok 'Shodo esta em execucao.'
        Add-Rel '6. Shodo' 'OK' "Servico '$($servicoShodo.Name)' em execucao"
    } else {
        Write-Aviso "Shodo esta parado. Tentando iniciar..."
        try {
            Start-Service -Name $servicoShodo.Name -ErrorAction Stop
            Start-Sleep -Milliseconds 1500
            $novoStatus = (Get-Service -Name $servicoShodo.Name).Status
            if ($novoStatus -eq 'Running') {
                Write-Ok 'Shodo iniciado com sucesso.'
                Add-Rel '6. Shodo' 'OK' "Servico iniciado (estava parado)"
            } else {
                Write-Aviso "Shodo nao iniciou (status: $novoStatus)."
                Add-Rel '6. Shodo' 'AVISO' "Nao foi possivel iniciar o servico (status: $novoStatus)"
            }
        } catch {
            Write-Falha ('Erro ao iniciar Shodo: ' + $_.Exception.Message)
            Add-Rel '6. Shodo' 'ERRO' ('Falha ao iniciar: ' + $_.Exception.Message)
        }
    }
} else {
    Write-Aviso 'Servico Shodo NAO encontrado neste computador.'
    Write-Info  'O Shodo e necessario para assinatura digital no PJe.'
    Write-Info  'Instale o Shodo e execute este script novamente para verificar.'
    Add-Rel '6. Shodo' 'AVISO' 'Servico nao instalado. Instale o Shodo para assinatura digital.'
}

# =========================================================================
# ETAPA 7 - Verificar servico Shomei
# =========================================================================

Write-Etapa '7/9  Verificando servico Shomei...'
Write-Host ''

$servicoShomei = Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'shomei' -or $_.DisplayName -match 'shomei' } |
    Select-Object -First 1

if ($servicoShomei) {
    Write-Info ("Servico encontrado: '$($servicoShomei.Name)' - Status: $($servicoShomei.Status)")
    if ($servicoShomei.Status -eq 'Running') {
        Write-Ok 'Shomei esta em execucao.'
        Add-Rel '7. Shomei' 'OK' "Servico '$($servicoShomei.Name)' em execucao"
    } else {
        Write-Aviso 'Shomei esta parado. Tentando iniciar...'
        try {
            Start-Service -Name $servicoShomei.Name -ErrorAction Stop
            Start-Sleep -Milliseconds 1500
            $novoStatus = (Get-Service -Name $servicoShomei.Name).Status
            if ($novoStatus -eq 'Running') {
                Write-Ok 'Shomei iniciado com sucesso.'
                Add-Rel '7. Shomei' 'OK' "Servico iniciado (estava parado)"
            } else {
                Write-Aviso "Shomei nao iniciou (status: $novoStatus)."
                Add-Rel '7. Shomei' 'AVISO' "Nao foi possivel iniciar o servico (status: $novoStatus)"
            }
        } catch {
            Write-Falha ('Erro ao iniciar Shomei: ' + $_.Exception.Message)
            Add-Rel '7. Shomei' 'ERRO' ('Falha ao iniciar: ' + $_.Exception.Message)
        }
    }
} else {
    Write-Aviso 'Servico Shomei NAO encontrado neste computador.'
    Write-Info  'O Shomei e necessario para assinatura digital no PJe.'
    Write-Info  'Instale o Shomei e execute este script novamente para verificar.'
    Add-Rel '7. Shomei' 'AVISO' 'Servico nao instalado. Instale o Shomei para assinatura digital.'
}

# =========================================================================
# ETAPA 8 - Testar conectividade com o PJe
# =========================================================================

Write-Etapa '8/9  Testando conectividade com pje.jus.br...'
Write-Host ''

[Net.ServicePointManager]::SecurityProtocol = (
    [Net.SecurityProtocolType]::Tls12 -bor
    [Net.SecurityProtocolType]::Tls11 -bor
    [Net.SecurityProtocolType]::Tls
)

$urlTeste   = 'https://pje.jus.br'
$conectOk   = $false
$conectDetalhe = ''

try {
    $req = [System.Net.HttpWebRequest]::Create($urlTeste)
    $req.Timeout          = 12000
    $req.AllowAutoRedirect = $true
    $req.UserAgent        = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    $resp = $req.GetResponse()
    $httpCode = [int]$resp.StatusCode
    $resp.Close()
    $conectOk     = $true
    $conectDetalhe = "HTTP $httpCode"
} catch [System.Net.WebException] {
    $webEx = $_.Exception
    if ($webEx.Response) {
        $httpCode = [int]$webEx.Response.StatusCode
        if ($httpCode -ge 200) {
            $conectOk     = $true
            $conectDetalhe = "HTTP $httpCode (site acessivel)"
        } else {
            $conectDetalhe = "HTTP $httpCode"
        }
    } elseif ($webEx.Message -match 'SSL|certificate|TLS') {
        $conectDetalhe = 'Erro de certificado SSL. Verifique certificados raiz do Windows.'
    } elseif ($webEx.Message -match 'proxy|407') {
        $conectDetalhe = 'Bloqueado por proxy.'
    } elseif ($webEx.Message -match 'timed out|timeout') {
        $conectDetalhe = 'Timeout (servidor nao respondeu em 12s).'
    } else {
        $conectDetalhe = $webEx.Message
        if ($conectDetalhe.Length -gt 80) { $conectDetalhe = $conectDetalhe.Substring(0, 77) + '...' }
    }
} catch {
    $conectDetalhe = $_.Exception.Message
    if ($conectDetalhe.Length -gt 80) { $conectDetalhe = $conectDetalhe.Substring(0, 77) + '...' }
}

if ($conectOk) {
    Write-Ok "pje.jus.br acessivel. $conectDetalhe"
    Add-Rel '8. Conectividade' 'OK' "pje.jus.br acessivel ($conectDetalhe)"
} else {
    Write-Aviso "pje.jus.br com problema: $conectDetalhe"
    Write-Info  'Verifique conexao com a internet, proxy ou VPN.'
    Add-Rel '8. Conectividade' 'AVISO' "pje.jus.br inacessivel: $conectDetalhe"
}

# =========================================================================
# ETAPA 9 - Relatorio final colorido
# =========================================================================

Write-Etapa '9/9  Relatorio final...'
Write-Host ''

Write-Host '======================================================' -ForegroundColor Cyan
Write-Host '   RELATORIO DE CONFIGURACAO DO AMBIENTE PJe          ' -ForegroundColor Cyan
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host ''

$erros  = @($relatorio | Where-Object { $_.Status -eq 'ERRO' })
$avisos = @($relatorio | Where-Object { $_.Status -eq 'AVISO' })
$oks    = @($relatorio | Where-Object { $_.Status -eq 'OK' })

foreach ($item in $relatorio) {
    $cor    = if ($item.Status -eq 'OK') { 'Green' } elseif ($item.Status -eq 'AVISO') { 'Yellow' } else { 'Red' }
    $prefixo = if ($item.Status -eq 'OK') { '[OK]   ' } elseif ($item.Status -eq 'AVISO') { '[!]    ' } else { '[ERRO] ' }
    Write-Host ('   ' + $prefixo + $item.Etapa.PadRight(22) + '  ') -ForegroundColor $cor -NoNewline
    Write-Host $item.Msg
}

Write-Host ''
$corRel = if ($erros.Count -gt 0) { 'Red' } elseif ($avisos.Count -gt 0) { 'Yellow' } else { 'Green' }
Write-Host ('   Resumo: ' + $oks.Count + ' OK  |  ' + $avisos.Count + ' Aviso(s)  |  ' + $erros.Count + ' Erro(s)') -ForegroundColor $corRel
Write-Host ''

if ($oks.Count -eq $relatorio.Count) {
    Write-Host '   Ambiente PJe configurado com sucesso!' -ForegroundColor Green
}
if ($avisos.Count -gt 0 -or $erros.Count -gt 0) {
    Write-Host '   Verifique os itens acima com [!] ou [ERRO] e resolva antes de usar o PJe.' -ForegroundColor Yellow
}

Write-Host ''
Write-Dest '   Configuracoes aplicadas para todos os usuarios:'
Write-Info ("   Usuarios processados : $usuariosConfig")
Write-Info ("   Backups criados      : $totalBackups")
Write-Info ("   URLs no exception.sites : $($urlsExcecao.Count)  (Shodo, Shomei, PJe, PROJUDI - 27 estados)")
Write-Info ("   Cache Java limpo em  : $totalCacheLimpo usuario(s)")

Write-Host ''
Write-Host ("   Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host ''
