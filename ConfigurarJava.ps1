# ConfigurarJava.ps1
# Configura Java 8 para sistemas juridicos brasileiros (PJe, PROJUDI, eProc, Shodo, Shomei)

$resumo = [System.Collections.Generic.List[string]]::new()

# -------------------------------------------------------------------------
# Funcoes auxiliares
# -------------------------------------------------------------------------

function Write-Etapa { param([string]$t) Write-Host "`n>> $t" -ForegroundColor Cyan }
function Write-Ok    { param([string]$t) Write-Host '   [OK] ' -ForegroundColor Green  -NoNewline; Write-Host $t }
function Write-Aviso { param([string]$t) Write-Host '   [!]  ' -ForegroundColor Yellow -NoNewline; Write-Host $t }
function Write-Falha { param([string]$t) Write-Host '   [X]  ' -ForegroundColor Red    -NoNewline; Write-Host $t }
function Write-Info  { param([string]$t) Write-Host "   $t" -ForegroundColor Gray }
function Add-Resumo  { param([string]$l) $script:resumo.Add($l) }

# Escreve arquivo de texto sem BOM (Java nao suporta BOM em .properties)
function Write-TextFile {
    param([string]$Caminho, [object]$Linhas)
    $enc = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllLines($Caminho, [string[]]$Linhas, $enc)
}

# =========================================================================
# Cabecalho
# =========================================================================

Write-Host ''
Write-Host '================================================' -ForegroundColor Cyan
Write-Host '  Java 8 - Configuracao para Sistemas Juridicos ' -ForegroundColor Cyan
Write-Host '================================================' -ForegroundColor Cyan
Write-Host ("  Iniciado em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host ''

# =========================================================================
# ETAPA 1 - Verificar Java 8
# =========================================================================

Write-Etapa '1. Verificando instalacao do Java 8...'

$javaHome = $null

# Busca no registro (64-bit e 32-bit)
$regRaizes = @(
    'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment',
    'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment'
)
foreach ($raiz in $regRaizes) {
    if (-not (Test-Path $raiz -ErrorAction SilentlyContinue)) { continue }
    Get-ChildItem -Path $raiz -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.PSChildName -like '1.8*' -and -not $javaHome) {
            $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($p.JavaHome -and (Test-Path "$($p.JavaHome)\bin\java.exe")) {
                $javaHome = $p.JavaHome
            }
        }
    }
    if ($javaHome) { break }
}

# Busca em caminhos comuns de instalacao
if (-not $javaHome) {
    foreach ($base in @('C:\Program Files\Java', 'C:\Program Files (x86)\Java')) {
        if (-not (Test-Path $base)) { continue }
        $dir = Get-ChildItem -Path $base -Directory -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -like 'jre1.8*' -or $_.Name -like 'jdk1.8*' } |
               Sort-Object Name -Descending |
               Select-Object -First 1
        if ($dir -and (Test-Path "$($dir.FullName)\bin\java.exe")) {
            $javaHome = $dir.FullName
            break
        }
    }
}

if (-not $javaHome) {
    Write-Falha 'Java 8 (JRE 1.8.x) nao encontrado neste computador.'
    Write-Info  'Baixe e instale em: https://www.java.com'
    Write-Info  'Execute este script novamente apos a instalacao.'
    Write-Host ''
    exit 1
}

$javaBin  = "$javaHome\bin\java.exe"
$verRaw   = & "$javaBin" -version 2>&1
$verLinha = ($verRaw | Select-Object -First 1).ToString()
Write-Ok "Versao encontrada: $verLinha"
Write-Info "Diretorio: $javaHome"
Add-Resumo "Java 8 encontrado: $verLinha"
Add-Resumo "Diretorio Java: $javaHome"

# =========================================================================
# ETAPA 2 - Localizar deployment.properties
# =========================================================================

Write-Etapa '2. Localizando arquivo deployment.properties...'

$possiveis = @(
    "$env:USERPROFILE\AppData\LocalLow\Sun\Java\Deployment\deployment.properties",
    "$env:APPDATA\Sun\Java\Deployment\deployment.properties",
    "$env:USERPROFILE\.java\deployment\deployment.properties",
    'C:\Windows\Sun\Java\Deployment\deployment.properties'
)

$deployProps = $null
$deployDir   = $null

foreach ($candidato in $possiveis) {
    if (Test-Path $candidato) {
        $deployProps = $candidato
        $deployDir   = Split-Path -Parent $candidato
        Write-Ok "Encontrado: $deployProps"
        break
    }
}

if (-not $deployProps) {
    $deployDir   = "$env:USERPROFILE\AppData\LocalLow\Sun\Java\Deployment"
    $deployProps = "$deployDir\deployment.properties"
    if (-not (Test-Path $deployDir)) {
        New-Item -ItemType Directory -Path $deployDir -Force -ErrorAction SilentlyContinue | Out-Null
    }
    Write-TextFile -Caminho $deployProps -Linhas @()
    Write-Aviso "Nao encontrado em nenhum local padrao."
    Write-Ok   "Criado novo arquivo em: $deployProps"
}

Add-Resumo "deployment.properties: $deployProps"

# =========================================================================
# ETAPA 3 - Backup do deployment.properties
# =========================================================================

Write-Etapa '3. Criando backup do deployment.properties...'

$ts         = Get-Date -Format 'yyyyMMdd_HHmmss'
$backupPath = "$deployProps.bak.$ts"

try {
    Copy-Item -Path $deployProps -Destination $backupPath -Force -ErrorAction Stop
    Write-Ok "Backup criado: $backupPath"
    Add-Resumo "Backup: $backupPath"
} catch {
    Write-Aviso "Nao foi possivel criar backup: $_"
}

# =========================================================================
# ETAPA 4 - Configurar nivel de seguranca MEDIUM
# =========================================================================

Write-Etapa '4. Configurando nivel de seguranca do Java...'

# MEDIUM foi removido do Java a partir do 8u20: os unicos niveis validos sao
# HIGH e VERY_HIGH. Gravar MEDIUM faz o Java ignorar e cair de volta em HIGH.
# Quem realmente libera os sistemas juridicos e' o exception.sites (etapa 5).
$chaveNivel  = 'deployment.security.level'
$chaveLocked = 'deployment.security.level.locked'
$chaveExpira = 'deployment.expiration.check.enabled'
$chaveWebJava = 'deployment.webjava.enabled'

$linhasDP   = [System.IO.File]::ReadAllLines($deployProps)
$novaDP     = [System.Collections.Generic.List[string]]::new()
$achouNivel = $false

foreach ($linha in $linhasDP) {
    # Qualquer chave .locked trava o painel do Java: removida do arquivo.
    if ($linha -match '^\s*deployment\..*\.locked\s*=') {
        Write-Aviso ('Removendo bloqueio: ' + ($linha -split '=')[0].Trim())
        continue
    }
    if ($linha -match "^\s*$chaveNivel\s*=") {
        $novaDP.Add("$chaveNivel=HIGH")
        $achouNivel = $true
    } elseif ($linha -match "^\s*$chaveExpira\s*=" -or $linha -match "^\s*$chaveWebJava\s*=") {
        continue
    } else {
        $novaDP.Add($linha)
    }
}
if (-not $achouNivel) { $novaDP.Add("$chaveNivel=HIGH") }

# Evita o aviso "Java desatualizado" que trava o usuario, e garante applets.
$novaDP.Add("$chaveExpira=false")
$novaDP.Add("$chaveWebJava=true")

Write-TextFile -Caminho $deployProps -Linhas $novaDP

if ($achouNivel) {
    Write-Ok 'deployment.security.level atualizado para HIGH.'
} else {
    Write-Ok 'deployment.security.level=HIGH adicionado.'
}
Write-Info 'Bloqueios (.locked) removidos e verificacao de expiracao desativada.'
Add-Resumo 'Seguranca: deployment.security.level=HIGH (bloqueios removidos)'

# =========================================================================
# ETAPA 5 - Configurar excecoes de sites
# =========================================================================

Write-Etapa '5. Configurando excecoes de sites para sistemas juridicos...'

$urlsNecessarias = [ordered]@{
    'https://127.0.0.1:9000'         = 'Shodo'
    'https://127.0.0.1:9003'         = 'Shomei'
    'http://127.0.0.1'               = 'PJe / PROJUDI local'
    'https://pje.jus.br'             = 'PJe nacional'
    'https://projudi.tjgo.jus.br'    = 'PROJUDI TJGO'
    'https://projudi.tjam.jus.br'    = 'PROJUDI TJAM'
    'https://projudi.tjrr.jus.br'    = 'PROJUDI TJRR'
    'https://projudi.tjap.jus.br'    = 'PROJUDI TJAP'
    'https://projudi.tjba.jus.br'    = 'PROJUDI TJBA'
    'https://projudi.tjpa.jus.br'    = 'PROJUDI TJPA'
    'https://projudi.tjmt.jus.br'    = 'PROJUDI TJMT'
    'https://projudi.tjms.jus.br'    = 'PROJUDI TJMS'
    'https://projudi.tjto.jus.br'    = 'PROJUDI TJTO'
    'https://projudi.tjpi.jus.br'    = 'PROJUDI TJPI'
    'https://projudi.tjma.jus.br'    = 'PROJUDI TJMA'
    'https://projudi.tjal.jus.br'    = 'PROJUDI TJAL'
    'https://projudi.tjse.jus.br'    = 'PROJUDI TJSE'
    'https://projudi.tjpb.jus.br'    = 'PROJUDI TJPB'
    'https://projudi.tjrn.jus.br'    = 'PROJUDI TJRN'
    'https://projudi.tjce.jus.br'    = 'PROJUDI TJCE'
    'https://projudi.tjpe.jus.br'    = 'PROJUDI TJPE'
    'https://projudi.tjac.jus.br'    = 'PROJUDI TJAC'
    'https://projudi.tjro.jus.br'    = 'PROJUDI TJRO'
    'https://projudi.tjrj.jus.br'    = 'PROJUDI TJRJ'
    'https://projudi.tjes.jus.br'    = 'PROJUDI TJES'
    'https://projudi.tjmg.jus.br'    = 'PROJUDI TJMG'
    'https://projudi.tjsp.jus.br'    = 'PROJUDI TJSP'
    'https://projudi.tjpr.jus.br'    = 'PROJUDI TJPR'
    'https://projudi.tjsc.jus.br'    = 'PROJUDI TJSC'
    'https://projudi.tjrs.jus.br'    = 'PROJUDI TJRS'
    'https://projudi.tjdft.jus.br'   = 'PROJUDI TJDFT'
    'https://eproc.jfrs.jus.br'      = 'eProc JFRS'
    'https://eproc1.trf4.jus.br'     = 'eProc TRF4 (1)'
    'https://eproc2.trf4.jus.br'     = 'eProc TRF4 (2)'
}

# Determina caminho do exception.sites a partir do deployment.properties
$chaveExcecoes = 'deployment.user.security.exception.sites'
$pathExcecoes  = $null

$dpAtual = [System.IO.File]::ReadAllLines($deployProps)
foreach ($linha in $dpAtual) {
    if ($linha -match "^$chaveExcecoes\s*=\s*(.+)$") {
        $pathExcecoes = ($Matches[1].Trim()) -replace '/', '\'
        break
    }
}

if (-not $pathExcecoes) {
    $pathExcecoes = "$deployDir\security\exception.sites"
}

# Cria o diretorio se nao existir
$dirExcecoes = Split-Path -Parent $pathExcecoes
if (-not (Test-Path $dirExcecoes)) {
    New-Item -ItemType Directory -Path $dirExcecoes -Force -ErrorAction SilentlyContinue | Out-Null
}

# Le URLs ja existentes no arquivo
$urlsExistentes = @()
if (Test-Path $pathExcecoes) {
    $urlsExistentes = [System.IO.File]::ReadAllLines($pathExcecoes) |
                      Where-Object { $_.Trim() -ne '' } |
                      ForEach-Object { $_.Trim() }
}

$conjExistentes = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
foreach ($u in $urlsExistentes) { [void]$conjExistentes.Add($u) }

$listaFinal = [System.Collections.Generic.List[string]]::new()
foreach ($u in $urlsExistentes) { $listaFinal.Add($u) }

$qtdAdicionados = 0
$qtdJaExistiam  = 0

foreach ($url in $urlsNecessarias.Keys) {
    $label = $urlsNecessarias[$url]
    if ($conjExistentes.Contains($url)) {
        Write-Aviso "Ja existe:  $url  ($label)"
        $qtdJaExistiam++
    } else {
        $listaFinal.Add($url)
        Write-Ok   "Adicionado: $url  ($label)"
        $qtdAdicionados++
    }
}

Write-TextFile -Caminho $pathExcecoes -Linhas $listaFinal

# Garante que deployment.properties aponta para o exception.sites
$pathExcecoesJava = $pathExcecoes -replace '\\', '/'
$dpAtual2   = [System.IO.File]::ReadAllLines($deployProps)
$dpLista2   = [System.Collections.Generic.List[string]]::new()
$achouChave = $false
foreach ($linha in $dpAtual2) {
    if ($linha -match "^$chaveExcecoes\s*=") {
        $dpLista2.Add("$chaveExcecoes=$pathExcecoesJava")
        $achouChave = $true
    } else {
        $dpLista2.Add($linha)
    }
}
if (-not $achouChave) { $dpLista2.Add("$chaveExcecoes=$pathExcecoesJava") }
Write-TextFile -Caminho $deployProps -Linhas $dpLista2

Write-Info "Arquivo exception.sites: $pathExcecoes"
Write-Info "Adicionados: $qtdAdicionados  |  Ja existiam: $qtdJaExistiam  |  Total na lista: $($listaFinal.Count)"
Add-Resumo "Excecoes: $qtdAdicionados URL(s) adicionada(s), $qtdJaExistiam ja existiam"
Add-Resumo "exception.sites: $pathExcecoes"

# =========================================================================
# ETAPA 6 - Limpar cache do Java
# =========================================================================

Write-Etapa '6. Limpando cache do Java...'

$dirsCache = @(
    "$env:USERPROFILE\AppData\LocalLow\Sun\Java\Deployment\cache",
    "$env:APPDATA\Sun\Java\Deployment\cache"
)

$totalBytes  = [long]0
$cacheLimpos = 0

foreach ($dir in $dirsCache) {
    if (-not (Test-Path $dir)) { continue }
    try {
        $arquivos = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue
        $bytes    = ($arquivos | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
        if ($bytes) { $totalBytes += [long]$bytes }
        Remove-Item -Path "$dir\*" -Recurse -Force -ErrorAction SilentlyContinue
        $cacheLimpos++
        $tamanho = if ($bytes -ge 1MB) { '{0:N1} MB' -f ($bytes / 1MB) } `
                   elseif ($bytes -ge 1KB) { '{0:N0} KB' -f ($bytes / 1KB) } `
                   else { "$bytes bytes" }
        Write-Ok "Cache limpo: $dir  ($tamanho)"
    } catch {
        Write-Aviso "Nao foi possivel limpar cache em: $dir"
    }
}

if ($cacheLimpos -eq 0) {
    Write-Info 'Pasta de cache nao encontrada ou ja estava vazia.'
    Add-Resumo 'Cache Java: nenhum arquivo encontrado'
} else {
    $totalStr = if ($totalBytes -ge 1MB) { '{0:N1} MB' -f ($totalBytes / 1MB) } `
                elseif ($totalBytes -ge 1KB) { '{0:N0} KB' -f ($totalBytes / 1KB) } `
                else { "$totalBytes bytes" }
    Add-Resumo "Cache Java limpo: $totalStr removidos"
}

# =========================================================================
# RESUMO FINAL
# =========================================================================

Write-Host ''
Write-Host '================================================' -ForegroundColor Green
Write-Host '   Configuracao concluida com sucesso!          ' -ForegroundColor Green
Write-Host '================================================' -ForegroundColor Green
Write-Host ''

foreach ($linha in $resumo) {
    Write-Host "  $linha" -ForegroundColor Gray
}

Write-Host ''
Write-Host '  Proximos passos recomendados:' -ForegroundColor Cyan
Write-Host '  1. Feche todos os navegadores abertos' -ForegroundColor White
Write-Host '  2. Acesse o sistema juridico normalmente' -ForegroundColor White
Write-Host '  3. Se aparecer aviso de seguranca Java, clique em Executar' -ForegroundColor White
Write-Host '  4. Se ainda houver problemas, verifique o token/certificado' -ForegroundColor White
Write-Host ''
Write-Host ("  Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host '================================================' -ForegroundColor Green
Write-Host ''
