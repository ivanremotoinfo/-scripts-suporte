# InstalarVisualC.ps1
# Verifica e instala redistribuiveis Visual C++ necessarios para programas juridicos

$ErrorActionPreference = 'Continue'
$precisaReiniciar = $false

# -------------------------------------------------------------------------
# Funcoes auxiliares
# -------------------------------------------------------------------------

function Write-Etapa { param([string]$t) Write-Host "`n>> $t" -ForegroundColor Cyan }
function Write-Ok    { param([string]$t) Write-Host '   [OK] ' -ForegroundColor Green  -NoNewline; Write-Host $t }
function Write-Aviso { param([string]$t) Write-Host '   [!]  ' -ForegroundColor Yellow -NoNewline; Write-Host $t }
function Write-Falha { param([string]$t) Write-Host '   [X]  ' -ForegroundColor Red    -NoNewline; Write-Host $t }
function Write-Info  { param([string]$t) Write-Host "   $t" -ForegroundColor Gray }

# =========================================================================
# Cabecalho
# =========================================================================

Write-Host ''
Write-Host '================================================' -ForegroundColor Cyan
Write-Host '   Instalador Visual C++ - Sistemas Juridicos  ' -ForegroundColor Cyan
Write-Host '================================================' -ForegroundColor Cyan
Write-Host ("   Iniciado em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host ''

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Falha 'Este script requer privilegios de Administrador.'
    Write-Info  'Execute o PowerShell como Administrador e tente novamente.'
    Write-Host ''
    exit 1
}
Write-Ok 'Executando como Administrador.'

# =========================================================================
# Definicao dos pacotes necessarios
# =========================================================================

$pacotes = @(
    [PSCustomObject]@{
        Nome    = 'Visual C++ 2005 SP1'
        Ano     = '2005'
        Arq     = 'x86'
        Padroes = @('2005')
        URL     = 'https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE'
        Arquivo = 'vcredist_2005_x86.exe'
        Params  = '/q:a /r:n'
    }
    [PSCustomObject]@{
        Nome    = 'Visual C++ 2005 SP1'
        Ano     = '2005'
        Arq     = 'x64'
        Padroes = @('2005')
        URL     = 'https://download.microsoft.com/download/6/B/B/6BB661D6-A8AE-4819-B79F-236472F6070C/vcredist_x64.EXE'
        Arquivo = 'vcredist_2005_x64.exe'
        Params  = '/q:a /r:n'
    }
    [PSCustomObject]@{
        Nome    = 'Visual C++ 2008 SP1'
        Ano     = '2008'
        Arq     = 'x86'
        Padroes = @('2008')
        URL     = 'https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe'
        Arquivo = 'vcredist_2008_x86.exe'
        Params  = '/q'
    }
    [PSCustomObject]@{
        Nome    = 'Visual C++ 2008 SP1'
        Ano     = '2008'
        Arq     = 'x64'
        Padroes = @('2008')
        URL     = 'https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe'
        Arquivo = 'vcredist_2008_x64.exe'
        Params  = '/q'
    }
    [PSCustomObject]@{
        Nome    = 'Visual C++ 2010 SP1'
        Ano     = '2010'
        Arq     = 'x86'
        Padroes = @('2010')
        URL     = 'https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe'
        Arquivo = 'vcredist_2010_x86.exe'
        Params  = '/quiet /norestart'
    }
    [PSCustomObject]@{
        Nome    = 'Visual C++ 2010 SP1'
        Ano     = '2010'
        Arq     = 'x64'
        Padroes = @('2010')
        URL     = 'https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe'
        Arquivo = 'vcredist_2010_x64.exe'
        Params  = '/quiet /norestart'
    }
    [PSCustomObject]@{
        Nome    = 'Visual C++ 2012 Update 4'
        Ano     = '2012'
        Arq     = 'x86'
        Padroes = @('2012')
        URL     = 'https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe'
        Arquivo = 'vcredist_2012_x86.exe'
        Params  = '/quiet /norestart'
    }
    [PSCustomObject]@{
        Nome    = 'Visual C++ 2012 Update 4'
        Ano     = '2012'
        Arq     = 'x64'
        Padroes = @('2012')
        URL     = 'https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe'
        Arquivo = 'vcredist_2012_x64.exe'
        Params  = '/quiet /norestart'
    }
    [PSCustomObject]@{
        Nome    = 'Visual C++ 2013 Update 5'
        Ano     = '2013'
        Arq     = 'x86'
        Padroes = @('2013')
        URL     = 'https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x86.exe'
        Arquivo = 'vcredist_2013_x86.exe'
        Params  = '/install /quiet /norestart'
    }
    [PSCustomObject]@{
        Nome    = 'Visual C++ 2013 Update 5'
        Ano     = '2013'
        Arq     = 'x64'
        Padroes = @('2013')
        URL     = 'https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe'
        Arquivo = 'vcredist_2013_x64.exe'
        Params  = '/install /quiet /norestart'
    }
    [PSCustomObject]@{
        Nome    = 'Visual C++ 2015-2022'
        Ano     = '2015-2022'
        Arq     = 'x86'
        Padroes = @('2015', '2017', '2019', '2022', '2015-2022')
        URL     = 'https://aka.ms/vs/17/release/vc_redist.x86.exe'
        Arquivo = 'vcredist_2015_2022_x86.exe'
        Params  = '/install /quiet /norestart'
    }
    [PSCustomObject]@{
        Nome    = 'Visual C++ 2015-2022'
        Ano     = '2015-2022'
        Arq     = 'x64'
        Padroes = @('2015', '2017', '2019', '2022', '2015-2022')
        URL     = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'
        Arquivo = 'vcredist_2015_2022_x64.exe'
        Params  = '/install /quiet /norestart'
    }
)

# =========================================================================
# ETAPA 1 - Listar redistribuiveis ja instalados
# =========================================================================

Write-Etapa '1. Listando redistribuiveis Visual C++ ja instalados...'
Write-Host ''

$regPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

$instalados = [System.Collections.Generic.List[PSObject]]::new()
$nomesUnicos = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($regPath in $regPaths) {
    $itens = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue |
        Get-ItemProperty -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Microsoft Visual C\+\+' }
    foreach ($item in $itens) {
        $chave = "$($item.DisplayName)|$($item.DisplayVersion)"
        if ($nomesUnicos.Add($chave)) {
            $instalados.Add($item)
        }
    }
}

if ($instalados.Count -gt 0) {
    $instalados | Sort-Object DisplayName | ForEach-Object {
        $arqLabel = if ($_.DisplayName -match '\(x64\)' -or $_.DisplayName -match '- x64') { 'x64' }
                    elseif ($_.DisplayName -match '\(x86\)' -or $_.DisplayName -match '- x86') { 'x86' }
                    else { '   ' }
        Write-Host ("   {0,-6}  {1}" -f "[$arqLabel]", $_.DisplayName) -ForegroundColor White
        if ($_.DisplayVersion) {
            Write-Host ("          Versao: {0}" -f $_.DisplayVersion) -ForegroundColor DarkGray
        }
    }
} else {
    Write-Aviso 'Nenhum redistribuivel Visual C++ encontrado.'
}

# Funcao de verificacao de instalacao
function Test-VCInstalado {
    param([string[]]$Padroes, [string]$Arq)
    foreach ($regPath in $regPaths) {
        $itens = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue |
            Get-ItemProperty -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match 'Microsoft Visual C\+\+' }
        foreach ($item in $itens) {
            $nome = $item.DisplayName
            $temArq = $nome -match [regex]::Escape("($Arq)") -or $nome -match "[\s-]$Arq[\s\.]"
            if (-not $temArq) { continue }
            foreach ($p in $Padroes) {
                if ($nome -match [regex]::Escape($p)) { return $true }
            }
        }
    }
    return $false
}

# =========================================================================
# ETAPA 2 - Verificar quais versoes essenciais estao faltando
# =========================================================================

Write-Etapa '2. Verificando versoes essenciais necessarias...'
Write-Host ''

$faltando = [System.Collections.Generic.List[PSObject]]::new()

foreach ($pkg in $pacotes) {
    $estaInstalado = Test-VCInstalado -Padroes $pkg.Padroes -Arq $pkg.Arq
    if ($estaInstalado) {
        Write-Ok "$($pkg.Nome) ($($pkg.Arq)) - ja instalado"
    } else {
        Write-Aviso "$($pkg.Nome) ($($pkg.Arq)) - FALTANDO"
        $faltando.Add($pkg)
    }
}

if ($faltando.Count -eq 0) {
    Write-Host ''
    Write-Ok 'Todos os redistribuiveis necessarios ja estao instalados.'
    Write-Host ''
    Write-Host ("   Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
    Write-Host '================================================' -ForegroundColor Green
    Write-Host ''
    exit 0
}

Write-Host ''
Write-Aviso "$($faltando.Count) pacote(s) serao baixados e instalados."

# =========================================================================
# ETAPAS 3 e 4 - Baixar e instalar os pacotes faltando
# =========================================================================

Write-Etapa "3/4. Baixando e instalando $($faltando.Count) pacote(s)..."

$tmpDir = $env:TEMP
$resumoInstalados  = [System.Collections.Generic.List[string]]::new()
$resumoFalhas      = [System.Collections.Generic.List[string]]::new()
$num = 0

foreach ($pkg in $faltando) {
    $num++
    $destino = Join-Path $tmpDir $pkg.Arquivo
    $label   = "$($pkg.Nome) ($($pkg.Arq))"

    Write-Host ''
    Write-Host ("   [{0}/{1}]  {2}" -f $num, $faltando.Count, $label) -ForegroundColor Cyan

    # ----- Download -----
    $downloadOk = $false
    Write-Info "Baixando de: $($pkg.URL)"

    # Tentativa 1: BITS Transfer (mostra progresso nativo)
    try {
        Import-Module BitsTransfer -ErrorAction Stop
        Start-BitsTransfer -Source $pkg.URL -Destination $destino `
            -Description "Baixando $label" -Priority Normal -ErrorAction Stop
        $downloadOk = $true
        Write-Ok 'Download concluido.'
    } catch {
        Write-Aviso "BITS indisponivel, usando WebRequest..."
        # Tentativa 2: Invoke-WebRequest com progresso manual
        try {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $pkg.URL -OutFile $destino `
                -UseBasicParsing -ErrorAction Stop
            $ProgressPreference = 'Continue'
            $downloadOk = $true
            Write-Ok 'Download concluido.'
        } catch {
            Write-Falha "Erro no download: $_"
            $resumoFalhas.Add("$label  (falha no download)")
            continue
        }
    }

    if (-not $downloadOk -or -not (Test-Path $destino)) {
        Write-Falha 'Arquivo nao encontrado apos o download.'
        $resumoFalhas.Add("$label  (arquivo nao baixado)")
        continue
    }

    $tamanhoMB = [math]::Round((Get-Item $destino).Length / 1MB, 1)
    Write-Info "Arquivo: $($pkg.Arquivo)  ($tamanhoMB MB)"

    # ----- Instalacao -----
    Write-Info "Instalando silenciosamente..."
    try {
        $proc = Start-Process -FilePath $destino `
            -ArgumentList $pkg.Params `
            -Wait -PassThru -NoNewWindow -ErrorAction Stop

        switch ($proc.ExitCode) {
            0    {
                Write-Ok "Instalado com sucesso."
                $resumoInstalados.Add($label)
            }
            3010 {
                Write-Ok "Instalado com sucesso. (reinicio necessario)"
                $resumoInstalados.Add("$label  [reinicio necessario]")
                $script:precisaReiniciar = $true
            }
            1638 {
                Write-Ok "Versao mais recente ja instalada (codigo 1638)."
                $resumoInstalados.Add("$label  [versao mais recente ja presente]")
            }
            default {
                Write-Falha "Instalacao encerrada com codigo: $($proc.ExitCode)"
                $resumoFalhas.Add("$label  (codigo de saida: $($proc.ExitCode))")
            }
        }
    } catch {
        Write-Falha "Erro ao executar instalador: $_"
        $resumoFalhas.Add("$label  (erro ao executar)")
    }

    # Remover arquivo temporario
    Remove-Item -Path $destino -Force -ErrorAction SilentlyContinue
}

# =========================================================================
# ETAPA 5 - Relatorio final
# =========================================================================

Write-Host ''
Write-Host '================================================' -ForegroundColor Green
Write-Host '   RELATORIO FINAL                              ' -ForegroundColor Green
Write-Host '================================================' -ForegroundColor Green
Write-Host ''

$jaInstalados = $pacotes.Count - $faltando.Count
Write-Host "   Ja instalados antes  : $jaInstalados de $($pacotes.Count)" -ForegroundColor White
Write-Host "   Instalados agora     : $($resumoInstalados.Count)" -ForegroundColor White
Write-Host "   Falhas               : $($resumoFalhas.Count)" -ForegroundColor White
Write-Host ''

if ($resumoInstalados.Count -gt 0) {
    Write-Host '   Instalados nesta execucao:' -ForegroundColor Green
    foreach ($linha in $resumoInstalados) {
        Write-Host "   + $linha" -ForegroundColor Green
    }
    Write-Host ''
}

if ($resumoFalhas.Count -gt 0) {
    Write-Host '   Falhas:' -ForegroundColor Red
    foreach ($linha in $resumoFalhas) {
        Write-Host "   x $linha" -ForegroundColor Red
    }
    Write-Host ''
    Write-Aviso 'Para os pacotes com falha, verifique a conexao com a internet e execute novamente.'
    Write-Host ''
}

if ($precisaReiniciar) {
    Write-Host '   IMPORTANTE: Reinicie o computador para concluir a instalacao.' -ForegroundColor Yellow
    Write-Host ''
}

if ($resumoFalhas.Count -eq 0 -and $resumoInstalados.Count -ge 0) {
    Write-Host '   Todos os redistribuiveis Visual C++ necessarios estao instalados.' -ForegroundColor Green
    Write-Host ''
}

Write-Host ("   Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host '================================================' -ForegroundColor Green
Write-Host ''
