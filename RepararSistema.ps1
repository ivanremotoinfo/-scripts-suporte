# RepararSistema.ps1
# Repara arquivos corrompidos do Windows usando SFC e DISM

$ErrorActionPreference = 'Continue'

$statusSFC           = 'nao executado'
$statusCheckHealth   = 'nao executado'
$statusScanHealth    = 'nao executado'
$statusRestoreHealth = 'nao executado'
$precisaReiniciar    = $false

# -------------------------------------------------------------------------
# Funcoes auxiliares
# -------------------------------------------------------------------------

function Write-Etapa { param([string]$t) Write-Host "`n>> $t" -ForegroundColor Cyan }
function Write-Ok    { param([string]$t) Write-Host '   [OK] ' -ForegroundColor Green  -NoNewline; Write-Host $t }
function Write-Aviso { param([string]$t) Write-Host '   [!]  ' -ForegroundColor Yellow -NoNewline; Write-Host $t }
function Write-Falha { param([string]$t) Write-Host '   [X]  ' -ForegroundColor Red    -NoNewline; Write-Host $t }
function Write-Info  { param([string]$t) Write-Host "   $t" -ForegroundColor Gray }

function Executar-DISM {
    param([string[]]$Argumentos)
    $linhas = [System.Collections.Generic.List[string]]::new()
    & dism.exe @Argumentos 2>&1 | ForEach-Object {
        $linha = $_.ToString()
        $linhas.Add($linha)
        Write-Host "   $linha" -ForegroundColor DarkGray
    }
    return $linhas -join ' '
}

# =========================================================================
# Cabecalho
# =========================================================================

Write-Host ''
Write-Host '================================================' -ForegroundColor Cyan
Write-Host '   Reparo de Arquivos Corrompidos do Windows    ' -ForegroundColor Cyan
Write-Host '================================================' -ForegroundColor Cyan
Write-Host ("   Iniciado em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host ''

# Verificar privilegios de administrador
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Falha 'Este script requer privilegios de Administrador.'
    Write-Info  'Clique com o botao direito no PowerShell e escolha "Executar como administrador".'
    Write-Host ''
    exit 1
}
Write-Ok 'Executando como Administrador.'

# =========================================================================
# ETAPA 1 - SFC /scannow
# =========================================================================

Write-Etapa '1/5  SFC /scannow - Verificando integridade dos arquivos do sistema...'
Write-Aviso 'Esta etapa varre todos os arquivos protegidos do Windows e pode demorar de 5 a 20 minutos.'
Write-Aviso 'Nao feche esta janela. Aguarde o progresso abaixo:'
Write-Host ''

& "$env:SystemRoot\System32\sfc.exe" /scannow

Write-Host ''

# Determinar resultado via CBS.log (SFC grava o resumo neste log)
$cbsLog = "$env:SystemRoot\Logs\CBS\CBS.log"
$sfcResultado = 'desconhecido'

if (Test-Path $cbsLog) {
    try {
        $cbsLinhas = Get-Content -Path $cbsLog -Tail 300 -Encoding Unicode -ErrorAction SilentlyContinue
        if (-not $cbsLinhas) {
            $cbsLinhas = Get-Content -Path $cbsLog -Tail 300 -ErrorAction SilentlyContinue
        }
        $cbsTexto = ($cbsLinhas -join ' ').ToLower()
        if ($cbsTexto -match 'did not find any integrity violations') {
            $sfcResultado = 'limpo'
        } elseif ($cbsTexto -match 'successfully repaired') {
            $sfcResultado = 'reparado'
        } elseif ($cbsTexto -match 'unable to fix' -or $cbsTexto -match 'unable to repair') {
            $sfcResultado = 'falhou'
        } elseif ($cbsTexto -match 'found corrupt files') {
            $sfcResultado = 'corrompido'
        } elseif ($cbsTexto -match 'could not perform') {
            $sfcResultado = 'erro'
        }
    } catch {}
}

switch ($sfcResultado) {
    'limpo'      {
        Write-Ok 'SFC: Nenhuma violacao de integridade encontrada.'
        $statusSFC = 'OK - sem violacoes'
    }
    'reparado'   {
        Write-Ok 'SFC: Arquivos corrompidos encontrados e reparados com sucesso.'
        $statusSFC = 'OK - arquivos reparados'
        $precisaReiniciar = $true
    }
    'falhou'     {
        Write-Falha 'SFC: Arquivos corrompidos encontrados, mas nao foi possivel reparar todos.'
        $statusSFC = 'ATENCAO - reparacao incompleta'
    }
    'corrompido' {
        Write-Aviso 'SFC: Arquivos corrompidos detectados.'
        $statusSFC = 'ATENCAO - corrupcao detectada'
    }
    'erro'       {
        Write-Falha 'SFC: Nao foi possivel executar a operacao solicitada.'
        $statusSFC = 'ERRO - operacao nao concluida'
    }
    default      {
        Write-Aviso 'SFC: Resultado nao determinado. Consulte: %windir%\Logs\CBS\CBS.log'
        $statusSFC = 'inconclusivo'
    }
}

# =========================================================================
# ETAPA 2 - DISM CheckHealth
# =========================================================================

Write-Etapa '2/5  DISM CheckHealth - Verificando estado da imagem do sistema...'
Write-Aviso 'Verificacao rapida dos metadados da imagem. Aguarde...'
Write-Host ''

$checkTexto = Executar-DISM -Argumentos @('/Online', '/Cleanup-Image', '/CheckHealth')

Write-Host ''
$checkProblema = $false

if ($checkTexto -match 'No component store corruption detected') {
    Write-Ok 'CheckHealth: Sem corrupcao detectada na imagem do sistema.'
    $statusCheckHealth = 'OK - sem corrupcao'
} elseif ($checkTexto -match 'component store is repairable' -or $checkTexto -match 'component store is corrupted') {
    Write-Aviso 'CheckHealth: Corrupcao detectada. ScanHealth sera executado a seguir.'
    $statusCheckHealth = 'ATENCAO - corrupcao detectada'
    $checkProblema = $true
} else {
    Write-Aviso 'CheckHealth: Resultado inconclusivo. Prosseguindo com ScanHealth por precaucao.'
    $statusCheckHealth = 'inconclusivo'
    $checkProblema = $true
}

# =========================================================================
# ETAPA 3 - DISM ScanHealth (condicional)
# =========================================================================

$scanProblema = $false

if ($checkProblema) {
    Write-Etapa '3/5  DISM ScanHealth - Verificacao aprofundada da imagem do sistema...'
    Write-Aviso 'Esta etapa realiza uma varredura completa e pode demorar varios minutos. Aguarde...'
    Write-Host ''

    $scanTexto = Executar-DISM -Argumentos @('/Online', '/Cleanup-Image', '/ScanHealth')

    Write-Host ''

    if ($scanTexto -match 'No component store corruption detected') {
        Write-Ok 'ScanHealth: Nenhuma corrupcao confirmada.'
        $statusScanHealth = 'OK - sem corrupcao'
    } elseif ($scanTexto -match 'component store is repairable' -or $scanTexto -match 'component store is corrupted') {
        Write-Aviso 'ScanHealth: Corrupcao confirmada. RestoreHealth sera executado a seguir.'
        $statusScanHealth = 'ATENCAO - corrupcao confirmada'
        $scanProblema = $true
    } else {
        Write-Aviso 'ScanHealth: Resultado inconclusivo. Tentando RestoreHealth por precaucao.'
        $statusScanHealth = 'inconclusivo'
        $scanProblema = $true
    }
} else {
    Write-Etapa '3/5  DISM ScanHealth - Pulado.'
    Write-Info 'CheckHealth nao detectou corrupcao. Verificacao aprofundada dispensada.'
    $statusScanHealth = 'pulado - sem necessidade'
}

# =========================================================================
# ETAPA 4 - DISM RestoreHealth (condicional)
# =========================================================================

if ($scanProblema) {
    Write-Etapa '4/5  DISM RestoreHealth - Reparando imagem do sistema...'
    Write-Aviso 'Esta etapa pode demorar de 10 a 30 minutos e requer conexao com a internet.'
    Write-Aviso 'NAO feche esta janela. Aguarde a conclusao:'
    Write-Host ''

    $restoreTexto = Executar-DISM -Argumentos @('/Online', '/Cleanup-Image', '/RestoreHealth')

    Write-Host ''

    if ($restoreTexto -match 'The restore operation completed successfully' -or
        $restoreTexto -match 'The operation completed successfully') {
        Write-Ok 'RestoreHealth: Imagem do sistema reparada com sucesso.'
        $statusRestoreHealth = 'OK - reparado com sucesso'
        $precisaReiniciar = $true
    } elseif ($restoreTexto -match 'Error' -or $restoreTexto -match 'Erro') {
        Write-Falha 'RestoreHealth: Erro durante o reparo. Verifique a conexao com a internet.'
        Write-Info  'Dica: conecte a internet e execute o script novamente, ou use uma midia ISO do Windows.'
        $statusRestoreHealth = 'FALHA - erro durante o reparo'
    } else {
        Write-Aviso 'RestoreHealth: Resultado inconclusivo. Verifique o log do DISM.'
        $statusRestoreHealth = 'inconclusivo'
    }
} else {
    Write-Etapa '4/5  DISM RestoreHealth - Pulado.'
    Write-Info 'Nenhuma corrupcao confirmada nas etapas anteriores. Reparo dispensado.'
    $statusRestoreHealth = 'pulado - sem necessidade'
}

# =========================================================================
# ETAPA 5 - Verificar necessidade de reinicializacao
# =========================================================================

Write-Etapa '5/5  Verificando necessidade de reinicializacao...'

$chavesReboot = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending'
)

foreach ($chave in $chavesReboot) {
    if (Test-Path $chave -ErrorAction SilentlyContinue) {
        $precisaReiniciar = $true
        break
    }
}

$sessionMgr = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
    -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
if ($sessionMgr -and $sessionMgr.PendingFileRenameOperations) {
    $precisaReiniciar = $true
}

if ($precisaReiniciar) {
    Write-Aviso 'Reinicializacao necessaria para concluir as reparacoes.'
} else {
    Write-Ok 'Nenhuma reinicializacao pendente detectada.'
}

# =========================================================================
# RELATORIO FINAL
# =========================================================================

Write-Host ''
Write-Host '================================================' -ForegroundColor Green
Write-Host '   RELATORIO FINAL                              ' -ForegroundColor Green
Write-Host '================================================' -ForegroundColor Green

$corSFC = if ($statusSFC -match '^OK') { 'Green' } elseif ($statusSFC -match 'ATENCAO|FALHA|ERRO') { 'Yellow' } else { 'Gray' }
$corCH  = if ($statusCheckHealth -match '^OK') { 'Green' } elseif ($statusCheckHealth -match 'ATENCAO|FALHA') { 'Yellow' } else { 'Gray' }
$corSH  = if ($statusScanHealth -match '^OK|^pulado') { 'Green' } elseif ($statusScanHealth -match 'ATENCAO|FALHA') { 'Yellow' } else { 'Gray' }
$corRH  = if ($statusRestoreHealth -match '^OK|^pulado') { 'Green' } elseif ($statusRestoreHealth -match 'FALHA') { 'Red' } elseif ($statusRestoreHealth -match 'ATENCAO') { 'Yellow' } else { 'Gray' }

Write-Host '   SFC /scannow       : ' -NoNewline -ForegroundColor White; Write-Host $statusSFC           -ForegroundColor $corSFC
Write-Host '   DISM CheckHealth   : ' -NoNewline -ForegroundColor White; Write-Host $statusCheckHealth   -ForegroundColor $corCH
Write-Host '   DISM ScanHealth    : ' -NoNewline -ForegroundColor White; Write-Host $statusScanHealth    -ForegroundColor $corSH
Write-Host '   DISM RestoreHealth : ' -NoNewline -ForegroundColor White; Write-Host $statusRestoreHealth -ForegroundColor $corRH

Write-Host ''
Write-Host '   Recomendacoes:' -ForegroundColor Cyan

if ($precisaReiniciar) {
    Write-Host '   - REINICIE o computador para aplicar as reparacoes concluidas.' -ForegroundColor Yellow
}

if ($statusRestoreHealth -like '*FALHA*') {
    Write-Host '   - Verifique a conexao com a internet e execute o script novamente.' -ForegroundColor Yellow
    Write-Host '   - Alternativa: use DISM com uma ISO do Windows:' -ForegroundColor Yellow
    Write-Host '     dism /Online /Cleanup-Image /RestoreHealth /Source:X:\Sources\install.wim' -ForegroundColor White
}

if ($statusSFC -like '*incompleta*' -or $statusSFC -like '*ERRO*') {
    Write-Host '   - Execute o SFC novamente apos reiniciar para verificar se foi resolvido.' -ForegroundColor Yellow
}

if ($statusSFC -match '^OK' -and $statusCheckHealth -match '^OK' -and -not $precisaReiniciar) {
    Write-Host '   - Nenhuma acao adicional necessaria. Sistema verificado e em bom estado.' -ForegroundColor Green
}

Write-Host ''
Write-Host '   Logs detalhados disponíveis em:' -ForegroundColor DarkGray
Write-Host "   - $env:SystemRoot\Logs\CBS\CBS.log" -ForegroundColor DarkGray
Write-Host "   - $env:SystemRoot\Logs\DISM\dism.log" -ForegroundColor DarkGray
Write-Host ''
Write-Host ("   Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host '================================================' -ForegroundColor Green
Write-Host ''
