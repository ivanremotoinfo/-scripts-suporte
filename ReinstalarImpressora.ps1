# ReinstalarImpressora.ps1
# Remove e reinstala driver de impressora com limpeza completa

$ErrorActionPreference = 'Continue'

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
Write-Host '   Remocao e Limpeza de Driver de Impressora    ' -ForegroundColor Cyan
Write-Host '================================================' -ForegroundColor Cyan
Write-Host ("   Iniciado em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host ''

# Verificar privilegios de administrador
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
# ETAPA 1 - Listar impressoras instaladas
# =========================================================================

Write-Etapa '1. Listando impressoras instaladas...'
Write-Host ''

$impressoras = @(Get-Printer -ErrorAction SilentlyContinue | Sort-Object Name)

if ($impressoras.Count -eq 0) {
    Write-Aviso 'Nenhuma impressora encontrada no sistema.'
    Write-Host ''
    exit 0
}

$i = 1
foreach ($imp in $impressoras) {
    $tipo = if ($imp.Type -eq 'Connection') { 'Rede' } else { 'Local' }
    Write-Host ("   [{0,2}]  {1}" -f $i, $imp.Name) -ForegroundColor White
    Write-Host ("         Driver : {0}" -f $imp.DriverName) -ForegroundColor Gray
    Write-Host ("         Porta  : {0}  |  Tipo: {1}" -f $imp.PortName, $tipo) -ForegroundColor Gray
    Write-Host ''
    $i++
}

# Selecao da impressora
$selecao = $null
do {
    $entrada = Read-Host '   Digite o numero da impressora a remover (0 para cancelar)'
    if ($entrada -eq '0') {
        Write-Info 'Operacao cancelada pelo usuario.'
        exit 0
    }
    if ($entrada -match '^\d+$') {
        $num = [int]$entrada
        if ($num -ge 1 -and $num -le $impressoras.Count) {
            $selecao = $num
        } else {
            Write-Aviso "Numero invalido. Digite entre 1 e $($impressoras.Count)."
        }
    } else {
        Write-Aviso 'Digite apenas o numero correspondente.'
    }
} while ($null -eq $selecao)

$impressoraSel = $impressoras[$selecao - 1]
$nomeImpressora = $impressoraSel.Name
$nomeDriver     = $impressoraSel.DriverName
$nomePorta      = $impressoraSel.PortName

Write-Host ''
Write-Host '   Impressora selecionada:' -ForegroundColor Cyan
Write-Host "   Nome   : $nomeImpressora" -ForegroundColor White
Write-Host "   Driver : $nomeDriver"     -ForegroundColor White
Write-Host "   Porta  : $nomePorta"      -ForegroundColor White
Write-Host ''

$confirma = Read-Host '   Confirma a remocao completa? Esta operacao nao pode ser desfeita. (S/N)'
if ($confirma -notmatch '^[Ss]$') {
    Write-Info 'Operacao cancelada pelo usuario.'
    exit 0
}

# Verificar se outras impressoras usam o mesmo driver
$outrasComDriver = @(Get-Printer | Where-Object {
    $_.DriverName -eq $nomeDriver -and $_.Name -ne $nomeImpressora
})

$removerDriver = $true
if ($outrasComDriver.Count -gt 0) {
    Write-Host ''
    Write-Aviso "O driver '$nomeDriver' esta em uso por outras impressoras:"
    foreach ($outra in $outrasComDriver) { Write-Info "  - $($outra.Name)" }
    Write-Aviso 'O driver NAO sera removido para nao afetar as demais impressoras.'
    $removerDriver = $false
}

# =========================================================================
# ETAPA 2 - Coletar informacoes do driver no registro
# =========================================================================

Write-Etapa '2. Coletando informacoes do driver no registro antes da remocao...'

$arquivosDriver = [System.Collections.Generic.List[string]]::new()

$regAmbientes = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3\$nomeDriver",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-4\$nomeDriver",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows NT x86\Drivers\Version-3\$nomeDriver"
)

foreach ($regPath in $regAmbientes) {
    if (-not (Test-Path $regPath -ErrorAction SilentlyContinue)) { continue }
    $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    Write-Ok "Driver localizado: $regPath"
    foreach ($propNome in @('DriverPath', 'DataFile', 'ConfigFile', 'HelpFile')) {
        $val = $props.$propNome
        if ($val -and $val.Trim() -ne '') { $arquivosDriver.Add($val.Trim()) }
    }
    if ($props.DependentFiles) {
        foreach ($dep in $props.DependentFiles) {
            if ($dep -and $dep.Trim() -ne '') { $arquivosDriver.Add($dep.Trim()) }
        }
    }
}

if ($arquivosDriver.Count -gt 0) {
    Write-Info "$($arquivosDriver.Count) arquivo(s) de driver mapeados para limpeza posterior."
} else {
    Write-Aviso 'Nenhum arquivo de driver encontrado no registro (sera feita limpeza generica).'
}

# =========================================================================
# ETAPA 3 - Remover a impressora
# =========================================================================

Write-Etapa "3. Removendo a impressora '$nomeImpressora'..."

$impressoraRemovida = $false
try {
    Remove-Printer -Name $nomeImpressora -ErrorAction Stop
    Write-Ok "Impressora '$nomeImpressora' removida."
    $impressoraRemovida = $true
} catch {
    Write-Aviso "Falha pelo cmdlet: $_"
    Write-Info  'Tentando remocao via WMI...'
    try {
        $wmiPrinter = Get-WmiObject -Class Win32_Printer |
            Where-Object { $_.Name -eq $nomeImpressora }
        if ($wmiPrinter) {
            $wmiPrinter.Delete() | Out-Null
            Write-Ok "Impressora removida via WMI."
            $impressoraRemovida = $true
        } else {
            Write-Falha 'Impressora nao encontrada via WMI.'
        }
    } catch {
        Write-Falha "Erro na remocao via WMI: $_"
    }
}

# =========================================================================
# ETAPA 4 - Remover o driver
# =========================================================================

$driverRemovido = $false

if ($removerDriver) {
    Write-Etapa "4. Removendo driver '$nomeDriver' do sistema..."

    # Tentativa 1: cmdlet padrao
    try {
        Remove-PrinterDriver -Name $nomeDriver -ErrorAction Stop
        Write-Ok "Driver removido pelo cmdlet padrao."
        $driverRemovido = $true
    } catch {
        Write-Aviso "Metodo 1 falhou: $_"
    }

    # Tentativa 2: com RemoveFromDriverStore
    if (-not $driverRemovido) {
        try {
            Remove-PrinterDriver -Name $nomeDriver -RemoveFromDriverStore -ErrorAction Stop
            Write-Ok "Driver removido com RemoveFromDriverStore."
            $driverRemovido = $true
        } catch {
            Write-Aviso "Metodo 2 falhou: $_"
        }
    }

    # Tentativa 3: via WMI
    if (-not $driverRemovido) {
        Write-Info 'Tentando remocao via WMI...'
        try {
            $wmiDrivers = Get-WmiObject -Class Win32_PrinterDriver |
                Where-Object { $_.Name -like "$nomeDriver*" }
            if ($wmiDrivers) {
                $wmiDrivers | ForEach-Object { $_.Delete() | Out-Null }
                Write-Ok 'Driver removido via WMI.'
                $driverRemovido = $true
            } else {
                Write-Aviso 'Driver nao localizado via WMI.'
            }
        } catch {
            Write-Aviso "Metodo WMI falhou: $_"
        }
    }

    if (-not $driverRemovido) {
        Write-Aviso 'Remocao automatica do driver nao foi possivel.'
        Write-Info  'A limpeza manual de arquivos e registro sera realizada a seguir.'
    }
} else {
    Write-Etapa '4. Remocao de driver pulada (em uso por outras impressoras).'
}

# =========================================================================
# ETAPA 5 - Parar Spooler e limpar fila de impressao
# =========================================================================

Write-Etapa '5. Parando Spooler e limpando fila de impressao...'

try {
    Stop-Service -Name Spooler -Force -ErrorAction Stop
    Write-Ok 'Servico Spooler parado.'
} catch {
    Write-Falha "Erro ao parar Spooler: $_"
}

$spoolPrinters = "$env:SystemRoot\System32\spool\PRINTERS"
if (Test-Path $spoolPrinters) {
    $filaItens = @(Get-ChildItem -Path $spoolPrinters -ErrorAction SilentlyContinue)
    if ($filaItens.Count -gt 0) {
        Remove-Item -Path "$spoolPrinters\*" -Force -ErrorAction SilentlyContinue
        Write-Ok "Fila de impressao limpa ($($filaItens.Count) arquivo(s) removidos)."
    } else {
        Write-Info 'Fila de impressao ja estava vazia.'
    }
}

# =========================================================================
# ETAPA 6 - Limpar arquivos residuais do driver em spool\drivers
# =========================================================================

Write-Etapa '6. Limpando arquivos residuais do driver em spool\drivers...'

$spoolDirs = @(
    "$env:SystemRoot\System32\spool\drivers\x64\3",
    "$env:SystemRoot\System32\spool\drivers\x64\4",
    "$env:SystemRoot\System32\spool\drivers\W32X86\3"
)

$arquivosRemovidos   = 0
$arquivosNaoRemovidos = 0

foreach ($arquivo in $arquivosDriver) {
    $caminhoFinal = $null
    if ([System.IO.Path]::IsPathRooted($arquivo)) {
        $caminhoFinal = $arquivo
    } else {
        foreach ($dir in $spoolDirs) {
            $candidato = Join-Path $dir $arquivo
            if (Test-Path $candidato) { $caminhoFinal = $candidato; break }
        }
    }
    if (-not $caminhoFinal -or -not (Test-Path $caminhoFinal)) { continue }
    try {
        Remove-Item -Path $caminhoFinal -Force -ErrorAction Stop
        Write-Ok "Removido: $(Split-Path $caminhoFinal -Leaf)"
        $arquivosRemovidos++
    } catch {
        Write-Aviso "Nao foi possivel remover: $(Split-Path $caminhoFinal -Leaf)"
        $arquivosNaoRemovidos++
    }
}

if ($arquivosDriver.Count -eq 0) {
    Write-Info 'Nenhum arquivo especifico mapeado; arquivos ja foram removidos pelo sistema.'
} elseif ($arquivosRemovidos -eq 0 -and $arquivosNaoRemovidos -eq 0) {
    Write-Info 'Arquivos do driver ja removidos automaticamente na etapa anterior.'
} else {
    Write-Info "Resultado: $arquivosRemovidos removido(s), $arquivosNaoRemovidos nao removido(s)."
}

# =========================================================================
# ETAPA 7 - Limpar entradas residuais no registro
# =========================================================================

Write-Etapa '7. Limpando entradas residuais no registro...'

$regLimpos = 0

# Entrada da impressora em Print\Printers
$regImpressora = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers\$nomeImpressora"
if (Test-Path $regImpressora -ErrorAction SilentlyContinue) {
    try {
        Remove-Item -Path $regImpressora -Recurse -Force -ErrorAction Stop
        Write-Ok "Registro da impressora removido: Print\Printers\$nomeImpressora"
        $regLimpos++
    } catch {
        Write-Aviso "Nao foi possivel remover registro da impressora: $_"
    }
} else {
    Write-Info 'Entrada de impressora no registro ja removida.'
}

# Entrada no hive SOFTWARE (presente em algumas versoes)
$regSoftware = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\$nomeImpressora"
if (Test-Path $regSoftware -ErrorAction SilentlyContinue) {
    try {
        Remove-Item -Path $regSoftware -Recurse -Force -ErrorAction Stop
        Write-Ok 'Entrada adicional removida do registro (SOFTWARE hive).'
        $regLimpos++
    } catch {
        Write-Aviso "Nao foi possivel remover entrada SOFTWARE: $_"
    }
}

# Entradas do driver nos ambientes de impressao
if ($removerDriver) {
    foreach ($regPath in $regAmbientes) {
        if (-not (Test-Path $regPath -ErrorAction SilentlyContinue)) { continue }
        try {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
            Write-Ok "Registro do driver removido: ...$(($regPath -split 'Environments')[1])"
            $regLimpos++
        } catch {
            Write-Aviso "Nao foi possivel remover entrada de driver: $regPath"
        }
    }
}

if ($regLimpos -eq 0) {
    Write-Info 'Nenhuma entrada residual encontrada no registro.'
}

# =========================================================================
# ETAPA 8 - Reiniciar servico Spooler
# =========================================================================

Write-Etapa '8. Reiniciando servico Spooler...'

try {
    Start-Service -Name Spooler -ErrorAction Stop
    Start-Sleep -Seconds 2
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if ($spooler -and $spooler.Status -eq 'Running') {
        Write-Ok 'Servico Spooler reiniciado e em execucao.'
    } else {
        Write-Aviso "Servico Spooler status: $($spooler.Status). Verifique em services.msc."
    }
} catch {
    Write-Falha "Erro ao iniciar Spooler: $_"
    Write-Info  'Inicie manualmente: services.msc > Spooler > Iniciar'
}

# =========================================================================
# Relatorio final e orientacoes
# =========================================================================

Write-Host ''
Write-Host '================================================' -ForegroundColor Green
Write-Host '   LIMPEZA CONCLUIDA - COMO REINSTALAR          ' -ForegroundColor Green
Write-Host '================================================' -ForegroundColor Green
Write-Host ''
Write-Host '   Impressora removida  : ' -NoNewline -ForegroundColor White
Write-Host $nomeImpressora -ForegroundColor Yellow
Write-Host '   Driver               : ' -NoNewline -ForegroundColor White
if ($removerDriver -and $driverRemovido) {
    Write-Host "$nomeDriver  [removido]" -ForegroundColor Green
} elseif ($removerDriver -and -not $driverRemovido) {
    Write-Host "$nomeDriver  [limpeza manual realizada]" -ForegroundColor Yellow
} else {
    Write-Host "$nomeDriver  [mantido - em uso por outras impressoras]" -ForegroundColor DarkGray
}
Write-Host ''
Write-Host '   Para reinstalar a impressora:' -ForegroundColor Cyan
Write-Host ''
Write-Host '   1. Acesse o site do fabricante e busque o driver usando:' -ForegroundColor White
Write-Host "         Nome da impressora : $nomeImpressora" -ForegroundColor Yellow
Write-Host "         Nome do driver     : $nomeDriver"     -ForegroundColor Yellow
Write-Host ''
Write-Host '   2. Baixe o driver para Windows 10/11 64-bit' -ForegroundColor White
Write-Host ''
Write-Host '   3. Execute o instalador como Administrador' -ForegroundColor White
Write-Host ''
Write-Host '   4. Ou adicione via Painel de Controle:' -ForegroundColor White
Write-Host '      Dispositivos e Impressoras > Adicionar Impressora' -ForegroundColor Gray
Write-Host ''
Write-Host ("   Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host '================================================' -ForegroundColor Green
Write-Host ''
