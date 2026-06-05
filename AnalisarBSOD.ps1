# AnalisarBSOD.ps1
# Analisa e identifica causas de Tela Azul (BSOD) no Windows

$ErrorActionPreference = 'Continue'
$dataLimite = (Get-Date).AddDays(-30)

# -------------------------------------------------------------------------
# Funcoes auxiliares
# -------------------------------------------------------------------------

function Write-Etapa { param([string]$t) Write-Host "`n>> $t" -ForegroundColor Cyan }
function Write-Ok    { param([string]$t) Write-Host '   [OK] ' -ForegroundColor Green  -NoNewline; Write-Host $t }
function Write-Aviso { param([string]$t) Write-Host '   [!]  ' -ForegroundColor Yellow -NoNewline; Write-Host $t }
function Write-Falha { param([string]$t) Write-Host '   [X]  ' -ForegroundColor Red    -NoNewline; Write-Host $t }
function Write-Info  { param([string]$t) Write-Host "   $t" -ForegroundColor Gray }
function Write-Dest  { param([string]$t) Write-Host "   $t" -ForegroundColor White }

function Format-CodBSOD {
    param([string]$Raw)
    $Raw = $Raw.Trim()
    if ($Raw -match '^0x[0-9a-fA-F]+$') {
        $val = [Convert]::ToUInt64($Raw, 16)
    } elseif ($Raw -match '^\d+$') {
        $val = [uint64]$Raw
    } else {
        return $Raw.ToUpper()
    }
    return '0x' + $val.ToString('X8')
}

function Get-NomeBSOD {
    param([string]$Codigo)
    $c = $bsodCodigos[$Codigo]
    if ($c) { return $c.Nome } else { return 'Codigo nao catalogado' }
}

# =========================================================================
# Dicionario de codigos BSOD (explicacoes em portugues)
# =========================================================================

$bsodCodigos = @{
    '0x0000000A' = @{
        Nome    = 'IRQL_NOT_LESS_OR_EQUAL'
        Causa   = 'Driver ou componente acessou memoria em nivel de interrupcao (IRQL) invalido.'
        Origem  = 'Driver defeituoso ou RAM com falha'
        Solucoes = @(
            'Atualize drivers de chipset, rede e USB'
            'Teste a RAM com Windows Memory Diagnostic ou memtest86'
            'Execute: verifier /standard /all para identificar driver causador'
        )
    }
    '0x00000019' = @{
        Nome    = 'BAD_POOL_HEADER'
        Causa   = 'Cabecalho do pool de memoria do kernel foi corrompido por driver com bug.'
        Origem  = 'Driver com vazamento ou corrupcao de memoria'
        Solucoes = @(
            'Desinstale programas/drivers recentemente instalados'
            'Execute: verifier /standard /all'
            'Teste RAM com memtest86'
        )
    }
    '0x0000001A' = @{
        Nome    = 'MEMORY_MANAGEMENT'
        Causa   = 'Falha grave no gerenciamento de memoria do kernel do Windows.'
        Origem  = 'RAM com defeito; SSD/HDD com erros; driver corrompido'
        Solucoes = @(
            'Teste RAM com memtest86 (pelo menos 2 passagens completas)'
            'Execute chkdsk /f /r no disco do sistema'
            'Verifique saude do SSD/HDD com ferramentas SMART'
        )
    }
    '0x0000001E' = @{
        Nome    = 'KMODE_EXCEPTION_NOT_HANDLED'
        Causa   = 'Driver ou aplicativo em modo kernel gerou excecao nao tratada pelo sistema.'
        Origem  = 'Driver incompativel ou com bug'
        Solucoes = @(
            'Verifique os 4 parametros do erro para identificar o modulo causador'
            'Desative ou remova drivers recentemente instalados'
            'Execute verifier.exe para rastrear o driver problematico'
        )
    }
    '0x00000024' = @{
        Nome    = 'NTFS_FILE_SYSTEM'
        Causa   = 'Erro critico no driver do sistema de arquivos NTFS.'
        Origem  = 'Corrupcao no disco; setores defeituosos no HDD/SSD'
        Solucoes = @(
            'Execute: chkdsk /f /r /x C: como Administrador'
            'Verifique saude do disco pelo SMART'
            'Se erros persistirem, considere backup e formatacao'
        )
    }
    '0x0000003B' = @{
        Nome    = 'SYSTEM_SERVICE_EXCEPTION'
        Causa   = 'Excecao nao tratada durante execucao de rotina de servico do sistema.'
        Origem  = 'Driver com bug; arquivo do sistema corrompido'
        Solucoes = @(
            'Execute: sfc /scannow como Administrador'
            'Identifique o modulo causador pelo segundo parametro do erro'
            'Atualize Windows e drivers de sistema'
        )
    }
    '0x00000050' = @{
        Nome    = 'PAGE_FAULT_IN_NONPAGED_AREA'
        Causa   = 'Acesso a pagina de memoria invalida ou inexistente em area nao paginavel.'
        Origem  = 'RAM com defeito; driver defeituoso; arquivo de sistema corrompido'
        Solucoes = @(
            'Teste RAM com memtest86'
            'Execute: sfc /scannow'
            'Verifique antivirus e drivers de filtro do sistema'
        )
    }
    '0x00000074' = @{
        Nome    = 'BAD_SYSTEM_CONFIG_INFO'
        Causa   = 'Informacoes de configuracao do sistema (BCD ou registro) estao corrompidas.'
        Origem  = 'Corrupcao no registro; falha de energia durante boot; disco com erros'
        Solucoes = @(
            'Execute Reparacao de Inicializacao pelo Windows PE/USB'
            'Use: bootrec /fixmbr && bootrec /fixboot && bootrec /rebuildbcd'
            'Execute sfc /scannow no ambiente de recuperacao'
        )
    }
    '0x0000007A' = @{
        Nome    = 'KERNEL_DATA_INPAGE_ERROR'
        Causa   = 'Falha ao ler dados do arquivo de paginacao (pagefile) a partir do disco.'
        Origem  = 'Setores defeituosos; RAM com falha; cabo SATA/NVMe danificado'
        Solucoes = @(
            'Execute: chkdsk /f /r'
            'Verifique saude do disco via SMART'
            'Teste RAM com memtest86'
            'Verifique e substitua cabo SATA se necessario'
        )
    }
    '0x0000007B' = @{
        Nome    = 'INACCESSIBLE_BOOT_DEVICE'
        Causa   = 'Windows nao conseguiu acessar o dispositivo de boot na inicializacao.'
        Origem  = 'Mudanca de modo SATA no BIOS (IDE/AHCI/RAID); driver de controlador'
        Solucoes = @(
            'Verifique modo SATA no BIOS/UEFI (use AHCI)'
            'Execute Reparacao de Inicializacao pelo DVD/USB do Windows'
            'Verifique conexoes fisicas do disco'
        )
    }
    '0x0000007E' = @{
        Nome    = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED'
        Causa   = 'Thread do sistema gerou excecao que nao foi tratada pelo sistema operacional.'
        Origem  = 'Driver incompativel; hardware defeituoso'
        Solucoes = @(
            'Identifique o modulo causador pelo segundo parametro do erro'
            'Atualize ou reinstale o driver identificado'
            'Execute verifier.exe'
        )
    }
    '0x0000007F' = @{
        Nome    = 'UNEXPECTED_KERNEL_MODE_TRAP'
        Causa   = 'Interrupcao de hardware inesperada na CPU em modo kernel.'
        Origem  = 'Hardware defeituoso (CPU/RAM/placa-mae); overclocking instavel'
        Solucoes = @(
            'Desative qualquer overclocking e redefina BIOS para padrao'
            'Teste RAM com memtest86'
            'Verifique temperatura da CPU'
        )
    }
    '0x00000096' = @{
        Nome    = 'INVALID_WORK_QUEUE_ITEM'
        Causa   = 'Item de fila de trabalho invalido encontrado pelo kernel.'
        Origem  = 'Driver com bug'
        Solucoes = @('Atualize todos os drivers do sistema', 'Execute verifier.exe')
    }
    '0x0000009F' = @{
        Nome    = 'DRIVER_POWER_STATE_FAILURE'
        Causa   = 'Driver em estado de energia inconsistente durante transicao de energia (sleep/hibernate).'
        Origem  = 'Driver de USB, rede ou chipset incompativel com gerenciamento de energia'
        Solucoes = @(
            'Atualize drivers de rede, USB e chipset'
            'Desative hibernacao: powercfg /h off'
            'Desconecte dispositivos USB durante testes de sleep'
        )
    }
    '0x000000D1' = @{
        Nome    = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL'
        Causa   = 'Driver tentou acessar pagina de memoria com nivel de interrupcao (IRQL) elevado demais.'
        Origem  = 'Driver de rede, USB ou antivirus com bug'
        Solucoes = @(
            'Verifique o nome do driver no segundo parametro do erro'
            'Atualize ou desinstale o driver identificado'
            'Verifique especialmente drivers de antivirus e VPN'
        )
    }
    '0x000000EF' = @{
        Nome    = 'CRITICAL_PROCESS_DIED'
        Causa   = 'Processo critico do Windows encerrou de forma inesperada.'
        Origem  = 'Arquivo do sistema corrompido; driver com bug; malware'
        Solucoes = @(
            'Execute: sfc /scannow'
            'Execute: DISM /Online /Cleanup-Image /RestoreHealth'
            'Verifique malware com Windows Defender offline'
        )
    }
    '0x00000101' = @{
        Nome    = 'CLOCK_WATCHDOG_TIMEOUT'
        Causa   = 'O processador nao recebeu interrupcao de relogio esperada no tempo limite.'
        Origem  = 'Overclocking instavel; defeito em CPU ou placa-mae; driver de chipset'
        Solucoes = @(
            'Desative overclocking e redefina BIOS para valores padrao'
            'Atualize driver de chipset'
            'Verifique temperatura da CPU (deve ficar abaixo de 85C sob carga)'
        )
    }
    '0x00000116' = @{
        Nome    = 'VIDEO_TDR_FAILURE'
        Causa   = 'Driver de video (GPU) nao respondeu ao sistema e nao conseguiu se recuperar.'
        Origem  = 'Driver de GPU desatualizado; GPU superaquecendo; GPU com defeito'
        Solucoes = @(
            'Use DDU (Display Driver Uninstaller) em modo seguro e reinstale o driver da GPU'
            'Verifique temperatura da GPU (deve ficar abaixo de 90C)'
            'Teste a GPU com FurMark para identificar instabilidade termica'
        )
    }
    '0x00000124' = @{
        Nome    = 'WHEA_UNCORRECTABLE_ERROR'
        Causa   = 'Erro de hardware nao corrigivel detectado pela arquitetura WHEA.'
        Origem  = 'CPU defeituosa; RAM com falha; placa-mae; superaquecimento; overclocking'
        Solucoes = @(
            'Desative qualquer overclocking imediatamente'
            'Verifique temperaturas de CPU e chipset'
            'Teste RAM com memtest86'
            'Pode indicar hardware fisicamente defeituoso - consulte assistencia tecnica'
        )
    }
    '0x00000133' = @{
        Nome    = 'DPC_WATCHDOG_VIOLATION'
        Causa   = 'O DPC Watchdog detectou que uma rotina DPC ou ISR excedeu o tempo limite.'
        Origem  = 'Driver de SSD/NVMe; driver de rede; firmware desatualizado'
        Solucoes = @(
            'Atualize firmware do SSD/NVMe pelo site do fabricante'
            'Atualize driver do controlador de armazenamento'
            'Atualize driver de rede e chipset'
        )
    }
    '0x00000154' = @{
        Nome    = 'UNEXPECTED_STORE_EXCEPTION'
        Causa   = 'O componente de armazenamento (geralmente SSD/NVMe) gerou excecao inesperada.'
        Origem  = 'SSD/NVMe com defeito ou firmware desatualizado'
        Solucoes = @(
            'Atualize firmware do SSD/NVMe'
            'Verifique saude do disco via SMART'
            'Considere substituicao do SSD se erros persistirem'
        )
    }
    '0x0000013A' = @{
        Nome    = 'KERNEL_MODE_HEAP_CORRUPTION'
        Causa   = 'Corrupcao no heap de memoria do modo kernel detectada.'
        Origem  = 'Driver com bug de corrupcao de memoria'
        Solucoes = @(
            'Execute verifier.exe com todas as verificacoes'
            'Atualize todos os drivers do sistema'
            'Analise o dump com WinDbg para identificar o driver causador'
        )
    }
}

# =========================================================================
# Cabecalho
# =========================================================================

Write-Host ''
Write-Host '================================================' -ForegroundColor Cyan
Write-Host '   Analisador de BSOD - Tela Azul do Windows   ' -ForegroundColor Cyan
Write-Host '================================================' -ForegroundColor Cyan
Write-Host ("   Iniciado em : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host ("   Periodo     : ultimos 30 dias") -ForegroundColor DarkGray
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

# =========================================================================
# ETAPA 1 - Verificar arquivos de dump de memoria
# =========================================================================

Write-Etapa '1/9  Verificando arquivos de dump de memoria...'
Write-Host ''

$dumpsMini   = @()
$dumpMemoria = $null
$totalDumps  = 0

$miniDumpDir = 'C:\Windows\Minidump'
if (Test-Path $miniDumpDir) {
    $dumpsMini = @(Get-ChildItem -Path $miniDumpDir -Filter '*.dmp' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)
    if ($dumpsMini.Count -gt 0) {
        Write-Ok "$($dumpsMini.Count) arquivo(s) de minidump encontrado(s) em $miniDumpDir"
        $totalDumps += $dumpsMini.Count
        $dumpsMini | Select-Object -First 10 | ForEach-Object {
            $tamanho = '{0:N0} KB' -f ($_.Length / 1KB)
            Write-Dest ("   {0}  {1,8}  {2}" -f $_.LastWriteTime.ToString('dd/MM/yyyy HH:mm'), $tamanho, $_.Name)
        }
        if ($dumpsMini.Count -gt 10) {
            Write-Info "   ... e mais $($dumpsMini.Count - 10) arquivo(s) mais antigos."
        }
    } else {
        Write-Info 'Nenhum minidump encontrado em C:\Windows\Minidump.'
    }
} else {
    Write-Info 'Pasta Minidump nao existe (configuracao de dump pode nao gerar minidumps).'
}

$memDmpPath = 'C:\Windows\MEMORY.DMP'
if (Test-Path $memDmpPath) {
    $memDmpInfo = Get-Item $memDmpPath
    $tamanhoGB  = '{0:N2} GB' -f ($memDmpInfo.Length / 1GB)
    Write-Ok "Dump completo encontrado: MEMORY.DMP  ($tamanhoGB)  -  $($memDmpInfo.LastWriteTime.ToString('dd/MM/yyyy HH:mm'))"
    $dumpMemoria = $memDmpInfo
    $totalDumps++
} else {
    Write-Info 'Arquivo MEMORY.DMP nao encontrado.'
}

if ($totalDumps -eq 0) {
    Write-Aviso 'Nenhum arquivo de dump encontrado. BSODs podem nao estar configurados para gerar dumps.'
    Write-Info  'Para habilitar: Painel de Controle > Sistema > Configuracoes Avancadas > Inicializacao e Recuperacao'
    Write-Info  'Selecione: Despejo de memoria pequeno (256 KB) ou Despejo de memoria do kernel'
}

# =========================================================================
# ETAPA 2 - Ler log de eventos (BugCheck, Kernel-Power ID 41, EventLog ID 6008)
# =========================================================================

Write-Etapa '2/9  Lendo log de eventos do sistema (ultimos 30 dias)...'
Write-Host ''

$eventosBSOD     = [System.Collections.Generic.List[PSObject]]::new()
$eventosKernel41 = [System.Collections.Generic.List[PSObject]]::new()
$eventosShutdown = [System.Collections.Generic.List[PSObject]]::new()

# BugCheck events (ID 1001 / provider BugCheck) - contem o stop code
try {
    $bugcheckEventos = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'BugCheck'
        StartTime    = $dataLimite
    } -ErrorAction SilentlyContinue
    if ($bugcheckEventos) {
        foreach ($ev in $bugcheckEventos) { $eventosBSOD.Add($ev) }
    }
} catch {}

# Tambem capturar pelo ID 1001 no System log caso o provider varie
try {
    $ev1001 = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 1001
        StartTime = $dataLimite
    } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'BugCheck|WindowsErrorReporting|WER' }
    if ($ev1001) {
        foreach ($ev in $ev1001) {
            if (-not ($eventosBSOD | Where-Object { $_.RecordId -eq $ev.RecordId })) {
                $eventosBSOD.Add($ev)
            }
        }
    }
} catch {}

# Kernel-Power ID 41 - desligamento inesperado (acompanha BSODs)
try {
    $kp41 = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-Kernel-Power'
        Id           = 41
        StartTime    = $dataLimite
    } -ErrorAction SilentlyContinue
    if ($kp41) { foreach ($ev in $kp41) { $eventosKernel41.Add($ev) } }
} catch {}

# EventLog ID 6008 - desligamento inesperado anterior
try {
    $ev6008 = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 6008
        StartTime = $dataLimite
    } -ErrorAction SilentlyContinue
    if ($ev6008) { foreach ($ev in $ev6008) { $eventosShutdown.Add($ev) } }
} catch {}

Write-Info "Eventos BugCheck encontrados : $($eventosBSOD.Count)"
Write-Info "Eventos Kernel-Power (ID 41) : $($eventosKernel41.Count)"
Write-Info "Eventos shutdown inesperado  : $($eventosShutdown.Count)"

# =========================================================================
# ETAPA 3 - Identificar codigos de erro BSOD mais recentes e frequentes
# =========================================================================

Write-Etapa '3/9  Identificando codigos de erro BSOD...'
Write-Host ''

$codigosEncontrados = [System.Collections.Generic.List[PSObject]]::new()

foreach ($ev in $eventosBSOD) {
    $codBruto = $null
    $param1   = $null

    # Tentativa 1: parsear XML estruturado
    try {
        $xml  = [xml]$ev.ToXml()
        $dados = $xml.Event.EventData.Data
        foreach ($d in $dados) {
            $attrName = if ($d.Name) { $d.Name } else { '' }
            if ($attrName -eq 'BugcheckCode') {
                $codBruto = $d.'#text'
            }
            if ($attrName -eq 'BugcheckParameter1') {
                $param1 = $d.'#text'
            }
        }
    } catch {}

    # Tentativa 2: regex na mensagem de texto
    if (-not $codBruto -or $codBruto -eq '0') {
        $matchHex = [regex]::Match($ev.Message, '0x[0-9a-fA-F]{8}')
        if ($matchHex.Success) {
            $codBruto = $matchHex.Value
        }
    }

    if ($codBruto) {
        $codFormatado = Format-CodBSOD -Raw $codBruto
        $codigosEncontrados.Add([PSCustomObject]@{
            Codigo    = $codFormatado
            Nome      = Get-NomeBSOD -Codigo $codFormatado
            Data      = $ev.TimeCreated
            Param1    = if ($param1) { Format-CodBSOD -Raw $param1 } else { '-' }
            EventoID  = $ev.Id
            RecordId  = $ev.RecordId
        })
    } else {
        # Registrar sem codigo conhecido
        $codigosEncontrados.Add([PSCustomObject]@{
            Codigo   = 'DESCONHECIDO'
            Nome     = 'Codigo nao extraido do evento'
            Data     = $ev.TimeCreated
            Param1   = '-'
            EventoID = $ev.Id
            RecordId = $ev.RecordId
        })
    }
}

# Tambem capturar codigos dos eventos Kernel-Power 41 se tiverem BugcheckCode
foreach ($ev in $eventosKernel41) {
    try {
        $xml  = [xml]$ev.ToXml()
        $dados = $xml.Event.EventData.Data
        $bugCode = $null
        foreach ($d in $dados) {
            if ($d.Name -eq 'BugcheckCode') { $bugCode = $d.'#text' }
        }
        if ($bugCode -and $bugCode -ne '0') {
            $codF = Format-CodBSOD -Raw $bugCode
            $jaExiste = $codigosEncontrados | Where-Object {
                [Math]::Abs(($_.Data - $ev.TimeCreated).TotalMinutes) -lt 5
            }
            if (-not $jaExiste) {
                $codigosEncontrados.Add([PSCustomObject]@{
                    Codigo   = $codF
                    Nome     = Get-NomeBSOD -Codigo $codF
                    Data     = $ev.TimeCreated
                    Param1   = '-'
                    EventoID = $ev.Id
                    RecordId = $ev.RecordId
                })
            }
        }
    } catch {}
}

$codigosOrdenados = $codigosEncontrados | Sort-Object Data -Descending

if ($codigosOrdenados.Count -eq 0) {
    Write-Ok 'Nenhum BSOD encontrado nos ultimos 30 dias. Sistema aparentemente estavel.'
} else {
    Write-Aviso "$($codigosOrdenados.Count) ocorrencia(s) de BSOD encontrada(s) nos ultimos 30 dias."
    Write-Host ''

    # Frequencia por codigo
    $frequencia = $codigosEncontrados | Group-Object Codigo |
        Sort-Object Count -Descending

    Write-Dest '   Codigos mais frequentes:'
    foreach ($g in $frequencia) {
        $nomeCode = Get-NomeBSOD -Codigo $g.Name
        $ultimaVez = ($g.Group | Sort-Object Data -Descending | Select-Object -First 1).Data
        $cor = if ($g.Count -ge 3) { 'Red' } elseif ($g.Count -ge 2) { 'Yellow' } else { 'White' }
        Write-Host ("   {0}  x{1,-3}  {2}  ultima: {3}" -f `
            $g.Name, $g.Count, $nomeCode, $ultimaVez.ToString('dd/MM/yyyy HH:mm')) -ForegroundColor $cor
    }
}

# =========================================================================
# ETAPA 4 - Explicar cada codigo de erro encontrado
# =========================================================================

$codigosUnicos = @($codigosEncontrados | Select-Object -ExpandProperty Codigo -Unique |
    Where-Object { $_ -ne 'DESCONHECIDO' })

if ($codigosUnicos.Count -gt 0) {
    Write-Etapa '4/9  Explicacao dos codigos de erro encontrados...'
    Write-Host ''

    foreach ($cod in $codigosUnicos) {
        $info = $bsodCodigos[$cod]
        $corCod = 'Red'
        Write-Host ("   CODIGO: $cod") -ForegroundColor $corCod
        if ($info) {
            Write-Host ("   Nome   : $($info.Nome)") -ForegroundColor Yellow
            Write-Host ("   Causa  : $($info.Causa)") -ForegroundColor White
            Write-Host ("   Origem : $($info.Origem)") -ForegroundColor Gray
        } else {
            Write-Host "   Nome   : Codigo nao catalogado neste script." -ForegroundColor Gray
            Write-Host "   Causa  : Consulte https://learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-code-reference2" -ForegroundColor Gray
        }
        Write-Host ''
    }
} else {
    Write-Etapa '4/9  Explicacao de codigos - nenhum codigo para analisar.'
}

# =========================================================================
# ETAPA 5 - Verificar drivers suspeitos cruzados com data dos BSODs
# =========================================================================

Write-Etapa '5/9  Verificando drivers suspeitos recentemente instalados ou atualizados...'
Write-Host ''

$datasBSOD = @($codigosEncontrados | Select-Object -ExpandProperty Data)

$driversRecentes = Get-WmiObject Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
    Where-Object { $_.DriverDate -and $_.DriverDate -ne '' -and $_.DeviceName } |
    ForEach-Object {
        try {
            $dataDrv = [Management.ManagementDateTimeConverter]::ToDateTime($_.DriverDate)
            [PSCustomObject]@{
                Dispositivo = $_.DeviceName
                Fabricante  = if ($_.DriverProviderName) { $_.DriverProviderName } else { 'Desconhecido' }
                Versao      = $_.DriverVersion
                DataDriver  = $dataDrv
                InfFile     = $_.InfName
            }
        } catch { $null }
    } | Where-Object { $_ -and $_.DataDriver -gt (Get-Date).AddDays(-60) } |
    Sort-Object DataDriver -Descending

$driversSuspeitos = [System.Collections.Generic.List[PSObject]]::new()

foreach ($drv in $driversRecentes) {
    foreach ($dataCrash in $datasBSOD) {
        $diff = ($dataCrash - $drv.DataDriver).TotalDays
        if ($diff -ge 0 -and $diff -le 14) {
            if (-not ($driversSuspeitos | Where-Object { $_.Dispositivo -eq $drv.Dispositivo })) {
                $drv | Add-Member -NotePropertyName 'DiasAntesBSOD' -NotePropertyValue ([math]::Round($diff, 1)) -Force
                $driversSuspeitos.Add($drv)
            }
        }
    }
}

if ($driversSuspeitos.Count -gt 0) {
    Write-Aviso "$($driversSuspeitos.Count) driver(s) instalado(s)/atualizado(s) nos 14 dias anteriores a um BSOD:"
    Write-Host ''
    foreach ($drv in ($driversSuspeitos | Sort-Object DiasAntesBSOD)) {
        Write-Host ("   [SUSPEITO] $($drv.Dispositivo)") -ForegroundColor Yellow
        Write-Host ("   Fabricante : $($drv.Fabricante)") -ForegroundColor Gray
        Write-Host ("   Versao     : $($drv.Versao)") -ForegroundColor Gray
        Write-Host ("   Instalado  : $($drv.DataDriver.ToString('dd/MM/yyyy'))  ($($drv.DiasAntesBSOD) dia(s) antes do BSOD)") -ForegroundColor Gray
        Write-Host ''
    }
} else {
    if ($driversRecentes.Count -gt 0) {
        Write-Ok 'Nenhum driver instalado nos 14 dias anteriores aos BSODs encontrados.'
        Write-Host ''
        Write-Info 'Drivers mais recentes instalados (60 dias):'
        $driversRecentes | Select-Object -First 8 | ForEach-Object {
            Write-Dest ("   {0}  {1}" -f $_.DataDriver.ToString('dd/MM/yyyy'), $_.Dispositivo)
        }
    } else {
        Write-Info 'Nenhum dado de driver recente disponivel via WMI.'
    }
}

# =========================================================================
# ETAPA 6 - Verificar temperatura e saude do disco via SMART
# =========================================================================

Write-Etapa '6/9  Verificando saude dos discos via SMART...'
Write-Host ''

$discos = Get-WmiObject -Class Win32_DiskDrive -ErrorAction SilentlyContinue

foreach ($disco in $discos) {
    $tamanhoGB = if ($disco.Size) { '{0:N0} GB' -f ($disco.Size / 1GB) } else { 'desconhecido' }
    $cor = if ($disco.Status -eq 'OK') { 'Green' } else { 'Yellow' }
    Write-Host ("   $($disco.Model)  [$tamanhoGB]  Status: $($disco.Status)") -ForegroundColor $cor
    if ($disco.Partitions) { Write-Info "   Particoes : $($disco.Partitions)  |  Interface: $($disco.InterfaceType)" }
}

# SMART - predicao de falha
Write-Host ''
$smartStatus = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue

if ($smartStatus) {
    foreach ($s in $smartStatus) {
        $nomeInst = $s.InstanceName -replace '.*\\', '' -replace '_\d+$', ''
        if ($s.PredictFailure) {
            Write-Falha "SMART ALERTA DE FALHA: $nomeInst"
            Write-Info  'Este disco pode falhar em breve. Faca backup imediatamente!'
        } else {
            Write-Ok "SMART OK: $nomeInst - sem predicao de falha iminente."
        }
    }
} else {
    Write-Aviso 'SMART nao disponivel via WMI neste sistema (normal em alguns NVMe ou RAID).'
}

# SMART - temperatura (atributo 0xC2 = 194 e 0xBE = 190)
$smartDados = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_ATAPISmartData -ErrorAction SilentlyContinue

if ($smartDados) {
    Write-Host ''
    foreach ($s in $smartDados) {
        $vs  = $s.VendorSpecific
        $temp = $null
        # Percorrer atributos SMART: inicio em offset 2, 12 bytes cada
        for ($i = 2; $i -lt 362 -and $i -lt $vs.Count; $i += 12) {
            $id = $vs[$i]
            if ($id -eq 194 -or $id -eq 190) {
                $temp = $vs[$i + 5]  # Primeiro byte do valor raw = temperatura em Celsius
                break
            }
        }
        if ($null -ne $temp) {
            $nomeInst = $s.InstanceName -replace '.*\\', '' -replace '_\d+$', ''
            $corTemp  = if ($temp -gt 55) { 'Red' } elseif ($temp -gt 45) { 'Yellow' } else { 'Green' }
            Write-Host ("   Temperatura SMART: $nomeInst = ${temp}C") -ForegroundColor $corTemp
            if ($temp -gt 55) { Write-Aviso 'Temperatura critica! Verifique ventilacao do gabinete.' }
        }
    }
}

# =========================================================================
# ETAPA 7 - Verificar se RAM passou por teste recente
# =========================================================================

Write-Etapa '7/9  Verificando historico de teste de memoria RAM...'
Write-Host ''

$testeMemoria = $null
$testeEncontrado = $false

# Verificar resultados do Windows Memory Diagnostic no log de eventos
try {
    $memDiagEvents = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results'
    } -MaxEvents 5 -ErrorAction SilentlyContinue
    if ($memDiagEvents) {
        $testeEncontrado = $true
        $ultimo = $memDiagEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $diasAtras = [math]::Round(((Get-Date) - $ultimo.TimeCreated).TotalDays, 0)
        if ($ultimo.Message -match 'no errors' -or $ultimo.Message -match 'sem erros' -or $ultimo.Id -eq 1201) {
            Write-Ok "Ultimo teste de memoria: $($ultimo.TimeCreated.ToString('dd/MM/yyyy'))  ($diasAtras dia(s) atras) - SEM ERROS detectados."
        } else {
            Write-Aviso "Ultimo teste de memoria: $($ultimo.TimeCreated.ToString('dd/MM/yyyy'))  ($diasAtras dia(s) atras)"
            Write-Dest "   Resultado: $($ultimo.Message -replace '\s+', ' ')"
        }
        $testeMemoria = $ultimo
    }
} catch {}

# Tentar pelo log Application com ID 1101
if (-not $testeEncontrado) {
    try {
        $memDiagApp = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            Id      = @(1101, 1102, 1103)
        } -MaxEvents 5 -ErrorAction SilentlyContinue
        if ($memDiagApp) {
            $testeEncontrado = $true
            $ultimo = $memDiagApp | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $diasAtras = [math]::Round(((Get-Date) - $ultimo.TimeCreated).TotalDays, 0)
            Write-Ok "Teste de memoria encontrado: $($ultimo.TimeCreated.ToString('dd/MM/yyyy'))  ($diasAtras dia(s) atras)"
        }
    } catch {}
}

if (-not $testeEncontrado) {
    Write-Aviso 'Nenhum teste de memoria recente encontrado no log de eventos.'
    Write-Info  'Para executar: Iniciar > "Diagnostico de Memoria do Windows" > Reiniciar agora e verificar problemas'
    Write-Info  'Alternativa: Baixe memtest86 (gratuito) em memtest86.com para teste mais completo'
}

# Verificar quantidade e velocidade de RAM
$ramInfo = Get-WmiObject Win32_PhysicalMemory -ErrorAction SilentlyContinue
if ($ramInfo) {
    $totalRAM = ($ramInfo | Measure-Object -Property Capacity -Sum).Sum / 1GB
    Write-Host ''
    Write-Info "RAM instalada: $totalRAM GB  |  Modulos: $($ramInfo.Count)"
    foreach ($m in $ramInfo) {
        $capGB   = [math]::Round($m.Capacity / 1GB, 0)
        $veloc   = if ($m.Speed) { "$($m.Speed) MHz" } else { 'velocidade desconhecida' }
        $slot    = if ($m.DeviceLocator) { $m.DeviceLocator } else { 'slot desconhecido' }
        $fabric  = if ($m.Manufacturer) { $m.Manufacturer } else { '' }
        Write-Dest ("   {0,-10}  {1,4} GB  {2}  {3}" -f $slot, $capGB, $veloc, $fabric)
    }
}

# =========================================================================
# ETAPA 8 - Sugerir solucoes especificas baseadas nos erros encontrados
# =========================================================================

Write-Etapa '8/9  Solucoes recomendadas com base nos erros encontrados...'
Write-Host ''

$solucoesRecomendadas = [System.Collections.Generic.List[string]]::new()
$solucoesJaAdicionadas = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Adicionar-Solucao { param([string]$s) if ($solucoesJaAdicionadas.Add($s)) { $solucoesRecomendadas.Add($s) } }

foreach ($cod in $codigosUnicos) {
    $info = $bsodCodigos[$cod]
    if ($info -and $info.Solucoes) {
        foreach ($sol in $info.Solucoes) { Adicionar-Solucao $sol }
    }
}

# Adicionar solucoes gerais se houver BSODs
if ($codigosEncontrados.Count -gt 0) {
    Adicionar-Solucao 'Execute: sfc /scannow no Prompt de Comando como Administrador'
    Adicionar-Solucao 'Execute: DISM /Online /Cleanup-Image /RestoreHealth'
    Adicionar-Solucao 'Certifique-se que o Windows esta atualizado (Windows Update)'
}

# Adicionar solucao de drivers suspeitos se encontrados
if ($driversSuspeitos.Count -gt 0) {
    Adicionar-Solucao 'Considere reverter ou remover os drivers suspeitos identificados na Etapa 5'
    Adicionar-Solucao 'Para reverter driver: Gerenciador de Dispositivos > driver > Propriedades > Driver > Reverter Driver'
}

# Adicionar solucao de SMART se ha alerta
$smartAlerta = $smartStatus | Where-Object { $_.PredictFailure }
if ($smartAlerta) {
    $solucoesRecomendadas.Insert(0, 'URGENTE: Faca backup imediato dos dados - SMART indica falha iminente no disco!')
    Adicionar-Solucao 'Substitua o disco com alerta SMART o mais rapido possivel'
}

if ($solucoesRecomendadas.Count -gt 0) {
    $numSol = 1
    foreach ($sol in $solucoesRecomendadas) {
        $cor = if ($sol -match 'URGENTE') { 'Red' } elseif ($numSol -le 3) { 'Yellow' } else { 'White' }
        Write-Host ("   $numSol. $sol") -ForegroundColor $cor
        $numSol++
    }
} else {
    Write-Ok 'Nenhum BSOD encontrado. Nenhuma solucao corretiva necessaria no momento.'
}

# =========================================================================
# ETAPA 9 - Relatorio final com linha do tempo dos crashes
# =========================================================================

Write-Etapa '9/9  Relatorio final - Linha do tempo dos eventos de crash...'
Write-Host ''

# Consolidar todos os eventos de crash em uma linha do tempo
$linhaDoTempo = [System.Collections.Generic.List[PSObject]]::new()

foreach ($ev in $codigosEncontrados) {
    $linhaDoTempo.Add([PSCustomObject]@{
        Data   = $ev.Data
        Tipo   = 'BSOD'
        Codigo = $ev.Codigo
        Nome   = $ev.Nome
        Cor    = 'Red'
    })
}
foreach ($ev in $eventosKernel41) {
    $jaTemBSOD = $codigosEncontrados | Where-Object {
        [Math]::Abs(($_.Data - $ev.TimeCreated).TotalMinutes) -lt 5
    }
    if (-not $jaTemBSOD) {
        $linhaDoTempo.Add([PSCustomObject]@{
            Data   = $ev.TimeCreated
            Tipo   = 'Deslig.Inesperado'
            Codigo = 'KernelPower-41'
            Nome   = 'Desligamento inesperado sem BSOD'
            Cor    = 'Yellow'
        })
    }
}
foreach ($ev in $eventosShutdown) {
    $linhaDoTempo.Add([PSCustomObject]@{
        Data   = $ev.TimeCreated
        Tipo   = 'Shutdown6008'
        Codigo = 'EventLog-6008'
        Nome   = 'Desligamento anterior inesperado'
        Cor    = 'DarkYellow'
    })
}

$linhaOrdenada = $linhaDoTempo | Sort-Object Data -Descending

if ($linhaOrdenada.Count -gt 0) {
    Write-Host ("   {'Data/Hora',-20}  {'Tipo',-18}  {'Codigo',-14}  Nome" -f @{}) -ForegroundColor Cyan
    Write-Host ("   {0,-20}  {1,-18}  {2,-14}  {3}" -f ('-'*19), ('-'*17), ('-'*13), ('-'*30)) -ForegroundColor DarkGray
    foreach ($item in $linhaOrdenada) {
        Write-Host ("   {0,-20}  {1,-18}  {2,-14}  {3}" -f `
            $item.Data.ToString('dd/MM/yyyy HH:mm:ss'),
            $item.Tipo,
            $item.Codigo,
            $item.Nome) -ForegroundColor $item.Cor
    }
    Write-Host ''
    Write-Host ("   Total de eventos de crash nos ultimos 30 dias: $($linhaOrdenada.Count)") -ForegroundColor White

    # Agrupamento por semana para identificar padroes
    $porSemana = $linhaOrdenada | Group-Object { $_.Data.ToString('yyyy-WW') }
    if ($porSemana.Count -gt 1) {
        Write-Host ''
        Write-Info 'Distribuicao por semana:'
        foreach ($semana in ($porSemana | Sort-Object Name -Descending)) {
            $primeiraData = ($semana.Group | Sort-Object Data | Select-Object -First 1).Data
            Write-Dest ("   Semana de {0,-12}: {1} evento(s)" -f $primeiraData.ToString('dd/MM/yyyy'), $semana.Count)
        }
    }
} else {
    Write-Ok 'Nenhum evento de crash registrado nos ultimos 30 dias.'
    Write-Info 'Sistema estavel no periodo analisado.'
}

# =========================================================================
# RESUMO EXECUTIVO
# =========================================================================

$corResumo = if ($codigosEncontrados.Count -eq 0) { 'Green' } elseif ($smartAlerta) { 'Red' } else { 'Yellow' }

Write-Host ''
Write-Host '================================================' -ForegroundColor $corResumo
Write-Host '   RESUMO DO DIAGNOSTICO                        ' -ForegroundColor $corResumo
Write-Host '================================================' -ForegroundColor $corResumo
Write-Host ''
Write-Host ("   BSODs nos ultimos 30 dias : $($codigosEncontrados.Count)") -ForegroundColor White
Write-Host ("   Codigos unicos            : $($codigosUnicos.Count)") -ForegroundColor White
Write-Host ("   Drivers suspeitos         : $($driversSuspeitos.Count)") -ForegroundColor White
Write-Host ("   Arquivos de dump          : $totalDumps") -ForegroundColor White
Write-Host ("   Teste de RAM recente      : $(if ($testeEncontrado) { 'Sim' } else { 'Nao encontrado' })") -ForegroundColor White
$smartOK = -not ($smartStatus | Where-Object { $_.PredictFailure })
Write-Host ("   SMART do disco            : $(if ($smartStatus) { if ($smartOK) { 'OK' } else { 'ALERTA DE FALHA' } } else { 'Nao disponivel' })") -ForegroundColor $(if ($smartOK -or -not $smartStatus) { 'White' } else { 'Red' })

if ($codigosEncontrados.Count -eq 0) {
    Write-Host ''
    Write-Host '   Sistema estavel no periodo analisado.' -ForegroundColor Green
} else {
    Write-Host ''
    Write-Host '   Para analise aprofundada dos arquivos .DMP use:' -ForegroundColor Cyan
    Write-Host '   WinDbg (gratuito no Microsoft Store) ou WhoCrashed (NirSoft)' -ForegroundColor Gray
    Write-Host '   Comando WinDbg: !analyze -v  (apos abrir o arquivo .dmp)' -ForegroundColor Gray
}

Write-Host ''
Write-Host ("   Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host '================================================' -ForegroundColor $corResumo
Write-Host ''
