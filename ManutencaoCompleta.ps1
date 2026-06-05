#Requires -RunAsAdministrator

$totalLiberadoBytes = [long]0

# =========================================================================
# EXCECOES DE INICIALIZACAO
# Programas cujos nomes ou caminhos contenham estes termos serao mantidos.
# =========================================================================

$script:excecoes = @(
    'PjeOffice', 'Java', 'jusched', 'jaureg', 'Shodo',
    'OneDrive', 'GoogleDrive', 'Google Drive', 'GD Token',
    'SafeNet', 'eToken', 'Safeid', 'AnyDesk', 'TeamViewer',
    'Certisign', 'Serpro', 'Valid'
)

# =========================================================================
# FUNCOES AUXILIARES
# =========================================================================

function Remove-Files {
    param([string]$Pasta, [string]$Filtro = '*', [int]$DiasAntigos = 0)
    if (-not (Test-Path $Pasta)) { return [long]0 }
    $liberado = [long]0
    try {
        if ($DiasAntigos -gt 0) {
            $limite = (Get-Date).AddDays(-$DiasAntigos)
            $itens = Get-ChildItem -Path $Pasta -Recurse -File -Filter $Filtro -ErrorAction SilentlyContinue |
                     Where-Object { $_.LastWriteTime -lt $limite }
        } else {
            $itens = Get-ChildItem -Path $Pasta -Recurse -File -Filter $Filtro -ErrorAction SilentlyContinue
        }
        foreach ($item in $itens) {
            try {
                $liberado += $item.Length
                Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                $liberado -= $item.Length
            }
        }
        Get-ChildItem -Path $Pasta -Recurse -Directory -ErrorAction SilentlyContinue |
            Sort-Object { $_.FullName.Length } -Descending |
            ForEach-Object {
                Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            }
    } catch {}
    return [long]$liberado
}

function Format-MB {
    param([long]$Bytes)
    return ('{0:N2} MB' -f ($Bytes / 1MB))
}

function Test-Excecao {
    param([string]$Nome, [string]$Comando)
    foreach ($exc in $script:excecoes) {
        if ($Nome    -like "*$exc*") { return $true }
        if ($Comando -like "*$exc*") { return $true }
    }
    return $false
}

function Write-Titulo {
    param([string]$Texto)
    Write-Host ''
    Write-Host ('=' * 60) -ForegroundColor Magenta
    Write-Host "  $Texto" -ForegroundColor Magenta
    Write-Host ('=' * 60) -ForegroundColor Magenta
    Write-Host ''
}

function Write-Etapa { param([string]$t) Write-Host "  >> $t" -ForegroundColor Cyan }
function Write-Ok    { param([string]$t) Write-Host "     [OK] $t" -ForegroundColor Green }
function Write-Aviso { param([string]$t) Write-Host "     [!]  $t" -ForegroundColor Yellow }
function Write-Falha { param([string]$t) Write-Host "     [X]  $t" -ForegroundColor Red }

# =========================================================================
# CABECALHO
# =========================================================================

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor Cyan
Write-Host '           MANUTENCAO COMPLETA DO PC                ' -ForegroundColor Cyan
Write-Host ('=' * 60) -ForegroundColor Cyan
Write-Host ("  Iniciado em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor Gray

# =========================================================================
# SELECAO DE DISCOS PARA OTIMIZACAO  (unica interacao do script)
# =========================================================================

$discosParaOtimizar = [System.Collections.Generic.List[string]]::new()
$discosParaOtimizar.Add('C')

$outrosDiscos = @(
    Get-Volume -ErrorAction SilentlyContinue |
    Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.DriveLetter -ne 'C' } |
    Sort-Object DriveLetter
)

if ($outrosDiscos.Count -gt 0) {
    Write-Host ''
    Write-Host ('  ' + ('-' * 56)) -ForegroundColor DarkGray
    Write-Host '  SELECAO DE DISCOS PARA OTIMIZACAO' -ForegroundColor Yellow
    Write-Host ('  ' + ('-' * 56)) -ForegroundColor DarkGray
    Write-Host '  O disco C: sera otimizado automaticamente.' -ForegroundColor Gray
    Write-Host '  Outros discos encontrados:' -ForegroundColor Gray
    Write-Host ''

    $mapaDiscos = @{}
    $idx = 1
    foreach ($vol in $outrosDiscos) {
        $letra  = [string]$vol.DriveLetter
        $rotulo = if ($vol.FileSystemLabel) { $vol.FileSystemLabel } else { 'sem rotulo' }
        $total  = [math]::Round($vol.Size / 1GB, 1)
        $livre  = [math]::Round($vol.SizeRemaining / 1GB, 1)
        Write-Host ("     [$idx] ${letra}:  $total GB total  $livre GB livres  ($rotulo)") -ForegroundColor White
        $mapaDiscos[$idx] = $letra
        $idx++
    }

    Write-Host ''
    Write-Host '  Digite os numeros separados por virgula (ex: 1,2)' -ForegroundColor Gray
    Write-Host '  ou pressione Enter para otimizar apenas o C:' -ForegroundColor Gray
    Write-Host ''
    $resposta = (Read-Host '  Discos adicionais').Trim()

    if ($resposta -ne '') {
        foreach ($parte in ($resposta -split ',')) {
            $n = $parte.Trim()
            if ($n -match '^\d+$' -and $mapaDiscos.ContainsKey([int]$n)) {
                $discosParaOtimizar.Add($mapaDiscos[[int]$n])
            }
        }
    }

    $listaSelecionada = ($discosParaOtimizar | ForEach-Object { "${_}:" }) -join '  '
    Write-Host ''
    Write-Host "  Discos selecionados: $listaSelecionada" -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * 56)) -ForegroundColor DarkGray
} else {
    Write-Host '  Apenas o disco C: encontrado. Otimizacao automatica.' -ForegroundColor Gray
}

# =========================================================================
# ETAPA 1 - LIMPEZA DE ARQUIVOS TEMPORARIOS
# =========================================================================

Write-Titulo 'ETAPA 1 - Arquivos Temporarios'

Write-Etapa 'Limpando TEMP do usuario (C:)...'
$bytes = Remove-Files -Pasta "C:\Users\$env:USERNAME\AppData\Local\Temp"
$totalLiberadoBytes += $bytes
Write-Ok "TEMP usuario : $(Format-MB $bytes) liberados"

Write-Etapa 'Limpando TEMP do sistema (C:\Windows\Temp)...'
$bytes = Remove-Files -Pasta 'C:\Windows\Temp'
$totalLiberadoBytes += $bytes
Write-Ok "TEMP sistema : $(Format-MB $bytes) liberados"

Write-Etapa 'Limpando Prefetch...'
$bytes = Remove-Files -Pasta 'C:\Windows\Prefetch' -Filtro '*.pf'
$totalLiberadoBytes += $bytes
Write-Ok "Prefetch     : $(Format-MB $bytes) liberados"

# =========================================================================
# ETAPA 2 - LIXEIRA
# =========================================================================

Write-Titulo 'ETAPA 2 - Lixeira'
Write-Etapa 'Esvaziando a Lixeira...'

try {
    $bytesLix = [long]0
    $soma = (Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue |
             Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
    if ($soma) { $bytesLix = [long]$soma }
    Clear-RecycleBin -DriveLetter 'C' -Force -Confirm:$false -ErrorAction Stop
    $totalLiberadoBytes += $bytesLix
    Write-Ok "Lixeira C: esvaziada: $(Format-MB $bytesLix) liberados"
} catch {
    Write-Aviso 'Lixeira ja estava vazia ou nao foi possivel esvaziar.'
}

# =========================================================================
# ETAPA 3 - CACHE DE MINIATURAS
# =========================================================================

Write-Titulo 'ETAPA 3 - Cache de Miniaturas'
Write-Etapa 'Removendo cache de miniaturas do Explorer...'

$pastaMini = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\Explorer"
$bytesMini = [long]0
foreach ($filtro in @('thumbcache_*.db', 'iconcache_*.db')) {
    $bytesMini += Remove-Files -Pasta $pastaMini -Filtro $filtro
}
$totalLiberadoBytes += $bytesMini
if ($bytesMini -gt 0) {
    Write-Ok "Cache de miniaturas: $(Format-MB $bytesMini) liberados"
} else {
    Write-Aviso 'Arquivos em uso pelo Explorer. Serao removidos no proximo logon.'
}

# =========================================================================
# ETAPA 4 - CACHE DO WINDOWS UPDATE
# =========================================================================

Write-Titulo 'ETAPA 4 - Cache do Windows Update'

Write-Etapa 'Parando servicos wuauserv e bits...'
try {
    Stop-Service -Name 'wuauserv' -Force -ErrorAction Stop
    Stop-Service -Name 'bits'     -Force -ErrorAction SilentlyContinue
    Write-Ok 'Servicos pausados.'

    Write-Etapa 'Removendo arquivos de cache de atualizacoes...'
    $bytes = Remove-Files -Pasta 'C:\Windows\SoftwareDistribution\Download'
    $totalLiberadoBytes += $bytes
    Write-Ok "Windows Update: $(Format-MB $bytes) liberados"
} catch {
    Write-Falha "Erro ao limpar cache do Windows Update: $_"
} finally {
    Start-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
    Start-Service -Name 'bits'     -ErrorAction SilentlyContinue
    Write-Ok 'Servicos wuauserv e bits reiniciados.'
}

# =========================================================================
# ETAPA 5 - PROGRAMAS NA INICIALIZACAO
# =========================================================================

Write-Titulo 'ETAPA 5 - Programas na Inicializacao'

# Valor binario que desativa o item (mesmo mecanismo do Gerenciador de Tarefas)
$binDesativado = [byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

$origens = @(
    @{
        RunKey      = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        ApprovalKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
        Label       = 'HKCU'
    },
    @{
        RunKey      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        ApprovalKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
        Label       = 'HKLM'
    }
)

$qtdMantidos    = 0
$qtdDesativados = 0
$qtdFalhas      = 0

$psProps = @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider')

Write-Host ('     {0,-36} {1,-6} {2}' -f 'Programa', 'Origem', 'Acao') -ForegroundColor White
Write-Host ('     ' + ('-' * 54)) -ForegroundColor DarkGray

foreach ($origem in $origens) {
    if (-not (Test-Path $origem.RunKey)) { continue }

    $props = Get-ItemProperty -Path $origem.RunKey -ErrorAction SilentlyContinue
    if (-not $props) { continue }

    $props.PSObject.Properties |
        Where-Object { $_.Name -notin $psProps } |
        ForEach-Object {
            $nomeProg  = $_.Name
            $cmdProg   = [string]$_.Value
            $nomeCurto = if ($nomeProg.Length -gt 34) { $nomeProg.Substring(0, 31) + '...' } else { $nomeProg }

            if (Test-Excecao -Nome $nomeProg -Comando $cmdProg) {
                Write-Host ('     {0,-36} {1,-6} {2}' -f $nomeCurto, $origem.Label, 'MANTIDO  ') -ForegroundColor Green
                $qtdMantidos++
            } else {
                try {
                    if (-not (Test-Path $origem.ApprovalKey)) {
                        New-Item -Path $origem.ApprovalKey -Force | Out-Null
                    }
                    Set-ItemProperty -Path $origem.ApprovalKey `
                        -Name $nomeProg -Value $binDesativado -Type Binary -ErrorAction Stop
                    Write-Host ('     {0,-36} {1,-6} {2}' -f $nomeCurto, $origem.Label, 'DESATIVADO') -ForegroundColor Yellow
                    $qtdDesativados++
                } catch {
                    Write-Host ('     {0,-36} {1,-6} {2}' -f $nomeCurto, $origem.Label, 'FALHA    ') -ForegroundColor Red
                    $qtdFalhas++
                }
            }
        }
}

Write-Host ''
Write-Ok "Mantidos: $qtdMantidos  |  Desativados: $qtdDesativados  |  Falhas: $qtdFalhas"
if ($qtdDesativados -gt 0) {
    Write-Aviso 'Programas desativados nao iniciarao mais na proxima reinicializacao.'
    Write-Aviso 'Para reativar: Gerenciador de Tarefas > guia Inicializar.'
}

# =========================================================================
# ETAPA 6 - OTIMIZACAO DE DISCO
# =========================================================================

Write-Titulo 'ETAPA 6 - Otimizacao de Disco'
Write-Aviso 'Esta etapa pode levar varios minutos dependendo do disco.'

foreach ($letra in $discosParaOtimizar) {
    Write-Etapa "Otimizando unidade ${letra}:\ ..."
    try {
        $numDisco  = (Get-Partition -DriveLetter $letra -ErrorAction Stop).DiskNumber
        $physDisk  = Get-PhysicalDisk -ErrorAction SilentlyContinue |
                     Where-Object { [int]$_.DeviceId -eq [int]$numDisco }
        $tipoMidia = if ($physDisk -and $physDisk.MediaType) { $physDisk.MediaType } else { 'HDD' }

        if ($tipoMidia -eq 'SSD') {
            Write-Ok "Tipo: SSD. Executando TRIM (ReTrim)..."
            Optimize-Volume -DriveLetter $letra -ReTrim -NormalPriority -ErrorAction Stop
            Write-Ok "TRIM concluido em ${letra}:\"
        } else {
            Write-Ok "Tipo: $tipoMidia. Executando desfragmentacao..."
            Optimize-Volume -DriveLetter $letra -Defrag -NormalPriority -ErrorAction Stop
            Write-Ok "Desfragmentacao concluida em ${letra}:\"
        }
    } catch {
        Write-Falha "Nao foi possivel otimizar ${letra}: $_"
    }
}

# =========================================================================
# ETAPA 7 - EFEITOS VISUAIS
# =========================================================================

Write-Titulo 'ETAPA 7 - Efeitos Visuais'
Write-Etapa 'Desativando efeitos visuais desnecessarios...'

$qtdEfeitos = 0

try {
    $chaveVFX = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
    if (-not (Test-Path $chaveVFX)) { New-Item -Path $chaveVFX -Force | Out-Null }
    Set-ItemProperty -Path $chaveVFX -Name 'VisualFXSetting' -Value 2 -Type DWord -ErrorAction Stop
    $qtdEfeitos++
    Write-Ok 'Modo de melhor desempenho ativado.'
} catch { Write-Aviso "Nao foi possivel ajustar VisualFXSetting: $_" }

try {
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\WindowMetrics' `
        -Name 'MinAnimate' -Value '0' -ErrorAction Stop
    $qtdEfeitos++
    Write-Ok 'Animacao de minimizar/maximizar janelas desativada.'
} catch {}

try {
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'DragFullWindows' -Value '0' -ErrorAction Stop
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'MenuShowDelay'   -Value '0' -ErrorAction Stop
    $qtdEfeitos += 2
    Write-Ok 'Conteudo ao arrastar e atraso de menus desativados.'
} catch {}

try {
    $chaveAdv = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    Set-ItemProperty -Path $chaveAdv -Name 'TaskbarAnimations'   -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path $chaveAdv -Name 'ListviewAlphaSelect'  -Value 0 -Type DWord -ErrorAction Stop
    Set-ItemProperty -Path $chaveAdv -Name 'ListviewShadow'       -Value 0 -Type DWord -ErrorAction Stop
    $qtdEfeitos += 3
    Write-Ok 'Animacoes da barra de tarefas e sombras de icones desativadas.'
} catch {}

try {
    & rundll32.exe user32.dll,UpdatePerUserSystemParameters 1 True
} catch {}

Write-Ok "$qtdEfeitos configuracao(s) ajustada(s)."
Write-Aviso 'Algumas mudancas visuais exigem logoff/logon para efeito completo.'

# =========================================================================
# RELATORIO FINAL
# =========================================================================

$totalMB = [math]::Round($totalLiberadoBytes / 1MB, 2)

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor Green
Write-Host '                 RELATORIO FINAL                    ' -ForegroundColor Green
Write-Host ('=' * 60) -ForegroundColor Green
Write-Host ''
Write-Host '  Etapas concluidas:' -ForegroundColor White
Write-Host '    [1] Arquivos temporarios limpos              [OK]' -ForegroundColor Green
Write-Host '    [2] Lixeira esvaziada                       [OK]' -ForegroundColor Green
Write-Host '    [3] Cache de miniaturas limpo               [OK]' -ForegroundColor Green
Write-Host '    [4] Cache do Windows Update limpo           [OK]' -ForegroundColor Green
Write-Host ("    [5] Inicializacao: $qtdMantidos mantido(s), $qtdDesativados desativado(s)  [OK]") -ForegroundColor Green
Write-Host '    [6] Discos otimizados                       [OK]' -ForegroundColor Green
Write-Host '    [7] Efeitos visuais ajustados               [OK]' -ForegroundColor Green
Write-Host ''
Write-Host ("  Espaco total liberado : $totalMB MB") -ForegroundColor Cyan
Write-Host ("  Concluido em          : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor Gray
Write-Host ''
Write-Host ('=' * 60) -ForegroundColor Green
Write-Host ''
