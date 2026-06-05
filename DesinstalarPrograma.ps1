#Requires -RunAsAdministrator

# =========================================================================
# FUNCOES AUXILIARES
# =========================================================================

function Write-Titulo {
    param([string]$Texto)
    Write-Host ''
    Write-Host ('=' * 62) -ForegroundColor Magenta
    Write-Host "  $Texto" -ForegroundColor Magenta
    Write-Host ('=' * 62) -ForegroundColor Magenta
    Write-Host ''
}

function Write-Etapa { param([string]$t) Write-Host "  >> $t" -ForegroundColor Cyan }
function Write-Ok    { param([string]$t) Write-Host "     [OK] $t" -ForegroundColor Green }
function Write-Aviso { param([string]$t) Write-Host "     [!]  $t" -ForegroundColor Yellow }
function Write-Falha { param([string]$t) Write-Host "     [X]  $t" -ForegroundColor Red }
function Write-Info  { param([string]$t) Write-Host "     $t" -ForegroundColor Gray }

$relatorio = [System.Collections.Generic.List[string]]::new()

function Add-Relatorio {
    param([string]$Linha)
    $script:relatorio.Add($Linha)
}

function Remove-Caminho {
    param([string]$Caminho)
    if (-not (Test-Path $Caminho)) { return }
    try {
        Remove-Item -Path $Caminho -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $Caminho)) {
            Write-Ok "Removido: $Caminho"
            Add-Relatorio "Removido: $Caminho"
        } else {
            Write-Aviso "Parcialmente removido: $Caminho"
            Add-Relatorio "Parcial: $Caminho"
        }
    } catch {
        Write-Falha "Erro ao remover $Caminho : $_"
    }
}

function Remove-ChaveRegistro {
    param([string]$Chave)
    if (-not (Test-Path $Chave)) { return }
    try {
        Remove-Item -Path $Chave -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok "Registro removido: $Chave"
        Add-Relatorio "Registro: $Chave"
    } catch {
        Write-Aviso "Nao foi possivel remover registro: $Chave"
    }
}

# =========================================================================
# CABECALHO
# =========================================================================

Write-Host ''
Write-Host ('=' * 62) -ForegroundColor Cyan
Write-Host '         DESINSTALADOR COMPLETO DE PROGRAMAS         ' -ForegroundColor Cyan
Write-Host ('=' * 62) -ForegroundColor Cyan

# =========================================================================
# ETAPA 1 - LISTAR TODOS OS PROGRAMAS INSTALADOS
# =========================================================================

Write-Titulo 'ETAPA 1 - Programas Instalados'
Write-Etapa 'Coletando lista de programas instalados...'

$todosPrograms  = [System.Collections.Generic.List[object]]::new()
$dedupIndex     = @{}

$chavesUninstall = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)

foreach ($raiz in $chavesUninstall) {
    if (-not (Test-Path $raiz)) { continue }
    Get-ChildItem -Path $raiz -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        if (-not $props) { return }
        $display   = ([string]$props.DisplayName).Trim()
        if ($display -eq '') { return }
        $uninstStr = [string]$props.UninstallString
        $quietStr  = [string]$props.QuietUninstallString
        if ($uninstStr -eq '' -and $quietStr -eq '') { return }
        $chaveDedup = ($display + '||' + [string]$props.DisplayVersion).ToLower()
        if ($dedupIndex.ContainsKey($chaveDedup)) { return }
        $dedupIndex[$chaveDedup] = $true
        $todosPrograms.Add([PSCustomObject]@{
            Nome          = $display
            Versao        = [string]$props.DisplayVersion
            Publicador    = [string]$props.Publisher
            Desinstalador = $uninstStr
            QuietString   = $quietStr
            RegistroPath  = $_.PSPath
            Fonte         = 'Registro'
        })
    }
}

if ($todosPrograms.Count -eq 0) {
    Write-Falha 'Nenhum programa encontrado no registro de instalacoes.'
    exit 1
}

$lista = @($todosPrograms | Sort-Object Nome)

Write-Ok "$($lista.Count) programas encontrados."
Write-Host ''
Write-Host ('  {0,5}  {1,-48} {2}' -f 'Num', 'Programa', 'Versao') -ForegroundColor White
Write-Host ('  ' + ('-' * 68)) -ForegroundColor DarkGray

for ($i = 0; $i -lt $lista.Count; $i++) {
    $prog   = $lista[$i]
    $num    = '{0,5}.' -f ($i + 1)
    $nome   = if ($prog.Nome.Length -gt 46) { $prog.Nome.Substring(0, 43) + '...' } else { $prog.Nome }
    $versao = if ($prog.Versao -ne '') { $prog.Versao } else { '' }
    Write-Host ('  {0}  {1,-48} {2}' -f $num, $nome, $versao) -ForegroundColor White
}

Write-Host ''

# =========================================================================
# ETAPA 2 - SELECAO E CONFIRMACAO
# =========================================================================

Write-Titulo 'ETAPA 2 - Selecao'

$escolha = (Read-Host '  Numero do programa a desinstalar (Enter para cancelar)').Trim()

if ($escolha -eq '') {
    Write-Aviso 'Operacao cancelada.'
    exit 0
}

if (-not ($escolha -match '^\d+$') -or [int]$escolha -lt 1 -or [int]$escolha -gt $lista.Count) {
    Write-Falha "Numero invalido. Digite um numero entre 1 e $($lista.Count)."
    exit 1
}

$alvo     = $lista[[int]$escolha - 1]
$nomeAlvo = $alvo.Nome

# Extrai nome base para busca de residuos: remove versao numerica e info de arquitetura
$nomeBusca = ($nomeAlvo -replace '\s+\d[\d.]*.*$', '').Trim()
if ($nomeBusca.Length -lt 3) { $nomeBusca = $nomeAlvo }

Write-Host ''
Write-Host "  Programa   : $nomeAlvo" -ForegroundColor Yellow
Write-Host "  Versao     : $($alvo.Versao)" -ForegroundColor Gray
Write-Host "  Publicador : $($alvo.Publicador)" -ForegroundColor Gray
Write-Host "  Limpeza    : buscara residuos com o termo '$nomeBusca'" -ForegroundColor Gray
Write-Host ''
$confirma = (Read-Host '  Confirmar desinstalacao? (s/N)').Trim()
if ($confirma -notmatch '^[sS]$') {
    Write-Aviso 'Operacao cancelada.'
    exit 0
}

Add-Relatorio "Programa desinstalado: $nomeAlvo"
Add-Relatorio "Versao: $($alvo.Versao)  |  Publicador: $($alvo.Publicador)"
Add-Relatorio ''

# =========================================================================
# ETAPA 4 - DESINSTALACAO OFICIAL
# =========================================================================

Write-Titulo 'ETAPA 4 - Desinstalacao'
Write-Etapa "Desinstalando '$nomeAlvo'..."

$desinstalou = $false

if ($alvo.Fonte -eq 'AppX') {
    $pkgFullName = $alvo.Desinstalador -replace '^AppX:', ''
    try {
        Remove-AppxPackage -Package $pkgFullName -AllUsers -ErrorAction Stop
        Write-Ok 'Pacote AppX removido.'
        $desinstalou = $true
    } catch {
        Write-Falha "Erro ao remover AppX: $_"
    }

} elseif ($alvo.Fonte -eq 'MSI') {
    $productCode = $alvo.Desinstalador -replace '^MSI:', ''
    try {
        $proc = Start-Process -FilePath 'msiexec.exe' `
            -ArgumentList "/x `"$productCode`" /qn /norestart" `
            -Wait -PassThru -ErrorAction Stop
        if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
            Write-Ok "MSI desinstalado (codigo $($proc.ExitCode))."
            $desinstalou = $true
        } else {
            Write-Aviso "msiexec encerrou com codigo $($proc.ExitCode). Verifique manualmente."
        }
    } catch {
        Write-Falha "Erro ao executar msiexec: $_"
    }

} else {
    # Registro: tenta QuietUninstallString primeiro, depois UninstallString
    $cmdStr = if ($alvo.QuietString -ne '') { $alvo.QuietString } else { $alvo.Desinstalador }

    if ($cmdStr -eq '') {
        Write-Falha 'String de desinstalacao nao encontrada.'
    } else {
        # Detecta se e MsiExec ou executavel comum
        if ($cmdStr -match '(?i)msiexec') {
            $args = $cmdStr -replace '(?i)msiexec\.exe', '' -replace '(?i)msiexec', ''
            $args = ($args.Trim() + ' /qn /norestart') -replace '\s+', ' '
            try {
                $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $args `
                    -Wait -PassThru -ErrorAction Stop
                Write-Ok "msiexec encerrou com codigo $($proc.ExitCode)."
                $desinstalou = $true
            } catch {
                Write-Falha "Erro msiexec: $_"
            }
        } else {
            # Extrai executavel e argumentos
            if ($cmdStr -match '^"([^"]+)"\s*(.*)$') {
                $exe  = $Matches[1]
                $args = $Matches[2].Trim()
            } elseif ($cmdStr -match '^(\S+)\s*(.*)$') {
                $exe  = $Matches[1]
                $args = $Matches[2].Trim()
            } else {
                $exe  = $cmdStr
                $args = ''
            }

            # Acrescenta flags silenciosas comuns se nao presentes
            $silentFlags = @('/S', '/s', '/silent', '/quiet', '/qn', '-silent', '-quiet')
            $jaTemFlag = $false
            foreach ($f in $silentFlags) {
                if ($args -like "*$f*") { $jaTemFlag = $true; break }
            }
            if (-not $jaTemFlag) { $args = ($args + ' /S').Trim() }

            try {
                if (Test-Path $exe) {
                    $proc = Start-Process -FilePath $exe -ArgumentList $args `
                        -Wait -PassThru -ErrorAction Stop
                    Write-Ok "Desinstalador encerrou com codigo $($proc.ExitCode)."
                    $desinstalou = $true
                } else {
                    Write-Falha "Executavel nao encontrado: $exe"
                }
            } catch {
                Write-Falha "Erro ao executar desinstalador: $_"
            }
        }
    }
}

if (-not $desinstalou) {
    Write-Aviso 'Desinstalacao oficial nao foi confirmada. Continuando limpeza de residuos...'
}

# Remove a chave de registro do desinstalador se ainda existir
if ($alvo.RegistroPath -ne '') {
    Remove-ChaveRegistro -Chave $alvo.RegistroPath
}

# =========================================================================
# ETAPA 5 - PASTAS RESIDUAIS
# =========================================================================

Write-Titulo 'ETAPA 5 - Pastas Residuais'

$pastasBusca = @(
    'C:\Program Files',
    'C:\Program Files (x86)',
    "$env:LOCALAPPDATA",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\..\LocalLow",
    'C:\ProgramData'
)

$encontrouPasta = $false
foreach ($raiz in $pastasBusca) {
    $raizReal = [System.IO.Path]::GetFullPath($raiz)
    if (-not (Test-Path $raizReal)) { continue }
    Get-ChildItem -Path $raizReal -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*$nomeBusca*" } |
        ForEach-Object {
            $encontrouPasta = $true
            Remove-Caminho -Caminho $_.FullName
        }
}

if (-not $encontrouPasta) {
    Write-Aviso 'Nenhuma pasta residual encontrada.'
}

# =========================================================================
# ETAPA 6 - REGISTRO RESIDUAL
# =========================================================================

Write-Titulo 'ETAPA 6 - Registro Residual'

$raizesRegistro = @(
    'HKLM:\SOFTWARE',
    'HKLM:\SOFTWARE\WOW6432Node',
    'HKCU:\SOFTWARE'
)

$subChavesAlvo = @('', 'Microsoft\Windows\CurrentVersion\Uninstall',
                   'Microsoft\Windows\CurrentVersion\Run',
                   'Microsoft\Windows\CurrentVersion\RunOnce',
                   'Classes\Installer\Products',
                   'Classes\Installer\Features')

$encontrouReg = $false
foreach ($raiz in $raizesRegistro) {
    if (-not (Test-Path $raiz)) { continue }
    # Busca direta na raiz por chaves com o nome do programa
    Get-ChildItem -Path $raiz -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -like "*$nomeBusca*" } |
        ForEach-Object {
            $encontrouReg = $true
            Remove-ChaveRegistro -Chave $_.PSPath
        }

    # Busca por DisplayName dentro das subchaves de Uninstall
    $uninstPath = "$raiz\Microsoft\Windows\CurrentVersion\Uninstall"
    if (Test-Path $uninstPath) {
        Get-ChildItem -Path $uninstPath -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($p -and [string]$p.DisplayName -like "*$nomeBusca*") {
                $encontrouReg = $true
                Remove-ChaveRegistro -Chave $_.PSPath
            }
        }
    }

    # Busca valores em Run/RunOnce
    foreach ($sub in @('Microsoft\Windows\CurrentVersion\Run',
                        'Microsoft\Windows\CurrentVersion\RunOnce')) {
        $runPath = "$raiz\$sub"
        if (-not (Test-Path $runPath)) { continue }
        $props = Get-ItemProperty -Path $runPath -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        $props.PSObject.Properties |
            Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSProvider') -and
                           ($_.Name -like "*$nomeBusca*" -or [string]$_.Value -like "*$nomeBusca*") } |
            ForEach-Object {
                try {
                    Remove-ItemProperty -Path $runPath -Name $_.Name -Force -ErrorAction SilentlyContinue
                    Write-Ok "Valor de registro removido: $runPath\$($_.Name)"
                    Add-Relatorio "Valor registro: $runPath\$($_.Name)"
                    $encontrouReg = $true
                } catch {}
            }
    }
}

if (-not $encontrouReg) {
    Write-Aviso 'Nenhuma chave de registro residual encontrada.'
}

# =========================================================================
# ETAPA 7 - ATALHOS
# =========================================================================

Write-Titulo 'ETAPA 7 - Atalhos'

$pastasAtalhos = @(
    [Environment]::GetFolderPath('Desktop'),
    [Environment]::GetFolderPath('CommonDesktopDirectory'),
    [Environment]::GetFolderPath('StartMenu'),
    [Environment]::GetFolderPath('CommonStartMenu'),
    [Environment]::GetFolderPath('Programs'),
    [Environment]::GetFolderPath('CommonPrograms')
)

$encontrouAtalho = $false
foreach ($pasta in $pastasAtalhos) {
    if (-not $pasta -or -not (Test-Path $pasta)) { continue }
    Get-ChildItem -Path $pasta -Recurse -Include '*.lnk', '*.url' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*$nomeBusca*" -or $_.BaseName -like "*$nomeBusca*" } |
        ForEach-Object {
            $encontrouAtalho = $true
            Remove-Caminho -Caminho $_.FullName
        }
    # Pastas de atalho com o nome do programa
    Get-ChildItem -Path $pasta -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*$nomeBusca*" } |
        ForEach-Object {
            $encontrouAtalho = $true
            Remove-Caminho -Caminho $_.FullName
        }
}

if (-not $encontrouAtalho) {
    Write-Aviso 'Nenhum atalho encontrado.'
}

# =========================================================================
# ETAPA 8 - LIMPEZA DO REGISTRO (CAMINHOS INVALIDOS)
# =========================================================================

Write-Titulo 'ETAPA 8 - Limpeza do Registro'

# Extrai o caminho do executavel de uma string de registro (remove aspas e argumentos)
function Get-CaminhoImagePath {
    param([string]$Valor)
    $v = $Valor.Trim()
    if ($v -eq '') { return '' }
    if ($v -match '^"([^"]+)"') {
        return [System.Environment]::ExpandEnvironmentVariables($Matches[1].Trim())
    }
    if ($v -match '(?i)^(.+?\.(exe|dll|sys|ocx|cpl|drv))(\s|$)') {
        return [System.Environment]::ExpandEnvironmentVariables($Matches[1].Trim())
    }
    $parte = ($v -split '\s+')[0]
    return [System.Environment]::ExpandEnvironmentVariables($parte.Trim('"'))
}

# ---- 8.1 Servicos com ImagePath invalido --------------------------------

Write-Etapa '8.1  Servicos com ImagePath apontando para arquivo inexistente...'

$svcVer = 0
$svcRem = 0
$svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services'

Get-ChildItem -Path $svcKey -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
    if (-not $p) { return }
    $imgPath = [string]$p.ImagePath
    if ($imgPath -eq '') { return }
    # Pula servicos nativos do Windows (system32, syswow64, \SystemRoot, drivers, \??\)
    if ($imgPath -match '(?i)(\\SystemRoot\\|\\Windows\\|system32|syswow64|\\drivers\\|\\?\?\\|^system)') { return }
    # Pula servicos de boot e sistema criticos (Start 0 ou 1)
    if ($null -ne $p.Start -and [int]$p.Start -le 1) { return }
    $caminho = Get-CaminhoImagePath -Valor $imgPath
    if ($caminho.Length -lt 5) { return }
    $svcVer++
    if (-not (Test-Path $caminho -ErrorAction SilentlyContinue)) {
        try {
            Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            $svcRem++
            Write-Ok "Servico orfao removido: $($_.PSChildName)  [$caminho]"
            Add-Relatorio "Servico orfao: $($_.PSChildName)"
        } catch {
            Write-Aviso "Sem permissao para remover servico: $($_.PSChildName)"
        }
    }
}
Write-Info "Servicos verificados: $svcVer  |  Removidos: $svcRem"

# ---- 8.2 SharedDLLs com caminhos inexistentes ---------------------------

Write-Etapa '8.2  SharedDLLs com caminho de arquivo inexistente...'

$sdllVer    = 0
$sdllRem    = 0
$sdllKey    = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs'
$psExclude  = @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider')

if (Test-Path $sdllKey) {
    $sdllProps = Get-ItemProperty -Path $sdllKey -ErrorAction SilentlyContinue
    if ($sdllProps) {
        $sdllProps.PSObject.Properties |
            Where-Object { $_.Name -notin $psExclude } |
            ForEach-Object {
                $caminho = [System.Environment]::ExpandEnvironmentVariables($_.Name)
                $sdllVer++
                if (-not (Test-Path $caminho -ErrorAction SilentlyContinue)) {
                    try {
                        Remove-ItemProperty -Path $sdllKey -Name $_.Name -Force -ErrorAction SilentlyContinue
                        $sdllRem++
                        Write-Ok "SharedDLL removida: $caminho"
                        Add-Relatorio "SharedDLL orfao: $caminho"
                    } catch {
                        Write-Aviso "Sem permissao para remover SharedDLL: $($_.Name)"
                    }
                }
            }
    }
}
Write-Info "SharedDLLs verificadas: $sdllVer  |  Removidas: $sdllRem"

# ---- Resumo ---------------------------------------------------------------

$totalEtapa8 = $svcRem + $sdllRem
Write-Host ''
Write-Ok "Limpeza do registro concluida. Entradas removidas: $totalEtapa8"
Add-Relatorio ''
Add-Relatorio "Etapa 8 - Registro: $svcRem servico(s) orfao(s), $sdllRem SharedDLL(s) orfao(s)"

# =========================================================================
# ETAPA 9 - LIMPEZA DO CACHE E REGISTRO MSI
# =========================================================================

Write-Titulo 'ETAPA 9 - Cache e Registro MSI'

# ---- 9.1 Arquivos .msi e .msp em C:\Windows\Installer ------------------

Write-Etapa '9.1  Arquivos em C:\Windows\Installer com nome do produto...'

$msiCacheDir = 'C:\Windows\Installer'
$msiVer      = 0
$msiRem      = 0
$msiBytes    = [long]0

if (Test-Path $msiCacheDir) {
    $installerCom = $null
    try {
        $installerCom = New-Object -ComObject WindowsInstaller.Installer -ErrorAction Stop

        Get-ChildItem -Path $msiCacheDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -eq '.msi' -or $_.Extension -eq '.msp' } |
            ForEach-Object {
                $arquivo  = $_
                $prodName = ''

                try {
                    if ($arquivo.Extension -eq '.msi') {
                        $db = $null
                        try {
                            $db = $installerCom.OpenDatabase($arquivo.FullName, 0)
                            $vw = $db.OpenView("SELECT Value FROM Property WHERE Property = 'ProductName'")
                            $vw.Execute()
                            $rec = $vw.Fetch()
                            if ($rec) {
                                $prodName = [string]$rec.StringData(1)
                                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($rec) | Out-Null
                            }
                            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($vw) | Out-Null
                        } finally {
                            if ($db) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($db) | Out-Null }
                        }
                    } elseif ($arquivo.Extension -eq '.msp') {
                        $sum = $null
                        try {
                            $sum = $installerCom.SummaryInformation($arquivo.FullName, 0)
                            $prodName = [string]$sum.Property(3)
                        } finally {
                            if ($sum) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($sum) | Out-Null }
                        }
                    }
                } catch { $prodName = '' }

                if ($prodName -eq '') { return }
                $msiVer++

                if ($prodName -like "*$nomeBusca*") {
                    $tamanho = $arquivo.Length
                    try {
                        Remove-Item -Path $arquivo.FullName -Force -ErrorAction SilentlyContinue
                        $msiRem++
                        $msiBytes += $tamanho
                        Write-Ok "Cache MSI removido: $($arquivo.Name)  [$prodName]"
                        Add-Relatorio "Cache MSI: $($arquivo.Name) ($prodName)"
                    } catch {
                        Write-Aviso "Sem permissao para remover: $($arquivo.Name)"
                    }
                }
            }
    } catch {
        Write-Aviso "WindowsInstaller.Installer nao disponivel: $_"
    } finally {
        if ($installerCom) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($installerCom) | Out-Null }
    }
}

$msiMB = if ($msiBytes -ge 1MB) { '{0:N1} MB' -f ($msiBytes / 1MB) } else { "$([int]($msiBytes / 1KB)) KB" }
Write-Info "Arquivos MSI/MSP com produto legivel: $msiVer  |  Removidos: $msiRem  ($msiMB liberados)"

# ---- 9.2 Entradas de registro MsiExec com nome do programa -------------

Write-Etapa '9.2  Registro MsiExec com nome do programa...'

$regMsiVer = 0
$regMsiRem = 0

# UserData: ...Installer\UserData\{SID}\Products\{GUID}\InstallProperties (DisplayName)
$userDataKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'
if (Test-Path $userDataKey) {
    Get-ChildItem -Path $userDataKey -ErrorAction SilentlyContinue | ForEach-Object {
        $productsPath = "$($_.PSPath)\Products"
        if (-not (Test-Path $productsPath)) { return }
        Get-ChildItem -Path $productsPath -ErrorAction SilentlyContinue | ForEach-Object {
            $installPropsPath = "$($_.PSPath)\InstallProperties"
            if (-not (Test-Path $installPropsPath)) { return }
            $props = Get-ItemProperty -Path $installPropsPath -ErrorAction SilentlyContinue
            $displayName = [string]$props.DisplayName
            if ($displayName -eq '') { return }
            $regMsiVer++
            if ($displayName -like "*$nomeBusca*") {
                $prodPath = $_.PSPath
                try {
                    Remove-Item -Path $prodPath -Recurse -Force -ErrorAction SilentlyContinue
                    $regMsiRem++
                    Write-Ok "UserData MSI removido: $displayName"
                    Add-Relatorio "Registro MSI UserData: $displayName"
                } catch {
                    Write-Aviso "Sem permissao para remover UserData: $displayName"
                }
            }
        }
    }
}

# Classes: HKLM\SOFTWARE\Classes\Installer\Products\{PackedGUID} (ProductName)
$classesProductsKey = 'HKLM:\SOFTWARE\Classes\Installer\Products'
if (Test-Path $classesProductsKey) {
    Get-ChildItem -Path $classesProductsKey -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        $prodName = [string]$props.ProductName
        if ($prodName -eq '') { return }
        $regMsiVer++
        if ($prodName -like "*$nomeBusca*") {
            try {
                Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                $regMsiRem++
                Write-Ok "Classes MSI removido: $prodName"
                Add-Relatorio "Registro MSI Classes: $prodName"
            } catch {
                Write-Aviso "Sem permissao para remover Classes: $prodName"
            }
        }
    }
}

Write-Info "Entradas de registro MSI verificadas: $regMsiVer  |  Removidas: $regMsiRem"
Write-Host ''
Add-Relatorio ''
Add-Relatorio "Etapa 9 - MSI: $msiRem arquivo(s) de cache, $regMsiRem entrada(s) de registro removidos"

# =========================================================================
# RELATORIO FINAL
# =========================================================================

Write-Host ''
Write-Host ('=' * 62) -ForegroundColor Green
Write-Host '                 RELATORIO FINAL                     ' -ForegroundColor Green
Write-Host ('=' * 62) -ForegroundColor Green
Write-Host ''

foreach ($linha in $relatorio) {
    if ($linha -eq '') {
        Write-Host ''
    } else {
        Write-Host "  $linha" -ForegroundColor Gray
    }
}

$totalItens = $relatorio | Where-Object { $_ -ne '' } | Measure-Object
Write-Host ''
Write-Host ("  Total de itens removidos: $($totalItens.Count)") -ForegroundColor Cyan
Write-Host ("  Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor Gray
Write-Host ''
Write-Host ('=' * 62) -ForegroundColor Green
Write-Host ''
