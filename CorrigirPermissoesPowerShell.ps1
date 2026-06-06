# CorrigirPermissoesPowerShell.ps1
# Resolve todos os tipos de bloqueio de execucao do PowerShell no Windows
#
# COMO EXECUTAR SE AINDA ESTIVER BLOQUEADO:
#   powershell.exe -ExecutionPolicy Bypass -File CorrigirPermissoesPowerShell.ps1

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
# Relatorio
# -------------------------------------------------------------------------

$relatorio = [System.Collections.Generic.List[PSObject]]::new()

function Add-Rel {
    param([string]$Etapa, [string]$Status, [string]$Msg)
    $relatorio.Add([PSCustomObject]@{ Etapa = $Etapa; Status = $Status; Msg = $Msg })
}

# =========================================================================
# Cabecalho
# =========================================================================

Write-Host ''
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host '   Corrigir Permissoes de Execucao do PowerShell      ' -ForegroundColor Cyan
Write-Host '   ExecutionPolicy | Registry | Zone.Identifier | GPO ' -ForegroundColor Cyan
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host ("   Iniciado em : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host ''

# =========================================================================
# ETAPA 2 - Verificar privilegios de Administrador
# =========================================================================

Write-Etapa '2/10  Verificando privilegios de Administrador...'
Write-Host ''

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if ($isAdmin) {
    Write-Ok 'Executando como Administrador. Todas as correcoes serao aplicadas.'
    Add-Rel '2. Administrador' 'OK' 'Script executando com privilegios de Administrador'
} else {
    Write-Aviso 'NAO esta sendo executado como Administrador.'
    Write-Info  'Correcoes no HKLM e para todos os usuarios exigem privilegios elevados.'
    Write-Info  'Execute novamente: clique direito no PowerShell > Executar como Administrador'
    Add-Rel '2. Administrador' 'AVISO' 'Sem privilegios de Admin. Algumas correcoes podem nao ser aplicadas.'
}

# =========================================================================
# ETAPA 1 - Corrigir ExecutionPolicy em todos os escopos
# =========================================================================

Write-Etapa '1/10  Corrigindo ExecutionPolicy em todos os escopos...'
Write-Host ''

$politicaAntes = Get-ExecutionPolicy -ErrorAction SilentlyContinue
Write-Info "Politica efetiva atual: $politicaAntes"
Write-Host ''

$escopos = @(
    @{ Nome = 'Process';       GPO = $false }
    @{ Nome = 'CurrentUser';   GPO = $false }
    @{ Nome = 'LocalMachine';  GPO = $false }
    @{ Nome = 'UserPolicy';    GPO = $true  }
    @{ Nome = 'MachinePolicy'; GPO = $true  }
)

$escoposOk    = 0
$escoposGPO   = 0
$escoposErro  = 0

foreach ($escopo in $escopos) {
    try {
        $politicaAtual = Get-ExecutionPolicy -Scope $escopo.Nome -ErrorAction SilentlyContinue
        if ($politicaAtual -eq 'Unrestricted') {
            Write-Ok ($escopo.Nome.PadRight(18) + ': ja esta como Unrestricted.')
            $escoposOk++
        } else {
            if ($escopo.GPO) {
                Write-Aviso ($escopo.Nome.PadRight(18) + ': controlado por GPO (valor atual: ' + $politicaAtual + '). Ignorando.')
                $escoposGPO++
            } else {
                Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope $escopo.Nome -Force -ErrorAction Stop
                Write-Ok ($escopo.Nome.PadRight(18) + ': corrigido para Unrestricted (era: ' + $politicaAtual + ').')
                $escoposOk++
            }
        }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'Group Policy|Politica de Grupo|GPO|cannot be set') {
            Write-Aviso ($escopo.Nome.PadRight(18) + ': bloqueado por GPO. Necessita administrador do dominio.')
            $escoposGPO++
        } else {
            Write-Falha ($escopo.Nome.PadRight(18) + ': erro - ' + $msg)
            $escoposErro++
        }
    }
}

$politicaDepois = Get-ExecutionPolicy -ErrorAction SilentlyContinue
Write-Host ''
Write-Info "Politica efetiva apos correcao: $politicaDepois"

if ($escoposErro -eq 0 -and $escoposGPO -eq 0) {
    Add-Rel '1. ExecutionPolicy' 'OK' "Todos os escopos definidos como Unrestricted"
} elseif ($escoposGPO -gt 0 -and $escoposErro -eq 0) {
    Add-Rel '1. ExecutionPolicy' 'AVISO' "$escoposOk escopo(s) corrigidos | $escoposGPO escopo(s) bloqueados por GPO"
} else {
    Add-Rel '1. ExecutionPolicy' 'AVISO' "$escoposOk OK | $escoposGPO GPO | $escoposErro erro(s)"
}

# =========================================================================
# ETAPA 6 - Verificar bloqueio por GPO antes de editar registro
# =========================================================================

Write-Etapa '6/10  Verificando bloqueio por GPO...'
Write-Host ''

$regGPOHKLM = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$regGPOHKCU = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$gpoAtivo   = $false

$gpoHKLM = Get-ItemProperty $regGPOHKLM -ErrorAction SilentlyContinue
if ($gpoHKLM) {
    $gpoAtivo = $true
    $gpoPolicy = $gpoHKLM.EnableScripts
    $gpoExec   = $gpoHKLM.ExecutionPolicy
    Write-Aviso 'GPO encontrada em HKLM (politica de maquina):'
    if ($null -ne $gpoPolicy) { Write-Dest ('   EnableScripts    = ' + $gpoPolicy) }
    if ($null -ne $gpoExec)   { Write-Dest ('   ExecutionPolicy  = ' + $gpoExec) }
    Write-Info  'Esta configuracao SO pode ser alterada pelo Administrador do Dominio (GPO).'
    Write-Info  'Contate o TI para liberar: Computer Config > Admin Templates > Windows Components > PowerShell'
}

$gpoHKCU = Get-ItemProperty $regGPOHKCU -ErrorAction SilentlyContinue
if ($gpoHKCU) {
    $gpoAtivo = $true
    Write-Aviso 'GPO encontrada em HKCU (politica de usuario):'
    $gpoExecU = $gpoHKCU.ExecutionPolicy
    if ($null -ne $gpoExecU) { Write-Dest ('   ExecutionPolicy  = ' + $gpoExecU) }
}

if (-not $gpoAtivo) {
    Write-Ok 'Nenhum bloqueio por GPO detectado.'
    Add-Rel '6. GPO' 'OK' 'Nenhuma politica de grupo bloqueando o PowerShell'
} else {
    Add-Rel '6. GPO' 'AVISO' 'GPO ativa detectada. Administrador do dominio deve liberar via GPMC.'
}

# =========================================================================
# ETAPA 4 - Corrigir registro HKLM (64 bits)
# =========================================================================

Write-Etapa '4/10  Corrigindo registro HKLM - PowerShell 64 bits...'
Write-Host ''

$regHKLM64 = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'

try {
    if (-not (Test-Path $regHKLM64)) {
        New-Item $regHKLM64 -Force | Out-Null
        Write-Info 'Chave HKLM 64 bits criada.'
    }
    $valorAtual = (Get-ItemProperty $regHKLM64 -ErrorAction SilentlyContinue).ExecutionPolicy
    Set-ItemProperty $regHKLM64 -Name 'ExecutionPolicy' -Value 'Unrestricted' -Type String -Force
    Write-Ok "HKLM 64 bits: ExecutionPolicy definida como Unrestricted (era: $valorAtual)."
    Add-Rel '4. HKLM 64 bits' 'OK' 'ExecutionPolicy=Unrestricted aplicado'
} catch {
    Write-Falha ('HKLM 64 bits: erro - ' + $_.Exception.Message)
    Add-Rel '4. HKLM 64 bits' 'ERRO' $_.Exception.Message
}

# =========================================================================
# ETAPA 7 - Corrigir registro HKLM (32 bits / WOW6432Node)
# =========================================================================

Write-Etapa '7/10  Corrigindo registro HKLM - PowerShell 32 bits (WOW6432Node)...'
Write-Host ''

$regHKLM32 = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'

try {
    if (-not (Test-Path $regHKLM32)) {
        New-Item $regHKLM32 -Force | Out-Null
        Write-Info 'Chave HKLM 32 bits criada.'
    }
    $valorAtual32 = (Get-ItemProperty $regHKLM32 -ErrorAction SilentlyContinue).ExecutionPolicy
    Set-ItemProperty $regHKLM32 -Name 'ExecutionPolicy' -Value 'Unrestricted' -Type String -Force
    Write-Ok "HKLM 32 bits: ExecutionPolicy definida como Unrestricted (era: $valorAtual32)."
    Add-Rel '7. HKLM 32 bits' 'OK' 'ExecutionPolicy=Unrestricted aplicado (WOW6432Node)'
} catch {
    Write-Falha ('HKLM 32 bits: erro - ' + $_.Exception.Message)
    Add-Rel '7. HKLM 32 bits' 'ERRO' $_.Exception.Message
}

# =========================================================================
# ETAPA 5 - Corrigir registro HKCU (usuario atual)
# =========================================================================

Write-Etapa '5/10  Corrigindo registro HKCU - usuario atual...'
Write-Host ''

$regHKCU = 'HKCU:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'

try {
    if (-not (Test-Path $regHKCU)) {
        New-Item $regHKCU -Force | Out-Null
        Write-Info 'Chave HKCU criada.'
    }
    $valorAtualHKCU = (Get-ItemProperty $regHKCU -ErrorAction SilentlyContinue).ExecutionPolicy
    Set-ItemProperty $regHKCU -Name 'ExecutionPolicy' -Value 'Unrestricted' -Type String -Force
    Write-Ok "HKCU: ExecutionPolicy definida como Unrestricted (era: $valorAtualHKCU)."
    Add-Rel '5. HKCU' 'OK' 'ExecutionPolicy=Unrestricted aplicado para o usuario atual'
} catch {
    Write-Falha ('HKCU: erro - ' + $_.Exception.Message)
    Add-Rel '5. HKCU' 'ERRO' $_.Exception.Message
}

# =========================================================================
# ETAPA 3 - Desbloquear arquivos .ps1 com Zone.Identifier
# =========================================================================

Write-Etapa '3/10  Desbloqueando arquivos .ps1 com Zone.Identifier (bloqueio de internet)...'
Write-Host ''

$nomesIgnorados  = '^(Public|All Users|Default|Default User|defaultuser0|desktop\.ini)$'
$usuarios = @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch $nomesIgnorados })

$totalBloqueados  = 0
$totalDesbloqueados = 0

foreach ($usuario in $usuarios) {
    $pastasUsuario = @(
        Join-Path $usuario.FullName 'Documents'
        Join-Path $usuario.FullName 'Downloads'
        Join-Path $usuario.FullName 'Desktop'
    )

    $bloqUsuario = 0
    foreach ($pasta in $pastasUsuario) {
        if (-not (Test-Path $pasta -ErrorAction SilentlyContinue)) { continue }
        $arquivosPS1 = @(Get-ChildItem $pasta -Filter '*.ps1' -Recurse -Force -ErrorAction SilentlyContinue)
        foreach ($arq in $arquivosPS1) {
            $zone = Get-Item $arq.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue
            if ($zone) {
                $totalBloqueados++
                $bloqUsuario++
                Unblock-File $arq.FullName -ErrorAction SilentlyContinue
                $zoneDepois = Get-Item $arq.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue
                if (-not $zoneDepois) { $totalDesbloqueados++ }
            }
        }
    }

    if ($bloqUsuario -gt 0) {
        Write-Ok ("$($usuario.Name): $bloqUsuario arquivo(s) desbloqueado(s).")
    } else {
        Write-Info ("$($usuario.Name): nenhum arquivo bloqueado em Documents/Downloads/Desktop.")
    }
}

# Pasta C:\Suporte (global)
if (Test-Path 'C:\Suporte') {
    $arquivosSuporte = @(Get-ChildItem 'C:\Suporte' -Filter '*.ps1' -Recurse -Force -ErrorAction SilentlyContinue)
    $bloqSuporte = 0
    foreach ($arq in $arquivosSuporte) {
        $zone = Get-Item $arq.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue
        if ($zone) {
            $totalBloqueados++
            $bloqSuporte++
            Unblock-File $arq.FullName -ErrorAction SilentlyContinue
            $zoneDepois = Get-Item $arq.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue
            if (-not $zoneDepois) { $totalDesbloqueados++ }
        }
    }
    if ($bloqSuporte -gt 0) {
        Write-Ok "C:\Suporte: $bloqSuporte arquivo(s) desbloqueado(s)."
    } else {
        Write-Info 'C:\Suporte: nenhum arquivo bloqueado.'
    }
} else {
    Write-Info 'C:\Suporte nao existe neste computador.'
}

Write-Host ''
if ($totalBloqueados -eq 0) {
    Write-Ok 'Nenhum arquivo .ps1 bloqueado por Zone.Identifier encontrado.'
    Add-Rel '3. Zone.Identifier' 'OK' 'Nenhum arquivo bloqueado encontrado'
} elseif ($totalDesbloqueados -eq $totalBloqueados) {
    Write-Ok "Zone.Identifier: $totalDesbloqueados de $totalBloqueados arquivo(s) desbloqueado(s) com sucesso."
    Add-Rel '3. Zone.Identifier' 'OK' "$totalDesbloqueados arquivo(s) desbloqueados de $totalBloqueados encontrados"
} else {
    $falhas = $totalBloqueados - $totalDesbloqueados
    Write-Aviso "$totalDesbloqueados desbloqueados, $falhas ainda bloqueados (possivelmente em uso)."
    Add-Rel '3. Zone.Identifier' 'AVISO' "$falhas arquivo(s) nao puderam ser desbloqueados"
}

# =========================================================================
# ETAPA 8 - Limpar cache do PowerShell (PSReadline e analise de modulos)
# =========================================================================

Write-Etapa '8/10  Limpando cache do PowerShell...'
Write-Host ''

$totalCacheLimpo = 0

foreach ($usuario in $usuarios) {
    $cachePaths = @(
        Join-Path $usuario.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline'
        Join-Path $usuario.FullName 'AppData\Local\Microsoft\Windows\PowerShell\CommandAnalysis'
        Join-Path $usuario.FullName 'AppData\Local\Microsoft\Windows\PowerShell\ModuleAnalysisCache'
    )

    $limpouAlgo = $false
    foreach ($cachePath in $cachePaths) {
        if (Test-Path $cachePath -ErrorAction SilentlyContinue) {
            $nomeCache = Split-Path $cachePath -Leaf
            $itens = @(Get-ChildItem $cachePath -Force -ErrorAction SilentlyContinue)
            Remove-Item $cachePath -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $cachePath)) {
                Write-Ok ("$($usuario.Name) [$nomeCache]: $($itens.Count) item(ns) removido(s).")
                $totalCacheLimpo++
                $limpouAlgo = $true
            }
        }
    }

    if (-not $limpouAlgo) {
        Write-Info ("$($usuario.Name): caches ja estavam limpos ou inacessiveis.")
    }
}

# Cache global do PowerShell em ProgramData
$cacheGlobal = 'C:\ProgramData\Microsoft\Windows\PowerShell'
if (Test-Path $cacheGlobal) {
    $arquivosCache = @(Get-ChildItem $cacheGlobal -Filter '*.cache' -Recurse -ErrorAction SilentlyContinue)
    if ($arquivosCache.Count -gt 0) {
        $arquivosCache | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Ok "Cache global: $($arquivosCache.Count) arquivo(s) .cache removido(s) em ProgramData."
        $totalCacheLimpo++
    }
}

if ($totalCacheLimpo -gt 0) {
    Add-Rel '8. Cache PS' 'OK' "Cache limpo em $totalCacheLimpo localizacao(oes)"
} else {
    Add-Rel '8. Cache PS' 'OK' 'Caches ja estavam limpos'
}

# =========================================================================
# ETAPA 9 - Testar execucao de script ps1
# =========================================================================

Write-Etapa '9/10  Testando execucao de script .ps1...'
Write-Host ''

$testeOk     = $false
$testeDetalhe = ''
$tempFile    = [System.IO.Path]::GetTempPath() + 'ps_exec_test_' + [System.Guid]::NewGuid().ToString('N') + '.ps1'

try {
    Set-Content $tempFile 'Write-Output "EXECUCAO_OK_PJE"' -Encoding UTF8

    # Desbloquear o proprio arquivo de teste (pode ser marcado como zona internet)
    Unblock-File $tempFile -ErrorAction SilentlyContinue

    $resultado = & $tempFile 2>&1
    if ($resultado -match 'EXECUCAO_OK_PJE') {
        $testeOk      = $true
        $testeDetalhe = 'Script .ps1 executado com sucesso na sessao atual.'
        Write-Ok $testeDetalhe
    } else {
        $testeDetalhe = 'Script executou mas retornou resultado inesperado: ' + $resultado
        Write-Aviso $testeDetalhe
    }
} catch {
    $testeDetalhe = 'Falha na execucao: ' + $_.Exception.Message
    Write-Falha $testeDetalhe
    Write-Info  'Se o erro for de politica, reinicie o PowerShell e tente novamente.'
    Write-Info  'Ou execute: powershell.exe -ExecutionPolicy Bypass -File seuScript.ps1'
} finally {
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
}

# Testar tambem com nova sessao powershell.exe para confirmar politica persistida
Write-Host ''
Write-Acao 'Testando execucao em nova sessao do PowerShell...'
$tempFile2 = [System.IO.Path]::GetTempPath() + 'ps_exec_test2_' + [System.Guid]::NewGuid().ToString('N') + '.ps1'
try {
    Set-Content $tempFile2 'Write-Output "SESSAO_NOVA_OK"' -Encoding UTF8
    Unblock-File $tempFile2 -ErrorAction SilentlyContinue
    $resultadoNovaSessao = powershell.exe -NoProfile -NonInteractive -File $tempFile2 2>&1
    if ($resultadoNovaSessao -match 'SESSAO_NOVA_OK') {
        Write-Ok 'Nova sessao PowerShell: execucao funcionando corretamente.'
        $testeNovaOk = $true
    } else {
        Write-Aviso ('Nova sessao retornou: ' + ($resultadoNovaSessao -join ' '))
        $testeNovaOk = $false
    }
} catch {
    Write-Aviso ('Erro na nova sessao: ' + $_.Exception.Message)
    $testeNovaOk = $false
} finally {
    Remove-Item $tempFile2 -Force -ErrorAction SilentlyContinue
}

if ($testeOk -and $testeNovaOk) {
    Add-Rel '9. Teste execucao' 'OK' 'Sessao atual e nova sessao executando scripts sem restricao'
} elseif ($testeOk) {
    Add-Rel '9. Teste execucao' 'AVISO' 'Sessao atual OK, nova sessao com restricao. Reinicie o PowerShell.'
} else {
    Add-Rel '9. Teste execucao' 'ERRO' $testeDetalhe
}

# =========================================================================
# ETAPA 10 - Relatorio final colorido
# =========================================================================

Write-Etapa '10/10  Relatorio final...'
Write-Host ''

Write-Host '======================================================' -ForegroundColor Cyan
Write-Host '   RELATORIO - PERMISSOES DE EXECUCAO DO POWERSHELL   ' -ForegroundColor Cyan
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host ''

foreach ($item in $relatorio) {
    $cor     = if ($item.Status -eq 'OK') { 'Green' } elseif ($item.Status -eq 'AVISO') { 'Yellow' } else { 'Red' }
    $prefixo = if ($item.Status -eq 'OK') { '[OK]   ' } elseif ($item.Status -eq 'AVISO') { '[!]    ' } else { '[ERRO] ' }
    Write-Host ('   ' + $prefixo) -ForegroundColor $cor -NoNewline
    Write-Host ($item.Etapa.PadRight(24) + '  ') -ForegroundColor White -NoNewline
    Write-Host $item.Msg -ForegroundColor $cor
}

$erros  = @($relatorio | Where-Object { $_.Status -eq 'ERRO' })
$avisos = @($relatorio | Where-Object { $_.Status -eq 'AVISO' })
$oks    = @($relatorio | Where-Object { $_.Status -eq 'OK' })

Write-Host ''
$corRes = if ($erros.Count -gt 0) { 'Red' } elseif ($avisos.Count -gt 0) { 'Yellow' } else { 'Green' }
Write-Host ('   Resumo: ' + $oks.Count + ' OK  |  ' + $avisos.Count + ' Aviso(s)  |  ' + $erros.Count + ' Erro(s)') -ForegroundColor $corRes

Write-Host ''
Write-Host '   Estado final da ExecutionPolicy:' -ForegroundColor White
$politicaFinal = Get-ExecutionPolicy -List -ErrorAction SilentlyContinue
foreach ($p in $politicaFinal) {
    $corPol = if ($p.ExecutionPolicy -eq 'Unrestricted') { 'Green' } elseif ($p.ExecutionPolicy -eq 'Undefined') { 'Gray' } else { 'Yellow' }
    Write-Host ('     ' + $p.Scope.ToString().PadRight(18) + ': ') -ForegroundColor DarkGray -NoNewline
    Write-Host $p.ExecutionPolicy -ForegroundColor $corPol
}

Write-Host ''
if ($gpoAtivo) {
    Write-Host '   ATENCAO GPO:' -ForegroundColor Yellow
    Write-Host '   Uma politica de grupo (GPO) esta restringindo o PowerShell.' -ForegroundColor Yellow
    Write-Host '   Para liberar permanentemente, o Administrador do Dominio deve:' -ForegroundColor Yellow
    Write-Host '   GPMC > Configuracoes do Computador > Modelos Administrativos' -ForegroundColor Gray
    Write-Host '         > Componentes do Windows > Windows PowerShell' -ForegroundColor Gray
    Write-Host '         > "Ativar a Execucao de Scripts" > Permitir todos os scripts' -ForegroundColor Gray
    Write-Host ''
}

Write-Host '   Dica: Se ainda houver bloqueio, execute o script assim:' -ForegroundColor DarkGray
Write-Host '   powershell.exe -ExecutionPolicy Bypass -File seuScript.ps1' -ForegroundColor DarkCyan
Write-Host ''
Write-Host ("   Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host ''
