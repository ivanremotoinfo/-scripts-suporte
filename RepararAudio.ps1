# RepararAudio.ps1
# Detecta e resolve automaticamente problemas de audio e microfone no Windows

$ErrorActionPreference = 'Continue'
$resolvidoHW    = $false
$etapaResolvida = ''
$acoesTomadas   = [System.Collections.Generic.List[string]]::new()

# -------------------------------------------------------------------------
# Funcoes auxiliares
# -------------------------------------------------------------------------

function Write-Etapa { param([string]$t) Write-Host "`n>> $t" -ForegroundColor Cyan }
function Write-Ok    { param([string]$t) Write-Host '   [OK] ' -ForegroundColor Green  -NoNewline; Write-Host $t }
function Write-Aviso { param([string]$t) Write-Host '   [!]  ' -ForegroundColor Yellow -NoNewline; Write-Host $t }
function Write-Falha { param([string]$t) Write-Host '   [X]  ' -ForegroundColor Red    -NoNewline; Write-Host $t }
function Write-Info  { param([string]$t) Write-Host "   $t" -ForegroundColor Gray }

function Get-DispositivosAudio {
    Get-PnpDevice -ErrorAction SilentlyContinue |
        Where-Object { $_.Class -in @('Media', 'AudioEndpoint') }
}

function Test-AudioFuncionando {
    $svcAudio = Get-Service -Name 'AudioSrv'             -ErrorAction SilentlyContinue
    $svcEndpt = Get-Service -Name 'AudioEndpointBuilder' -ErrorAction SilentlyContinue
    $devOK    = @(Get-PnpDevice -ErrorAction SilentlyContinue |
        Where-Object { $_.Class -eq 'Media' -and $_.Status -eq 'OK' })
    $servicosOK = ($svcAudio -and $svcAudio.Status -eq 'Running') -and
                  ($svcEndpt -and $svcEndpt.Status -eq 'Running')
    return ($servicosOK -and $devOK.Count -gt 0)
}

function Verifica-EResolvido {
    param([string]$EtapaLabel)
    if ($script:resolvidoHW) { return $true }
    if (Test-AudioFuncionando) {
        $script:resolvidoHW    = $true
        $script:etapaResolvida = $EtapaLabel
        Write-Ok 'Audio detectado e funcionando: servicos ativos e dispositivo OK.'
        return $true
    }
    return $false
}

function Descricao-ProblemCode {
    param([int]$Code)
    switch ($Code) {
        0   { 'Funcionando normalmente' }
        1   { 'Nao configurado corretamente' }
        10  { 'Nao foi possivel iniciar' }
        22  { 'Desabilitado manualmente' }
        28  { 'Driver nao instalado' }
        43  { 'Erro reportado pelo dispositivo (codigo 43)' }
        45  { 'Nao esta conectado' }
        52  { 'Windows nao pode verificar assinatura do driver' }
        default { "Erro codigo $Code" }
    }
}

# =========================================================================
# Cabecalho
# =========================================================================

Write-Host ''
Write-Host '================================================' -ForegroundColor Cyan
Write-Host '   Reparo Automatico de Audio e Microfone       ' -ForegroundColor Cyan
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
# ETAPA 1 - Verificar dispositivos de audio (incluindo desabilitados e com erro)
# =========================================================================

Write-Etapa '1/8  Verificando dispositivos de audio no sistema...'
Write-Host ''

$todosDispositivos = @(Get-DispositivosAudio)
$dispositivosMedia = @($todosDispositivos | Where-Object { $_.Class -eq 'Media' })

# WMI para nomes amigaveis de placas de som
$wmiAudio = @(Get-WmiObject -Class Win32_SoundDevice -ErrorAction SilentlyContinue)

if ($dispositivosMedia.Count -gt 0) {
    Write-Info "$($dispositivosMedia.Count) controlador(es) de audio encontrado(s):"
    Write-Host ''
    foreach ($dev in $dispositivosMedia) {
        $cor = switch ($dev.Status) { 'OK' { 'Green' } 'Error' { 'Yellow' } default { 'Gray' } }
        $statusDesc = Descricao-ProblemCode -Code ([int]$dev.ProblemCode)
        Write-Host ("   $($dev.FriendlyName)") -ForegroundColor $cor
        Write-Host ("   Status : $statusDesc  |  Classe: $($dev.Class)") -ForegroundColor DarkGray
        Write-Host ("   ID     : $($dev.InstanceId)") -ForegroundColor DarkGray
        Write-Host ''
    }
} else {
    Write-Aviso 'Nenhum controlador de audio detectado (classe Media).'
}

# Endpoints de audio (saida/entrada)
$endpoints = @($todosDispositivos | Where-Object { $_.Class -eq 'AudioEndpoint' })
if ($endpoints.Count -gt 0) {
    $epOK   = @($endpoints | Where-Object { $_.Status -eq 'OK' })
    $epErro = @($endpoints | Where-Object { $_.Status -ne 'OK' })
    Write-Info "$($epOK.Count) endpoint(s) de audio ativo(s), $($epErro.Count) com problema."
    Write-Host ''
}

# Servicos
$svcAudio = Get-Service -Name 'AudioSrv'             -ErrorAction SilentlyContinue
$svcEndpt = Get-Service -Name 'AudioEndpointBuilder' -ErrorAction SilentlyContinue
$corSvcA  = if ($svcAudio -and $svcAudio.Status -eq 'Running') { 'Green' } else { 'Yellow' }
$corSvcE  = if ($svcEndpt -and $svcEndpt.Status -eq 'Running') { 'Green' } else { 'Yellow' }
Write-Host ("   AudioSrv             : {0}" -f $(if ($svcAudio) { $svcAudio.Status } else { 'nao encontrado' })) -ForegroundColor $corSvcA
Write-Host ("   AudioEndpointBuilder : {0}" -f $(if ($svcEndpt) { $svcEndpt.Status } else { 'nao encontrado' })) -ForegroundColor $corSvcE
Write-Host ''

Verifica-EResolvido -EtapaLabel 'audio ja funcionando antes de qualquer reparo' | Out-Null

# =========================================================================
# ETAPA 2 - Reabilitar dispositivos de audio desabilitados
# =========================================================================

if (-not $resolvidoHW) {
    Write-Etapa '2/8  Reabilitando dispositivos de audio desabilitados...'

    $desabilitados = @($todosDispositivos | Where-Object { $_.ProblemCode -eq 22 })

    if ($desabilitados.Count -gt 0) {
        foreach ($dev in $desabilitados) {
            Write-Info "Reabilitando: $($dev.FriendlyName) [$($dev.Class)]"
            try {
                Enable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false -ErrorAction Stop
                Write-Ok "Reabilitado: $($dev.FriendlyName)"
                $acoesTomadas.Add("Dispositivo de audio reabilitado: $($dev.FriendlyName)")
            } catch {
                Write-Aviso "Falha pelo cmdlet: $_ - tentando pnputil..."
                & pnputil /enable-device $dev.InstanceId 2>&1 | ForEach-Object { Write-Info $_.ToString() }
            }
        }
        Write-Info 'Aguardando reconhecimento do dispositivo...'
        Start-Sleep -Seconds 3
        $todosDispositivos = @(Get-DispositivosAudio)
    } else {
        Write-Info 'Nenhum dispositivo de audio desabilitado encontrado.'
    }

    Verifica-EResolvido -EtapaLabel 'dispositivo de audio reabilitado (estava desabilitado)' | Out-Null
}

# =========================================================================
# ETAPA 3 - Verificar e reativar servicos de audio
# =========================================================================

if (-not $resolvidoHW) {
    Write-Etapa '3/8  Verificando e reativando servicos de audio...'

    $servicosAlvo = @(
        [PSCustomObject]@{ Nome = 'AudioEndpointBuilder'; Display = 'Windows Audio Endpoint Builder'; Tipo = 'Automatic' }
        [PSCustomObject]@{ Nome = 'AudioSrv';             Display = 'Windows Audio';                  Tipo = 'Automatic' }
    )

    $precisaReiniciar = $false

    foreach ($svcInfo in $servicosAlvo) {
        $svc = Get-Service -Name $svcInfo.Nome -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-Aviso "$($svcInfo.Display): servico nao encontrado no sistema."
            continue
        }
        if ($svc.StartType -eq 'Disabled') {
            try {
                Set-Service -Name $svcInfo.Nome -StartupType $svcInfo.Tipo -ErrorAction Stop
                Write-Ok "$($svcInfo.Display): tipo alterado de Disabled para $($svcInfo.Tipo)."
                $acoesTomadas.Add("Servico reabilitado: $($svcInfo.Display)")
            } catch {
                Write-Aviso "Nao foi possivel reabilitar $($svcInfo.Display): $_"
            }
        }
        if ($svc.Status -ne 'Running') {
            $precisaReiniciar = $true
        }
    }

    # Reiniciar servicos se necessario (ordem: parar AudioSrv, parar Builder, iniciar Builder, iniciar AudioSrv)
    if ($precisaReiniciar -or -not (Test-AudioFuncionando)) {
        Write-Info 'Reiniciando servicos de audio (AudioEndpointBuilder -> AudioSrv)...'
        try {
            Stop-Service -Name 'AudioSrv'             -Force -ErrorAction SilentlyContinue
            Stop-Service -Name 'AudioEndpointBuilder' -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Start-Service -Name 'AudioEndpointBuilder' -ErrorAction Stop
            Start-Sleep -Seconds 1
            Start-Service -Name 'AudioSrv'             -ErrorAction Stop
            Start-Sleep -Seconds 3
            Write-Ok 'Servicos de audio reiniciados com sucesso.'
            $acoesTomadas.Add('Servicos AudioSrv e AudioEndpointBuilder reiniciados')
        } catch {
            Write-Falha "Erro ao reiniciar servicos: $_"
        }
    } else {
        Write-Ok 'Servicos de audio ja estao em execucao.'
    }

    Verifica-EResolvido -EtapaLabel 'servicos de audio reativados' | Out-Null
}

# =========================================================================
# ETAPA 4 - Corrigir permissoes de microfone HKLM (sempre executa)
# =========================================================================

Write-Etapa '4/8  Corrigindo permissoes de acesso ao microfone - sistema (HKLM)...'

$regHKLMMic = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone'

try {
    if (-not (Test-Path $regHKLMMic)) {
        New-Item -Path $regHKLMMic -Force -ErrorAction Stop | Out-Null
        Write-Info 'Chave de consentimento de microfone criada no HKLM.'
    }
    $valAtual = (Get-ItemProperty -Path $regHKLMMic -Name 'Value' -ErrorAction SilentlyContinue).Value
    if ($valAtual -ne 'Allow') {
        Set-ItemProperty -Path $regHKLMMic -Name 'Value' -Value 'Allow' -Type String -ErrorAction Stop
        Write-Ok "HKLM microphone\Value: '$valAtual' alterado para 'Allow'."
        $acoesTomadas.Add('Permissao HKLM microphone definida para Allow')
    } else {
        Write-Ok "HKLM microphone\Value: ja configurado como 'Allow'."
    }
} catch {
    Write-Falha "Nao foi possivel configurar permissao HKLM: $_"
}

# =========================================================================
# ETAPA 5 - Habilitar microfone para apps Win32 e navegadores HKCU (sempre executa)
# =========================================================================

Write-Etapa '5/8  Habilitando acesso ao microfone para apps e navegadores (HKCU)...'

$regHKCUMic = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone'

try {
    if (-not (Test-Path $regHKCUMic)) {
        New-Item -Path $regHKCUMic -Force -ErrorAction Stop | Out-Null
        Write-Info 'Chave de consentimento de microfone criada no HKCU.'
    }
    $valAtual = (Get-ItemProperty -Path $regHKCUMic -Name 'Value' -ErrorAction SilentlyContinue).Value
    if ($valAtual -ne 'Allow') {
        Set-ItemProperty -Path $regHKCUMic -Name 'Value' -Value 'Allow' -Type String -ErrorAction Stop
        Write-Ok "HKCU microphone\Value: '$valAtual' alterado para 'Allow'."
        $acoesTomadas.Add('Permissao HKCU microphone definida para Allow')
    } else {
        Write-Ok "HKCU microphone\Value: ja configurado como 'Allow'."
    }

    # NonPackaged: habilitar para apps Win32 / navegadores (Chrome, Edge, Zoom, Teams etc.)
    $regNP = "$regHKCUMic\NonPackaged"
    if (-not (Test-Path $regNP)) {
        New-Item -Path $regNP -Force -ErrorAction SilentlyContinue | Out-Null
    }
    $npVal = (Get-ItemProperty -Path $regNP -Name 'Value' -ErrorAction SilentlyContinue).Value
    if ($npVal -ne 'Allow') {
        Set-ItemProperty -Path $regNP -Name 'Value' -Value 'Allow' -Type String -ErrorAction SilentlyContinue
        Write-Ok "HKCU microphone\NonPackaged\Value: '$npVal' alterado para 'Allow'."
        $acoesTomadas.Add('Permissao HKCU microphone NonPackaged (apps Win32) definida para Allow')
    } else {
        Write-Ok "HKCU microphone\NonPackaged\Value: ja configurado como 'Allow'."
    }
} catch {
    Write-Falha "Nao foi possivel configurar permissao HKCU: $_"
}

if (-not $resolvidoHW) {
    Verifica-EResolvido -EtapaLabel 'permissoes de microfone corrigidas no registro' | Out-Null
}

# =========================================================================
# ETAPA 6 - Verificar dispositivos de reproducao e gravacao padrao
# =========================================================================

if (-not $resolvidoHW) {
    Write-Etapa '6/8  Verificando dispositivos de reproducao e gravacao padrao...'

    $mmDevicesBase = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio'
    $tipos = @(
        [PSCustomObject]@{ Chave = 'Render';  Nome = 'Reproducao (saida)'    }
        [PSCustomObject]@{ Chave = 'Capture'; Nome = 'Gravacao (microfone)'  }
    )

    foreach ($tipo in $tipos) {
        $regPath = "$mmDevicesBase\$($tipo.Chave)"
        if (-not (Test-Path $regPath -ErrorAction SilentlyContinue)) {
            Write-Aviso "$($tipo.Nome): caminho de registro nao encontrado."
            continue
        }
        $devs        = @(Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue)
        $ativos      = @($devs | Where-Object {
            (Get-ItemProperty -Path $_.PSPath -Name 'DeviceState' -ErrorAction SilentlyContinue).DeviceState -eq 1
        })
        $desabilitados = @($devs | Where-Object {
            (Get-ItemProperty -Path $_.PSPath -Name 'DeviceState' -ErrorAction SilentlyContinue).DeviceState -eq 2
        })
        $naoPresentes = @($devs | Where-Object {
            (Get-ItemProperty -Path $_.PSPath -Name 'DeviceState' -ErrorAction SilentlyContinue).DeviceState -in @(4, 8)
        })

        $cor = if ($ativos.Count -gt 0) { 'Green' } else { 'Yellow' }
        Write-Host ("   {0,-30}: {1} ativo(s), {2} desabilitado(s), {3} ausente(s)" -f `
            $tipo.Nome, $ativos.Count, $desabilitados.Count, $naoPresentes.Count) -ForegroundColor $cor

        if ($ativos.Count -eq 0 -and $desabilitados.Count -gt 0) {
            Write-Aviso "Nenhum dispositivo de $($tipo.Nome) ativo. Tentando reabilitar endpoints..."
            $epDesab = @(Get-PnpDevice -ErrorAction SilentlyContinue |
                Where-Object { $_.Class -eq 'AudioEndpoint' -and $_.ProblemCode -eq 22 })
            foreach ($ep in $epDesab) {
                try {
                    Enable-PnpDevice -InstanceId $ep.InstanceId -Confirm:$false -ErrorAction Stop
                    Write-Ok "Endpoint reabilitado: $($ep.FriendlyName)"
                    $acoesTomadas.Add("Endpoint de audio reabilitado: $($ep.FriendlyName)")
                } catch {
                    Write-Aviso "Nao foi possivel reabilitar endpoint $($ep.FriendlyName): $_"
                }
            }
        } elseif ($ativos.Count -eq 0) {
            Write-Aviso "Nenhum dispositivo de $($tipo.Nome) detectado. Verifique conexao fisica."
        }
    }

    Start-Sleep -Seconds 2
    Verifica-EResolvido -EtapaLabel 'dispositivo de audio padrao ativado' | Out-Null
}

# =========================================================================
# ETAPA 7 - Limpar UpperFilters e LowerFilters corrompidos (classe de audio)
# =========================================================================

if (-not $resolvidoHW) {
    Write-Etapa '7/8  Limpando UpperFilters e LowerFilters corrompidos para classe de audio...'

    # Classe principal de audio: Sound, video and game controllers
    $classesAudio = [ordered]@{
        'Audio (Sound Controllers)' = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}'
    }

    # Classe USB (limpeza conservadora - apenas entradas invalidas)
    $classesUSB = [ordered]@{
        'USB Controllers' = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{36fc9e60-c465-11cf-8056-444553540000}'
    }

    # Classe de audio: remover UpperFilters/LowerFilters corrompidos
    foreach ($classe in $classesAudio.GetEnumerator()) {
        $regPath = $classe.Value
        if (-not (Test-Path $regPath -ErrorAction SilentlyContinue)) {
            Write-Info "$($classe.Key): chave nao encontrada no registro."
            continue
        }
        foreach ($filtro in @('UpperFilters', 'LowerFilters')) {
            $prop = Get-ItemProperty -Path $regPath -Name $filtro -ErrorAction SilentlyContinue
            if ($prop -and $null -ne $prop.$filtro) {
                $valorAntes = @($prop.$filtro | Where-Object { $_ }) -join ', '
                # Manter apenas entradas com servico existente
                $valoresValidos = @($prop.$filtro | Where-Object {
                    $_.Trim() -ne '' -and
                    (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Trim())" -ErrorAction SilentlyContinue)
                })
                if ($valoresValidos.Count -lt @($prop.$filtro).Count) {
                    try {
                        if ($valoresValidos.Count -eq 0) {
                            Remove-ItemProperty -Path $regPath -Name $filtro -ErrorAction Stop
                            Write-Ok "Removido $filtro de $($classe.Key) (entradas invalidas: [$valorAntes])."
                        } else {
                            Set-ItemProperty -Path $regPath -Name $filtro -Value $valoresValidos -Type MultiString -ErrorAction Stop
                            Write-Ok "Limpado $filtro de $($classe.Key) - entradas invalidas removidas."
                        }
                        $acoesTomadas.Add("Removido $filtro corrompido de $($classe.Key)")
                    } catch {
                        Write-Aviso "Nao foi possivel limpar $filtro de $($classe.Key): $_"
                    }
                } else {
                    Write-Info "$filtro em $($classe.Key): todas as entradas validas (OK)."
                }
            } else {
                Write-Info "$filtro em $($classe.Key): nao configurado (OK)."
            }
        }
    }

    # USB: limpeza conservadora (apenas entradas vazias ou invalidas)
    foreach ($classe in $classesUSB.GetEnumerator()) {
        $regPath = $classe.Value
        if (-not (Test-Path $regPath -ErrorAction SilentlyContinue)) { continue }
        foreach ($filtro in @('UpperFilters', 'LowerFilters')) {
            $prop = Get-ItemProperty -Path $regPath -Name $filtro -ErrorAction SilentlyContinue
            if (-not $prop -or $null -eq $prop.$filtro) { continue }
            $valoresAtuais = @($prop.$filtro | Where-Object { $_ -ne $null })
            $valoresValidos = @($valoresAtuais | Where-Object {
                $_.Trim() -ne '' -and
                (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Trim())" -ErrorAction SilentlyContinue)
            })
            if ($valoresValidos.Count -lt $valoresAtuais.Count) {
                $removidas = ($valoresAtuais | Where-Object { $valoresValidos -notcontains $_ }) -join ', '
                try {
                    if ($valoresValidos.Count -eq 0) {
                        Remove-ItemProperty -Path $regPath -Name $filtro -ErrorAction Stop
                    } else {
                        Set-ItemProperty -Path $regPath -Name $filtro -Value $valoresValidos -Type MultiString -ErrorAction Stop
                    }
                    Write-Ok "Limpado $filtro de $($classe.Key): entradas invalidas removidas [$removidas]."
                    $acoesTomadas.Add("Limpado $filtro em $($classe.Key)")
                } catch {
                    Write-Aviso "Nao foi possivel limpar $filtro de $($classe.Key): $_"
                }
            } else {
                Write-Info "$filtro em $($classe.Key): valido (OK)."
            }
        }
    }

    # Reiniciar servicos apos limpeza de filtros
    Write-Info 'Reiniciando servicos apos limpeza de filtros...'
    Stop-Service -Name 'AudioSrv'             -Force -ErrorAction SilentlyContinue
    Stop-Service -Name 'AudioEndpointBuilder' -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Service -Name 'AudioEndpointBuilder' -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Start-Service -Name 'AudioSrv'             -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    Verifica-EResolvido -EtapaLabel 'UpperFilters/LowerFilters de audio removidos e servicos reiniciados' | Out-Null
}

# =========================================================================
# ETAPA 8 - Forcar rescan de dispositivos de audio via pnputil
# =========================================================================

if (-not $resolvidoHW) {
    Write-Etapa '8/8  Forcando rescan de dispositivos de audio via pnputil...'

    Write-Info 'Executando: pnputil /scan-devices'
    $pnpSaida = & pnputil /scan-devices 2>&1
    $pnpSaida | ForEach-Object { Write-Info $_.ToString() }

    Write-Info 'Aguardando reenumeracao de dispositivos...'
    Start-Sleep -Seconds 5

    $todosDispositivos = @(Get-DispositivosAudio)
    Verifica-EResolvido -EtapaLabel 'rescan de audio via pnputil /scan-devices' | Out-Null
}

# =========================================================================
# RELATORIO FINAL
# =========================================================================

$corFinal = if ($resolvidoHW) { 'Green' } else { 'Yellow' }

Write-Host ''
Write-Host '================================================' -ForegroundColor $corFinal
Write-Host '   RELATORIO FINAL                              ' -ForegroundColor $corFinal
Write-Host '================================================' -ForegroundColor $corFinal
Write-Host ''

if ($resolvidoHW) {
    Write-Host '   Status : AUDIO DETECTADO E FUNCIONANDO' -ForegroundColor Green
    Write-Host ''
    $devsFinais = @(Get-PnpDevice -ErrorAction SilentlyContinue |
        Where-Object { $_.Class -eq 'Media' -and $_.Status -eq 'OK' })
    foreach ($d in $devsFinais) {
        Write-Host "   Dispositivo : $($d.FriendlyName)" -ForegroundColor Green
    }
    if ($etapaResolvida) {
        Write-Host ''
        Write-Host "   Resolvido em: $etapaResolvida" -ForegroundColor White
    }
} else {
    Write-Host '   Status : AUDIO NAO DETECTADO APOS TODAS AS ETAPAS' -ForegroundColor Red
    Write-Host ''
    $dispositivosAtuais = @(Get-DispositivosAudio)
    if ($dispositivosAtuais.Count -gt 0) {
        Write-Host '   Dispositivos encontrados mas com problemas:' -ForegroundColor Yellow
        foreach ($d in ($dispositivosAtuais | Where-Object { $_.Class -eq 'Media' })) {
            $desc = Descricao-ProblemCode -Code ([int]$d.ProblemCode)
            Write-Host "   - $($d.FriendlyName): $desc" -ForegroundColor Yellow
        }
    } else {
        Write-Host '   Nenhum controlador de audio detectado pelo sistema.' -ForegroundColor Red
    }
}

# Relatorio de permissoes de microfone
Write-Host ''
Write-Host '   Permissoes de microfone:' -ForegroundColor Cyan
$chkHKLM = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone' -Name 'Value' -ErrorAction SilentlyContinue).Value
$chkHKCU = (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone' -Name 'Value' -ErrorAction SilentlyContinue).Value
$chkNP   = (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged' -Name 'Value' -ErrorAction SilentlyContinue).Value
$corHKLM = if ($chkHKLM -eq 'Allow') { 'Green' } else { 'Yellow' }
$corHKCU = if ($chkHKCU -eq 'Allow') { 'Green' } else { 'Yellow' }
$corNP   = if ($chkNP   -eq 'Allow') { 'Green' } else { 'Yellow' }
Write-Host "   HKLM sistema    : $chkHKLM" -ForegroundColor $corHKLM
Write-Host "   HKCU usuario    : $chkHKCU" -ForegroundColor $corHKCU
Write-Host "   HKCU Win32/apps : $chkNP"   -ForegroundColor $corNP

if ($acoesTomadas.Count -gt 0) {
    Write-Host ''
    Write-Host '   Acoes realizadas nesta execucao:' -ForegroundColor Cyan
    foreach ($acao in $acoesTomadas) {
        Write-Host "   + $acao" -ForegroundColor White
    }
}

if (-not $resolvidoHW) {
    Write-Host ''
    Write-Host '   Proximos passos (sem precisar formatar):' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '   1. Verifique o volume e se o audio nao esta no mudo' -ForegroundColor White
    Write-Host '      Clique com botao direito no icone de som na barra de tarefas > Sons.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   2. Verifique o mixer de volume por aplicativo' -ForegroundColor White
    Write-Host '      Botao direito no icone de som > Abrir Mixer de Volume.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   3. Defina o dispositivo de audio padrao manualmente' -ForegroundColor White
    Write-Host '      Painel de Controle > Som > aba Reproducao > botao direito > Definir como padrao.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   4. Atualize o driver de audio pelo Gerenciador de Dispositivos' -ForegroundColor White
    Write-Host '      devmgmt.msc > Som, video e game controllers > driver > Atualizar driver.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   5. Baixe driver Realtek ou do fabricante do notebook diretamente do site' -ForegroundColor White
    Write-Host '      Use o modelo exato do seu computador para encontrar o driver correto.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   6. Execute o Solucionador de Problemas de Audio do Windows' -ForegroundColor White
    Write-Host '      Configuracoes > Sistema > Solucionar Problemas > Audio.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   7. Verifique se o audio nao esta sendo capturado por outro dispositivo' -ForegroundColor White
    Write-Host '      Painel de Controle > Som > aba Reproducao: veja se ha dispositivo Bluetooth ativo.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   8. Para microfone bloqueado em app especifico' -ForegroundColor White
    Write-Host '      Configuracoes > Privacidade > Microfone: verifique permissao por app.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   9. Reinstale o driver de audio via linha de comando (remove e reinstala)' -ForegroundColor White
    Write-Host '      pnputil /delete-driver oem##.inf /uninstall /force' -ForegroundColor Gray
    Write-Host '      Depois: pnputil /scan-devices' -ForegroundColor Gray
}

Write-Host ''
Write-Host ("   Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host '================================================' -ForegroundColor $corFinal
Write-Host ''
