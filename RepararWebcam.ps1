# RepararWebcam.ps1
# Detecta e resolve automaticamente todos os problemas comuns de webcam

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

function Get-DispositivosCamera {
    Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        ($_.Class -in @('Camera', 'Image')) -or
        ($_.FriendlyName -match '(?i)(webcam|camera|\bcam\b)' -and
         $_.FriendlyName -notmatch '(?i)(virtual|scanner|fax|projector|imagin)')
    }
}

function Test-CameraFuncionando {
    @(Get-DispositivosCamera | Where-Object { $_.Status -eq 'OK' })
}

function Verifica-EResolvido {
    param([string]$EtapaLabel)
    if ($script:resolvidoHW) { return $true }
    $camsOK = Test-CameraFuncionando
    if ($camsOK.Count -gt 0) {
        $script:resolvidoHW    = $true
        $script:etapaResolvida = $EtapaLabel
        foreach ($c in $camsOK) {
            Write-Ok "Camera detectada e funcionando: $($c.FriendlyName)"
        }
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
        52  { 'Windows nao pode verificar assinatura digital do driver' }
        default { "Erro codigo $Code" }
    }
}

# =========================================================================
# Cabecalho
# =========================================================================

Write-Host ''
Write-Host '================================================' -ForegroundColor Cyan
Write-Host '   Reparo Automatico de Webcam / Camera         ' -ForegroundColor Cyan
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
# ETAPA 1 - Verificar dispositivos de camera (incluindo desabilitados e com erro)
# =========================================================================

Write-Etapa '1/8  Verificando dispositivos de camera no sistema...'
Write-Host ''

$todasCameras = @(Get-DispositivosCamera)

if ($todasCameras.Count -gt 0) {
    Write-Info "$($todasCameras.Count) dispositivo(s) de camera encontrado(s):"
    Write-Host ''
    foreach ($cam in $todasCameras) {
        $cor = switch ($cam.Status) {
            'OK'    { 'Green' }
            'Error' { 'Yellow' }
            default { 'Gray' }
        }
        $statusDesc = Descricao-ProblemCode -Code ([int]$cam.ProblemCode)
        Write-Host ("   {0}" -f $cam.FriendlyName) -ForegroundColor $cor
        Write-Host ("   Status : {0}  |  Classe: {1}" -f $statusDesc, $cam.Class) -ForegroundColor DarkGray
        Write-Host ("   ID     : {0}" -f $cam.InstanceId) -ForegroundColor DarkGray
        Write-Host ''
    }
} else {
    Write-Aviso 'Nenhum dispositivo de camera encontrado no sistema.'
    Write-Info  'A camera pode estar completamente desconectada ou sem driver algum.'
    Write-Host ''
}

Verifica-EResolvido -EtapaLabel 'camera ja funcionando antes de qualquer reparo' | Out-Null

# =========================================================================
# ETAPA 2 - Reabilitar cameras desabilitadas
# =========================================================================

if (-not $resolvidoHW) {
    Write-Etapa '2/8  Reabilitando cameras desabilitadas...'

    $camerasDesab = @($todasCameras | Where-Object { $_.ProblemCode -eq 22 })

    if ($camerasDesab.Count -gt 0) {
        foreach ($cam in $camerasDesab) {
            Write-Info "Reabilitando: $($cam.FriendlyName)"
            try {
                Enable-PnpDevice -InstanceId $cam.InstanceId -Confirm:$false -ErrorAction Stop
                Write-Ok "Reabilitada: $($cam.FriendlyName)"
                $acoesTomadas.Add("Camera reabilitada: $($cam.FriendlyName)")
            } catch {
                Write-Aviso "Falha pelo cmdlet: $_ - tentando via pnputil..."
                & pnputil /enable-device $cam.InstanceId 2>&1 | ForEach-Object { Write-Info $_.ToString() }
            }
        }
        Write-Info 'Aguardando sistema reconhecer o dispositivo...'
        Start-Sleep -Seconds 3
        $todasCameras = @(Get-DispositivosCamera)
    } else {
        Write-Info 'Nenhuma camera desabilitada encontrada.'
    }

    Verifica-EResolvido -EtapaLabel 'camera reabilitada (estava desabilitada)' | Out-Null
}

# =========================================================================
# ETAPA 3 - Reinstalar driver de cameras com erro
# =========================================================================

if (-not $resolvidoHW) {
    Write-Etapa '3/8  Reinstalando driver de cameras com erro...'

    $camerasErro = @($todasCameras | Where-Object {
        $_.Status -eq 'Error' -and $_.ProblemCode -notin @(22, 45)
    })

    if ($camerasErro.Count -gt 0) {
        foreach ($cam in $camerasErro) {
            $probDesc = Descricao-ProblemCode -Code ([int]$cam.ProblemCode)
            Write-Info "Reinstalando driver: $($cam.FriendlyName) - $probDesc"
            try {
                Disable-PnpDevice -InstanceId $cam.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 1000
                Enable-PnpDevice -InstanceId $cam.InstanceId -Confirm:$false -ErrorAction Stop
                Write-Ok "Driver recarregado: $($cam.FriendlyName)"
                $acoesTomadas.Add("Driver reinstalado: $($cam.FriendlyName)")
            } catch {
                Write-Aviso "Falha no ciclo disable/enable: $_"
            }
        }
        Write-Info 'Aguardando recarregamento do driver...'
        Start-Sleep -Seconds 4
        Write-Info 'Acionando pnputil para atualizar drivers disponiveis...'
        & pnputil /scan-devices 2>&1 | Out-Null
        Start-Sleep -Seconds 3
        $todasCameras = @(Get-DispositivosCamera)
    } else {
        Write-Info 'Nenhuma camera com erro de driver identificada.'
    }

    Verifica-EResolvido -EtapaLabel 'driver de camera reinstalado' | Out-Null
}

# =========================================================================
# ETAPA 4 - Limpar UpperFilters e LowerFilters corrompidos
# =========================================================================

if (-not $resolvidoHW) {
    Write-Etapa '4/8  Limpando UpperFilters e LowerFilters corrompidos no registro...'

    # Classes de camera: limpeza total (seguro - filtros nao sao necessarios)
    $classesCamera = [ordered]@{
        'Camera Windows 10'   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}'
        'Imaging Devices'     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc6-810f-11d0-bec7-08002be2092f}'
    }

    # Classe USB: limpeza conservadora (remove apenas entradas invalidas/vazias)
    $classesUSB = [ordered]@{
        'USB Controllers'     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{36fc9e60-c465-11cf-8056-444553540000}'
    }

    foreach ($classe in $classesCamera.GetEnumerator()) {
        $regPath = $classe.Value
        if (-not (Test-Path $regPath -ErrorAction SilentlyContinue)) {
            Write-Info "$($classe.Key): chave de registro nao encontrada (OK)."
            continue
        }
        foreach ($filtro in @('UpperFilters', 'LowerFilters')) {
            $prop = Get-ItemProperty -Path $regPath -Name $filtro -ErrorAction SilentlyContinue
            if ($prop -and $null -ne $prop.$filtro) {
                $valorAntes = ($prop.$filtro | Where-Object { $_ }) -join ', '
                try {
                    Remove-ItemProperty -Path $regPath -Name $filtro -ErrorAction Stop
                    Write-Ok "Removido $filtro de $($classe.Key): [$valorAntes]"
                    $acoesTomadas.Add("Removido $filtro de $($classe.Key)")
                } catch {
                    Write-Aviso "Nao foi possivel remover $filtro de $($classe.Key): $_"
                }
            } else {
                Write-Info "$filtro em $($classe.Key): nao configurado (OK)."
            }
        }
    }

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
                $entradas = ($valoresAtuais | Where-Object { $valoresValidos -notcontains $_ }) -join ', '
                try {
                    if ($valoresValidos.Count -eq 0) {
                        Remove-ItemProperty -Path $regPath -Name $filtro -ErrorAction Stop
                    } else {
                        Set-ItemProperty -Path $regPath -Name $filtro -Value $valoresValidos -Type MultiString -ErrorAction Stop
                    }
                    Write-Ok "Limpado $filtro de $($classe.Key) - entradas invalidas removidas: [$entradas]"
                    $acoesTomadas.Add("Limpado $filtro em $($classe.Key)")
                } catch {
                    Write-Aviso "Nao foi possivel limpar $filtro de $($classe.Key): $_"
                }
            } else {
                Write-Info "$filtro em $($classe.Key): todas as entradas validas (OK)."
            }
        }
    }

    Write-Info 'Aguardando aplicacao das alteracoes no registro...'
    Start-Sleep -Seconds 2
    $todasCameras = @(Get-DispositivosCamera)

    Verifica-EResolvido -EtapaLabel 'UpperFilters/LowerFilters corrompidos removidos' | Out-Null
}

# =========================================================================
# ETAPA 5 - Verificar e reativar servicos de camera
# =========================================================================

if (-not $resolvidoHW) {
    Write-Etapa '5/8  Verificando e reativando servicos de camera...'

    $servicosAlvo = @(
        [PSCustomObject]@{ Nome = 'FrameServer';         Display = 'Windows Camera Frame Server' }
        [PSCustomObject]@{ Nome = 'WPDBusEnum';          Display = 'Windows Portable Device Enumerator' }
        [PSCustomObject]@{ Nome = 'DevicesFlowUserSvc';  Display = 'Devices Flow User Service' }
        [PSCustomObject]@{ Nome = 'VideoCaptureService'; Display = 'Video Capture Service' }
    )

    foreach ($svcInfo in $servicosAlvo) {
        # Servicos per-sessao tem sufixo; buscar qualquer instancia
        $svc = Get-Service -Name $svcInfo.Nome -ErrorAction SilentlyContinue
        if (-not $svc) {
            $svc = Get-Service | Where-Object { $_.Name -like "$($svcInfo.Nome)*" } | Select-Object -First 1
        }
        if (-not $svc) {
            Write-Info "$($svcInfo.Display): nao disponivel neste Windows."
            continue
        }

        if ($svc.StartType -eq 'Disabled') {
            try {
                Set-Service -Name $svc.Name -StartupType Manual -ErrorAction Stop
                Write-Ok "$($svcInfo.Display): tipo de inicializacao alterado de Disabled para Manual."
                $acoesTomadas.Add("Servico reabilitado: $($svcInfo.Display)")
            } catch {
                Write-Aviso "Nao foi possivel reabilitar $($svcInfo.Display): $_"
            }
        }

        if ($svc.Status -ne 'Running') {
            try {
                Start-Service -Name $svc.Name -ErrorAction Stop
                Write-Ok "$($svcInfo.Display): iniciado com sucesso."
                $acoesTomadas.Add("Servico iniciado: $($svcInfo.Display)")
            } catch {
                Write-Aviso "Nao foi possivel iniciar $($svcInfo.Display): $_"
            }
        } else {
            Write-Ok "$($svcInfo.Display): ja em execucao."
        }
    }

    Start-Sleep -Seconds 2
    Verifica-EResolvido -EtapaLabel 'servicos de camera reativados' | Out-Null
}

# =========================================================================
# ETAPA 6 - Corrigir permissoes HKLM ConsentStore (sempre executa)
# =========================================================================

Write-Etapa '6/8  Corrigindo permissoes de acesso a camera - sistema (HKLM)...'

$regHKLM = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'

try {
    if (-not (Test-Path $regHKLM)) {
        New-Item -Path $regHKLM -Force -ErrorAction Stop | Out-Null
        Write-Info 'Chave de consentimento de camera criada no HKLM.'
    }
    $valAtual = (Get-ItemProperty -Path $regHKLM -Name 'Value' -ErrorAction SilentlyContinue).Value
    if ($valAtual -ne 'Allow') {
        Set-ItemProperty -Path $regHKLM -Name 'Value' -Value 'Allow' -Type String -ErrorAction Stop
        Write-Ok "HKLM webcam\Value: '$valAtual' alterado para 'Allow'."
        $acoesTomadas.Add("Permissao HKLM webcam definida para Allow")
    } else {
        Write-Ok "HKLM webcam\Value: ja configurado como 'Allow'."
    }
} catch {
    Write-Falha "Nao foi possivel configurar permissao HKLM: $_"
}

# =========================================================================
# ETAPA 7 - Habilitar acesso para apps do usuario (HKCU) (sempre executa)
# =========================================================================

Write-Etapa '7/8  Habilitando acesso a camera para apps do usuario (HKCU)...'

$regHKCU = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'

try {
    if (-not (Test-Path $regHKCU)) {
        New-Item -Path $regHKCU -Force -ErrorAction Stop | Out-Null
        Write-Info 'Chave de consentimento de camera criada no HKCU.'
    }
    $valAtual = (Get-ItemProperty -Path $regHKCU -Name 'Value' -ErrorAction SilentlyContinue).Value
    if ($valAtual -ne 'Allow') {
        Set-ItemProperty -Path $regHKCU -Name 'Value' -Value 'Allow' -Type String -ErrorAction Stop
        Write-Ok "HKCU webcam\Value: '$valAtual' alterado para 'Allow'."
        $acoesTomadas.Add("Permissao HKCU webcam definida para Allow")
    } else {
        Write-Ok "HKCU webcam\Value: ja configurado como 'Allow'."
    }

    # Apps Win32/desktop (NonPackaged)
    $regNP = "$regHKCU\NonPackaged"
    if (Test-Path $regNP) {
        $npVal = (Get-ItemProperty -Path $regNP -Name 'Value' -ErrorAction SilentlyContinue).Value
        if ($npVal -eq 'Deny') {
            Set-ItemProperty -Path $regNP -Name 'Value' -Value 'Allow' -Type String -ErrorAction SilentlyContinue
            Write-Ok "HKCU webcam\NonPackaged\Value: 'Deny' alterado para 'Allow'."
            $acoesTomadas.Add("Permissao HKCU webcam NonPackaged definida para Allow")
        } else {
            Write-Ok "HKCU webcam\NonPackaged\Value: '$npVal' (OK)."
        }
    }
} catch {
    Write-Falha "Nao foi possivel configurar permissao HKCU: $_"
}

# Verificar apos ajuste de permissoes
if (-not $resolvidoHW) {
    Verifica-EResolvido -EtapaLabel 'permissoes de camera corrigidas no registro' | Out-Null
}

# =========================================================================
# ETAPA 8 - Forcar rescan de dispositivos USB via pnputil
# =========================================================================

if (-not $resolvidoHW) {
    Write-Etapa '8/8  Forcando rescan de dispositivos USB via pnputil...'

    Write-Info 'Executando: pnputil /scan-devices'
    $pnpSaida = & pnputil /scan-devices 2>&1
    $pnpSaida | ForEach-Object { Write-Info $_.ToString() }

    Write-Info 'Aguardando reenumeracao de dispositivos USB...'
    Start-Sleep -Seconds 5

    $todasCameras = @(Get-DispositivosCamera)
    Verifica-EResolvido -EtapaLabel 'rescan USB via pnputil /scan-devices' | Out-Null
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
    Write-Host '   Status : CAMERA DETECTADA E FUNCIONANDO' -ForegroundColor Green
    Write-Host ''
    $camsFinais = Test-CameraFuncionando
    foreach ($c in $camsFinais) {
        Write-Host "   Camera : $($c.FriendlyName)" -ForegroundColor Green
        Write-Host "   Classe : $($c.Class)  |  ID: $($c.InstanceId)" -ForegroundColor DarkGray
    }
    if ($etapaResolvida) {
        Write-Host ''
        Write-Host "   Resolvido em: $etapaResolvida" -ForegroundColor White
    }
} else {
    Write-Host '   Status : CAMERA NAO DETECTADA APOS TODAS AS ETAPAS' -ForegroundColor Red
    Write-Host ''
    if ($todasCameras.Count -gt 0) {
        Write-Host '   Dispositivos encontrados mas com problemas:' -ForegroundColor Yellow
        foreach ($cam in $todasCameras) {
            $desc = Descricao-ProblemCode -Code ([int]$cam.ProblemCode)
            Write-Host "   - $($cam.FriendlyName): $desc" -ForegroundColor Yellow
        }
    } else {
        Write-Host '   Nenhum dispositivo de camera detectado pelo sistema operacional.' -ForegroundColor Red
    }
}

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
    Write-Host '   1. Tecla fisica de camera no notebook' -ForegroundColor White
    Write-Host '      Verifique combinacao Fn + F6 (ou outra) para ativar/desativar camera.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   2. BIOS/UEFI - camera pode estar desabilitada no firmware' -ForegroundColor White
    Write-Host '      Reinicie > Del ou F2 > busque "Camera", "Webcam" ou "Integrated Camera".' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   3. Driver manual pelo site do fabricante do notebook' -ForegroundColor White
    Write-Host '      Dell, HP, Lenovo, ASUS etc. - use o modelo exato para baixar o driver de camera.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   4. Gerenciador de Dispositivos - verificar alteracoes de hardware' -ForegroundColor White
    Write-Host '      devmgmt.msc > menu Acao > Verificar alteracoes de hardware.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   5. Reinstalar app de Camera da Microsoft Store' -ForegroundColor White
    Write-Host '      PowerShell (Admin): Get-AppxPackage *camera* | Remove-AppxPackage' -ForegroundColor Gray
    Write-Host '      Depois reinstale pela Microsoft Store buscando por "Camera".' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   6. Windows Update - drivers de camera podem ser entregues via WU' -ForegroundColor White
    Write-Host '      Configuracoes > Windows Update > Verificar atualizacoes.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   7. Solucionador de problemas de camera integrado do Windows' -ForegroundColor White
    Write-Host '      Configuracoes > Sistema > Solucionar Problemas > Outros solucionadores > Camera.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '   8. Camera USB externa: teste em porta USB 2.0 direta (sem hub)' -ForegroundColor White
    Write-Host '      Evite extensores e hubs. Prefira portas traseiras do gabinete.' -ForegroundColor Gray
}

Write-Host ''
Write-Host ("   Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host '================================================' -ForegroundColor $corFinal
Write-Host ''
