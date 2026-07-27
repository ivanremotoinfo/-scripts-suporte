# CorrigirRede.ps1
# Corrige problemas de rede e internet em dois niveis:
#   BASICO   - seguro, nao derruba a conexao (flush DNS, ARP, renovar IP)
#   PROFUNDO - reset de TCP/IP e Winsock (DERRUBA a conexao, exige confirmacao)

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
Write-Host '        Correcao de Rede e Internet             ' -ForegroundColor Cyan
Write-Host '================================================' -ForegroundColor Cyan
Write-Host ("  Iniciado em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
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
# ETAPA 0 - Detectar acesso remoto e configuracao atual de rede
# =========================================================================

Write-Etapa '0. Verificando como esta o acesso a esta maquina...'

# AnyDesk, RDP, TeamViewer: um reset de rede derruba o atendimento no meio.
$procRemoto = @(Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessName -match '(?i)^(anydesk|teamviewer|rustdesk|vncserver|winvnc)' })
$sessaoRDP  = ($env:SESSIONNAME -and $env:SESSIONNAME -match '(?i)^RDP')

$acessoRemoto = ($procRemoto.Count -gt 0) -or $sessaoRDP

if ($acessoRemoto) {
    Write-Host ''
    Write-Host '   ###########################################################' -ForegroundColor Red
    Write-Host '   #  ATENCAO: ACESSO REMOTO DETECTADO NESTA MAQUINA         #' -ForegroundColor Red
    Write-Host '   ###########################################################' -ForegroundColor Red
    if ($procRemoto.Count -gt 0) {
        foreach ($p in ($procRemoto | Select-Object -Unique ProcessName)) {
            Write-Info ('   Programa em execucao : ' + $p.ProcessName)
        }
    }
    if ($sessaoRDP) { Write-Info ('   Sessao RDP           : ' + $env:SESSIONNAME) }
    Write-Host ''
    Write-Aviso 'O modo PROFUNDO derruba a conexao de rede e VOCE PERDE O ACESSO.'
    Write-Info  'Para reconectar seria preciso alguem no local reiniciar a maquina.'
    Write-Host ''
} else {
    Write-Ok 'Nenhum programa de acesso remoto detectado nesta maquina.'
}

# Configuracao atual: IP fixo x DHCP (o reset profundo devolve tudo para DHCP)
Write-Host ''
Write-Info 'Configuracao de rede atual:'
$temIPFixo = $false
try {
    $adaptadores = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue |
        Where-Object { $_.NetAdapter.Status -eq 'Up' })
    foreach ($ad in $adaptadores) {
        $ipv4 = @($ad.IPv4Address)[0]
        $origem = if ($ipv4) { $ipv4.PrefixOrigin } else { 'sem IP' }
        if ($origem -eq 'Manual') { $temIPFixo = $true }
        $gw = if ($ad.IPv4DefaultGateway) { @($ad.IPv4DefaultGateway)[0].NextHop } else { '-' }
        $dns = ($ad.DNSServer | Where-Object { $_.AddressFamily -eq 2 } |
                ForEach-Object { $_.ServerAddresses }) -join ', '
        Write-Host ("   {0}" -f $ad.InterfaceAlias) -ForegroundColor White
        Write-Host ("     IP      : {0}  ({1})" -f $(if ($ipv4) { $ipv4.IPAddress } else { '-' }), $origem) -ForegroundColor Gray
        Write-Host ("     Gateway : {0}" -f $gw) -ForegroundColor Gray
        Write-Host ("     DNS     : {0}" -f $(if ($dns) { $dns } else { '-' })) -ForegroundColor Gray
    }
} catch {
    Write-Aviso "Nao foi possivel ler a configuracao atual: $_"
}

if ($temIPFixo) {
    Write-Host ''
    Write-Aviso 'Esta maquina usa IP FIXO (manual) em pelo menos um adaptador.'
    Write-Info  'O modo PROFUNDO apaga essa configuracao e devolve o adaptador para DHCP.'
    Write-Info  'Anote os dados acima antes de prosseguir.'
}

# =========================================================================
# ETAPA 0.1 - Escolher o modo
# =========================================================================

Write-Host ''
Write-Host '   ------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host '   [1] BASICO   - limpa cache DNS/ARP e renova o IP' -ForegroundColor Green
Write-Host '                  Nao derruba a conexao. Resolve a maioria dos casos.' -ForegroundColor DarkGray
Write-Host '   [2] PROFUNDO - basico + reset de TCP/IP e Winsock' -ForegroundColor Yellow
Write-Host '                  DERRUBA A CONEXAO e exige reiniciar o computador.' -ForegroundColor DarkGray
Write-Host '   [0] Cancelar' -ForegroundColor DarkGray
Write-Host '   ------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host ''

$modo = (Read-Host '   Opcao').Trim()

if ($modo -eq '0' -or $modo -eq '') {
    Write-Info 'Operacao cancelada. Nenhuma alteracao foi feita.'
    Write-Host ''
    exit 0
}

$modoProfundo = ($modo -eq '2')

if ($modoProfundo) {
    Write-Host ''
    Write-Aviso 'Modo PROFUNDO selecionado. Serao executados:'
    Write-Info  '  - ipconfig /release e /renew  (a conexao cai por alguns segundos)'
    Write-Info  '  - netsh int ip reset          (zera a config TCP/IP, volta para DHCP)'
    Write-Info  '  - netsh winsock reset         (zera o catalogo Winsock)'
    Write-Info  '  - reinicializacao do computador sera necessaria'
    if ($acessoRemoto) {
        Write-Host ''
        Write-Host '   VOCE ESTA CONECTADO REMOTAMENTE - VAI PERDER O ACESSO AGORA.' -ForegroundColor Red
    }
    Write-Host ''
    $conf = Read-Host '   Confirma o modo PROFUNDO? (S/N)'
    if ($conf -notmatch '^[Ss]') {
        Write-Info 'Modo profundo cancelado. Seguindo apenas com o modo BASICO.'
        $modoProfundo = $false
    }
}

# =========================================================================
# ETAPA 1 - Limpar cache DNS  (seguro)
# =========================================================================

Write-Etapa '1. Limpando cache DNS (ipconfig /flushdns)...'

try {
    & ipconfig /flushdns | Out-Null
    Write-Ok 'Cache DNS limpo.'
} catch {
    Write-Aviso "Falha ao limpar cache DNS: $_"
}

# =========================================================================
# ETAPA 2 - Limpar cache ARP  (seguro)
# =========================================================================

Write-Etapa '2. Limpando cache ARP (arp -d *)...'

try {
    & arp -d '*' 2>&1 | Out-Null
    Write-Ok 'Cache ARP limpo.'
} catch {
    Write-Aviso 'Cache ARP: nao foi possivel limpar (normal em algumas versoes do Windows).'
}

# =========================================================================
# ETAPA 3 - Renovar IP  (release apenas no modo profundo)
# =========================================================================

if ($modoProfundo) {
    Write-Etapa '3. Liberando e renovando endereco IP (release + renew)...'
    try {
        & ipconfig /release 2>&1 | Out-Null
        Write-Ok 'IP liberado.'
    } catch {
        Write-Aviso "Falha ao liberar IP: $_"
    }
} else {
    Write-Etapa '3. Renovando endereco IP (ipconfig /renew, sem release)...'
}

try {
    $saida = & ipconfig /renew 2>&1
    $erros = $saida | Where-Object { $_ -match '(?i)(erro|error|failed|falhou|incapaz|unable)' }
    if ($erros) {
        Write-Aviso 'Renovacao com avisos. Verifique cabo ou sinal Wi-Fi.'
    } else {
        Write-Ok 'IP renovado.'
    }
} catch {
    Write-Aviso "Falha ao renovar IP: $_"
}

# =========================================================================
# ETAPA 4 - Reset TCP/IP e Winsock  (apenas modo profundo)
# =========================================================================

if ($modoProfundo) {
    Write-Etapa '4. Resetando TCP/IP (netsh int ip reset)...'
    try {
        & netsh int ip reset 2>&1 | Out-Null
        Write-Ok 'TCP/IP resetado.'
        $precisaReiniciar = $true
    } catch {
        Write-Aviso "Falha ao resetar TCP/IP: $_"
    }

    Write-Etapa '5. Resetando catalogo Winsock (netsh winsock reset)...'
    try {
        & netsh winsock reset 2>&1 | Out-Null
        Write-Ok 'Winsock resetado.'
        $precisaReiniciar = $true
    } catch {
        Write-Aviso "Falha ao resetar Winsock: $_"
    }
} else {
    Write-Etapa '4. Reset de TCP/IP e Winsock - pulado (modo BASICO).'
    Write-Info 'Se o problema continuar, execute novamente e escolha o modo PROFUNDO.'
}

# =========================================================================
# ETAPA 5 - Endereco IP obtido
# =========================================================================

Write-Etapa '6. Endereco IP atual...'

try {
    $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
           Where-Object {
               $_.IPAddress -notlike '127.*' -and
               $_.IPAddress -notlike '169.254.*' -and
               $_.PrefixOrigin -ne 'WellKnown'
           }

    if ($ips) {
        foreach ($ip in $ips) {
            Write-Ok "  $($ip.InterfaceAlias)  ->  $($ip.IPAddress)"
        }
    } else {
        Write-Aviso 'Nenhum IP valido obtido. Endereco 169.254.x.x indica falha DHCP.'
        Write-Info  'Verifique se o roteador esta ligado e o cabo conectado.'
    }
} catch {
    Write-Aviso "Nao foi possivel consultar o IP: $_"
}

# =========================================================================
# ETAPA 6 - Testar conectividade
# =========================================================================

Write-Etapa '7. Testando conectividade com a internet...'

$alvos = @(
    [PSCustomObject]@{ Alvo = 'google.com'; Label = 'Google (google.com)' },
    [PSCustomObject]@{ Alvo = '8.8.8.8';    Label = 'DNS Google (8.8.8.8)' }
)

$totalOk = 0

foreach ($item in $alvos) {
    try {
        $ok = Test-Connection -ComputerName $item.Alvo -Count 2 -Quiet -ErrorAction SilentlyContinue
        if ($ok) {
            Write-Ok "Conectividade OK  ->  $($item.Label)"
            $totalOk++
        } else {
            Write-Falha "Sem resposta de    ->  $($item.Label)"
        }
    } catch {
        Write-Falha "Erro ao testar     ->  $($item.Label)"
    }
}

$conectou = ($totalOk -gt 0)

if (-not $conectou) {
    Write-Host ''
    Write-Aviso 'Nenhum host respondeu ao ping. Possiveis causas:'
    Write-Info  '     - Cabo de rede desconectado ou Wi-Fi desligado'
    Write-Info  '     - Roteador sem acesso a internet'
    if ($precisaReiniciar) {
        Write-Info  '     - Reinicialize o computador (reset TCP/IP e Winsock aplicados)'
    }
}

# =========================================================================
# RESULTADO FINAL
# =========================================================================

$corFinal = if ($conectou) { 'Green' } else { 'Yellow' }

Write-Host ''
Write-Host '================================================' -ForegroundColor $corFinal

if ($conectou -and -not $precisaReiniciar) {
    Write-Host '   Rede corrigida e internet funcionando!     ' -ForegroundColor Green
} elseif ($conectou -and $precisaReiniciar) {
    Write-Host '   Internet funcionando - reinicio pendente.  ' -ForegroundColor Green
} else {
    Write-Host '   Correcao aplicada - sem conectividade.     ' -ForegroundColor Yellow
}

Write-Host ("   Modo executado: " + $(if ($modoProfundo) { 'PROFUNDO' } else { 'BASICO' })) -ForegroundColor DarkGray

if ($precisaReiniciar) {
    Write-Host ''
    Write-Host '   ATENCAO: Reinicie o computador para        ' -ForegroundColor Yellow
    Write-Host '   concluir o reset do TCP/IP e do Winsock.   ' -ForegroundColor Yellow
    if ($temIPFixo) {
        Write-Host '   Reconfigure o IP FIXO anotado no inicio.   ' -ForegroundColor Yellow
    }
}

Write-Host '================================================' -ForegroundColor $corFinal
Write-Host ''
