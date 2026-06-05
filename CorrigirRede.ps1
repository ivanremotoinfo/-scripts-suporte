#Requires -RunAsAdministrator

$precisaReiniciar = $false

# -------------------------------------------------------------------------
# Funcoes auxiliares
# -------------------------------------------------------------------------

function Write-Etapa { param([string]$t) Write-Host "`n>> $t" -ForegroundColor Cyan }
function Write-Ok    { param([string]$t) Write-Host '   [OK] ' -ForegroundColor Green  -NoNewline; Write-Host $t }
function Write-Aviso { param([string]$t) Write-Host '   [!]  ' -ForegroundColor Yellow -NoNewline; Write-Host $t }
function Write-Falha { param([string]$t) Write-Host '   [X]  ' -ForegroundColor Red    -NoNewline; Write-Host $t }
function Write-Info  { param([string]$t) Write-Host "   $t" -ForegroundColor Gray }

# -------------------------------------------------------------------------
# Cabecalho
# -------------------------------------------------------------------------

Write-Host ''
Write-Host '================================================' -ForegroundColor Cyan
Write-Host '        Correcao de Rede e Internet             ' -ForegroundColor Cyan
Write-Host '================================================' -ForegroundColor Cyan
Write-Host ("  Iniciado em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host ''

# =========================================================================
# ETAPA 1 - Liberar endereco IP
# =========================================================================

Write-Etapa '1. Liberando endereco IP atual (ipconfig /release)...'

try {
    $saida = & ipconfig /release 2>&1
    $erros = $saida | Where-Object { $_ -match 'erro|error|failed|falhou' }
    if ($erros) {
        Write-Aviso 'IP liberado com avisos (normal em conexoes sem DHCP ativo).'
    } else {
        Write-Ok 'IP liberado com sucesso.'
    }
} catch {
    Write-Aviso "Falha ao liberar IP: $_"
}

# =========================================================================
# ETAPA 2 - Renovar endereco IP
# =========================================================================

Write-Etapa '2. Renovando endereco IP (ipconfig /renew)...'

try {
    $saida = & ipconfig /renew 2>&1
    $erros = $saida | Where-Object { $_ -match 'erro|error|failed|falhou|incapaz|unable' }
    if ($erros) {
        Write-Aviso 'Renovacao com avisos. Verifique cabo ou sinal Wi-Fi.'
    } else {
        Write-Ok 'IP renovado com sucesso.'
    }
} catch {
    Write-Aviso "Falha ao renovar IP: $_"
}

# =========================================================================
# ETAPA 3 - Exibir novo IP obtido
# =========================================================================

Write-Etapa '3. Novo endereco IP obtido...'

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
    Write-Aviso "Nao foi possivel consultar o novo IP: $_"
}

# =========================================================================
# ETAPA 4 - Limpar cache DNS
# =========================================================================

Write-Etapa '4. Limpando cache DNS (ipconfig /flushdns)...'

try {
    $saida = & ipconfig /flushdns 2>&1
    Write-Ok 'Cache DNS limpo.'
} catch {
    Write-Aviso "Falha ao limpar cache DNS: $_"
}

# =========================================================================
# ETAPA 5 - Resetar configuracoes TCP/IP
# =========================================================================

Write-Etapa '5. Resetando configuracoes TCP/IP (netsh int ip reset)...'

try {
    $saida = & netsh int ip reset 2>&1
    Write-Ok 'TCP/IP resetado.'
    Write-Info 'Reinicializacao necessaria para aplicar completamente.'
    $precisaReiniciar = $true
} catch {
    Write-Aviso "Falha ao resetar TCP/IP: $_"
}

# =========================================================================
# ETAPA 6 - Resetar Winsock
# =========================================================================

Write-Etapa '6. Resetando catalogo Winsock (netsh winsock reset)...'

try {
    $saida = & netsh winsock reset 2>&1
    Write-Ok 'Winsock resetado.'
    Write-Info 'Reinicializacao necessaria para aplicar completamente.'
    $precisaReiniciar = $true
} catch {
    Write-Aviso "Falha ao resetar Winsock: $_"
}

# =========================================================================
# ETAPA 7 - Limpar cache ARP
# =========================================================================

Write-Etapa '7. Limpando cache ARP (arp -d *)...'

try {
    $saida = & arp -d '*' 2>&1
    Write-Ok 'Cache ARP limpo.'
} catch {
    Write-Aviso 'Cache ARP: nao foi possivel limpar (normal em algumas versoes do Windows).'
}

# =========================================================================
# ETAPA 8 - Testar conectividade
# =========================================================================

Write-Etapa '8. Testando conectividade com a internet...'

$alvos = @(
    [PSCustomObject]@{ Host = 'google.com'; Label = 'Google (google.com)' },
    [PSCustomObject]@{ Host = '8.8.8.8';   Label = 'DNS Google (8.8.8.8)' }
)

$totalOk  = 0
$totalFail = 0

foreach ($alvo in $alvos) {
    try {
        $ok = Test-Connection -ComputerName $alvo.Host -Count 2 -Quiet -ErrorAction SilentlyContinue
        if ($ok) {
            Write-Ok "Conectividade OK  ->  $($alvo.Label)"
            $totalOk++
        } else {
            Write-Falha "Sem resposta de    ->  $($alvo.Label)"
            $totalFail++
        }
    } catch {
        Write-Falha "Erro ao testar     ->  $($alvo.Label)"
        $totalFail++
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

if ($precisaReiniciar) {
    Write-Host ''
    Write-Host '   ATENCAO: Reinicie o computador para        ' -ForegroundColor Yellow
    Write-Host '   concluir o reset do TCP/IP e do Winsock.   ' -ForegroundColor Yellow
}

Write-Host '================================================' -ForegroundColor $corFinal
Write-Host ''
