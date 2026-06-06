# SuporteADV.ps1
# Menu interativo de suporte tecnico para escritorios de advocacia
# Todos os scripts sao baixados do GitHub em tempo de execucao
# Para executar:  powershell.exe -ExecutionPolicy Bypass -File SuporteADV.ps1
# Ou via web:     irm https://raw.githubusercontent.com/ivanremotoinfo/-scripts-suporte/main/SuporteADV.ps1 | iex

$ErrorActionPreference = 'Continue'

# Liberar execucao de scripts nesta sessao
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue

# =========================================================================
# CONFIGURACAO
# =========================================================================

$baseUrl = 'https://raw.githubusercontent.com/ivanremotoinfo/-scripts-suporte/main/'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

$mapaScripts = @{
    1  = 'DiagnosticoCompleto.ps1'
    2  = 'ListarCertificados.ps1'
    3  = 'AnalisarBSOD.ps1'
    4  = 'ManutencaoCompleta.ps1'
    5  = 'LimparCacheNavegadores.ps1'
    6  = 'LimparFilaImpressao.ps1'
    7  = 'InstalarVisualC.ps1'
    8  = 'RepararSistema.ps1'
    9  = 'CorrigirRede.ps1'
    10 = 'CorrigirProxy.ps1'
    11 = 'CorrigirPermissoesPowerShell.ps1'
    12 = 'RepararAudio.ps1'
    13 = 'RepararWebcam.ps1'
    14 = 'LimparCertificadosVencidos.ps1'
    15 = 'ConfigurarJava.ps1'
    16 = 'ConfigurarPJe.ps1'
    17 = 'DesinstalarPrograma.ps1'
    18 = 'ReinstalarImpressora.ps1'
}

# =========================================================================
# FUNCAO: EXIBIR MENU
# =========================================================================

function Mostrar-Menu {
    Clear-Host

    $dt      = Get-Date -Format 'dd/MM/yyyy  HH:mm:ss'
    $pcNome  = $env:COMPUTERNAME
    $usuario = $env:USERNAME

    # -- Cabecalho ---------------------------------------------------------
    Write-Host ''
    Write-Host '  +==============================================================+' -ForegroundColor DarkCyan
    Write-Host '  |                                                              |' -ForegroundColor DarkCyan
    Write-Host '  |      ~~~  S U P O R T E  .  A D V  .  B R  ~~~             |' -ForegroundColor Cyan
    Write-Host '  |      Suporte Tecnico em TI para Escritorios de Advocacia    |' -ForegroundColor White
    Write-Host '  |                                                              |' -ForegroundColor DarkCyan
    Write-Host '  +==============================================================+' -ForegroundColor DarkCyan

    Write-Host ("  Data: $dt    PC: $pcNome    User: $usuario") -ForegroundColor DarkGray

    if ($isAdmin) {
        Write-Host '  Privilegios: [Administrador]' -ForegroundColor Green
    } else {
        Write-Host '  Privilegios: [Usuario Limitado]  AVISO: execute como Administrador!' -ForegroundColor Red
    }

    Write-Host '  +==============================================================+' -ForegroundColor DarkCyan
    Write-Host ''

    # -- Categoria: DIAGNOSTICO --------------------------------------------
    Write-Host '  --- DIAGNOSTICO -----------------------------------------------' -ForegroundColor Cyan
    Write-Host '  [ 1 ]  Diagnostico Completo do PC' -ForegroundColor Cyan
    Write-Host '  [ 2 ]  Listar Certificados Digitais' -ForegroundColor Cyan
    Write-Host '  [ 3 ]  Analisar Tela Azul (BSOD)' -ForegroundColor Cyan
    Write-Host ''

    # -- Categoria: MANUTENCAO ---------------------------------------------
    Write-Host '  --- MANUTENCAO ------------------------------------------------' -ForegroundColor Green
    Write-Host '  [ 4 ]  Manutencao Completa do PC' -ForegroundColor Green
    Write-Host '  [ 5 ]  Limpar Cache dos Navegadores' -ForegroundColor Green
    Write-Host '  [ 6 ]  Limpar Fila de Impressao' -ForegroundColor Green
    Write-Host '  [ 7 ]  Instalar Visual C++ Redistribuiveis' -ForegroundColor Green
    Write-Host ''

    # -- Categoria: REPAROS ------------------------------------------------
    Write-Host '  --- REPAROS ---------------------------------------------------' -ForegroundColor Yellow
    Write-Host '  [ 8 ]  Reparar Arquivos do Sistema (SFC / DISM)' -ForegroundColor Yellow
    Write-Host '  [ 9 ]  Corrigir Rede e Internet' -ForegroundColor Yellow
    Write-Host '  [10 ]  Corrigir Proxy e Certificados de Rede' -ForegroundColor Yellow
    Write-Host '  [11 ]  Corrigir Permissoes do PowerShell' -ForegroundColor Yellow
    Write-Host '  [12 ]  Reparar Audio e Microfone' -ForegroundColor Yellow
    Write-Host '  [13 ]  Reparar Webcam' -ForegroundColor Yellow
    Write-Host ''

    # -- Categoria: CERTIFICADOS -------------------------------------------
    Write-Host '  --- CERTIFICADOS ----------------------------------------------' -ForegroundColor Magenta
    Write-Host '  [14 ]  Limpar Certificados Vencidos' -ForegroundColor Magenta
    Write-Host '  [15 ]  Configurar Java para Sistemas Juridicos' -ForegroundColor Magenta
    Write-Host '  [16 ]  Configurar Ambiente PJe Completo' -ForegroundColor Magenta
    Write-Host ''

    # -- Categoria: PROGRAMAS ----------------------------------------------
    Write-Host '  --- PROGRAMAS -------------------------------------------------' -ForegroundColor Blue
    Write-Host '  [17 ]  Desinstalar Programa Completamente' -ForegroundColor Blue
    Write-Host '  [18 ]  Remover Impressora Completamente' -ForegroundColor Blue
    Write-Host ''

    Write-Host '  +==============================================================+' -ForegroundColor DarkCyan
    Write-Host '  [ 0 ]  Sair' -ForegroundColor DarkGray
    Write-Host '  +==============================================================+' -ForegroundColor DarkCyan
    Write-Host ''
}

# =========================================================================
# FUNCAO: BAIXAR E EXECUTAR SCRIPT DO GITHUB
# =========================================================================

function Executar-Script {
    param([int]$numero)

    $arquivo = $mapaScripts[$numero]
    $url     = $baseUrl + $arquivo

    Write-Host ''
    Write-Host ('  +' + ('=' * 62) + '+') -ForegroundColor DarkCyan
    Write-Host ("  |  Aguarde... baixando $arquivo do GitHub") -ForegroundColor Yellow
    Write-Host ("  |  $url") -ForegroundColor DarkGray
    Write-Host ('  +' + ('=' * 62) + '+') -ForegroundColor DarkCyan
    Write-Host ''

    $baixouOk = $false
    $tmpArq   = ''

    try {
        $resposta = Invoke-RestMethod -Uri $url -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
        $conteudo = $resposta.ToString()

        if ($conteudo.Length -lt 20) {
            throw 'Arquivo vazio ou nao encontrado no repositorio.'
        }

        $tmpArq = [System.IO.Path]::GetTempPath() + 'sadv_' + [System.Guid]::NewGuid().ToString('N') + '.ps1'
        [System.IO.File]::WriteAllText($tmpArq, $conteudo, [System.Text.Encoding]::UTF8)
        Unblock-File $tmpArq -ErrorAction SilentlyContinue

        $baixouOk = $true

    } catch {
        Write-Host '  [ERRO] Nao foi possivel baixar o script.' -ForegroundColor Red
        Write-Host ("  Arquivo : $arquivo") -ForegroundColor DarkRed
        Write-Host ("  Erro    : $($_.Exception.Message)") -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '  Verifique se existe conexao com a internet e se o arquivo' -ForegroundColor Yellow
        Write-Host ("  ja foi publicado no repositorio GitHub.") -ForegroundColor Yellow
        Write-Host ("  URL esperada: $url") -ForegroundColor DarkGray
    }

    if ($baixouOk) {
        Write-Host ("  >> Executando: $arquivo") -ForegroundColor Green
        Write-Host ('  ' + ('-' * 62)) -ForegroundColor DarkGray
        Write-Host ''

        try {
            & $tmpArq
        } catch {
            Write-Host ''
            Write-Host ("  [ERRO durante execucao] $($_.Exception.Message)") -ForegroundColor Red
        }

        if ($tmpArq -and (Test-Path $tmpArq)) {
            Remove-Item $tmpArq -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host ''
    Write-Host ('  ' + ('-' * 62)) -ForegroundColor DarkGray
    Write-Host '  Pressione ENTER para voltar ao menu principal...' -ForegroundColor DarkGray
    $null = Read-Host
}

# =========================================================================
# LOOP PRINCIPAL DO MENU
# =========================================================================

while ($true) {
    Mostrar-Menu

    $entrada = Read-Host '  Opcao'
    $entrada = $entrada.Trim()

    if ($entrada -eq '0') {
        Clear-Host
        Write-Host ''
        Write-Host '  Ate logo!  suporte.adv.br' -ForegroundColor Cyan
        Write-Host ''
        break
    }

    # Validar numero
    $num = 0
    $valido = [int]::TryParse($entrada, [ref]$num)

    if ($valido -and $num -ge 1 -and $num -le 18) {
        Executar-Script -numero $num
    } else {
        Write-Host ''
        Write-Host ("  Opcao invalida: '$entrada'  |  Digite um numero de 0 a 18.") -ForegroundColor Red
        Start-Sleep -Milliseconds 1500
    }
}
