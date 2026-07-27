# SuporteADV.ps1
# Menu unico de suporte tecnico para escritorios de advocacia.
# Reune num so menu as ferramentas proprias (baixadas do GitHub) e todas as
# ferramentas da ManutencaoCompleta.ps1 (v2), acionadas por parametro.
# Para executar:  powershell.exe -ExecutionPolicy Bypass -File SuporteADV.ps1
# Ou via web:     irm https://raw.githubusercontent.com/ivanremotoinfo/-scripts-suporte/main/SuporteADV.ps1 | iex

$ErrorActionPreference = 'Continue'
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue

# =========================================================================
# CONFIGURACAO
# =========================================================================

$baseUrl = 'https://raw.githubusercontent.com/ivanremotoinfo/-scripts-suporte/main/'
$scriptV2 = 'ManutencaoCompleta.ps1'   # motor com ~40 ferramentas

# Versao = data da ultima alteracao publicada. Aparece no cabecalho e no
# relatorio, para saber qual versao o cliente rodou quando ele relatar algo.
$versaoMenu = '2026.07.27'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

# Cada item do menu:
#   N     = numero
#   Cat   = categoria (agrupa e colore)
#   Label = texto curto (cabe em 2 colunas)
#   Tipo  = 'v2' (chama o motor v2)  |  'script' (baixa um .ps1 proprio)
#   Alvo  = nome do .ps1 (quando Tipo='script')
#   Args  = parametros passados ao v2 (quando Tipo='v2')
$menu = @(
    # --- DIAGNOSTICO ---   (Args e' hashtable p/ splat correto no v2)
    @{ Cat='DIAGNOSTICO'; Label='Diagnostico Completo do PC';    Tipo='v2';     Args=@{ Ferramenta='diagnostico' } }
    @{ Cat='DIAGNOSTICO'; Label='Saude dos Discos (SMART)';      Tipo='v2';     Args=@{ Ferramenta='smart' } }
    @{ Cat='DIAGNOSTICO'; Label='Maiores Consumidores de RAM';   Tipo='v2';     Args=@{ Ferramenta='topprocessos' } }
    @{ Cat='DIAGNOSTICO'; Label='Listar Certificados Digitais';  Tipo='v2';     Args=@{ Ferramenta='certificados' } }
    @{ Cat='DIAGNOSTICO'; Label='Analisar Tela Azul (BSOD)';     Tipo='v2';     Args=@{ Ferramenta='bsod' } }

    # --- MANUTENCAO E LIMPEZA ---
    @{ Cat='MANUTENCAO';  Label='Manutencao Completa (tudo)';    Tipo='v2';     Args=@{} }
    @{ Cat='MANUTENCAO';  Label='Simular (nao altera nada)';      Tipo='v2';     Args=@{ SomenteRelatorio=$true } }
    @{ Cat='MANUTENCAO';  Label='Limpar Temporarios';            Tipo='v2';     Args=@{ Ferramenta='temp' } }
    @{ Cat='MANUTENCAO';  Label='Esvaziar Lixeira';              Tipo='v2';     Args=@{ Ferramenta='lixeira' } }
    @{ Cat='MANUTENCAO';  Label='Cache dos Navegadores';         Tipo='v2';     Args=@{ Ferramenta='navegadores' } }
    @{ Cat='MANUTENCAO';  Label='Cache de Aplicativos';          Tipo='v2';     Args=@{ Ferramenta='appcache' } }
    @{ Cat='MANUTENCAO';  Label='Cache do Windows Update';       Tipo='v2';     Args=@{ Ferramenta='windowsupdate' } }
    @{ Cat='MANUTENCAO';  Label='Miniaturas do Explorer';        Tipo='v2';     Args=@{ Ferramenta='miniaturas' } }
    @{ Cat='MANUTENCAO';  Label='Limpeza Pesada (WinSxS)';       Tipo='v2';     Args=@{ Ferramenta='winsxs' } }
    @{ Cat='MANUTENCAO';  Label='Apagar pasta do AnyDesk';       Tipo='v2';     Args=@{ Ferramenta='anydesk' } }
    @{ Cat='MANUTENCAO';  Label='Visual C++ Redistribuiveis';    Tipo='v2';     Args=@{ Ferramenta='visualc' } }

    # --- SEGURANCA E ANTIVIRUS ---
    @{ Cat='SEGURANCA';   Label='Escanear Virus (ClamAV+VT)';    Tipo='v2';     Args=@{ EscanearVirus=$true } }
    @{ Cat='SEGURANCA';   Label='Restaurar Quarentena';          Tipo='v2';     Args=@{ RestaurarQuarentena=$true } }
    @{ Cat='SEGURANCA';   Label='Desativar Antivirus+Firewall';  Tipo='v2';     Args=@{ DesativarDefender=$true; DesativarFirewall=$true } }
    @{ Cat='SEGURANCA';   Label='Reativar Antivirus+Firewall';   Tipo='v2';     Args=@{ ReativarTudo=$true } }
    @{ Cat='SEGURANCA';   Label='Abrir Protecao Virus/Ameacas';  Tipo='v2';     Args=@{ Ferramenta='protecaovirus' } }

    # --- REPAROS ---
    @{ Cat='REPAROS';     Label='Reparar Sistema (SFC/DISM)';    Tipo='v2';     Args=@{ Ferramenta='sfc' } }
    @{ Cat='REPAROS';     Label='Corrigir Rede e Internet';      Tipo='v2';     Args=@{ Ferramenta='corrigirrede' } }
    @{ Cat='REPAROS';     Label='Corrigir Proxy e Certif. Rede'; Tipo='v2';     Args=@{ Ferramenta='proxycert' } }
    @{ Cat='REPAROS';     Label='Reparar Fila de Impressao';     Tipo='v2';     Args=@{ Ferramenta='spooler' } }
    @{ Cat='REPAROS';     Label='Reparar acesso a %appdata%';    Tipo='v2';     Args=@{ Ferramenta='appdata' } }
    @{ Cat='REPAROS';     Label='Reiniciar Explorer';            Tipo='v2';     Args=@{ Ferramenta='explorer' } }
    @{ Cat='REPAROS';     Label='Agendar Chkdsk (verif. disco)'; Tipo='v2';     Args=@{ Ferramenta='chkdsk' } }
    @{ Cat='REPAROS';     Label='Reparar Apps da Store (AppX)';  Tipo='v2';     Args=@{ Ferramenta='appx' } }
    @{ Cat='REPAROS';     Label='Sincronizar Horario (NTP)';     Tipo='v2';     Args=@{ Ferramenta='horario' } }
    @{ Cat='REPAROS';     Label='Renovar IP (DHCP)';             Tipo='v2';     Args=@{ Ferramenta='ip' } }
    @{ Cat='REPAROS';     Label='Atualizar GPO (dominio)';       Tipo='v2';     Args=@{ Ferramenta='gpupdate' } }
    @{ Cat='REPAROS';     Label='Permissoes do PowerShell';      Tipo='v2';     Args=@{ Ferramenta='permissoesps' } }
    @{ Cat='REPAROS';     Label='Reparar Audio e Microfone';     Tipo='v2';     Args=@{ Ferramenta='audio' } }
    @{ Cat='REPAROS';     Label='Reparar Webcam';                Tipo='v2';     Args=@{ Ferramenta='webcam' } }

    # --- OTIMIZACAO ---
    @{ Cat='OTIMIZACAO';  Label='Otimizar Disco (SSD/HDD)';      Tipo='v2';     Args=@{ Ferramenta='otimizar' } }
    @{ Cat='OTIMIZACAO';  Label='Gerenciar Inicializacao';       Tipo='v2';     Args=@{ Ferramenta='inicializacao' } }
    @{ Cat='OTIMIZACAO';  Label='Efeitos Visuais + Energia';     Tipo='v2';     Args=@{ Ferramenta='efeitos' } }
    @{ Cat='OTIMIZACAO';  Label='Memoria Virtual (pagefile)';    Tipo='v2';     Args=@{ Ferramenta='memoriavirtual' } }

    # --- CERTIFICADOS E JURIDICO ---
    @{ Cat='CERTIFICADOS';Label='Limpar Certificados Vencidos';  Tipo='v2';     Args=@{ Ferramenta='limparcerts' } }
    @{ Cat='CERTIFICADOS';Label='Configurar Java (Juridico)';    Tipo='v2';     Args=@{ Ferramenta='java' } }
    @{ Cat='CERTIFICADOS';Label='Configurar Ambiente PJe';       Tipo='v2';     Args=@{ Ferramenta='pje' } }

    # --- PROGRAMAS ---
    @{ Cat='PROGRAMAS';   Label='Desinstalar Programa';          Tipo='v2';     Args=@{ Ferramenta='desinstalar' } }
    @{ Cat='PROGRAMAS';   Label='Remover Impressora';            Tipo='v2';     Args=@{ Ferramenta='impressora' } }

    # --- ATALHOS ADMIN ---
    @{ Cat='ATALHOS';     Label='Dispositivos, Servicos e Token';  Tipo='v2'; Args=@{ Ferramenta='consoles' } }
    @{ Cat='ATALHOS';     Label='Abrir pasta %appdata%';           Tipo='v2'; Args=@{ Ferramenta='abrirappdata' } }
)
# Converte para objetos e NUMERA na ordem em que os itens estao declarados
# acima - que e' a mesma ordem em que aparecem na tela. Antes o numero era
# fixo em cada item, e opcao nova recebia numero alto: ela ia parar no fim da
# categoria dela (no meio do menu) em vez do fim da tela, e nao se achava.
# Agora, para acrescentar uma opcao, basta declarar na posicao certa: a
# numeracao se ajusta sozinha e continua sem buraco.
$numero = 0
$menu = $menu | ForEach-Object {
    $numero++
    $obj = [pscustomobject]$_
    $obj | Add-Member -NotePropertyName 'N' -NotePropertyValue $numero -Force
    $obj
}

$categorias = @(
    @{ Nome='DIAGNOSTICO';  Titulo='DIAGNOSTICO';           Cor='Cyan' }
    @{ Nome='MANUTENCAO';   Titulo='MANUTENCAO E LIMPEZA';  Cor='Green' }
    @{ Nome='SEGURANCA';    Titulo='SEGURANCA E ANTIVIRUS'; Cor='Red' }
    @{ Nome='REPAROS';      Titulo='REPAROS';               Cor='Yellow' }
    @{ Nome='OTIMIZACAO';   Titulo='OTIMIZACAO';            Cor='White' }
    @{ Nome='CERTIFICADOS'; Titulo='CERTIFICADOS E JURIDICO'; Cor='Magenta' }
    @{ Nome='PROGRAMAS';    Titulo='PROGRAMAS';             Cor='Blue' }
    @{ Nome='ATALHOS';      Titulo='ATALHOS ADMINISTRATIVOS'; Cor='Cyan' }
)

$maxOpt = ($menu | ForEach-Object { $_.N } | Measure-Object -Maximum).Maximum

# =========================================================================
# FUNCAO: EXIBIR MENU (duas colunas por categoria, cabe na tela)
# =========================================================================

function Get-LarguraConsole {
    # Largura util da janela. Se o host nao informar (ISE, redirecionamento),
    # assume 80, que e' o padrao do console do Windows.
    $w = 0
    try { $w = [int]$Host.UI.RawUI.WindowSize.Width } catch { }
    if ($w -lt 40) { $w = 80 }
    return $w
}

function Mostrar-Menu {
    Clear-Host
    $dt = Get-Date -Format 'dd/MM/yyyy  HH:mm:ss'

    # Layout adaptativo: com janela larga usa 2 colunas; estreita, 1 coluna.
    # Antes a largura era fixa em 64 e os rotulos maiores estouravam a moldura.
    $largura   = Get-LarguraConsole
    $celaMax   = ($menu | ForEach-Object { ('[{0,2}] {1}' -f $_.N, $_.Label).Length } |
                  Measure-Object -Maximum).Maximum
    $colA      = $celaMax + 2
    $duasCol   = ($largura -ge ($colA + $celaMax + 4))
    $miolo     = if ($duasCol) { $colA + $celaMax } else { $celaMax }
    if ($miolo -lt 60) { $miolo = 60 }
    if ($miolo -gt ($largura - 4)) { $miolo = $largura - 4 }

    $barra  = '  +' + ('=' * $miolo) + '+'
    $titulo = '~~~  S U P O R T E . A D V . B R  ~~~'
    $sub    = 'Suporte Tecnico em TI para Escritorios de Advocacia'

    function Linha-Central { param([string]$t, [string]$cor)
        $pad = [math]::Max(0, $miolo - $t.Length)
        $esq = [math]::Floor($pad / 2)
        Write-Host ('  |' + (' ' * $esq) + $t + (' ' * ($pad - $esq)) + '|') -ForegroundColor $cor
    }

    Write-Host ''
    Write-Host $barra -ForegroundColor DarkCyan
    Linha-Central $titulo 'Cyan'
    Linha-Central $sub    'White'
    Write-Host $barra -ForegroundColor DarkCyan
    Write-Host ("  $dt   PC: $env:COMPUTERNAME   User: $env:USERNAME") -ForegroundColor DarkGray
    Write-Host ("  versao $versaoMenu   |   suporte.adv.br") -ForegroundColor DarkGray
    if ($isAdmin) {
        Write-Host '  Privilegios: [Administrador]' -ForegroundColor Green
    } else {
        Write-Host '  Privilegios: [Usuario Limitado]  AVISO: execute como Administrador!' -ForegroundColor Red
    }
    Write-Host $barra -ForegroundColor DarkCyan

    foreach ($cat in $categorias) {
        $itens = @($menu | Where-Object { $_.Cat -eq $cat.Nome } | Sort-Object N)
        if ($itens.Count -eq 0) { continue }
        Write-Host ''
        Write-Host ("  --- {0} " -f $cat.Titulo) -ForegroundColor $cat.Cor -NoNewline
        Write-Host (('-' * [math]::Max(0, $miolo - $cat.Titulo.Length - 5))) -ForegroundColor DarkGray

        $passo = if ($duasCol) { 2 } else { 1 }
        for ($i = 0; $i -lt $itens.Count; $i += $passo) {
            $a = $itens[$i]
            $celA = ('[{0,2}] {1}' -f $a.N, $a.Label)
            if ($duasCol -and ($i + 1 -lt $itens.Count)) {
                $b = $itens[$i + 1]
                $celB = ('[{0,2}] {1}' -f $b.N, $b.Label)
                Write-Host ('  ' + $celA.PadRight($colA) + $celB) -ForegroundColor $cat.Cor
            } else {
                Write-Host ('  ' + $celA) -ForegroundColor $cat.Cor
            }
        }
    }

    Write-Host ''
    Write-Host $barra -ForegroundColor DarkCyan
    Write-Host '  [ 0 ]  Sair' -ForegroundColor DarkGray
    Write-Host $barra -ForegroundColor DarkCyan
    Write-Host ''
}

# =========================================================================
# DOWNLOAD (com cache do v2 na sessao para nao rebaixar 181 KB toda vez)
# =========================================================================

$script:v2Tmp = $null

function Get-ScriptTemp {
    param([string]$Arquivo, [switch]$Cachear)

    if ($Cachear -and $script:v2Tmp -and (Test-Path $script:v2Tmp)) { return $script:v2Tmp }

    $url = $baseUrl + $Arquivo
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $conteudo = (Invoke-RestMethod -Uri $url -UseBasicParsing -TimeoutSec 90 -ErrorAction Stop).ToString()
    if ($conteudo.Length -lt 20) { throw 'Arquivo vazio ou nao encontrado no repositorio.' }
    # O GitHub raw devolve o BOM como caractere (U+FEFF). Se regravassemos com
    # BOM, o arquivo ganharia BOM duplo e o param()/CmdletBinding deixaria de
    # ser a 1a instrucao -> erro de parse. Removemos o BOM e gravamos sem BOM.
    $conteudo = $conteudo.TrimStart([char]0xFEFF)
    $encSemBom = New-Object System.Text.UTF8Encoding($false)

    $tmp = [System.IO.Path]::GetTempPath() + 'sadv_' + [System.Guid]::NewGuid().ToString('N') + '.ps1'
    [System.IO.File]::WriteAllText($tmp, $conteudo, $encSemBom)
    Unblock-File $tmp -ErrorAction SilentlyContinue
    if ($Cachear) { $script:v2Tmp = $tmp }
    return $tmp
}

# =========================================================================
# EXECUTAR UM ITEM DO MENU
# =========================================================================

function Executar-Item {
    param($item)

    $ehV2   = ($item.Tipo -eq 'v2')
    $arquivo = if ($ehV2) { $scriptV2 } else { $item.Alvo }
    $argsV2  = if ($ehV2 -and $item.Args -is [hashtable]) { $item.Args } else { @{} }
    $descArgs = ($argsV2.GetEnumerator() | ForEach-Object {
        if ($_.Value -is [bool]) { "-$($_.Key)" } else { "-$($_.Key) $($_.Value)" }
    }) -join ' '

    Write-Host ''
    Write-Host ('  +' + ('=' * 62) + '+') -ForegroundColor DarkCyan
    Write-Host ("  |  [{0}] {1}" -f $item.N, $item.Label) -ForegroundColor Yellow
    Write-Host ("  |  Baixando $arquivo do GitHub...") -ForegroundColor DarkGray
    Write-Host ('  +' + ('=' * 62) + '+') -ForegroundColor DarkCyan
    Write-Host ''

    $tmp = $null
    try {
        $tmp = Get-ScriptTemp -Arquivo $arquivo -Cachear:$ehV2
    } catch {
        Write-Host '  [ERRO] Nao foi possivel baixar o script.' -ForegroundColor Red
        Write-Host ("  Arquivo : $arquivo") -ForegroundColor DarkRed
        Write-Host ("  Erro    : $($_.Exception.Message)") -ForegroundColor DarkGray
        Write-Host '  Verifique a conexao com a internet e se o arquivo existe no repositorio.' -ForegroundColor Yellow
        return
    }

    Write-Host ('  >> Executando...' + $(if ($descArgs) { " ($descArgs)" } else { '' })) -ForegroundColor Green
    Write-Host ('  ' + ('-' * 62)) -ForegroundColor DarkGray
    Write-Host ''
    try {
        if ($argsV2.Count) { & $tmp @argsV2 } else { & $tmp }
    } catch {
        Write-Host ''
        Write-Host ("  [ERRO durante execucao] $($_.Exception.Message)") -ForegroundColor Red
    }

    # Scripts proprios (nao-v2) usam arquivo temporario descartavel
    if (-not $ehV2 -and $tmp -and (Test-Path $tmp)) {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
}

# =========================================================================
# LOOP PRINCIPAL
# =========================================================================

if (-not $isAdmin) {
    Write-Host ''
    Write-Host '  AVISO: varias opcoes exigem Administrador. Feche e reabra o PowerShell' -ForegroundColor Yellow
    Write-Host '  como Administrador para o funcionamento completo.' -ForegroundColor Yellow
    Start-Sleep -Seconds 2
}

try {
    while ($true) {
        Mostrar-Menu
        $entrada = (Read-Host '  Opcao').Trim()

        if ($entrada -eq '0') {
            Clear-Host
            Write-Host ''
            Write-Host '  Ate logo!  suporte.adv.br' -ForegroundColor Cyan
            Write-Host ''
            break
        }

        $num = 0
        if ([int]::TryParse($entrada, [ref]$num)) {
            $item = $menu | Where-Object { $_.N -eq $num } | Select-Object -First 1
            if ($item) {
                Executar-Item -item $item
                Write-Host ''
                Write-Host ('  ' + ('-' * 62)) -ForegroundColor DarkGray
                Write-Host '  Pressione ENTER para voltar ao menu principal...' -ForegroundColor DarkGray
                $null = Read-Host
                continue
            }
        }
        Write-Host ''
        Write-Host ("  Opcao invalida: '$entrada'  |  Digite um numero de 0 a $maxOpt.") -ForegroundColor Red
        Start-Sleep -Milliseconds 1500
    }
} finally {
    # Limpa o cache do v2 ao sair
    if ($script:v2Tmp -and (Test-Path $script:v2Tmp)) {
        Remove-Item $script:v2Tmp -Force -ErrorAction SilentlyContinue
    }
}
