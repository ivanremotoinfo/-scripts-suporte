#Requires -RunAsAdministrator
<#
=============================================================================
 MANUTENCAO COMPLETA DO PC - v2.0
=============================================================================

 IMPORTANTE - PROTECAO DE CREDENCIAIS
 -------------------------------------
 A limpeza de navegadores desta versao remove APENAS arquivos de cache.
 Senhas salvas, sessoes logadas, cookies, favoritos e historico NUNCA sao
 tocados. Existem tres camadas de protecao (ver regiao PROTECAO):
   1. Lista branca: so pastas de cache conhecidas entram na limpeza.
   2. Lista negra : qualquer caminho com arquivo/pasta de credencial e
                    recusado, mesmo que a lista branca aponte para ele.
   3. Guarda por arquivo: cada arquivo e verificado antes do delete.
 Navegador aberto e PULADO (nao encerramos processo do usuario).

 EXEMPLOS DE USO
 ---------------
   .\ManutencaoCompleta-v2.ps1
       Execucao padrao: limpeza segura, relatorio e otimizacao.

   .\ManutencaoCompleta-v2.ps1 -SomenteRelatorio
       Nao altera NADA. Apenas diagnostica e mostra o que seria feito.

   .\ManutencaoCompleta-v2.ps1 -LimpezaAgressiva -RepararSistema
       Inclui WinSxS/cleanmgr e DISM+SFC (demorado, 20-40 min).

   .\ManutencaoCompleta-v2.ps1 -SemInteracao -PularInicializacao
       Modo desatendido para agendador/GPO.

 REVERSAO
 --------
 Antes de qualquer alteracao no registro sao gerados:
   - Ponto de restauracao do sistema
   - Backup .reg das chaves alteradas + RESTAURAR.cmd
 Local: %ProgramData%\SuporteTI\Logs\<MAQUINA>_<data>\

 OBS: arquivo salvo SEM acentos de proposito, para nao quebrar em consoles
      com codepage 850/1252 (mesma convencao da v1).
=============================================================================
#>

[CmdletBinding()]
param(
    # Nao altera nada: apenas diagnostica e lista o que seria feito.
    [switch]$SomenteRelatorio,

    # Pula etapas individuais
    [switch]$PularLimpeza,
    [switch]$PularNavegadores,
    [switch]$PularInicializacao,
    [switch]$PularOtimizacao,
    [switch]$PularEfeitosVisuais,

    # Etapas opcionais (demoradas ou irreversiveis)
    [switch]$LimpezaAgressiva,      # WinSxS /ResetBase, cleanmgr
    [switch]$RepararSistema,        # DISM /RestoreHealth + SFC /scannow
    [switch]$ResetarRede,           # winsock/ip reset (exige reboot)
    [switch]$DesativarHibernacao,   # libera hiberfil.sys (nao use em notebook)

    # Aplica a desativacao de inicializacao sem perguntar
    [switch]$AplicarInicializacao,

    # Diagnostica e repara o acesso a %appdata% no Explorer + cria atalhos
    [switch]$RepararAppData,

    # Remove dados do AnyDesk em %APPDATA% (opt-in: reseta ID e senha)
    [switch]$LimparAnyDesk,
    [ValidateSet('Completo', 'SomenteLogs')]
    [string]$AnyDeskModo = 'SomenteLogs',
    [switch]$ForcarFecharAnyDesk,

    # Modo desatendido: nunca usa Read-Host
    [switch]$SemInteracao,

    # Nao criar ponto de restauracao (nao recomendado)
    [switch]$SemPontoRestauracao,

    # Inclui a analise do WinSxS via DISM na estimativa (leva 1 a 3 min)
    [switch]$EstimativaCompleta,

    # --- Ferramenta unica (chamado pelo menu SuporteADV; roda so ela e sai) ---
    [string]$Ferramenta,

    # --- Reparos rapidos (opt-in) ---
    [switch]$RepararSpooler,        # limpa fila de impressao travada
    [switch]$ReiniciarExplorer,     # recria miniaturas/icones na hora
    [switch]$AgendarChkdsk,         # marca o disco para verificacao no boot
    [switch]$RepararAppX,           # re-registra apps da Microsoft Store
    [switch]$AtualizarGPO,          # gpupdate /force (maquinas em dominio)
    [switch]$RenovarIP,             # release/renew DHCP
    [switch]$CorrigirProxy,         # remove proxy manual sequestrado

    # --- Antivirus e firewall (modo standalone - nao roda a manutencao) ---
    [switch]$DesativarDefender,     # desativa a protecao do Windows Defender
    [switch]$DesativarFirewall,     # desativa o firewall nos 3 perfis
    [switch]$ReativarDefender,      # reativa o Defender e restaura padroes
    [switch]$ReativarFirewall,      # reativa o firewall nos 3 perfis
    [switch]$ReativarTudo,          # reativa Defender + firewall + AV de terceiros
    [switch]$ConfirmarProtecao,     # obrigatorio para desativar em -SemInteracao

    # --- Scanner de malware ClamAV (modo standalone, portatil p/ AnyDesk) ---
    [switch]$EscanearVirus,         # ativa o modo scanner de virus
    [string]$CaminhoScan,           # arquivo ou pasta a escanear (vazio = seletor grafico)
    [string]$ClamAVDir,             # onde fica/baixa o ClamAV portatil (temporario)
    [string]$ClamAVCache,           # pasta FIXA (pendrive/rede) p/ reaproveitar entre clientes
    [string]$ClamAVZip,             # zip do ClamAV portatil ja baixado (p/ carregar via AnyDesk)
    [string]$ClamAVUrl,             # URL direta do zip (vazio = resolve a ultima via GitHub)
    [string[]]$ExcluirPastas,       # subpastas a ignorar no scan recursivo
    [switch]$SemAtualizarAssinaturas, # pula o freshclam (usa base local)
    [switch]$SemHash,               # nao calcula SHA256 (mais rapido em pastas grandes)
    [switch]$LimparAposScan,        # remove o ClamAV baixado ao terminar (sem rastro)

    # --- Camada 2: VirusTotal (checagem de hash) ---
    [string]$VirusTotalKey,         # API key; se vazio, usa config.json ou virustotal.txt
    [switch]$SemVirusTotal,         # desativa a camada VirusTotal (so ClamAV)
    [switch]$VTTodos,               # modo pasta: consulta o VT de TODOS os arquivos (nao so os suspeitos)
    [int]$VTLimite = 100,           # maximo de consultas ao VT por execucao (0 = sem limite)

    # --- Remocao de ameacas (mediante autorizacao) ---
    [switch]$RemoverAmeacas,        # apos o scan, remove os arquivos detectados
    [switch]$ApagarDefinitivo,      # apaga de vez (padrao: move para quarentena reversivel)
    [switch]$ConfirmarRemocao,      # obrigatorio para remover em -SemInteracao
    [int]$VTLimiarRemocao = 3,      # min. de engines do VT para contar como ameaca removivel

    # --- Restauracao de quarentena (falso positivo) ---
    [switch]$RestaurarQuarentena,   # modo standalone: devolve arquivos da quarentena
    [string]$QuarentenaPath,        # pasta/manifesto da quarentena (vazio = localiza a mais recente)
    [switch]$ConfirmarRestauracao,  # obrigatorio para restaurar em -SemInteracao

    [string]$PastaLog = "$env:ProgramData\SuporteTI\Logs",

    # Copia o relatorio HTML para um compartilhamento de rede
    [string]$DestinoRelatorio,

    # Nao abrir o log em txt automaticamente ao terminar a manutencao
    [switch]$NaoAbrirLog
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'Continue'

# =========================================================================
# REGIAO: ESTADO GLOBAL
# =========================================================================

$script:resultados    = [System.Collections.Generic.List[object]]::new()
$script:alertas       = [System.Collections.Generic.List[string]]::new()
$script:bytesPorEtapa = @{}
$script:inicio        = Get-Date
$script:carimbo       = $script:inicio.ToString('yyyy-MM-dd_HH-mm-ss')
$script:pastaExec     = Join-Path $PastaLog ("{0}_{1}" -f $env:COMPUTERNAME, $script:carimbo)

# =========================================================================
# REGIAO: EXCECOES DE INICIALIZACAO
# Programas cujos nomes ou caminhos contenham estes termos serao MANTIDOS.
# =========================================================================

$script:excecoes = @(
    # --- Juridico / certificado digital (originais da v1) ---
    'PjeOffice', 'Java', 'jusched', 'jaureg', 'Shodo',
    'SafeNet', 'eToken', 'Safeid', 'Certisign', 'Serpro', 'Valid',
    'Soluti', 'AC ', 'Token', 'Smartcard', 'SCR', 'Gemalto', 'Watchdata',
    'Assinador', 'Sign', 'ITI', 'Neoid',
    # Middlewares de token/leitora - desativar QUEBRA a assinatura digital
    'ePass', 'ePass2003', 'EnterSafe', 'Feitian', 'Etoken', 'Alladin',
    'Aladdin', 'Morpho', 'Oberthur', 'Giesecke', 'Athena', 'ASEDrive',
    'Bit4id', 'Perto', 'Vasco', 'CertificateRegistration',

    # --- Nuvem / sincronizacao (originais + novos) ---
    'OneDrive', 'GoogleDrive', 'Google Drive', 'GD Token',
    'Dropbox', 'Nextcloud', 'Egnyte', 'Box Sync', 'MEGA', 'pCloud',

    # --- Acesso remoto (originais) ---
    'AnyDesk', 'TeamViewer', 'RustDesk', 'Splashtop', 'LogMeIn', 'Supremo',
    'DWAgent', 'DWService', 'Atera', 'ScreenConnect', 'ConnectWise', 'Ammyy',

    # --- SEGURANCA: nunca desativar ---
    'SecurityHealth', 'Defender', 'MsMpEng', 'Avast', 'AVG', 'Avira',
    'Bitdefender', 'Kaspersky', 'ESET', 'egui', 'Sophos', 'McAfee',
    'Norton', 'Symantec', 'Trend', 'Sentinel', 'CrowdStrike', 'Malwarebytes',
    'Firewall', 'VPN', 'FortiClient', 'GlobalProtect',

    # --- DRIVERS / HARDWARE: desativar quebra audio, touchpad, video ---
    'Realtek', 'RtkAud', 'RAVCpl', 'RtkNGUI', 'Waves', 'Nahimic',
    'SynTP', 'Synaptics', 'ELAN', 'Alps', 'Touchpad',
    'IgfxTray', 'HotKeysCmds', 'Persistence', 'Intel', 'DPTF',
    'NVIDIA', 'NvBackend', 'AMD', 'ATI', 'RadeonSoftware',
    'Dell', 'Lenovo', 'Hewlett', 'HPMSGSVC', 'Asus', 'Acer', 'Vantage',
    'Bluetooth', 'BTTray', 'Wireless', 'Killer',

    # --- Impressora / scanner: desativar quebra digitalizacao e alertas ---
    'Epson', 'EEvent', 'EPLTarget', 'Canon', 'Brother', 'Samsung Printer',
    'HP Smart', 'Xerox', 'Kyocera', 'Ricoh', 'Scan', 'Twain', 'NUSB', 'RUSB',

    # --- Gestao / backup / senhas ---
    'Backup', 'Veeam', 'Acronis', 'Carbonite',
    'Bitwarden', 'LastPass', '1Password', 'KeePass', 'Dashlane',

    # --- Sistemas de escritorio de advocacia / ponto / ERP ---
    'Astrea', 'Projuris', 'SAJ', 'Themis', 'Legal', 'Espider', 'ADVBOX',
    'Ponto', 'Henry', 'Control iD', 'Dimep', 'Madis',
    'Nota Fiscal', 'Sefaz', 'Emissor', 'Dominio', 'Contabil'
)

# =========================================================================
# REGIAO: PROTECAO
# Nada aqui pode ser removido, em nenhuma circunstancia.
# =========================================================================

# Arquivos que guardam senhas, cookies, sessoes ou a chave que decifra tudo.
# ATENCAO: 'Local State' guarda a chave mestra do Chrome/Edge. Se apagar,
# TODAS as senhas salvas viram lixo indecifravel - nunca inclua na limpeza.
$script:ArquivosProtegidos = @(
    # Chromium (Chrome, Edge, Brave, Vivaldi, Opera)
    'Login Data', 'Login Data-journal',
    'Login Data For Account', 'Login Data For Account-journal',
    'Web Data', 'Web Data-journal',
    'Local State', 'Preferences', 'Secure Preferences',
    'Cookies', 'Cookies-journal',
    'History', 'History-journal', 'Bookmarks', 'Bookmarks.bak',
    'Favicons', 'Top Sites', 'Shortcuts', 'Affiliation Database',
    'Trust Tokens', 'Network Action Predictor',
    # Firefox
    'logins.json', 'logins-backup.json', 'key3.db', 'key4.db',
    'cert9.db', 'cert8.db', 'signons.sqlite', 'cookies.sqlite',
    'places.sqlite', 'formhistory.sqlite', 'prefs.js', 'sessionstore.jsonlz4',
    # Credenciais do Windows
    'ntuser.dat', 'Credentials'
)

# Pastas que podem conter tokens de sessao ou dados de extensao.
# Apagar 'Local Storage' ou 'IndexedDB' desloga o usuario de varios sites.
$script:PastasProtegidas = @(
    'Local Storage', 'Session Storage', 'Sessions', 'IndexedDB',
    'databases', 'File System', 'Extension State', 'Extensions',
    'Local Extension Settings', 'Sync Extension Settings', 'Sync Data',
    'Web Applications', 'Storage', 'Safe Browsing', 'AutofillStrikeDatabase',
    'Network',                       # Chrome novo guarda Cookies aqui
    'Crypto',                        # DPAPI
    'Protect', 'Microsoft\Protect', 'Microsoft\Credentials',
    'Microsoft\Vault', 'Microsoft\Crypto', 'SystemCertificates'
)

# UNICAS pastas que a limpeza de navegador pode remover (lista branca).
$script:CachesPermitidos = @(
    'Cache', 'Cache_Data', 'Code Cache', 'GPUCache', 'DawnCache',
    'GrShaderCache', 'ShaderCache', 'Media Cache', 'Application Cache',
    'Service Worker\CacheStorage', 'Service Worker\ScriptCache',
    'cache2', 'startupCache', 'thumbnails', 'jumpListCache'
)

# Caminhos que NUNCA podem ser alvo de remocao recursiva.
$script:RaizesProibidas = @(
    'C:\', "$env:SystemDrive\", "$env:SystemRoot", "$env:SystemRoot\System32",
    "$env:ProgramFiles", "${env:ProgramFiles(x86)}", 'C:\Users',
    $env:USERPROFILE, $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData
)

# Indices pre-computados. Sem isso, a guarda usava Split-Path (um cmdlet)
# dentro de loops aninhados: 41 ms por arquivo, ou 54 minutos para varrer o
# cache do Chrome. Com HashSet a mesma checagem cai para microssegundos.
$script:idxArquivosProtegidos = New-Object 'System.Collections.Generic.HashSet[string]' (
    [string[]]$script:ArquivosProtegidos, [System.StringComparer]::OrdinalIgnoreCase)

$script:idxPastasProtegidas = New-Object 'System.Collections.Generic.HashSet[string]' (
    [System.StringComparer]::OrdinalIgnoreCase)
foreach ($p in $script:PastasProtegidas) {
    # guarda so o ultimo segmento ('Microsoft\Protect' -> 'Protect')
    $i = $p.LastIndexOf('\')
    [void]$script:idxPastasProtegidas.Add($(if ($i -ge 0) { $p.Substring($i + 1) } else { $p }))
}

function Test-CaminhoProtegido {
    <# Retorna $true se o caminho tocar em qualquer credencial. #>
    param([string]$Caminho)
    if ([string]::IsNullOrWhiteSpace($Caminho)) { return $true }

    $segmentos = $Caminho.Split([char]'\')

    # Ultimo segmento = nome do arquivo/pasta folha
    if ($script:idxArquivosProtegidos.Contains($segmentos[$segmentos.Length - 1])) { return $true }

    # Qualquer segmento do caminho batendo com pasta protegida ja bloqueia.
    foreach ($seg in $segmentos) {
        if ($script:idxPastasProtegidas.Contains($seg)) { return $true }
    }
    return $false
}

function Test-CaminhoSeguroParaLimpeza {
    <# Impede remocao recursiva em raizes de sistema ou perfil. #>
    param([string]$Caminho)
    if ([string]::IsNullOrWhiteSpace($Caminho)) { return $false }
    $norm = $Caminho.TrimEnd('\')
    foreach ($raiz in $script:RaizesProibidas) {
        if ([string]::IsNullOrWhiteSpace($raiz)) { continue }
        if ($norm -eq $raiz.TrimEnd('\')) { return $false }
    }
    if ($norm.Length -lt 8) { return $false }   # ex.: "C:\Temp" e o minimo
    return $true
}

# =========================================================================
# REGIAO: SAIDA / FORMATACAO
# =========================================================================

function Write-Titulo {
    param([string]$Texto)
    Write-Host ''
    Write-Host ('=' * 68) -ForegroundColor Magenta
    Write-Host "  $Texto" -ForegroundColor Magenta
    Write-Host ('=' * 68) -ForegroundColor Magenta
    Write-Host ''
}

function Write-Etapa { param([string]$t) Write-Host "  >> $t" -ForegroundColor Cyan }
function Write-Ok    { param([string]$t) Write-Host "     [OK] $t" -ForegroundColor Green }
function Write-Aviso { param([string]$t) Write-Host "     [!]  $t" -ForegroundColor Yellow }
function Write-Falha { param([string]$t) Write-Host "     [X]  $t" -ForegroundColor Red }
function Write-Info  { param([string]$t) Write-Host "     $t" -ForegroundColor Gray }
function Write-Simul { param([string]$t) Write-Host "     [SIMULACAO] $t" -ForegroundColor DarkYellow }
# Usadas pelas ferramentas que vieram dos sub-scripts:
function Write-Dest  { param([string]$t) Write-Host "     $t" -ForegroundColor White }
function Write-Acao  { param([string]$t) Write-Host "     [>>] $t" -ForegroundColor Magenta }

function Read-HostComTimeout {
    <#
      Read-Host com tempo limite: se o operador nao digitar nada em N segundos,
      retorna vazio e o fluxo segue (evita a manutencao ficar "presa" num
      prompt quando roda pela opcao 4 do menu). Cai para Read-Host normal se o
      host nao suportar leitura de tecla (ISE, remoto, etc.).
    #>
    param([string]$Prompt, [int]$Segundos = 20)

    # Sem RawUI (ex.: ISE) ou modo desatendido -> comportamento simples
    if ($SemInteracao) { return '' }
    $temRaw = $false
    try { $null = $Host.UI.RawUI.KeyAvailable; $temRaw = $true } catch { $temRaw = $false }
    if (-not $temRaw) { try { return (Read-Host $Prompt) } catch { return '' } }

    Write-Host -NoNewline ("{0} (segue sozinho em {1}s): " -f $Prompt, $Segundos)
    $sb  = New-Object System.Text.StringBuilder
    $fim = (Get-Date).AddSeconds($Segundos)
    while ((Get-Date) -lt $fim) {
        if ($Host.UI.RawUI.KeyAvailable) {
            $k = $Host.UI.RawUI.ReadKey('IncludeKeyDown,NoEcho')
            if ($k.VirtualKeyCode -eq 13) { Write-Host ''; return $sb.ToString().Trim() }   # Enter
            elseif ($k.VirtualKeyCode -eq 8) {                                                # Backspace
                if ($sb.Length -gt 0) { [void]$sb.Remove($sb.Length - 1, 1); Write-Host -NoNewline "`b `b" }
            } elseif ($k.Character) {
                [void]$sb.Append($k.Character); Write-Host -NoNewline $k.Character
            }
            $fim = (Get-Date).AddSeconds($Segundos)   # cada tecla reinicia a contagem
        }
        Start-Sleep -Milliseconds 100
    }
    Write-Host ''
    Write-Info 'Tempo esgotado - seguindo apenas com o disco C:.'
    return $sb.ToString().Trim()
}

function Format-Tamanho {
    param([long]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N2} KB' -f ($Bytes / 1KB)) }
    return "$Bytes B"
}

function Add-Resultado {
    param(
        [string]$Etapa,
        [ValidateSet('OK', 'PARCIAL', 'FALHA', 'PULADO', 'SIMULADO')][string]$Status,
        [long]$Bytes = 0,
        [string]$Detalhe = ''
    )
    $script:resultados.Add([pscustomobject]@{
        Etapa    = $Etapa
        Status   = $Status
        Liberado = if ($Bytes -gt 0) { Format-Tamanho $Bytes } else { '-' }
        Bytes    = $Bytes
        Detalhe  = $Detalhe
    })
}

function Add-Alerta {
    param([string]$Texto)
    $script:alertas.Add($Texto)
    Write-Falha $Texto
}

function Invoke-Etapa {
    <# Executa uma etapa isolando falhas e cronometrando. #>
    param([string]$Nome, [int]$Numero, [int]$Total, [switch]$Pular, [scriptblock]$Acao)

    Write-Titulo "ETAPA $Numero/$Total - $Nome"
    if ($Pular) {
        Write-Aviso 'Etapa pulada por parametro.'
        Add-Resultado -Etapa $Nome -Status 'PULADO'
        return
    }
    Write-Progress -Activity 'Manutencao Completa' -Status "[$Numero/$Total] $Nome" `
                   -PercentComplete ([math]::Min(100, ($Numero - 1) / $Total * 100))
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $bytes = & $Acao
        if ($bytes -isnot [long] -and $bytes -isnot [int]) { $bytes = [long]0 }
        $sw.Stop()
        $st = if ($SomenteRelatorio) { 'SIMULADO' } else { 'OK' }
        Add-Resultado -Etapa $Nome -Status $st -Bytes ([long]$bytes) `
                      -Detalhe ('{0:N1}s' -f $sw.Elapsed.TotalSeconds)
    } catch {
        $sw.Stop()
        Write-Falha "$Nome : $($_.Exception.Message)"
        Add-Resultado -Etapa $Nome -Status 'FALHA' -Detalhe $_.Exception.Message
    }
}

# =========================================================================
# REGIAO: REMOCAO SEGURA
# =========================================================================

function Remove-Files {
    <#
      Remove arquivos de uma pasta contabilizando SOMENTE o que foi de fato
      apagado. Correcao da v1: usa -ErrorAction Stop, senao o catch nunca
      dispara e arquivos em uso entram na conta como se tivessem sido
      liberados. Usa -LiteralPath para nomes com [ ] (comum em downloads).
    #>
    param(
        [string]$Pasta,
        [string]$Filtro = '*',
        [int]$DiasAntigos = 0,
        [switch]$IgnorarGuardaCredencial
    )

    if ([string]::IsNullOrWhiteSpace($Pasta)) { return [long]0 }
    if (-not (Test-Path -LiteralPath $Pasta)) { return [long]0 }
    if (-not (Test-CaminhoSeguroParaLimpeza $Pasta)) {
        Write-Falha "Caminho recusado por seguranca: $Pasta"
        return [long]0
    }
    if (-not $IgnorarGuardaCredencial -and (Test-CaminhoProtegido $Pasta)) {
        Write-Falha "Caminho protegido (credenciais), ignorado: $Pasta"
        return [long]0
    }

    $liberado = [long]0
    $bloqueados = 0

    try {
        $itens = Get-ChildItem -LiteralPath $Pasta -Recurse -File -Filter $Filtro -Force -ErrorAction SilentlyContinue
        if ($DiasAntigos -gt 0) {
            $limite = (Get-Date).AddDays(-$DiasAntigos)
            $itens = $itens | Where-Object { $_.LastWriteTime -lt $limite }
        }

        foreach ($item in $itens) {
            # Guarda por arquivo: mesmo dentro de pasta liberada, credencial nao cai.
            if (-not $IgnorarGuardaCredencial -and (Test-CaminhoProtegido $item.FullName)) { continue }

            $tam = $item.Length
            if ($SomenteRelatorio) { $liberado += $tam; continue }
            try {
                Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
                $liberado += $tam
            } catch {
                $bloqueados++
            }
        }

        # Remove diretorios vazios remanescentes (do mais profundo para o raso).
        if (-not $SomenteRelatorio) {
            Get-ChildItem -LiteralPath $Pasta -Recurse -Directory -Force -ErrorAction SilentlyContinue |
                Sort-Object { $_.FullName.Length } -Descending |
                ForEach-Object {
                    if (Test-CaminhoProtegido $_.FullName) { return }
                    if ((Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
                        Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
        }
    } catch { }

    if ($bloqueados -gt 0) { Write-Info "($bloqueados arquivo(s) em uso, mantidos)" }
    return [long]$liberado
}

function Get-EspacoLivre {
    param([string]$Letra = 'C')
    $v = Get-Volume -DriveLetter $Letra -ErrorAction SilentlyContinue
    if ($v) { return [long]$v.SizeRemaining }
    return [long]0
}

# =========================================================================
# REGIAO: BACKUP E REVERSAO
# =========================================================================

function New-PontoRestauracao {
    param([string]$Descricao = 'Manutencao Completa - SuporteTI')
    if ($SomenteRelatorio) { Write-Simul 'Criaria ponto de restauracao.'; return $false }
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        # O Windows ignora pontos criados a menos de 24h; zerar libera a criacao.
        $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        if (Test-Path $k) {
            Set-ItemProperty -Path $k -Name 'SystemRestorePointCreationFrequency' -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }
        Checkpoint-Computer -Description $Descricao -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        Write-Ok 'Ponto de restauracao criado.'
        return $true
    } catch {
        Write-Aviso "Ponto de restauracao indisponivel: $($_.Exception.Message)"
        return $false
    }
}

function Backup-Registro {
    param([string]$Destino)
    if ($SomenteRelatorio) { Write-Simul 'Exportaria backup do registro.'; return }

    $pastaReg = Join-Path $Destino 'backup-registro'
    New-Item -ItemType Directory -Path $pastaReg -Force -ErrorAction SilentlyContinue | Out-Null

    $chaves = [ordered]@{
        'Run_HKCU'       = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'Run_HKLM'       = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'Run_HKLM32'     = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        'StartupApp_CU'  = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
        'StartupApp_LM'  = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
        'Desktop'        = 'HKCU\Control Panel\Desktop'
        'VisualEffects'  = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
        'ExplorerAdv'    = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    }

    $exportadas = 0
    foreach ($nome in $chaves.Keys) {
        $arq = Join-Path $pastaReg "$nome.reg"
        & reg.exe export $chaves[$nome] $arq /y 2>$null | Out-Null
        if (Test-Path $arq) { $exportadas++ }
    }

    # Script de reversao de um clique
    $cmd = @"
@echo off
REM Restaura o estado do registro anterior a manutencao de $($script:carimbo)
echo Restaurando chaves de registro...
for %%F in ("%~dp0*.reg") do reg import "%%F"
echo.
echo Concluido. Reinicie o computador para aplicar.
pause
"@
    Set-Content -Path (Join-Path $pastaReg 'RESTAURAR.cmd') -Value $cmd -Encoding ASCII
    Write-Ok "Backup do registro: $exportadas chave(s) em $pastaReg"
    Write-Info 'Para reverter: execute RESTAURAR.cmd como administrador.'
}

# =========================================================================
# REGIAO: BACKUP DE CREDENCIAIS DO NAVEGADOR
#
# Motivo: relato de campo de que apos a manutencao os usuarios ficavam
# deslogados dos sites. Como nem todo usuario lembra a senha, aqui a rede de
# seguranca e copiar os arquivos de credencial ANTES de qualquer alteracao.
# Se algo (este script ou nao) apagar a sessao, da para restaurar.
#
# ATENCAO - CONTEUDO SENSIVEL: o backup inclui as senhas cifradas e o
# 'Local State', que guarda a chave usada para decifra-las. A pasta recebe
# ACL restrita (so o usuario e Administradores). So funciona no MESMO
# usuario e MESMA maquina - a protecao DPAPI e amarrada ao perfil.
# =========================================================================

function Get-PerfisNavegador {
    $bases = [ordered]@{
        'Chrome'  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        'Edge'    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        'Brave'   = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
        'Vivaldi' = "$env:LOCALAPPDATA\Vivaldi\User Data"
        'Opera'   = "$env:APPDATA\Opera Software\Opera Stable"
    }
    $saida = @()
    foreach ($nome in $bases.Keys) {
        $base = $bases[$nome]
        if (-not (Test-Path -LiteralPath $base)) { continue }
        $perfis = @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile*' })
        if ($perfis.Count -eq 0) { $perfis = @(Get-Item -LiteralPath $base -ErrorAction SilentlyContinue) }
        foreach ($p in $perfis) {
            $saida += [pscustomobject]@{ Navegador = $nome; Base = $base; Perfil = $p.Name; Caminho = $p.FullName }
        }
    }
    # Firefox: credenciais ficam no APPDATA (roaming), nunca no LOCALAPPDATA.
    $ffBase = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path -LiteralPath $ffBase) {
        Get-ChildItem -LiteralPath $ffBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $saida += [pscustomobject]@{ Navegador = 'Firefox'; Base = $ffBase; Perfil = $_.Name; Caminho = $_.FullName }
        }
    }
    return $saida
}

function Get-ArquivosCredenciais {
    <# Lista os arquivos que carregam senha, cookie ou sessao. #>
    $relativos = @(
        'Login Data', 'Login Data For Account', 'Web Data',
        'Cookies', 'Network\Cookies', 'Preferences', 'Bookmarks',
        'logins.json', 'key4.db', 'cert9.db', 'cookies.sqlite', 'places.sqlite'
    )
    $lista = @()
    foreach ($p in (Get-PerfisNavegador)) {
        foreach ($rel in $relativos) {
            $full = Join-Path $p.Caminho $rel
            if (Test-Path -LiteralPath $full -PathType Leaf) {
                $lista += [pscustomobject]@{
                    Navegador = $p.Navegador; Perfil = $p.Perfil
                    Arquivo = $rel; Caminho = $full
                    Tamanho = (Get-Item -LiteralPath $full -Force).Length
                }
            }
        }
        # 'Local State' fica na raiz do User Data, um nivel acima do perfil.
        $ls = Join-Path (Split-Path $p.Caminho -Parent) 'Local State'
        if ((Test-Path -LiteralPath $ls -PathType Leaf) -and $p.Navegador -ne 'Firefox') {
            if (-not ($lista | Where-Object { $_.Caminho -eq $ls })) {
                $lista += [pscustomobject]@{
                    Navegador = $p.Navegador; Perfil = '(comum)'
                    Arquivo = 'Local State'; Caminho = $ls
                    Tamanho = (Get-Item -LiteralPath $ls -Force).Length
                }
            }
        }
    }
    return $lista
}

function Protect-PastaBackup {
    param([string]$Caminho)
    try {
        $sidUsuario = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        & icacls.exe $Caminho /inheritance:r /grant:r "*${sidUsuario}:(OI)(CI)F" '*S-1-5-32-544:(OI)(CI)F' 2>$null | Out-Null
    } catch { Write-Aviso 'Nao foi possivel restringir permissoes da pasta de backup.' }
}

function Backup-CredenciaisNavegador {
    param([string]$Destino)

    $arquivos = @(Get-ArquivosCredenciais)
    if ($arquivos.Count -eq 0) { Write-Info 'Nenhum perfil de navegador encontrado.'; return }

    Write-Info "$($arquivos.Count) arquivo(s) de credencial localizado(s)."
    if ($SomenteRelatorio) {
        Write-Simul 'Faria backup das senhas/sessoes antes de limpar.'
        $arquivos | Group-Object Navegador |
            ForEach-Object { Write-Info ("  {0,-10} {1} arquivo(s)" -f $_.Name, $_.Count) }
        return
    }

    $pastaCred = Join-Path $Destino 'backup-credenciais'
    New-Item -ItemType Directory -Path $pastaCred -Force -ErrorAction SilentlyContinue | Out-Null
    Protect-PastaBackup -Caminho $pastaCred

    $copiados = 0; $falhas = 0
    foreach ($a in $arquivos) {
        $sub = Join-Path $pastaCred ("{0}\{1}" -f $a.Navegador, $a.Perfil)
        New-Item -ItemType Directory -Path $sub -Force -ErrorAction SilentlyContinue | Out-Null
        $destArq = Join-Path $sub ($a.Arquivo -replace '\\', '_')
        try {
            Copy-Item -LiteralPath $a.Caminho -Destination $destArq -Force -ErrorAction Stop
            $copiados++
        } catch {
            # Arquivo bloqueado pelo navegador aberto: tenta via copia de sombra simples
            $falhas++
        }
    }

    # Manifesto para conferencia e restauracao
    $arquivos | Select-Object Navegador, Perfil, Arquivo, Tamanho, Caminho |
        Export-Csv -Path (Join-Path $pastaCred 'manifesto.csv') -NoTypeInformation -Encoding UTF8

    $script:pastaCredenciais = $pastaCred
    Write-Ok "Credenciais copiadas: $copiados arquivo(s)."
    if ($falhas -gt 0) {
        Write-Aviso "$falhas arquivo(s) bloqueado(s) por navegador aberto - feche os navegadores para backup completo."
    }
    Write-Info "Backup em: $pastaCred"
    Write-Aviso 'Esta pasta contem senhas cifradas. Nao envie por e-mail nem copie para pendrive comum.'
}

function Restore-CredenciaisNavegador {
    <#
      Restaura o backup feito por Backup-CredenciaisNavegador.
      Uso: feche TODOS os navegadores e execute
        . .\ManutencaoCompleta-v2.ps1 ; Restore-CredenciaisNavegador -Origem '<pasta>\backup-credenciais'
    #>
    param([Parameter(Mandatory)][string]$Origem)

    $manifesto = Join-Path $Origem 'manifesto.csv'
    if (-not (Test-Path -LiteralPath $manifesto)) { throw "Manifesto nao encontrado em $Origem" }

    $abertos = Get-NavegadoresAbertos
    if ($abertos.Count -gt 0) {
        throw "Feche antes: $($abertos.Values -join ', ')"
    }

    $ok = 0
    foreach ($linha in (Import-Csv -Path $manifesto)) {
        $origemArq = Join-Path $Origem ("{0}\{1}\{2}" -f $linha.Navegador, $linha.Perfil, ($linha.Arquivo -replace '\\', '_'))
        if (-not (Test-Path -LiteralPath $origemArq)) { continue }
        try {
            $pastaDestino = Split-Path $linha.Caminho -Parent
            if (-not (Test-Path -LiteralPath $pastaDestino)) {
                New-Item -ItemType Directory -Path $pastaDestino -Force | Out-Null
            }
            Copy-Item -LiteralPath $origemArq -Destination $linha.Caminho -Force -ErrorAction Stop
            $ok++
        } catch { Write-Falha "Falha ao restaurar $($linha.Caminho): $($_.Exception.Message)" }
    }
    Write-Ok "$ok arquivo(s) de credencial restaurado(s). Abra o navegador e confira."
}

function Get-SnapshotCredenciais {
    <# Fotografa tamanho e existencia para conferir depois. #>
    $snap = @{}
    foreach ($a in (Get-ArquivosCredenciais)) { $snap[$a.Caminho] = $a.Tamanho }
    return $snap
}

function Test-IntegridadeCredenciais {
    <#
      Compara com a foto inicial. Alerta so se o arquivo SUMIU ou encolheu
      de forma relevante - crescer ou variar pouco e uso normal do navegador.
    #>
    param([hashtable]$Antes)
    if (-not $Antes -or $Antes.Count -eq 0) { return }

    $problemas = 0
    foreach ($caminho in $Antes.Keys) {
        $tamAntes = [long]$Antes[$caminho]
        if (-not (Test-Path -LiteralPath $caminho -PathType Leaf)) {
            Add-Alerta "CREDENCIAL REMOVIDA: $caminho - restaure pelo backup."
            $problemas++
            continue
        }
        $tamDepois = (Get-Item -LiteralPath $caminho -Force).Length
        if ($tamAntes -gt 0 -and $tamDepois -lt ($tamAntes * 0.9)) {
            Add-Alerta ("CREDENCIAL ENCOLHEU: {0} ({1} -> {2})" -f $caminho, (Format-Tamanho $tamAntes), (Format-Tamanho $tamDepois))
            $problemas++
        }
    }
    if ($problemas -eq 0) {
        Write-Ok "Integridade das credenciais confirmada: $($Antes.Count) arquivo(s) intactos."
    } else {
        Write-Falha "$problemas arquivo(s) de credencial alterado(s) - ver instrucoes de restauracao."
    }
}

# =========================================================================
# REGIAO: DIAGNOSTICO
# =========================================================================

function Get-RelatorioSistema {
    $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs  = Get-CimInstance Win32_ComputerSystem  -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $bat = Get-CimInstance Win32_Battery   -ErrorAction SilentlyContinue

    $uptime = if ($os) { (Get-Date) - $os.LastBootUpTime } else { New-TimeSpan }
    $fastBoot = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' `
                 -Name 'HiberbootEnabled' -ErrorAction SilentlyContinue).HiberbootEnabled

    [pscustomobject]@{
        Maquina     = $env:COMPUTERNAME
        Usuario     = if ($cs) { $cs.UserName } else { $env:USERNAME }
        Fabricante  = if ($cs) { "$($cs.Manufacturer) $($cs.Model)".Trim() } else { 'n/d' }
        Windows     = if ($os) { "$($os.Caption) build $($os.BuildNumber)" } else { 'n/d' }
        CPU         = if ($cpu) { $cpu.Name.Trim() } else { 'n/d' }
        RAMTotal    = if ($cs) { '{0:N1} GB' -f ($cs.TotalPhysicalMemory / 1GB) } else { 'n/d' }
        RAMLivre    = if ($os) { '{0:N1} GB' -f ($os.FreePhysicalMemory / 1MB) } else { 'n/d' }
        Uptime      = '{0}d {1}h {2}m' -f $uptime.Days, $uptime.Hours, $uptime.Minutes
        UptimeDias  = $uptime.Days
        Bateria     = if ($bat) { "$($bat.EstimatedChargeRemaining)%" } else { 'Desktop / sem bateria' }
        FastStartup = if ($fastBoot -eq 1) { 'Ligado' } else { 'Desligado' }
    }
}

function Test-SaudeDiscos {
    $lista = @()
    foreach ($d in (Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
        $rel = Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction SilentlyContinue
        $lista += [pscustomobject]@{
            Disco       = $d.FriendlyName
            Tipo        = $d.MediaType
            Barramento  = $d.BusType
            Tamanho     = Format-Tamanho $d.Size
            Saude       = $d.HealthStatus
            Desgaste    = if ($rel -and $null -ne $rel.Wear) { "$($rel.Wear)%" } else { 'n/d' }
            HorasLigado = if ($rel) { $rel.PowerOnHours } else { 'n/d' }
            Temperatura = if ($rel -and $rel.Temperature) { "$($rel.Temperature) C" } else { 'n/d' }
        }
    }
    return $lista
}

function Get-TempoBoot {
    try {
        Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100
        } -MaxEvents 5 -ErrorAction Stop | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $ms  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'BootTime' }).'#text'
            [pscustomobject]@{
                Data     = $_.TimeCreated.ToString('dd/MM/yyyy HH:mm')
                Segundos = [math]::Round([double]$ms / 1000, 1)
            }
        }
    } catch { return @() }
}

function Get-TipoMidia {
    <#
      Correcao da v1: comparar DeviceId com DiskNumber falha em NVMe, RAID,
      Storage Spaces e VM (MediaType volta 'Unspecified'), fazendo o script
      DESFRAGMENTAR UM SSD. Na duvida assumimos SSD: TRIM em HDD e inofensivo,
      defrag em SSD gasta ciclos de escrita a toa.
    #>
    param([string]$Letra)
    try {
        $disco = Get-Partition -DriveLetter $Letra -ErrorAction Stop | Get-Disk -ErrorAction Stop
        $phys  = Get-PhysicalDisk -ErrorAction SilentlyContinue |
                 Where-Object { $_.DeviceId -eq [string]$disco.Number }
        if ($phys) {
            if ($phys.MediaType -eq 'SSD')                 { return 'SSD' }
            if ($phys.MediaType -eq 'HDD')                 { return 'HDD' }
            if ($phys.BusType -in @('NVMe', 'RAID'))       { return 'SSD' }
            if ($phys.SpindleSpeed -eq 0)                  { return 'SSD' }
        }
        return 'Desconhecido'
    } catch { return 'Desconhecido' }
}

function Get-PerfisAntigos {
    # Medir o tamanho varre o perfil inteiro e pode levar minutos, por isso
    # so acontece com -Medir (ligado pelo -EstimativaCompleta).
    param([int]$DiasSemUso = 180, [switch]$Medir)
    Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { -not $_.Special -and $_.LastUseTime -and $_.LastUseTime -lt (Get-Date).AddDays(-$DiasSemUso) } |
        ForEach-Object {
            $tam = 0
            if ($Medir) {
                try {
                    $tam = (Get-ChildItem $_.LocalPath -Recurse -File -Force -ErrorAction SilentlyContinue |
                            Measure-Object Length -Sum).Sum
                } catch { }
            }
            [pscustomobject]@{
                Perfil    = $_.LocalPath
                UltimoUso = $_.LastUseTime.ToString('dd/MM/yyyy')
                Tamanho   = if ($Medir) { Format-Tamanho ([long]$tam) } else { '(nao medido)' }
            }
        }
}

# =========================================================================
# REGIAO: DIAGNOSTICO AVANCADO (somente leitura)
# Ideias aproveitadas do toolkit de suporte, adaptadas para rodar sem
# interacao e sem depender do idioma do Windows.
# =========================================================================

function Get-InfoInventario {
    <# Serial e modelo para inventario/chamado. #>
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $cs   = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $so   = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    [pscustomobject]@{
        NumeroSerie   = if ($bios) { $bios.SerialNumber } else { 'n/d' }
        Fabricante    = if ($bios) { $bios.Manufacturer } else { 'n/d' }
        VersaoBIOS    = if ($bios) { $bios.SMBIOSBIOSVersion } else { 'n/d' }
        DataBIOS      = if ($bios -and $bios.ReleaseDate) { $bios.ReleaseDate.ToString('dd/MM/yyyy') } else { 'n/d' }
        Modelo        = if ($cs) { $cs.Model } else { 'n/d' }
        Dominio       = if ($cs) { $cs.Domain } else { 'n/d' }
        EmDominio     = if ($cs) { $cs.PartOfDomain } else { $false }
        Arquitetura   = if ($so) { $so.OSArchitecture } else { 'n/d' }
        InstaladoEm   = if ($so -and $so.InstallDate) { $so.InstallDate.ToString('dd/MM/yyyy') } else { 'n/d' }
        Processo64bit = [Environment]::Is64BitProcess
    }
}

function Get-DispositivosComErro {
    <#
      Drivers com problema. Filtra os fantasmas conhecidos: portas PS/2 em
      maquina que so tem USB, adaptadores virtuais de RDP/NoMachine e
      dispositivos ROOT\ de software aparecem como 'Error' em praticamente
      todo Windows saudavel e nao significam nada.
    #>
    $fantasmas = @(
        'ACPI\PNP0303',      # Teclado PS/2 legado
        'ACPI\PNP0F03',      # Mouse PS/2 legado
        'ACPI\PNP0F13',
        'ROOT\SYNTH3DVSP',   # Microsoft RemoteFX
        'ROOT\RDPBUS', 'ROOT\UMBUS', 'ROOT\SPACEPORT'
    )
    try {
        Get-PnpDevice -Status Error, Degraded -ErrorAction Stop |
            Where-Object {
                $id = $_.InstanceId
                -not ($fantasmas | Where-Object { $id -like "$_*" })
            } |
            Select-Object @{n='Dispositivo'; e={$_.FriendlyName}}, Status, Class, InstanceId
    } catch { return @() }
}

function Get-TopProcessos {
    param([ValidateSet('CPU', 'Memoria')][string]$Por = 'Memoria', [int]$Top = 8)
    $procs = Get-Process -ErrorAction SilentlyContinue
    if ($Por -eq 'CPU') { $procs = $procs | Sort-Object CPU -Descending }
    else { $procs = $procs | Sort-Object WorkingSet64 -Descending }
    $procs | Select-Object -First $Top @{n='Processo'; e={$_.ProcessName}},
        @{n='RAM'; e={ Format-Tamanho ([long]$_.WorkingSet64) }},
        @{n='CPU(s)'; e={ if ($_.CPU) { [math]::Round($_.CPU, 1) } else { 0 } }}
}

function Get-ErrosRecentes {
    <#
      Erros recentes dos logs. Filtra por Level=2 (numerico) e nao pelo texto
      'Erro'/'Error' - o texto muda com o idioma do Windows e quebraria a
      deteccao em maquina em ingles.
    #>
    param([int]$Horas = 72, [int]$Max = 8)
    $desde = (Get-Date).AddHours(-$Horas)
    $saida = @()
    foreach ($log in @('System', 'Application')) {
        try {
            $saida += Get-WinEvent -FilterHashtable @{ LogName = $log; Level = 2; StartTime = $desde } `
                        -MaxEvents $Max -ErrorAction Stop |
                      Select-Object @{n='Log'; e={$log}},
                        @{n='Quando'; e={$_.TimeCreated.ToString('dd/MM HH:mm')}},
                        Id, @{n='Origem'; e={$_.ProviderName}},
                        @{n='Mensagem'; e={ ($_.Message -split "`n")[0] -replace '\s+', ' ' }}
        } catch { }
    }
    return $saida
}

function Get-FalhasLogon {
    param([int]$Dias = 7, [int]$Max = 5)
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625
                                         StartTime = (Get-Date).AddDays(-$Dias) } `
                     -MaxEvents $Max -ErrorAction Stop |
            Select-Object @{n='Quando'; e={$_.TimeCreated.ToString('dd/MM HH:mm')}},
                          @{n='Conta'; e={ ([regex]::Match($_.Message, '(?im)^\s*(?:Account Name|Nome da Conta):\s*(.+)$')).Groups[1].Value.Trim() }}
    } catch { return @() }
}

function Get-AdminsLocais {
    # Usa o SID do grupo (S-1-5-32-544) porque o nome muda por idioma:
    # 'Administrators' em ingles, 'Administradores' em portugues.
    try {
        $grupo = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
        Get-LocalGroupMember -Group $grupo.Name -ErrorAction Stop |
            Select-Object @{n='Membro'; e={$_.Name}}, ObjectClass, PrincipalSource
    } catch { return @() }
}

function Get-ProgramasInstalados {
    $chaves = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty $chaves -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
        Select-Object @{n='Programa'; e={$_.DisplayName}},
                      @{n='Versao'; e={$_.DisplayVersion}},
                      @{n='Fabricante'; e={$_.Publisher}},
                      @{n='Instalado'; e={$_.InstallDate}} |
        Sort-Object Programa -Unique
}

function Get-ProgramasDesinstalaveis {
    <#
      Lista os programas do jeito que aparecem em "Programas e Recursos" do
      Painel de Controle (appwiz.cpl): exclui componentes de sistema,
      atualizacoes/hotfixes/KBs e entradas sem desinstalador. Traz tambem o
      comando de desinstalacao para poder remover.
    #>
    $chaves = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty $chaves -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -and
            -not $_.SystemComponent -and
            -not $_.ParentKeyName -and
            -not $_.ParentDisplayName -and
            ($_.ReleaseType -notin @('Security Update', 'Update Rollup', 'Hotfix', 'Update')) -and
            ($_.UninstallString -or $_.WindowsInstaller) -and
            ($_.DisplayName -notmatch '^KB\d{6,}')
        } |
        Select-Object @{n='Nome'; e={$_.DisplayName.Trim()}},
                      @{n='Versao'; e={$_.DisplayVersion}},
                      @{n='Fabricante'; e={$_.Publisher}},
                      @{n='Desinstalar'; e={$_.UninstallString}},
                      @{n='QuietUninstall'; e={$_.QuietUninstallString}},
                      @{n='MSI'; e={[bool]$_.WindowsInstaller}},
                      @{n='Codigo'; e={$_.PSChildName}} |
        Sort-Object Nome
}

function Show-DiagnosticoCompleto {
    <# Diagnostico completo, SOMENTE LEITURA (nao altera nada). #>
    Write-Titulo 'DIAGNOSTICO COMPLETO DO PC'

    Write-Etapa 'Sistema e inventario:'
    Get-RelatorioSistema | Format-List | Out-Host
    Get-InfoInventario   | Format-List | Out-Host

    Write-Etapa 'Saude dos discos (SMART):'
    Test-SaudeDiscos | Format-Table -AutoSize | Out-Host

    Write-Etapa 'Horario do sistema:'
    Test-HorarioSistema | Format-List | Out-Host

    Write-Etapa 'Servicos criticos fora de execucao:'
    $svc = @(Test-ServicosCriticos)
    if ($svc.Count) { $svc | Format-Table -AutoSize | Out-Host } else { Write-Ok 'Todos os servicos criticos em execucao.' }

    Write-Etapa 'Dispositivos com erro:'
    $dev = @(Get-DispositivosComErro)
    if ($dev.Count) { $dev | Format-Table -AutoSize | Out-Host } else { Write-Ok 'Nenhum dispositivo com erro.' }

    Write-Etapa 'Proxy manual:'
    Test-ProxyManual | Format-List | Out-Host

    Write-Etapa 'Maiores consumidores de memoria:'
    Get-TopProcessos -Por Memoria -Top 10 | Format-Table -AutoSize | Out-Host

    Write-Etapa 'Impressoras instaladas:'
    $imp = @(Get-StatusImpressoras)
    if ($imp.Count) { $imp | Format-Table -AutoSize | Out-Host } else { Write-Info 'Nenhuma impressora.' }

    Write-Etapa 'Erros recentes nos logs (72h):'
    $ev = @(Get-ErrosRecentes -Horas 72 -Max 8)
    if ($ev.Count) { $ev | Format-Table -AutoSize -Wrap | Out-Host } else { Write-Ok 'Sem erros recentes.' }

    Write-Etapa 'Falhas de logon (7 dias):'
    $fl = @(Get-FalhasLogon -Dias 7 -Max 5)
    if ($fl.Count) { $fl | Format-Table -AutoSize | Out-Host } else { Write-Ok 'Nenhuma falha de logon.' }

    Write-Etapa 'Administradores locais:'
    @(Get-AdminsLocais) | Format-Table -AutoSize | Out-Host

    Write-Etapa 'Ultimas atualizacoes do Windows:'
    @(Get-HistoricoUpdates -Max 8) | Format-Table -AutoSize | Out-Host

    Write-Etapa 'Programas instalados:'
    @(Get-ProgramasInstalados) | Format-Table -AutoSize | Out-Host
}

function Publicar-RelatorioTemp {
    <#
      Chamado APOS Stop-Transcript. Copia a transcricao para um TXT em %TEMP%,
      abre no Bloco de Notas e NAO deixa o .log salvo na pasta de logs (o
      tecnico usa "Salvar Como" se quiser guardar). Com -RemoverPastaLog apaga
      tambem a pasta de logs inteira (usado no diagnostico, que so le).
    #>
    param([switch]$RemoverPastaLog)

    $tmp = $null
    try {
        $origem = Join-Path $script:pastaExec 'manutencao.log'
        $tmp = Join-Path $env:TEMP ('Diagnostico_' + $env:COMPUTERNAME + '_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt')
        if (Test-Path -LiteralPath $origem) {
            Copy-Item -LiteralPath $origem -Destination $tmp -Force -ErrorAction Stop
            Remove-Item -LiteralPath $origem -Force -ErrorAction SilentlyContinue   # nao deixa copia salva
        }
    } catch { }

    Write-Host ''
    if ($tmp -and (Test-Path -LiteralPath $tmp)) {
        Write-Host '  >>> RELATORIO (temporario, nao salvo):' -ForegroundColor Cyan
        Write-Host ("      $tmp") -ForegroundColor White
        Write-Host '      Para guardar: no Bloco de Notas use Arquivo > Salvar Como.' -ForegroundColor DarkGray
        if (-not $NaoAbrirLog -and -not $SemInteracao) {
            # Tenta varios metodos ate abrir; avisa se nenhum funcionar.
            $aberto = $false
            try { Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$tmp`"" -ErrorAction Stop; $aberto = $true } catch { }
            if (-not $aberto) { try { Invoke-Item -LiteralPath $tmp -ErrorAction Stop; $aberto = $true } catch { } }
            if (-not $aberto) { try { Start-Process -FilePath $tmp -ErrorAction Stop; $aberto = $true } catch { } }
            if (-not $aberto) {
                Write-Host '      [!] Nao consegui abrir automaticamente - abra o caminho acima manualmente.' -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host '  [!] Nao foi possivel gerar o relatorio TXT temporario.' -ForegroundColor Yellow
    }

    if ($RemoverPastaLog -and $script:pastaExec -and (Test-Path -LiteralPath $script:pastaExec)) {
        Remove-Item -LiteralPath $script:pastaExec -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-HistoricoUpdates {
    param([int]$Max = 8)
    try {
        $sessao   = New-Object -ComObject Microsoft.Update.Session
        $buscador = $sessao.CreateUpdateSearcher()
        $total    = $buscador.GetTotalHistoryCount()
        if ($total -le 0) { return @() }
        $buscador.QueryHistory(0, [math]::Min($Max, $total)) | ForEach-Object {
            $res = switch ($_.ResultCode) {
                2 { 'Sucesso' } 3 { 'Sucesso c/ erros' } 4 { 'FALHOU' } 5 { 'Cancelado' } default { 'Em andamento' }
            }
            [pscustomobject]@{
                Data      = $_.Date.ToString('dd/MM/yyyy')
                Resultado = $res
                Titulo    = if ($_.Title.Length -gt 70) { $_.Title.Substring(0, 67) + '...' } else { $_.Title }
            }
        }
    } catch { return @() }
}

function Test-ServicosCriticos {
    <#
      Verifica apenas os servicos que costumam derrubar o usuario quando
      param. Listar todos os servicos parados (como faria Get-Service |
      Where Stopped) traria centenas de itens normais e inuteis.
    #>
    $criticos = [ordered]@{
        'Spooler'            = 'Fila de impressao'
        'Audiosrv'           = 'Audio do Windows'
        'AudioEndpointBuilder' = 'Dispositivos de audio'
        'Dhcp'               = 'Cliente DHCP (rede)'
        'Dnscache'           = 'Cache DNS'
        'LanmanWorkstation'  = 'Acesso a pastas de rede'
        'W32Time'            = 'Horario do sistema'
        'wuauserv'           = 'Windows Update'
        'BITS'               = 'Transferencia em segundo plano'
        'WinDefend'          = 'Microsoft Defender'
        'Themes'             = 'Temas / interface'
        'SENS'               = 'Notificacao de eventos'
        'ProfSvc'            = 'Servico de perfis de usuario'
        'SCardSvr'           = 'Smart Card (token de certificado)'
        'CertPropSvc'        = 'Propagacao de certificados'
    }
    $saida = @()
    foreach ($nome in $criticos.Keys) {
        $svc = Get-Service -Name $nome -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        if ($svc.Status -eq 'Running') { continue }

        # StartType 'Manual' parado NAO e problema: no Windows 10 varios
        # servicos (W32Time, wuauserv, CertPropSvc...) sao trigger-start e
        # so sobem quando alguem precisa deles. Alertar sobre isso enche o
        # relatorio de ruido e faz o tecnico ignorar o alerta que importa.
        $gravidade = switch ([string]$svc.StartType) {
            'Automatic' { 'PROBLEMA' }
            'Disabled'  { 'DESATIVADO' }
            default     { 'normal (sob demanda)' }
        }
        $saida += [pscustomobject]@{
            Servico = $nome; Descricao = $criticos[$nome]
            Status = [string]$svc.Status; Inicializacao = [string]$svc.StartType
            Gravidade = $gravidade
        }
    }
    return $saida
}

function Test-ProxyManual {
    <# Proxy manual ativo e causa classica de "a internet parou". #>
    $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    if ($p -and $p.ProxyEnable -eq 1) {
        return [pscustomobject]@{ Ativo = $true; Servidor = $p.ProxyServer; Excecoes = $p.ProxyOverride }
    }
    return [pscustomobject]@{ Ativo = $false; Servidor = ''; Excecoes = '' }
}

function Test-HorarioSistema {
    <#
      Relogio fora do ar quebra assinatura digital, PJe, HTTPS e login de
      dominio. Vale um alerta destacado no relatorio.
    #>
    $info = [ordered]@{
        Local        = (Get-Date).ToString('dd/MM/yyyy HH:mm:ss')
        FusoHorario  = (Get-TimeZone -ErrorAction SilentlyContinue).DisplayName
        ServicoW32   = (Get-Service W32Time -ErrorAction SilentlyContinue).Status
        DesvioNTP    = 'nao medido'
    }
    try {
        $saida = & w32tm.exe /stripchart /computer:pool.ntp.br /samples:2 /dataonly 2>$null
        $m = [regex]::Matches(($saida -join ' '), '([+-]?\d+[.,]\d+)s')
        if ($m.Count -gt 0) {
            $valores = $m | ForEach-Object { [double]($_.Groups[1].Value -replace ',', '.') }
            $info['DesvioNTP'] = ('{0:N2}s' -f ($valores | Measure-Object -Average).Average)
            $info['DesvioSegundos'] = [math]::Abs(($valores | Measure-Object -Average).Average)
        }
    } catch { }
    return [pscustomobject]$info
}

# =========================================================================
# REGIAO: REPAROS RAPIDOS (opt-in)
# =========================================================================

function Sync-HorarioSistema {
    if ($SomenteRelatorio) { Write-Simul 'Sincronizaria o relogio via NTP.'; return }
    try {
        $svc = Get-Service W32Time -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') {
            Set-Service W32Time -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service W32Time -ErrorAction SilentlyContinue
        }
        $r = & w32tm.exe /resync /force 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Ok 'Horario sincronizado via NTP.' }
        else {
            # Fallback: re-registra o servico e tenta de novo
            & w32tm.exe /register 2>$null | Out-Null
            Start-Service W32Time -ErrorAction SilentlyContinue
            & w32tm.exe /resync /force 2>$null | Out-Null
            Write-Ok 'Horario sincronizado apos re-registro do w32time.'
        }
    } catch { Write-Aviso "Nao foi possivel sincronizar o horario: $($_.Exception.Message)" }
}

function Repair-Spooler {
    <# Fila de impressao travada: para o servico, limpa a fila, religa. #>
    if ($SomenteRelatorio) {
        $n = @(Get-ChildItem "$env:SystemRoot\System32\spool\PRINTERS" -File -ErrorAction SilentlyContinue).Count
        Write-Simul "Limparia a fila de impressao ($n arquivo(s) presos)."
        return [long]0
    }
    $liberado = [long]0
    try {
        $svc = Get-Service -Name Spooler -ErrorAction Stop
        Write-Etapa 'Parando o spooler de impressao...'
        Stop-Service -Name Spooler -Force -ErrorAction Stop

        $fila = "$env:SystemRoot\System32\spool\PRINTERS"
        $itens = @(Get-ChildItem -LiteralPath $fila -File -Force -ErrorAction SilentlyContinue)
        foreach ($i in $itens) {
            try { $t = $i.Length; Remove-Item -LiteralPath $i.FullName -Force -ErrorAction Stop; $liberado += $t } catch { }
        }
        Write-Ok "Fila limpa: $($itens.Count) trabalho(s) removido(s)."
    } catch {
        Write-Falha "Erro no spooler: $($_.Exception.Message)"
    } finally {
        Start-Service -Name Spooler -ErrorAction SilentlyContinue
        $st = (Get-Service -Name Spooler -ErrorAction SilentlyContinue).Status
        if ($st -eq 'Running') { Write-Ok 'Spooler reiniciado.' } else { Write-Falha "Spooler ficou em estado: $st" }
    }
    return [long]$liberado
}

function Get-StatusImpressoras {
    try {
        Get-Printer -ErrorAction Stop | Select-Object Name, DriverName, PortName,
            @{n='Status'; e={$_.PrinterStatus}}, @{n='Padrao'; e={ $_.Name -eq (Get-CimInstance Win32_Printer -Filter 'Default=TRUE' -EA SilentlyContinue).Name }}
    } catch { return @() }
}

function Restart-Explorer {
    <# Util logo apos limpar miniaturas: forca a reconstrucao do cache. #>
    if ($SomenteRelatorio) { Write-Simul 'Reiniciaria o Explorer.'; return }
    try {
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        if (-not (Get-Process explorer -ErrorAction SilentlyContinue)) {
            Start-Process explorer.exe
            Start-Sleep -Seconds 1
        }
        Write-Ok 'Explorer reiniciado (icones e miniaturas serao recriados).'
    } catch { Write-Aviso "Nao foi possivel reiniciar o Explorer: $($_.Exception.Message)" }
}

function Reset-ProxyManual {
    $proxy = Test-ProxyManual
    if (-not $proxy.Ativo) { Write-Ok 'Nenhum proxy manual configurado.'; return }
    Write-Aviso "Proxy manual ativo: $($proxy.Servidor)"
    if ($SomenteRelatorio) { Write-Simul 'Desativaria o proxy manual.'; return }
    try {
        $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        Set-ItemProperty -Path $k -Name ProxyEnable -Value 0 -Type DWord -ErrorAction Stop
        Write-Ok 'Proxy manual desativado.'
    } catch { Write-Falha "Falha ao desativar proxy: $($_.Exception.Message)" }
}

function Request-Chkdsk {
    <#
      Nao roda chkdsk /f interativo (ele pergunta S/N e travaria o script).
      Marca o volume como sujo, o que agenda a verificacao no proximo boot.
    #>
    param([string]$Letra = 'C')
    if ($SomenteRelatorio) { Write-Simul "Agendaria verificacao de disco em ${Letra}:"; return }
    try {
        $sujo = (& fsutil.exe dirty query "${Letra}:") -join ' '
        Write-Info $sujo
        & chkdsk.exe "${Letra}:" /f /r /x 2>&1 | Out-Null
        & fsutil.exe dirty set "${Letra}:" | Out-Null
        Write-Ok "Verificacao de ${Letra}: agendada para a proxima reinicializacao."
        $script:precisaReiniciar = $true
    } catch { Write-Aviso "Nao foi possivel agendar chkdsk: $($_.Exception.Message)" }
}

function Repair-AppXPackages {
    if ($SomenteRelatorio) { Write-Simul 'Re-registraria os apps da Microsoft Store.'; return }
    Write-Aviso 'Re-registrando apps da Store - pode levar varios minutos.'
    $ok = 0; $erro = 0
    Get-AppXPackage -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
        $manifesto = Join-Path $_.InstallLocation 'AppXManifest.xml'
        if (Test-Path -LiteralPath $manifesto) {
            try { Add-AppxPackage -DisableDevelopmentMode -Register $manifesto -ErrorAction Stop; $ok++ }
            catch { $erro++ }
        }
    }
    Write-Ok "Apps re-registrados: $ok  |  falhas: $erro"
}

function Invoke-GPUpdate {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if (-not $cs -or -not $cs.PartOfDomain) { Write-Info 'Maquina fora de dominio - gpupdate dispensado.'; return }
    if ($SomenteRelatorio) { Write-Simul 'Executaria gpupdate /force.'; return }
    try { & gpupdate.exe /force 2>&1 | Out-Null; Write-Ok 'Politicas de grupo atualizadas.' }
    catch { Write-Aviso "gpupdate falhou: $($_.Exception.Message)" }
}

function Update-EnderecoIP {
    if ($SomenteRelatorio) { Write-Simul 'Renovaria o endereco IP (DHCP).'; return }
    try {
        & ipconfig.exe /release | Out-Null
        & ipconfig.exe /renew   | Out-Null
        Write-Ok 'Endereco IP renovado via DHCP.'
    } catch { Write-Aviso "Falha ao renovar IP: $($_.Exception.Message)" }
}

function Restart-AnyDesk {
    $proc = Get-Process -Name AnyDesk -ErrorAction SilentlyContinue
    if ($SomenteRelatorio) { Write-Simul 'Reiniciaria o AnyDesk.'; return }
    try {
        if ($proc) { $proc | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2 }
        foreach ($p in @("$env:ProgramFiles\AnyDesk\AnyDesk.exe",
                         "${env:ProgramFiles(x86)}\AnyDesk\AnyDesk.exe",
                         "$env:ProgramData\AnyDesk\AnyDesk.exe")) {
            if (Test-Path -LiteralPath $p) { Start-Process $p; Write-Ok 'AnyDesk reiniciado.'; return }
        }
        Write-Aviso 'Executavel do AnyDesk nao localizado.'
    } catch { Write-Aviso "Falha ao reiniciar AnyDesk: $($_.Exception.Message)" }
}

# =========================================================================
# REGIAO: ANTIVIRUS E FIREWALL (desativar / reativar)
#
# AVISO DE SEGURANCA: desativar a protecao deixa a maquina exposta. Use so
# em rede confiavel, pelo tempo minimo necessario (ex.: instalar um software
# que o AV bloqueia por engano), e REATIVE em seguida.
#
# LIMITACOES REAIS - o que um script NAO consegue burlar:
#  - Tamper Protection (Windows 10 1903+): bloqueia desativar o Defender por
#    script/registro. So desliga na interface: Seguranca do Windows >
#    Protecao contra virus e ameacas > Gerenciar configuracoes >
#    Protecao contra adulteracao. Depois disso o script desativa o resto.
#  - Autoprotecao de AV de terceiros (Avast, Bitdefender, Kaspersky, ESET...):
#    impede parar o servico externamente; normalmente exige senha na propria
#    interface do antivirus. O script tenta e relata o que nao conseguiu.
# =========================================================================

function Get-EstadoProtecao {
    $def = $null
    try { $def = Get-MpComputerStatus -ErrorAction Stop } catch { }

    $fw = @{}
    try {
        Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { $fw[$_.Name] = [bool]$_.Enabled }
    } catch { }

    $terceiros = @()
    try {
        # SecurityCenter2 lista todos os AV registrados (inclui o Defender)
        $terceiros = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
            ForEach-Object {
                # productState em hex: byte do meio indica se esta ativo (1x)
                $estado = '{0:x6}' -f $_.productState
                [pscustomobject]@{
                    Nome    = $_.displayName
                    Ativo   = ($estado.Substring(2, 2) -match '^1')
                    Caminho = $_.pathToSignedProductExe
                    EhDefender = ($_.displayName -match 'Defender')
                }
            })
    } catch { }

    [pscustomobject]@{
        DefenderPresente     = [bool]$def
        TamperProtection     = if ($def) { [bool]$def.IsTamperProtected } else { $null }
        RealtimeAtivo        = if ($def) { [bool]$def.RealTimeProtectionEnabled } else { $null }
        AntivirusAtivo       = if ($def) { [bool]$def.AntivirusEnabled } else { $null }
        FirewallPerfis       = $fw
        AntivirusRegistrados = $terceiros
        AVterceirosAtivos    = @($terceiros | Where-Object { -not $_.EhDefender -and $_.Ativo })
    }
}

function Backup-EstadoProtecao {
    param([string]$Destino)
    try {
        $estado = Get-EstadoProtecao
        $arq = Join-Path $Destino 'estado-protecao.json'
        $estado | ConvertTo-Json -Depth 5 | Set-Content -Path $arq -Encoding UTF8
        Write-Info "Estado da protecao salvo em: $arq"
    } catch { Write-Aviso "Nao foi possivel salvar o estado da protecao: $($_.Exception.Message)" }
}

function Disable-FirewallCompleto {
    if ($SomenteRelatorio) { Write-Simul 'Desativaria o firewall nos 3 perfis.'; return }
    try {
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False -ErrorAction Stop
        Write-Ok 'Firewall DESATIVADO (Domain, Public, Private).'
        Add-Alerta 'FIREWALL DESATIVADO - reative com -ReativarFirewall assim que possivel.'
    } catch { Write-Falha "Falha ao desativar firewall: $($_.Exception.Message)" }
}

function Enable-FirewallCompleto {
    if ($SomenteRelatorio) { Write-Simul 'Reativaria o firewall nos 3 perfis.'; return }
    try {
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -ErrorAction Stop
        Write-Ok 'Firewall REATIVADO (Domain, Public, Private).'
    } catch { Write-Falha "Falha ao reativar firewall: $($_.Exception.Message)" }
}

function Set-SmartScreenReputacao {
    <#
      Liga/desliga o "Controle de aplicativo e do navegador" / "Protecao
      baseada em reputacao" (SmartScreen do Windows, do Edge e das apps da
      Store, alem do bloqueio de apps potencialmente indesejados no Edge).
      Sao politicas de REGISTRO - NAO sao bloqueadas pela Tamper Protection.
    #>
    param([bool]$Ativo)
    $ok = $true
    $sys  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    $edge = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    $exp  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
    $ah   = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost'
    try {
        if ($Ativo) {
            # Reativar: REMOVE as politicas (volta ao padrao ligado, sem deixar
            # a UI "gerenciada pela organizacao") e religa as config. diretas.
            Remove-ItemProperty -Path $sys  -Name 'EnableSmartScreen'     -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $sys  -Name 'ShellSmartScreenLevel' -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $edge -Name 'SmartScreenEnabled'    -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $edge -Name 'SmartScreenPuaEnabled' -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $exp -Name 'SmartScreenEnabled' -Value 'Warn' -Type String -ErrorAction SilentlyContinue
            if (-not (Test-Path $ah)) { New-Item -Path $ah -Force | Out-Null }
            Set-ItemProperty -Path $ah -Name 'EnableWebContentEvaluation' -Value 1 -Type DWord -ErrorAction SilentlyContinue
        } else {
            # Desativar tudo (SmartScreen Windows/Explorer/Edge/Store + PUA Edge)
            foreach ($k in @($sys, $edge, $ah)) { if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null } }
            Set-ItemProperty -Path $sys  -Name 'EnableSmartScreen'          -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $exp  -Name 'SmartScreenEnabled'         -Value 'Off' -Type String -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $edge -Name 'SmartScreenEnabled'         -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $edge -Name 'SmartScreenPuaEnabled'      -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $ah   -Name 'EnableWebContentEvaluation' -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }
    } catch { $ok = $false }
    return $ok
}

function Open-TokenAdmin {
    <#
      Abre o app de administracao de token de certificado digital. Como o
      programa varia por fabricante, tenta caminhos conhecidos e, se nao achar,
      procura um atalho no Menu Iniciar por palavra-chave. Cobre:
        1) GD Burti / StarSign  -> Token Administration (Giesecke & Devrient)
        2) SafeNet / eToken 5110 -> SafeNet Authentication Client (Thales/Gemalto)
        3) Feitian ePass2003     -> ePass2003 PKI Client (EnterSafe)
        4) Aladdin / eToken PRO  -> SafeNet Auth. Client / eToken Properties
        5) Athena / IDProtect    -> IDProtect Client (Athena Smartcard)
      Retorna $true se abriu algo.
    #>
    $pf   = $env:ProgramFiles
    $pf86 = ${env:ProgramFiles(x86)}
    $cands = @(
        # 2/4 - SafeNet Authentication Client (eToken 5110, Aladdin eToken PRO)
        "$pf\SafeNet\Authentication\SAC\x64\SACTools.exe"
        "$pf\SafeNet\Authentication\SAC\x32\SACTools.exe"
        "$pf86\SafeNet\Authentication\SAC\x64\SACTools.exe"
        "$pf86\SafeNet\Authentication\SAC\x32\SACTools.exe"
        "$pf\Gemalto\SafeNet Authentication Client\Tools\SACTools.exe"
        "$pf86\Gemalto\SafeNet Authentication Client\Tools\SACTools.exe"
        # 4 - eToken Properties (Aladdin legado)
        "$pf\Aladdin\eToken\PKIClient\x32\eTProps.exe"
        "$pf86\Aladdin\eToken\PKIClient\x32\eTProps.exe"
        # 1 - GD Burti / StarSign (Giesecke & Devrient) - Token Administration
        "$pf\Giesecke & Devrient\StarSign Token Administration\TokenAdmin.exe"
        "$pf86\Giesecke & Devrient\StarSign Token Administration\TokenAdmin.exe"
        "$pf\Giesecke Devrient\StarSign Crypto USB Token\TokenAdmin.exe"
        "$pf86\Giesecke Devrient\StarSign Crypto USB Token\TokenAdmin.exe"
        # 3 - Feitian ePass2003 / EnterSafe PKI
        "$pf\EnterSafe\ePass2003\ePass2003Token.exe"
        "$pf86\EnterSafe\ePass2003\ePass2003Token.exe"
        "$pf86\Feitian\ePass2003\ePass2003Token.exe"
        # 5 - Athena IDProtect Client
        "$pf\Athena\IDProtect Client\IDProtectClient.exe"
        "$pf86\Athena Smartcard Solutions\IDProtect Client\IDProtectClient.exe"
        "$pf86\Athena\IDProtect Client\IDProtectClient.exe"
    )
    foreach ($c in $cands) {
        if ($c -and (Test-Path -LiteralPath $c)) { Start-Process $c -ErrorAction SilentlyContinue; return $true }
    }
    # Procura atalho no Menu Iniciar (rapido - pastas pequenas). Cobre os 5
    # modelos pelo nome do programa/pasta.
    $chave = 'token|safenet|etoken|aladdin|gemalto|thales|starsign|giesecke|devrient|feitian|epass|entersafe|idprotect|athena|autenticac|certificad'
    $menus = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
               "$env:APPDATA\Microsoft\Windows\Start Menu\Programs")
    foreach ($m in $menus) {
        if (-not (Test-Path -LiteralPath $m)) { continue }
        $lnk = Get-ChildItem -LiteralPath $m -Recurse -Filter '*.lnk' -ErrorAction SilentlyContinue |
               Where-Object { $_.FullName -match $chave } |
               Select-Object -First 1
        if ($lnk) { Start-Process $lnk.FullName -ErrorAction SilentlyContinue; return $true }
    }
    return $false
}

function Disable-DefenderCompleto {
    $st = Get-EstadoProtecao

    if ($SomenteRelatorio) {
        Write-Simul 'Desativaria: SmartScreen (app/navegador/reputacao), PUA, acesso controlado a pastas'
        Write-Simul 'e as configuracoes de protecao contra virus/ameacas do Defender.'
        return
    }

    # 1) Controle de aplicativo e do navegador + Protecao baseada em reputacao
    #    (SmartScreen). Politicas de registro - funcionam mesmo com Tamper ON.
    if (Set-SmartScreenReputacao -Ativo:$false) {
        Write-Ok 'Controle de aplicativo/navegador + protecao por reputacao (SmartScreen) desativados.'
    } else {
        Write-Aviso 'Nao foi possivel desativar todo o SmartScreen.'
    }

    if (-not $st.DefenderPresente) { Write-Info 'Windows Defender nao esta presente/ativo nesta maquina.'; return }

    # 2) Configuracoes de protecao contra virus e ameacas (nucleo do Defender).
    #    Estas SIM sao bloqueadas pela Tamper Protection.
    if ($st.TamperProtection) {
        Write-Host ''
        Write-Host '  ##############################################################' -ForegroundColor Red
        Write-Host '  #  PROTECAO CONTRA ADULTERACAO (TAMPER PROTECTION) LIGADA     #' -ForegroundColor Red
        Write-Host '  ##############################################################' -ForegroundColor Red
        Write-Host '  O ANTIVIRUS (Protecao contra virus e ameacas) NAO pode ser' -ForegroundColor Yellow
        Write-Host '  desativado por script enquanto isso estiver LIGADO. E uma trava' -ForegroundColor Yellow
        Write-Host '  da Microsoft contra malware - NENHUM programa consegue burlar.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host '  PASSO A PASSO (manual, so uma vez):' -ForegroundColor White
        Write-Host '   1) Vou abrir a tela de Seguranca do Windows agora.' -ForegroundColor Gray
        Write-Host '   2) Em "Configuracoes de protecao contra virus e ameacas",' -ForegroundColor Gray
        Write-Host '      clique em "Gerenciar configuracoes".' -ForegroundColor Gray
        Write-Host '   3) Desligue "Protecao contra adulteracao".' -ForegroundColor Gray
        Write-Host '   4) Rode a opcao 18 novamente.' -ForegroundColor Gray
        Write-Host ''
        if (-not $SemInteracao) {
            try { Start-Process 'windowsdefender://threatsettings' -ErrorAction Stop }
            catch { try { Start-Process 'windowsdefender:' -ErrorAction SilentlyContinue } catch { } }
        }
        Add-Alerta 'ANTIVIRUS NAO desativado: Tamper Protection ligada (desligue na tela que abriu e rode a opcao 18 de novo).'
        Add-Alerta 'Firewall e SmartScreen JA foram desativados - reative com -ReativarTudo (opcao 19) ao terminar.'
        return
    }

    $prefs = [ordered]@{
        DisableRealtimeMonitoring     = $true
        DisableBehaviorMonitoring     = $true
        DisableBlockAtFirstSeen       = $true
        DisableIOAVProtection         = $true
        DisableScriptScanning         = $true
        DisableArchiveScanning        = $true
        DisableEmailScanning          = $true
        DisableRemovableDriveScanning = $true
    }
    $ok = 0; $falhou = 0
    foreach ($p in $prefs.Keys) {
        try { Set-MpPreference -$p $prefs[$p] -ErrorAction Stop; $ok++ } catch { $falhou++ }
    }
    try { Set-MpPreference -MAPSReporting Disabled -ErrorAction SilentlyContinue } catch { }          # Protecao via nuvem
    try { Set-MpPreference -SubmitSamplesConsent NeverSend -ErrorAction SilentlyContinue } catch { }  # Envio de amostras
    try { Set-MpPreference -PUAProtection Disabled -ErrorAction SilentlyContinue } catch { }          # Apps potencialmente indesejados
    try { Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue } catch { } # Acesso controlado a pastas
    try { Set-MpPreference -EnableNetworkProtection Disabled -ErrorAction SilentlyContinue } catch { }      # Protecao de rede

    # Reforco via politica (persiste apos reboot enquanto TP estiver desligada)
    try {
        $k1 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        $k2 = "$k1\Real-Time Protection"
        foreach ($k in @($k1, $k2)) { if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null } }
        Set-ItemProperty -Path $k1 -Name 'DisableAntiSpyware' -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $k1 -Name 'PUAProtection' -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $k2 -Name 'DisableRealtimeMonitoring' -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $k2 -Name 'DisableBehaviorMonitoring' -Value 1 -Type DWord -ErrorAction SilentlyContinue
    } catch { }

    $depois = Get-EstadoProtecao
    if ($depois.RealtimeAtivo) {
        Write-Aviso "Protecao em tempo real ainda ativa ($ok pref. aplicadas, $falhou falharam)."
        Write-Info  'O Windows pode reativar sozinho apos alguns minutos ou no reboot.'
    } else {
        Write-Ok "Configuracoes de virus/ameacas desativadas ($ok aplicadas): tempo real, nuvem, amostras, PUA, acesso a pastas."
    }
    Add-Alerta 'DEFENDER + SmartScreen DESATIVADOS - reative com -ReativarTudo assim que possivel.'
}

function Enable-DefenderCompleto {
    if ($SomenteRelatorio) { Write-Simul 'Reativaria Defender, SmartScreen, PUA e restauraria os padroes.'; return }

    # 1) Reativa Controle de aplicativo/navegador + Protecao por reputacao
    if (Set-SmartScreenReputacao -Ativo:$true) { Write-Ok 'Controle de aplicativo/navegador + reputacao (SmartScreen) reativados.' }

    # 2) Remove as politicas que forcavam a desativacao do Defender
    try {
        $k1 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        $k2 = "$k1\Real-Time Protection"
        foreach ($n in @('DisableAntiSpyware', 'PUAProtection')) { Remove-ItemProperty -Path $k1 -Name $n -ErrorAction SilentlyContinue }
        foreach ($n in @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring')) {
            Remove-ItemProperty -Path $k2 -Name $n -ErrorAction SilentlyContinue
        }
    } catch { }

    $prefs = @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableBlockAtFirstSeen',
               'DisableIOAVProtection', 'DisableScriptScanning', 'DisableArchiveScanning',
               'DisableEmailScanning', 'DisableRemovableDriveScanning')
    foreach ($p in $prefs) { try { Set-MpPreference -$p $false -ErrorAction SilentlyContinue } catch { } }
    try { Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue } catch { }          # Protecao via nuvem
    try { Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue } catch { } # Envio de amostras
    try { Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue } catch { }            # PUA (padrao: ligado)
    # Acesso controlado a pastas volta ao padrao do Windows (desligado).
    try { Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue } catch { }

    try {
        $svc = Get-Service WinDefend -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') { Start-Service WinDefend -ErrorAction SilentlyContinue }
    } catch { }
    try { Update-MpSignature -ErrorAction SilentlyContinue } catch { }

    $st = Get-EstadoProtecao
    if ($st.RealtimeAtivo) { Write-Ok 'Defender + SmartScreen REATIVADOS e assinaturas atualizadas.' }
    else { Write-Aviso 'Comandos enviados, mas a protecao em tempo real ainda consta inativa. Reinicie e confira.' }
}

function Disable-AntivirusTerceiros {
    <#
      Melhor esforco para AV de terceiros. A autoprotecao da maioria bloqueia
      parar o servico externamente - o script tenta e relata o que resistiu.
    #>
    $st = Get-EstadoProtecao
    $avs = @($st.AntivirusRegistrados | Where-Object { -not $_.EhDefender })
    if ($avs.Count -eq 0) { Write-Info 'Nenhum antivirus de terceiros instalado.'; return }

    Write-Etapa "Antivirus de terceiros detectado(s): $($avs.Nome -join ', ')"

    # Servicos e processos por fabricante conhecido
    $padroes = @(
        'avast', 'avg', 'aswbIDSAgent', 'bdservicehost', 'vsserv', 'bitdefender',
        'avp', 'kavfs', 'klnagent', 'kaspersky', 'ekrn', 'egui', 'eset',
        'mfe', 'macmnsvc', 'masvc', 'mcshield', 'mfemms', 'McAfee',
        'nortonsecurity', 'nsservice', 'ns', 'symantec', 'ccSvcHst', 'SepMasterService',
        'sophos', 'savservice', 'swi_service', 'webroot', 'wrsa',
        'msmpsvc', 'panda', 'psanhost', 'trendmicro', 'tmlisten', 'ntrtscan',
        'avira', 'avguard', 'sched', 'CylanceSvc', 'SentinelAgent', 'CSFalconService'
    )

    if ($SomenteRelatorio) {
        Write-Simul 'Tentaria parar servicos e processos dos antivirus de terceiros.'
        return
    }

    $parados = 0; $resistiram = 0
    foreach ($p in $padroes) {
        foreach ($svc in @(Get-Service -Name "*$p*" -ErrorAction SilentlyContinue)) {
            if ($svc.Status -eq 'Running') {
                try {
                    Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
                    Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                    Write-Ok "Servico parado: $($svc.Name)"
                    $parados++
                } catch {
                    Write-Aviso "Autoprotecao bloqueou: $($svc.Name)"
                    $resistiram++
                }
            } else {
                try { Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue } catch { }
            }
        }
        foreach ($proc in @(Get-Process -Name "*$p*" -ErrorAction SilentlyContinue)) {
            try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop } catch { $resistiram++ }
        }
    }

    Write-Ok "AV de terceiros: $parados servico(s) parado(s), $resistiram bloqueado(s) pela autoprotecao."
    if ($resistiram -gt 0) {
        Write-Aviso 'A autoprotecao impede a desativacao por script. Desative pela interface do antivirus.'
        Write-Info  'Normalmente: clique-direito no icone da bandeja > Desativar / Pausar protecao.'
    }
    Add-Alerta 'Tentativa de desativar AV de terceiros - CONFIRME na interface e reative depois.'
}

function Enable-AntivirusTerceiros {
    $st = Get-EstadoProtecao
    $avs = @($st.AntivirusRegistrados | Where-Object { -not $_.EhDefender })
    if ($avs.Count -eq 0) { Write-Info 'Nenhum antivirus de terceiros instalado.'; return }
    if ($SomenteRelatorio) { Write-Simul 'Reativaria os servicos dos antivirus de terceiros.'; return }

    $padroes = @('avast', 'avg', 'aswbIDSAgent', 'bdservicehost', 'vsserv', 'avp', 'kavfs',
                 'ekrn', 'mfemms', 'masvc', 'nsservice', 'SepMasterService', 'savservice',
                 'swi_service', 'wrsa', 'tmlisten', 'ntrtscan', 'avguard', 'sched',
                 'CylanceSvc', 'SentinelAgent', 'CSFalconService')
    $religados = 0
    foreach ($p in $padroes) {
        foreach ($svc in @(Get-Service -Name "*$p*" -ErrorAction SilentlyContinue)) {
            try {
                Set-Service -Name $svc.Name -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service -Name $svc.Name -ErrorAction SilentlyContinue
                $religados++
            } catch { }
        }
    }
    Write-Ok "AV de terceiros: $religados servico(s) religado(s)."
    Write-Info 'Reinicie a maquina para garantir a reativacao completa; confirme o icone na bandeja.'
}

function Invoke-GerenciarProtecao {
    <#
      Orquestra desativar/reativar com backup e confirmacao. Roda em modo
      standalone: NAO executa a manutencao de 16 etapas.
    #>
    $vaiDesativar = $DesativarDefender -or $DesativarFirewall
    $vaiReativar  = $ReativarDefender  -or $ReativarFirewall

    Write-Titulo 'ANTIVIRUS E FIREWALL'

    $estado = Get-EstadoProtecao
    Write-Etapa 'Estado atual da protecao:'
    Write-Info  ("Defender presente : {0}" -f $estado.DefenderPresente)
    Write-Info  ("  Tempo real ativo: {0}" -f $estado.RealtimeAtivo)
    Write-Info  ("  Tamper Protection: {0}" -f $estado.TamperProtection)
    foreach ($perfil in $estado.FirewallPerfis.Keys) {
        Write-Info ("Firewall {0,-8}: {1}" -f $perfil, $(if ($estado.FirewallPerfis[$perfil]) { 'ON' } else { 'OFF' }))
    }
    if ($estado.AntivirusRegistrados.Count -gt 0) {
        Write-Info ("Antivirus registrados: {0}" -f (($estado.AntivirusRegistrados | ForEach-Object { $_.Nome }) -join ', '))
    }
    Write-Host ''

    # Backup do estado antes de qualquer mudanca
    Backup-EstadoProtecao -Destino $script:pastaExec

    # Confirmacao para desativar (acao que reduz seguranca)
    if ($vaiDesativar -and -not $SomenteRelatorio) {
        Write-Falha 'ATENCAO: desativar a protecao expoe a maquina a virus e ataques de rede.'
        if ($SemInteracao) {
            if (-not $ConfirmarProtecao) {
                Write-Falha 'Modo desatendido: use -ConfirmarProtecao para autorizar a desativacao. Cancelado.'
                return
            }
        } else {
            $r = (Read-Host '  Desativar a protecao agora? (S/N)').Trim()
            if ($r -notmatch '^[SsYy]') { Write-Aviso 'Cancelado pelo operador.'; return }
        }
    }

    if ($DesativarFirewall) { Disable-FirewallCompleto }
    if ($DesativarDefender) {
        Disable-DefenderCompleto
        Disable-AntivirusTerceiros
    }
    if ($ReativarFirewall)  { Enable-FirewallCompleto }
    if ($ReativarDefender)  {
        Enable-DefenderCompleto
        Enable-AntivirusTerceiros
    }

    Write-Host ''
    Write-Etapa 'Estado apos a operacao:'
    $depois = Get-EstadoProtecao
    Write-Info ("Defender tempo real: {0}" -f $depois.RealtimeAtivo)
    foreach ($perfil in $depois.FirewallPerfis.Keys) {
        Write-Info ("Firewall {0,-8}: {1}" -f $perfil, $(if ($depois.FirewallPerfis[$perfil]) { 'ON' } else { 'OFF' }))
    }
}

# =========================================================================
# REGIAO: SCANNER DE MALWARE (ClamAV portatil)
#
# Ferramenta de segunda opiniao para uso em atendimento remoto (AnyDesk):
# baixa a engine ClamAV portatil e as assinaturas na hora, escaneia um
# arquivo ou uma pasta inteira, gera log com SHA256 e pode se auto-remover
# sem deixar rastro na maquina do cliente.
#
# Nao substitui o antivirus residente - e um verificador sob demanda, util
# para conferir um instalador baixado, uma pasta suspeita ou um pendrive.
#
# DICA DE FLUXO (AnyDesk): baixe uma vez o zip portatil do ClamAV
#   (clamav-x.y.z.win.x64.zip em https://www.clamav.net/downloads) e carregue
#   junto; aponte -ClamAVZip para ele. Evita baixar ~150 MB em cada cliente.
# =========================================================================

function Resolve-PastaClamAV {
    <#
      Define onde o ClamAV portatil vai morar. Prioridade:
        1. -ClamAVCache : pasta fixa (pendrive/rede) - reaproveitada e NUNCA
                          removida automaticamente
        2. -ClamAVDir   : pasta temporaria escolhida
        3. padrao       : subpasta ao lado do log (facil de achar/remover)
    #>
    if ($ClamAVCache) { return $ClamAVCache }
    if ($ClamAVDir)   { return $ClamAVDir }
    return (Join-Path $script:pastaExec 'clamav')
}

function Get-ClamAVPortable {
    <#
      Garante clamscan.exe disponivel. Ordem de preferencia:
        1. Ja existe em -ClamAVDir            -> usa
        2. -ClamAVZip apontado                -> extrai
        3. Baixa de -ClamAVUrl                -> extrai
      Retorna o caminho da pasta com os .exe, ou $null se falhar.
      $script:clamBaixado indica se foi baixado (para a limpeza no fim).
    #>
    $destino = Resolve-PastaClamAV
    $script:clamBaixado = $false

    # 1. Binario ja presente?
    $exe = Get-ChildItem -Path $destino -Filter 'clamscan.exe' -Recurse -ErrorAction SilentlyContinue |
           Select-Object -First 1
    if ($exe) { Write-Ok "ClamAV encontrado: $($exe.DirectoryName)"; return $exe.DirectoryName }

    New-Item -ItemType Directory -Path $destino -Force -ErrorAction SilentlyContinue | Out-Null
    $zipLocal = Join-Path $destino 'clamav-portable.zip'

    # 2. Zip fornecido?
    if ($ClamAVZip -and (Test-Path -LiteralPath $ClamAVZip)) {
        Write-Etapa "Usando ClamAV do zip fornecido: $ClamAVZip"
        Copy-Item -LiteralPath $ClamAVZip -Destination $zipLocal -Force -ErrorAction SilentlyContinue
    } else {
        # 3. Download
        if ($SomenteRelatorio) { Write-Simul 'Baixaria o ClamAV portatil (~220 MB).'; return $null }

        $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Resolve a URL: usa -ClamAVUrl se dado; senao pega a ultima release
        # oficial no GitHub do Cisco-Talos (mais confiavel que clamav.net,
        # que bloqueia download automatizado com 403).
        $url = $ClamAVUrl
        if ([string]::IsNullOrWhiteSpace($url)) {
            try {
                Write-Etapa 'Descobrindo a versao mais recente do ClamAV (GitHub)...'
                $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/Cisco-Talos/clamav/releases/latest' `
                        -UserAgent $ua -TimeoutSec 30 -ErrorAction Stop
                $asset = $rel.assets | Where-Object { $_.name -like '*win.x64.zip' } | Select-Object -First 1
                if ($asset) { $url = $asset.browser_download_url; Write-Ok "Versao: $($rel.tag_name)" }
            } catch { Write-Aviso "Nao foi possivel consultar o GitHub: $($_.Exception.Message)" }
        }
        if ([string]::IsNullOrWhiteSpace($url)) {
            Write-Falha 'Sem URL para baixar o ClamAV.'
            Write-Info  'Alternativa: baixe o zip manualmente e use -ClamAVZip <caminho>.'
            return $null
        }

        Write-Etapa "Baixando ClamAV portatil (~220 MB)... pode levar alguns minutos."
        try {
            $antigo = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $url -OutFile $zipLocal -UserAgent $ua -UseBasicParsing -ErrorAction Stop
            $ProgressPreference = $antigo
            $script:clamBaixado = $true
            Write-Ok 'Download concluido.'
        } catch {
            Write-Falha "Falha ao baixar o ClamAV: $($_.Exception.Message)"
            Write-Info  'Alternativa: baixe o zip manualmente e use -ClamAVZip <caminho>.'
            return $null
        }
    }

    # Extrai
    try {
        Write-Etapa 'Extraindo ClamAV...'
        Expand-Archive -Path $zipLocal -DestinationPath $destino -Force -ErrorAction Stop
        Remove-Item -LiteralPath $zipLocal -Force -ErrorAction SilentlyContinue

        # Remove arquivos de depuracao/dev que nao sao usados para escanear
        # (~850 MB). Deixa o cache enxuto - importante em pendrive/rede.
        $lixo = @(Get-ChildItem -Path $destino -Include '*.pdb', '*.lib', '*.exp' -Recurse -ErrorAction SilentlyContinue)
        if ($lixo.Count -gt 0) {
            $mb = ($lixo | Measure-Object Length -Sum).Sum / 1MB
            $lixo | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Ok ("Removidos {0} arquivo(s) de depuracao ({1:N0} MB) - cache enxuto." -f $lixo.Count, $mb)
        }
    } catch {
        Write-Falha "Falha ao extrair o ClamAV: $($_.Exception.Message)"
        return $null
    }

    $exe = Get-ChildItem -Path $destino -Filter 'clamscan.exe' -Recurse -ErrorAction SilentlyContinue |
           Select-Object -First 1
    if ($exe) { Write-Ok "ClamAV pronto: $($exe.DirectoryName)"; return $exe.DirectoryName }

    Write-Falha 'clamscan.exe nao encontrado apos a extracao.'
    return $null
}

function Initialize-ClamConfig {
    <# Cria freshclam.conf/clamd.conf minimos e a pasta de assinaturas. #>
    param([string]$PastaBin)
    $dbDir = Join-Path (Split-Path $PastaBin -Parent) 'database'
    if ((Split-Path $PastaBin -Leaf) -eq 'clamav') { $dbDir = Join-Path $PastaBin 'database' }
    New-Item -ItemType Directory -Path $dbDir -Force -ErrorAction SilentlyContinue | Out-Null

    $freshConf = Join-Path $PastaBin 'freshclam.conf'
    if (-not (Test-Path -LiteralPath $freshConf)) {
        @(
            "# gerado automaticamente pela Manutencao v2"
            "DatabaseDirectory $dbDir"
            "DatabaseMirror database.clamav.net"
            "ConnectTimeout 60"
            "ReceiveTimeout 120"
        ) | Set-Content -Path $freshConf -Encoding ASCII
    }
    return $dbDir
}

function Update-ClamSignatures {
    param([string]$PastaBin, [string]$DbDir)

    $fresh = Join-Path $PastaBin 'freshclam.exe'
    $temBase = @(Get-ChildItem -Path $DbDir -Include '*.cvd', '*.cld' -Recurse -ErrorAction SilentlyContinue).Count -gt 0

    if ($SemAtualizarAssinaturas) {
        if ($temBase) { Write-Aviso 'Atualizacao pulada (-SemAtualizarAssinaturas). Usando base local.'; return $true }
        Write-Falha 'Sem base local e atualizacao pulada - impossivel escanear.'
        return $false
    }
    if ($SomenteRelatorio) { Write-Simul 'Atualizaria as assinaturas (freshclam).'; return $true }
    if (-not (Test-Path -LiteralPath $fresh)) {
        Write-Aviso 'freshclam.exe ausente; seguindo com a base que houver.'
        return $temBase
    }

    Write-Etapa 'Atualizando assinaturas do ClamAV (freshclam)...'
    try {
        $conf = Join-Path $PastaBin 'freshclam.conf'
        # A barra de progresso do freshclam gera milhares de linhas (cada
        # atualizacao de byte). Filtramos as linhas de progresso e mostramos
        # so o que interessa (base atualizada, versao, avisos).
        & $fresh --config-file="$conf" --datadir="$DbDir" 2>&1 | ForEach-Object {
            $l = ([string]$_).Trim()
            if (-not $l) { return }
            if ($l -match 'ETA:|[KM]iB/|\[=*>? *\]|Time: *\d') { return }
            Write-Info $l
        }
        if ($LASTEXITCODE -eq 0) { Write-Ok 'Assinaturas atualizadas.'; return $true }
        Write-Aviso "freshclam retornou codigo $LASTEXITCODE."
    } catch {
        Write-Aviso "Falha de rede no freshclam: $($_.Exception.Message)"
    }

    # Falha de rede: decidir como prosseguir
    if ($temBase) {
        if ($SemInteracao) { Write-Aviso 'Prosseguindo com base local desatualizada (modo desatendido).'; return $true }
        $r = (Read-Host '  Nao atualizou. Escanear com a base local desatualizada? (S/N)').Trim()
        return ($r -match '^[SsYy]')
    }
    Write-Falha 'Sem assinaturas locais e sem rede - scan cancelado.'
    return $false
}

function Select-CaminhoScanGrafico {
    <# Seletor grafico de arquivo ou pasta quando -CaminhoScan nao e passado. #>
    if ($SemInteracao) { return $null }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $escolha = [System.Windows.Forms.MessageBox]::Show(
            "Sim = escolher um ARQUIVO`nNao = escolher uma PASTA",
            'O que deseja escanear?', 'YesNoCancel', 'Question')
        if ($escolha -eq 'Yes') {
            $dlg = New-Object System.Windows.Forms.OpenFileDialog
            $dlg.Title = 'Selecione o arquivo a escanear'
            if ($dlg.ShowDialog() -eq 'OK') { return $dlg.FileName }
        } elseif ($escolha -eq 'No') {
            $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
            $dlg.Description = 'Selecione a pasta a escanear'
            if ($dlg.ShowDialog() -eq 'OK') { return $dlg.SelectedPath }
        }
    } catch { Write-Aviso "Seletor grafico indisponivel: $($_.Exception.Message)" }
    return $null
}

function Get-FileHashSafe {
    param([string]$Caminho, [switch]$Force)
    # -Force calcula o hash mesmo com -SemHash (o VirusTotal precisa do hash).
    if ($SemHash -and -not $Force) { return '' }
    try { return (Get-FileHash -LiteralPath $Caminho -Algorithm SHA256 -ErrorAction Stop).Hash }
    catch { return '' }
}

# --- VirusTotal (Camada 2): checagem de hash SHA256 -----------------------

function Get-VTConfigPath {
    <# config.json vive na pasta mais persistente disponivel. #>
    if ($ClamAVCache) { return (Join-Path $ClamAVCache 'config.json') }
    $dirScript = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.PSCommandPath }
    if ($dirScript -and (Test-Path $dirScript)) { return (Join-Path $dirScript 'config.json') }
    $fallback = Join-Path $env:LOCALAPPDATA 'SuporteTI'
    New-Item -ItemType Directory -Path $fallback -Force -ErrorAction SilentlyContinue | Out-Null
    return (Join-Path $fallback 'config.json')
}

function Get-VirusTotalKey {
    <#
      Resolve a API key na ordem: -VirusTotalKey > config.json > virustotal.txt
      (ao lado do script) > pergunta ao operador. Salva em config.json para
      nao pedir de novo. Retorna a key ou $null.
    #>
    if ($VirusTotalKey) { return $VirusTotalKey.Trim() }

    $cfgPath = Get-VTConfigPath
    if (Test-Path -LiteralPath $cfgPath) {
        try {
            $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
            if ($cfg.VirusTotalKey) { return ([string]$cfg.VirusTotalKey).Trim() }
        } catch { }
    }

    # Importa de virustotal.txt ao lado do script (conveniencia do Ivan)
    $dirScript = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.PSCommandPath }
    foreach ($cand in @((Join-Path $dirScript 'virustotal.txt'), 'C:\suporteti\virustotal.txt')) {
        if ($cand -and (Test-Path -LiteralPath $cand)) {
            $txt = Get-Content -LiteralPath $cand -Raw
            $m = [regex]::Match($txt, '[A-Fa-f0-9]{64}')
            if ($m.Success) {
                Save-VirusTotalKey -Chave $m.Value -CfgPath $cfgPath
                Write-Info "API key do VirusTotal importada de $cand"
                return $m.Value
            }
        }
    }

    # Pergunta ao operador (uma vez) se estiver interativo
    if (-not $SemInteracao) {
        $r = (Read-Host '  Cole a API key do VirusTotal (Enter p/ pular)').Trim()
        if ($r) { Save-VirusTotalKey -Chave $r -CfgPath $cfgPath; return $r }
    }
    return $null
}

function Save-VirusTotalKey {
    param([string]$Chave, [string]$CfgPath)
    try {
        $cfg = if (Test-Path -LiteralPath $CfgPath) { Get-Content -LiteralPath $CfgPath -Raw | ConvertFrom-Json } else { [pscustomobject]@{} }
        $cfg | Add-Member -NotePropertyName VirusTotalKey -NotePropertyValue $Chave -Force
        $cfg | ConvertTo-Json | Set-Content -LiteralPath $CfgPath -Encoding UTF8
        Write-Ok "API key salva em $CfgPath (nao sera pedida de novo)."
    } catch { Write-Aviso "Nao foi possivel salvar a API key: $($_.Exception.Message)" }
}

# Fila de horarios das chamadas, para respeitar 4 req/min da API gratuita
$script:vtChamadas = [System.Collections.Generic.Queue[datetime]]::new()

function Wait-VirusTotalRate {
    while ($true) {
        # descarta chamadas com mais de 60s
        while ($script:vtChamadas.Count -gt 0 -and ([datetime]::Now - $script:vtChamadas.Peek()).TotalSeconds -ge 60) {
            [void]$script:vtChamadas.Dequeue()
        }
        if ($script:vtChamadas.Count -lt 4) { break }
        $espera = 60 - ([datetime]::Now - $script:vtChamadas.Peek()).TotalSeconds
        if ($espera -gt 0) {
            Write-Info ("Aguardando {0:N0}s (limite de 4 consultas/min do VirusTotal)..." -f $espera)
            Start-Sleep -Seconds ([math]::Ceiling($espera))
        }
    }
}

function Invoke-VirusTotalLookup {
    <# Consulta um hash no VirusTotal. Retorna objeto com o veredito. #>
    param([string]$Hash, [string]$ApiKey)

    if ([string]::IsNullOrWhiteSpace($Hash)) {
        return [pscustomobject]@{ Estado = 'sem-hash'; Malicioso = 0; Total = 0; Texto = 'sem hash' }
    }
    Wait-VirusTotalRate
    try {
        $resp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$Hash" `
                    -Headers @{ 'x-apikey' = $ApiKey } -TimeoutSec 30 -ErrorAction Stop
        $script:vtChamadas.Enqueue([datetime]::Now)
        $s = $resp.data.attributes.last_analysis_stats
        $mal = [int]$s.malicious; $susp = [int]$s.suspicious
        $tot = [int]$s.malicious + [int]$s.suspicious + [int]$s.undetected + [int]$s.harmless + [int]$s.timeout
        return [pscustomobject]@{
            Estado    = 'conhecido'
            Malicioso = $mal
            Suspeito  = $susp
            Total     = $tot
            Texto     = "$mal/$tot maliciosos" + $(if ($susp -gt 0) { " (+$susp suspeitos)" } else { '' })
        }
    } catch {
        $script:vtChamadas.Enqueue([datetime]::Now)
        $code = $null
        try { $code = [int]$_.Exception.Response.StatusCode.value__ } catch { }
        switch ($code) {
            404     { return [pscustomobject]@{ Estado = 'desconhecido'; Malicioso = 0; Total = 0; Texto = 'hash nunca visto no VT' } }
            401     { return [pscustomobject]@{ Estado = 'erro'; Malicioso = 0; Total = 0; Texto = 'API key invalida (401)' } }
            403     { return [pscustomobject]@{ Estado = 'erro'; Malicioso = 0; Total = 0; Texto = 'acesso negado (403)' } }
            429     { return [pscustomobject]@{ Estado = 'erro'; Malicioso = 0; Total = 0; Texto = 'limite diario/min atingido (429)' } }
            default { return [pscustomobject]@{ Estado = 'erro'; Malicioso = 0; Total = 0; Texto = "erro: $($_.Exception.Message)" } }
        }
    }
}

function Invoke-VirusScan {
    <# Orquestra o scan completo. Retorna um codigo de saida (0 limpo, 1 infectado, 2 erro). #>

    Write-Titulo 'SCANNER DE MALWARE (ClamAV + VirusTotal)'

    # Cache persistente: engine e assinaturas ficam guardados e reaproveitados
    $script:clamPersistente = [bool]$ClamAVCache
    if ($script:clamPersistente) {
        Write-Info "Cache persistente: $ClamAVCache (reaproveitado entre clientes, nao sera removido)."
    }

    # 1. Resolver o alvo
    $alvo = $CaminhoScan
    if ([string]::IsNullOrWhiteSpace($alvo)) {
        Write-Etapa 'Nenhum caminho informado - abrindo seletor...'
        $alvo = Select-CaminhoScanGrafico
    }
    if ([string]::IsNullOrWhiteSpace($alvo) -or -not (Test-Path -LiteralPath $alvo)) {
        Write-Falha 'Nenhum caminho valido para escanear. Use -CaminhoScan <arquivo|pasta>.'
        return 2
    }
    $ehPasta = (Get-Item -LiteralPath $alvo).PSIsContainer
    Write-Info ("Alvo: $alvo  ({0})" -f $(if ($ehPasta) { 'pasta - scan recursivo' } else { 'arquivo unico' }))

    # 1b. Camada 2: VirusTotal (opcional, nao bloqueante)
    $vtKey = $null; $vtAtivo = $false
    if (-not $SemVirusTotal) {
        $vtKey = Get-VirusTotalKey
        if ($vtKey) {
            $vtAtivo = $true
            $mascara = $vtKey.Substring(0, 6) + '...' + $vtKey.Substring($vtKey.Length - 4)
            Write-Ok "VirusTotal ativo (key $mascara). Limite: $(if ($VTLimite -gt 0){"$VTLimite consultas"}else{'sem limite'})."
            if ($ehPasta -and -not $VTTodos) {
                Write-Info 'Modo pasta: VirusTotal consulta so os arquivos que o ClamAV apontar. Use -VTTodos para todos.'
            }
        } else {
            Write-Aviso 'Sem API key do VirusTotal - seguindo somente com ClamAV (camada 2 desativada).'
            Write-Info  'Crie uma conta gratuita em virustotal.com, gere a key e use -VirusTotalKey ou config.json.'
        }
    }

    # 2. Preparar engine e assinaturas
    $pastaBin = Get-ClamAVPortable
    if (-not $pastaBin) { return 2 }
    $dbDir = Initialize-ClamConfig -PastaBin $pastaBin
    if (-not (Update-ClamSignatures -PastaBin $pastaBin -DbDir $dbDir)) { return 2 }

    $clamscan = Join-Path $pastaBin 'clamscan.exe'
    if (-not (Test-Path -LiteralPath $clamscan)) { Write-Falha 'clamscan.exe nao encontrado.'; return 2 }

    if ($SomenteRelatorio) {
        Write-Simul "Escanearia '$alvo' com ClamAV (limite 4 GB por arquivo)."
        return 0
    }

    # 3. Montar argumentos - ajustados para arquivos grandes (2GB+)
    $scanArgs = @(
        "--database=$dbDir"
        '--max-filesize=4000M'
        '--max-scansize=4000M'
        '--max-recursion=20'
        '--max-files=0'
        '--alert-exceeds-max=yes'
        '--stdout'
    )
    if ($ehPasta) {
        $scanArgs += '--recursive'
        foreach ($ex in ($ExcluirPastas | Where-Object { $_ })) { $scanArgs += "--exclude-dir=$ex" }
    }
    $scanArgs += $alvo

    # 4. Contar total para o progresso (modo pasta)
    $total = 1
    if ($ehPasta) {
        Write-Etapa 'Contabilizando arquivos...'
        $total = [math]::Max(1, @(Get-ChildItem -LiteralPath $alvo -Recurse -File -Force -ErrorAction SilentlyContinue).Count)
        Write-Info "$total arquivo(s) a verificar."
    }

    # 5. CAMADA 1 - ClamAV: executa transmitindo a saida linha a linha.
    #    Guarda um registro por arquivo (sem consultar o VT aqui, para nao
    #    travar a leitura do stdout do clamscan com os delays da API).
    $registros = [System.Collections.Generic.List[object]]::new()
    $erros = 0; $lidos = 0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Etapa 'Camada 1 - Escaneando com ClamAV...'
    & $clamscan @scanArgs 2>&1 | ForEach-Object {
        $linha = [string]$_
        $arq = $null; $clam = $null; $ameaca = ''
        # clamscan imprime "<caminho>: OK" | "<caminho>: <Ameaca> FOUND" | "<caminho>: <erro> ERROR"
        if ($linha -match '^(.*): (.+) FOUND$') {
            $arq = $Matches[1]; $ameaca = $Matches[2]; $clam = 'INFECTADO'; $lidos++
            Write-Falha "INFECTADO (ClamAV): $arq  ->  $ameaca"
        }
        elseif ($linha -match '^(.*): OK$') {
            $arq = $Matches[1]; $clam = 'LIMPO'; $lidos++
        }
        elseif ($linha -match '^(.*): (.+) ERROR$') {
            $arq = $Matches[1]; $clam = 'ERRO'; $ameaca = $Matches[2]; $erros++; $lidos++
        }
        if ($arq) {
            $registros.Add([pscustomobject]@{
                Data = (Get-Date).ToString('s'); Arquivo = $arq; Hash = ''
                ClamAV = $(if ($clam -eq 'INFECTADO') { "INFECTADO: $ameaca" } elseif ($clam -eq 'ERRO') { "ERRO: $ameaca" } else { 'LIMPO' })
                ClamInfectado = ($clam -eq 'INFECTADO')
                VirusTotal = 'nao consultado'
                VTMalicioso = 0
            })
        }
        if ($ehPasta -and $lidos -gt 0) {
            Write-Progress -Activity 'Camada 1: ClamAV' `
                -Status "$lidos / $total  |  infectados: $(@($registros | Where-Object ClamInfectado).Count)" `
                -PercentComplete ([math]::Min(100, $lidos / $total * 100))
        }
    }
    $codigo = $LASTEXITCODE
    Write-Progress -Activity 'Camada 1: ClamAV' -Completed

    # 6. CAMADA 2 - VirusTotal: consulta hashes.
    #    Arquivo unico: sempre. Pasta: so os apontados pelo ClamAV, salvo -VTTodos.
    if ($vtAtivo) {
        $alvosVT = if (-not $ehPasta -or $VTTodos) { @($registros) } else { @($registros | Where-Object ClamInfectado) }
        # nao consulta ERRO (sem hash confiavel)
        $alvosVT = @($alvosVT | Where-Object { $_.ClamAV -notlike 'ERRO:*' })

        if ($alvosVT.Count -gt 0) {
            $limite = if ($VTLimite -gt 0) { [math]::Min($VTLimite, $alvosVT.Count) } else { $alvosVT.Count }
            if ($alvosVT.Count -gt $limite) {
                Write-Aviso "VirusTotal: $($alvosVT.Count) arquivos elegiveis, consultando os primeiros $limite (limite/rate)."
            }
            Write-Etapa "Camada 2 - Consultando VirusTotal ($limite hash)..."
            $n = 0
            foreach ($reg in ($alvosVT | Select-Object -First $limite)) {
                $n++
                Write-Progress -Activity 'Camada 2: VirusTotal' -Status "$n / $limite" -PercentComplete ($n / $limite * 100)
                if (-not $reg.Hash) { $reg.Hash = Get-FileHashSafe $reg.Arquivo -Force }
                $vt = Invoke-VirusTotalLookup -Hash $reg.Hash -ApiKey $vtKey
                $reg.VirusTotal = $vt.Texto
                $reg.VTMalicioso = [int]$vt.Malicioso
                if ($vt.Malicioso -gt 0) { Write-Falha "VirusTotal: $($reg.Arquivo)  ->  $($vt.Texto)" }
            }
            Write-Progress -Activity 'Camada 2: VirusTotal' -Completed
        } else {
            Write-Info 'VirusTotal: nada elegivel para consulta (nenhum suspeito). Use -VTTodos para checar tudo.'
        }
    }
    $sw.Stop()

    # Calcula hash dos demais arquivos para o log (se ainda nao tiver e -SemHash off)
    if (-not $SemHash) {
        foreach ($reg in $registros) { if (-not $reg.Hash -and $reg.ClamAV -notlike 'ERRO:*') { $reg.Hash = Get-FileHashSafe $reg.Arquivo } }
    }

    # Veredito combinado
    $suspeitos = @($registros | Where-Object { $_.ClamInfectado -or $_.VTMalicioso -gt 0 })

    # 7. Gravar log CSV (com as duas camadas)
    $arqLog = Join-Path $script:pastaExec ("scan-virus_{0}.csv" -f (Get-Date -Format 'HHmmss'))
    try {
        $registros | Select-Object Data, Arquivo, Hash, ClamAV, VirusTotal |
            Export-Csv -Path $arqLog -NoTypeInformation -Encoding UTF8
    } catch { }

    # 8. Resumo
    Write-Host ''
    Write-Host ('  ' + ('-' * 64)) -ForegroundColor DarkGray
    if (-not $ehPasta) {
        $item = Get-Item -LiteralPath $alvo
        $reg = $registros | Select-Object -First 1
        Write-Info ("Arquivo    : {0}" -f $item.Name)
        Write-Info ("Tamanho    : {0}" -f (Format-Tamanho $item.Length))
        Write-Info ("SHA256     : {0}" -f $(if ($reg -and $reg.Hash) { $reg.Hash } else { '(nao calculado)' }))
        Write-Info ("Tempo      : {0:N1}s" -f $sw.Elapsed.TotalSeconds)
        if ($reg) {
            if ($reg.ClamInfectado) { Write-Falha "ClamAV     : $($reg.ClamAV)" } else { Write-Ok "ClamAV     : $($reg.ClamAV)" }
            if ($vtAtivo) {
                if ($reg.VTMalicioso -gt 0) { Write-Falha "VirusTotal : $($reg.VirusTotal)" } else { Write-Ok "VirusTotal : $($reg.VirusTotal)" }
            }
        }
        Write-Host ''
        if ($suspeitos.Count -gt 0) {
            Write-Falha '>>> VEREDITO: SUSPEITO / INFECTADO - nao execute este arquivo.'
        } else { Write-Ok '>>> VEREDITO: LIMPO nas duas camadas.' }
    } else {
        Write-Info ("Arquivos verificados : {0}" -f $lidos)
        Write-Info ("Erros de leitura     : {0}" -f $erros)
        Write-Info ("Consultas VirusTotal : {0}" -f @($registros | Where-Object { $_.VirusTotal -ne 'nao consultado' }).Count)
        Write-Info ("Tempo total          : {0:N1}s" -f $sw.Elapsed.TotalSeconds)
        Write-Host ''
        if ($suspeitos.Count -eq 0) {
            Write-Ok ">>> VEREDITO: nenhuma ameaca encontrada nas camadas ativas."
        } else {
            Write-Falha ">>> AMEACAS/SUSPEITAS: $($suspeitos.Count)"
            foreach ($s in $suspeitos) {
                $det = @()
                if ($s.ClamInfectado) { $det += "ClamAV: $($s.ClamAV -replace '^INFECTADO: ','')" }
                if ($s.VTMalicioso -gt 0) { $det += "VT: $($s.VirusTotal)" }
                Write-Falha "   $($s.Arquivo)  ->  $($det -join '  |  ')"
            }
            Add-Alerta "$($suspeitos.Count) arquivo(s) suspeito(s)/infectado(s) - ver $arqLog"
        }
    }
    Write-Info ("Log: $arqLog")

    # 9. Remocao de ameacas (mediante autorizacao)
    if ($RemoverAmeacas) {
        Remove-Ameacas -Registros $registros | Out-Null
    } elseif ($suspeitos.Count -gt 0) {
        Write-Info 'Para remover as ameacas, rode de novo com -RemoverAmeacas (quarentena) ou -RemoverAmeacas -ApagarDefinitivo.'
    }

    # 10. Limpeza opcional (sem rastro)
    if ($script:clamPersistente) {
        # Cache fixo: manter sempre, senao perde o sentido de reaproveitar.
        if ($LimparAposScan) { Write-Info 'Cache persistente (-ClamAVCache): -LimparAposScan ignorado, base mantida.' }
        else { Write-Ok 'Engine e assinaturas mantidas no cache para o proximo cliente.' }
    } elseif ($LimparAposScan) {
        Invoke-LimpezaClamAV
    } elseif ($script:clamBaixado -and -not $SemInteracao) {
        $r = (Read-Host '  Remover o ClamAV baixado para nao deixar rastro? (S/N)').Trim()
        if ($r -match '^[SsYy]') { Invoke-LimpezaClamAV }
    }

    return $codigo
}

function Remove-Ameacas {
    <#
      Remove as ameacas detectadas, mediante autorizacao. Por padrao move
      para uma pasta de QUARENTENA (renomeando p/ .vir, sem poder executar) e
      grava um manifesto para restaurar. Com -ApagarDefinitivo, exclui de vez.
      Retorna a quantidade removida.
    #>
    param([object[]]$Registros)

    # Criterio de remocao: ClamAV infectou OU VT >= limiar (consenso, evita
    # remover por 1 engine obscuro do VirusTotal).
    $alvos = @($Registros | Where-Object { $_.ClamInfectado -or $_.VTMalicioso -ge $VTLimiarRemocao })
    if ($alvos.Count -eq 0) { Write-Ok 'Nenhuma ameaca elegivel para remocao.'; return 0 }

    Write-Host ''
    Write-Aviso "Arquivos marcados para remocao: $($alvos.Count)"
    foreach ($a in $alvos) {
        $motivo = @()
        if ($a.ClamInfectado)               { $motivo += ($a.ClamAV -replace '^INFECTADO: ', 'ClamAV=') }
        if ($a.VTMalicioso -ge $VTLimiarRemocao) { $motivo += "VT=$($a.VTMalicioso)" }
        Write-Falha "   $($a.Arquivo)   [$($motivo -join ', ')]"
    }

    $acao = if ($ApagarDefinitivo) { 'APAGAR DEFINITIVAMENTE' } else { 'mover para quarentena' }
    Write-Host ''
    Write-Aviso "Acao: $acao"

    if ($SomenteRelatorio) { Write-Simul "Removeria $($alvos.Count) arquivo(s) ($acao)."; return 0 }

    # Autorizacao explicita
    if ($SemInteracao) {
        if (-not $ConfirmarRemocao) {
            Write-Falha 'Modo desatendido: use -ConfirmarRemocao para autorizar a remocao. Nada foi removido.'
            return 0
        }
    } else {
        $palavra = if ($ApagarDefinitivo) { 'APAGAR' } else { 'QUARENTENA' }
        $r = (Read-Host "  Digite $palavra para confirmar a remocao").Trim()
        if ($r -ne $palavra) { Write-Aviso 'Cancelado pelo operador. Nada foi removido.'; return 0 }
    }

    # Prepara quarentena (se nao for exclusao definitiva)
    $pastaQ = Join-Path $script:pastaExec 'quarentena'
    $manifesto = Join-Path $pastaQ 'quarentena.csv'
    if (-not $ApagarDefinitivo) {
        New-Item -ItemType Directory -Path $pastaQ -Force -ErrorAction SilentlyContinue | Out-Null
        try { Protect-PastaBackup -Caminho $pastaQ } catch { }
    }

    $removidos = 0; $falhas = 0
    foreach ($a in $alvos) {
        if (-not (Test-Path -LiteralPath $a.Arquivo)) { continue }  # ja removido pelo AV residente
        try {
            if ($ApagarDefinitivo) {
                Remove-Item -LiteralPath $a.Arquivo -Force -ErrorAction Stop
                Write-Ok "Apagado: $($a.Arquivo)"
            } else {
                # nome unico na quarentena, extensao .vir (nao executa)
                $hash8 = if ($a.Hash) { $a.Hash.Substring(0, 8) } else { (Get-Random).ToString('x8') }
                $destArq = Join-Path $pastaQ ("{0}_{1}.vir" -f (Split-Path $a.Arquivo -Leaf), $hash8)
                Move-Item -LiteralPath $a.Arquivo -Destination $destArq -Force -ErrorAction Stop
                [pscustomobject]@{
                    Data = (Get-Date).ToString('s'); Original = $a.Arquivo
                    Quarentena = $destArq; Hash = $a.Hash; Motivo = $a.ClamAV
                } | Export-Csv -Path $manifesto -NoTypeInformation -Encoding UTF8 -Append
                Write-Ok "Quarentena: $($a.Arquivo)"
            }
            $removidos++
        } catch {
            $falhas++
            Write-Falha "Falhou (em uso?): $($a.Arquivo) - $($_.Exception.Message)"
        }
    }

    Write-Host ''
    Write-Ok "Removidos: $removidos  |  Falhas: $falhas"
    if ($falhas -gt 0) {
        Write-Aviso 'Arquivos em uso nao puderam ser removidos. Feche o programa/processo e rode de novo,'
        Write-Info  'ou reinicie em Modo de Seguranca para remover arquivos travados por malware ativo.'
    }
    if (-not $ApagarDefinitivo -and $removidos -gt 0) {
        Write-Info "Quarentena em: $pastaQ"
        Write-Info "Para restaurar um arquivo: mova-o de volta e remova a extensao .vir (ver $manifesto)."
    }
    return $removidos
}

function Find-ManifestoQuarentena {
    <#
      Resolve o manifesto da quarentena a partir de -QuarentenaPath (pasta ou
      CSV) ou, se vazio, localiza o quarentena.csv mais recente sob a pasta de
      logs e no cache do ClamAV.
    #>
    param([string]$Origem)

    if ($Origem) {
        if (Test-Path -LiteralPath $Origem -PathType Leaf) { return $Origem }
        $csv = Join-Path $Origem 'quarentena.csv'
        if (Test-Path -LiteralPath $csv) { return $csv }
        Write-Falha "Nao achei quarentena.csv em: $Origem"
        return $null
    }

    # Auto-localiza o mais recente
    $bases = @($PastaLog)
    if ($ClamAVCache) { $bases += $ClamAVCache }
    $achados = foreach ($b in $bases) {
        if ($b -and (Test-Path $b)) {
            Get-ChildItem -Path $b -Filter 'quarentena.csv' -Recurse -File -ErrorAction SilentlyContinue
        }
    }
    $maisRecente = $achados | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($maisRecente) { return $maisRecente.FullName }

    Write-Falha 'Nenhuma quarentena encontrada. Informe a pasta com -QuarentenaPath.'
    return $null
}

function Restore-Quarentena {
    <#
      Devolve arquivos da quarentena ao local original (falso positivo).
      ATENCAO: restaura algo que foi marcado como ameaca - exige confirmacao.
    #>
    Write-Titulo 'RESTAURAR QUARENTENA'

    $manifesto = Find-ManifestoQuarentena -Origem $QuarentenaPath
    if (-not $manifesto) { return 2 }
    Write-Info "Manifesto: $manifesto"

    $itens = @(Import-Csv -LiteralPath $manifesto -ErrorAction SilentlyContinue)
    # so linhas ainda em quarentena (o arquivo .vir existe)
    $itens = @($itens | Where-Object { $_.Quarentena -and (Test-Path -LiteralPath $_.Quarentena) })
    if ($itens.Count -eq 0) { Write-Aviso 'Nada a restaurar (quarentena vazia ou ja restaurada).'; return 0 }

    Write-Host ''
    Write-Aviso "Arquivos na quarentena: $($itens.Count)"
    $i = 0
    foreach ($it in $itens) {
        $i++
        Write-Host ("     [$i] {0}" -f $it.Original) -ForegroundColor White
        Write-Host ("         motivo original: {0}" -f $it.Motivo) -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Falha 'ATENCAO: estes arquivos foram marcados como ameaca. Restaure apenas se tiver certeza.'

    # Selecao + confirmacao
    $selecionados = $itens
    if ($SomenteRelatorio) { Write-Simul "Restauraria $($itens.Count) arquivo(s)."; return 0 }

    if ($SemInteracao) {
        if (-not $ConfirmarRestauracao) {
            Write-Falha 'Modo desatendido: use -ConfirmarRestauracao para autorizar. Nada restaurado.'
            return 0
        }
    } else {
        Write-Info 'Digite os numeros a restaurar (ex: 1,3), T para todos, ou Enter para cancelar.'
        $resp = (Read-Host '  Restaurar').Trim()
        if ($resp -eq '') { Write-Aviso 'Cancelado.'; return 0 }
        if ($resp -notmatch '^[Tt]') {
            $nums = @()
            foreach ($p in ($resp -split ',')) { $n = $p.Trim(); if ($n -match '^\d+$') { $nums += [int]$n } }
            $selecionados = @($itens | Where-Object { $nums -contains ([array]::IndexOf($itens, $_) + 1) })
            if ($selecionados.Count -eq 0) { Write-Aviso 'Nenhum indice valido. Cancelado.'; return 0 }
        }
    }

    $ok = 0; $falhas = 0
    foreach ($it in $selecionados) {
        try {
            $destino = $it.Original
            $pastaDestino = Split-Path $destino -Parent
            if (-not (Test-Path -LiteralPath $pastaDestino)) {
                New-Item -ItemType Directory -Path $pastaDestino -Force -ErrorAction SilentlyContinue | Out-Null
            }
            if (Test-Path -LiteralPath $destino) {
                Write-Aviso "Ja existe no destino, pulado: $destino"
                continue
            }
            Move-Item -LiteralPath $it.Quarentena -Destination $destino -Force -ErrorAction Stop
            Write-Ok "Restaurado: $destino"
            $ok++
        } catch {
            $falhas++
            Write-Falha "Falha ao restaurar $($it.Original): $($_.Exception.Message)"
        }
    }

    Write-Host ''
    Write-Ok "Restaurados: $ok  |  Falhas: $falhas"
    if ($ok -gt 0) {
        Write-Aviso 'Considere adicionar o arquivo a excecao do antivirus se for falso positivo confirmado.'
    }
    return 0
}

function Invoke-LimpezaClamAV {
    if ($script:clamPersistente) { Write-Info 'Cache persistente - nao removido.'; return }
    $destino = Resolve-PastaClamAV
    if (-not (Test-Path -LiteralPath $destino)) { return }
    try {
        Remove-Item -LiteralPath $destino -Recurse -Force -ErrorAction Stop
        Write-Ok "ClamAV removido: $destino"
    } catch { Write-Aviso "Nao foi possivel remover o ClamAV: $($_.Exception.Message)" }
}

# =========================================================================
# REGIAO: NAVEGADORES (limpeza de cache com protecao de credenciais)
# =========================================================================

function Get-CaminhosCacheNavegador {
    <#
      Fonte unica das pastas de cache de navegador: usada tanto pela limpeza
      quanto pela estimativa, para as duas nunca divergirem.
      Devolve apenas pastas da lista branca $script:CachesPermitidos.
    #>
    $chromium = [ordered]@{
        'chrome'  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        'msedge'  = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        'brave'   = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
        'vivaldi' = "$env:LOCALAPPDATA\Vivaldi\User Data"
        'opera'   = "$env:APPDATA\Opera Software\Opera Stable"
    }
    $rotulos = @{
        'chrome' = 'Chrome'; 'msedge' = 'Edge'; 'brave' = 'Brave'
        'vivaldi' = 'Vivaldi'; 'opera' = 'Opera'; 'firefox' = 'Firefox'
    }

    $saida = @()
    foreach ($proc in $chromium.Keys) {
        $base = $chromium[$proc]
        if (-not (Test-Path -LiteralPath $base)) { continue }

        $perfis = @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile*' -or $_.Name -eq 'Guest Profile' })
        if ($perfis.Count -eq 0 -and (Test-Path (Join-Path $base 'Cache'))) {
            $perfis = @(Get-Item -LiteralPath $base -ErrorAction SilentlyContinue)
        }
        foreach ($perfil in $perfis) {
            foreach ($cache in $script:CachesPermitidos) {
                $alvo = Join-Path $perfil.FullName $cache
                if (-not (Test-Path -LiteralPath $alvo)) { continue }
                if (Test-CaminhoProtegido $alvo) { continue }
                $saida += [pscustomobject]@{ Processo = $proc; Navegador = $rotulos[$proc]; Caminho = $alvo }
            }
        }
    }

    # Firefox: cache no LOCALAPPDATA. As credenciais ficam no APPDATA e nao
    # entram aqui em nenhuma hipotese.
    $ffCache = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path -LiteralPath $ffCache) {
        Get-ChildItem -LiteralPath $ffCache -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($c in @('cache2', 'startupCache', 'thumbnails', 'jumpListCache')) {
                $alvo = Join-Path $_.FullName $c
                if (Test-Path -LiteralPath $alvo) {
                    $saida += [pscustomobject]@{ Processo = 'firefox'; Navegador = 'Firefox'; Caminho = $alvo }
                }
            }
        }
    }

    foreach ($extra in @("$env:LOCALAPPDATA\Microsoft\Windows\INetCache",
                         "$env:LOCALAPPDATA\Microsoft\Windows\WebCache")) {
        if (Test-Path -LiteralPath $extra) {
            $saida += [pscustomobject]@{ Processo = 'ie'; Navegador = 'IE/WebView'; Caminho = $extra }
        }
    }
    return $saida
}

function Get-NavegadoresAbertos {
    $mapa = @{
        'chrome'   = 'Google Chrome'
        'msedge'   = 'Microsoft Edge'
        'brave'    = 'Brave'
        'firefox'  = 'Mozilla Firefox'
        'vivaldi'  = 'Vivaldi'
        'opera'    = 'Opera'
    }
    $abertos = @{}
    foreach ($proc in $mapa.Keys) {
        if (Get-Process -Name $proc -ErrorAction SilentlyContinue) { $abertos[$proc] = $mapa[$proc] }
    }
    return $abertos
}

function Clear-CacheNavegadores {
    <#
      Remove SOMENTE cache. Senhas, cookies, sessoes, favoritos e historico
      sao preservados por tres camadas: lista branca de pastas de cache,
      Test-CaminhoProtegido no caminho e Test-CaminhoProtegido por arquivo
      dentro de Remove-Files.
    #>
    $abertos = Get-NavegadoresAbertos
    $total   = [long]0

    Write-Info 'Preservados: senhas salvas, sessoes logadas, cookies, favoritos e historico.'

    $chromium = [ordered]@{
        'chrome'  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        'msedge'  = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        'brave'   = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
        'vivaldi' = "$env:LOCALAPPDATA\Vivaldi\User Data"
        'opera'   = "$env:APPDATA\Opera Software\Opera Stable"
    }

    foreach ($proc in $chromium.Keys) {
        $base = $chromium[$proc]
        if (-not (Test-Path -LiteralPath $base)) { continue }

        if ($abertos.ContainsKey($proc)) {
            Write-Aviso "$($abertos[$proc]) esta aberto - cache PULADO (feche e rode de novo)."
            continue
        }

        $perfis = @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile*' -or $_.Name -eq 'Guest Profile' })
        if ($perfis.Count -eq 0 -and (Test-Path (Join-Path $base 'Cache'))) {
            $perfis = @(Get-Item -LiteralPath $base)   # Opera Stable nao usa subperfil
        }

        $subtotal = [long]0
        foreach ($perfil in $perfis) {
            foreach ($cache in $script:CachesPermitidos) {
                $alvo = Join-Path $perfil.FullName $cache
                if (-not (Test-Path -LiteralPath $alvo)) { continue }
                # Rede dupla: mesmo na lista branca, caminho protegido nao passa.
                if (Test-CaminhoProtegido $alvo) { continue }
                $subtotal += Remove-Files -Pasta $alvo
            }
        }
        $rotulo = @{ 'chrome'='Chrome'; 'msedge'='Edge'; 'brave'='Brave'
                     'vivaldi'='Vivaldi'; 'opera'='Opera' }[$proc]
        if ($subtotal -gt 0) { Write-Ok ("{0,-18}: {1}" -f $rotulo, (Format-Tamanho $subtotal)) }
        $total += $subtotal
    }

    # --- Firefox ---
    # O cache fica em LOCALAPPDATA; logins.json / key4.db / cookies.sqlite
    # ficam em APPDATA, que NAO e tocado aqui de proposito.
    if ($abertos.ContainsKey('firefox')) {
        Write-Aviso 'Mozilla Firefox esta aberto - cache PULADO (feche e rode de novo).'
    } else {
        $ffCache = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path -LiteralPath $ffCache) {
            $sub = [long]0
            Get-ChildItem -LiteralPath $ffCache -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                foreach ($c in @('cache2', 'startupCache', 'thumbnails', 'jumpListCache')) {
                    $alvo = Join-Path $_.FullName $c
                    if (Test-Path -LiteralPath $alvo) { $sub += Remove-Files -Pasta $alvo }
                }
            }
            if ($sub -gt 0) { Write-Ok ("{0,-18}: {1}" -f 'Firefox', (Format-Tamanho $sub)) }
            $total += $sub
        }
    }

    # --- Cache do Internet Explorer / WebView (nao guarda senha) ---
    $total += Remove-Files -Pasta "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
    $total += Remove-Files -Pasta "$env:LOCALAPPDATA\Microsoft\Windows\WebCache"

    if ($total -eq 0) { Write-Aviso 'Nada removido (navegadores abertos ou cache ja limpo).' }
    return $total
}

# =========================================================================
# REGIAO: ESTIMATIVA DE ESPACO RECUPERAVEL (somente disco C:)
# So MEDE, nao remove. Escopada ao C: a pedido - medir a lixeira de todos os
# discos deixava o sistema lento.
# =========================================================================

$script:fso = $null
function Get-FSO {
    # FileSystemObject reaproveitado: calcula o tamanho recursivo de uma pasta
    # numa unica chamada nativa (~12x mais rapido que Get-ChildItem -Recurse).
    if (-not $script:fso) { try { $script:fso = New-Object -ComObject Scripting.FileSystemObject } catch { } }
    return $script:fso
}

function Measure-Pasta {
    param([string]$Caminho, [string]$Filtro = '*', [int]$DiasAntigos = 0, [switch]$IgnorarGuarda)

    if ([string]::IsNullOrWhiteSpace($Caminho) -or -not (Test-Path -LiteralPath $Caminho)) {
        return [pscustomobject]@{ Bytes = [long]0; Arquivos = 0 }
    }

    # Caminho RAPIDO: pasta inteira, sem filtro nem corte por data -> FSO.
    # So mede (nunca apaga), entao dispensar a guarda de credencial aqui e
    # inofensivo; a limpeza real (Remove-Files) mantem a guarda.
    if ($Filtro -eq '*' -and $DiasAntigos -eq 0) {
        $fso = Get-FSO
        if ($fso) {
            try {
                $sz = [long]$fso.GetFolder($Caminho).Size
                return [pscustomobject]@{ Bytes = $sz; Arquivos = 0 }
            } catch { }  # cai para o metodo preciso em caso de erro/permissao
        }
    }

    # Caminho PRECISO: com filtro ou idade (pastas pequenas) -> Get-ChildItem.
    try {
        $itens = @(Get-ChildItem -LiteralPath $Caminho -Recurse -File -Filter $Filtro -Force -ErrorAction SilentlyContinue)
        if ($DiasAntigos -gt 0) {
            $limite = (Get-Date).AddDays(-$DiasAntigos)
            $itens = @($itens | Where-Object { $_.LastWriteTime -lt $limite })
        }
        if (-not $IgnorarGuarda) {
            $itens = @($itens | Where-Object { -not (Test-CaminhoProtegido $_.FullName) })
        }
        $m = $itens | Measure-Object -Property Length -Sum
        return [pscustomobject]@{ Bytes = [long]$m.Sum; Arquivos = [int]$m.Count }
    } catch {
        return [pscustomobject]@{ Bytes = [long]0; Arquivos = 0 }
    }
}

function Get-PotencialLimpeza {
    param([switch]$Completa)

    $itens = [System.Collections.Generic.List[object]]::new()
    function Add-Item {
        param([string]$Categoria, [long]$Bytes, [int]$Arquivos, [string]$Quando, [string]$Obs = '')
        $itens.Add([pscustomobject]@{
            Categoria = $Categoria; Bytes = $Bytes; Tamanho = (Format-Tamanho $Bytes)
            Arquivos = $Arquivos; Quando = $Quando; Observacao = $Obs
        })
    }

    Write-Etapa 'Calculando espaco recuperavel no disco C: (somente leitura)...'

    $m = Measure-Pasta $env:TEMP
    Add-Item 'TEMP do usuario' $m.Bytes $m.Arquivos 'padrao'

    $m = Measure-Pasta "$env:SystemRoot\Temp"
    Add-Item 'TEMP do sistema' $m.Bytes $m.Arquivos 'padrao'

    $bytes = [long]0; $qtd = 0
    foreach ($p in @("$env:ProgramData\Microsoft\Windows\WER\ReportQueue",
                     "$env:ProgramData\Microsoft\Windows\WER\ReportArchive",
                     "$env:LOCALAPPDATA\CrashDumps")) {
        $m = Measure-Pasta $p; $bytes += $m.Bytes; $qtd += $m.Arquivos
    }
    # Mesma janela de 30 dias usada na limpeza, senao a previsao prometeria
    # espaco que nao vai ser liberado.
    $m = Measure-Pasta "$env:SystemRoot\Minidump" -DiasAntigos 30
    $bytes += $m.Bytes; $qtd += $m.Arquivos
    $dump = "$env:SystemRoot\MEMORY.DMP"
    if (Test-Path -LiteralPath $dump) {
        $bytes += (Get-Item -LiteralPath $dump -Force).Length; $qtd++
    }
    $m = Measure-Pasta "$env:SystemRoot\Logs\CBS" -DiasAntigos 7
    $bytes += $m.Bytes; $qtd += $m.Arquivos
    Add-Item 'Relatorios de erro e dumps' $bytes $qtd 'padrao'

    # Lixeira: SOMENTE C: (medir todos os discos deixava lento).
    $lix = Measure-Pasta ('C:\' + '$Recycle.Bin') -IgnorarGuarda
    Add-Item 'Lixeira (C:)' $lix.Bytes $lix.Arquivos 'padrao'

    $bytes = [long]0; $qtd = 0
    foreach ($f in @('thumbcache_*.db', 'iconcache_*.db')) {
        $m = Measure-Pasta "$env:LOCALAPPDATA\Microsoft\Windows\Explorer" -Filtro $f
        $bytes += $m.Bytes; $qtd += $m.Arquivos
    }
    Add-Item 'Cache de miniaturas' $bytes $qtd 'padrao'

    $m = Measure-Pasta "$env:SystemRoot\SoftwareDistribution\Download"
    $mDO = Measure-Pasta "$env:SystemRoot\SoftwareDistribution\DeliveryOptimization"
    Add-Item 'Windows Update / Delivery Opt.' ($m.Bytes + $mDO.Bytes) ($m.Arquivos + $mDO.Arquivos) 'padrao'

    $m  = Measure-Pasta "$env:LOCALAPPDATA\Package Cache" -DiasAntigos 90
    $m2 = Measure-Pasta "$env:LOCALAPPDATA\Downloaded Installations" -DiasAntigos 90
    Add-Item 'Instaladores antigos (90 dias)' ($m.Bytes + $m2.Bytes) ($m.Arquivos + $m2.Arquivos) 'padrao'

    $abertos = Get-NavegadoresAbertos
    $porNavegador = @{}
    foreach ($c in (Get-CaminhosCacheNavegador)) {
        $m = Measure-Pasta $c.Caminho
        if (-not $porNavegador.ContainsKey($c.Navegador)) {
            $porNavegador[$c.Navegador] = [pscustomobject]@{ Bytes = [long]0; Arquivos = 0; Processo = $c.Processo }
        }
        $porNavegador[$c.Navegador].Bytes    += $m.Bytes
        $porNavegador[$c.Navegador].Arquivos += $m.Arquivos
    }
    foreach ($nav in ($porNavegador.Keys | Sort-Object)) {
        $d = $porNavegador[$nav]
        $obs = if ($abertos.ContainsKey($d.Processo)) { 'ABERTO - feche para liberar' } else { 'senhas preservadas' }
        Add-Item "Cache: $nav" $d.Bytes $d.Arquivos 'padrao' $obs
    }

    $apps = [ordered]@{
        'Java Deployment' = "$env:LOCALAPPDATA\Sun\Java\Deployment\cache"
        'PjeOffice logs'  = "$env:USERPROFILE\.pjeoffice-pro\logs"
        'Shodo logs'      = "$env:USERPROFILE\.shodo\logs"
        'Teams'           = "$env:APPDATA\Microsoft\Teams\Cache"
        'Teams (novo)'    = "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Default\Cache"
        'Office'          = "$env:LOCALAPPDATA\Microsoft\Office\16.0\OfficeFileCache"
        'Adobe'           = "$env:LOCALAPPDATA\Adobe\Acrobat\DC\Cache"
        'Spotify'         = "$env:LOCALAPPDATA\Spotify\Data"
        'Discord'         = "$env:APPDATA\discord\Cache"
    }
    $bytes = [long]0; $qtd = 0
    foreach ($n in $apps.Keys) {
        $m = Measure-Pasta $apps[$n]
        $bytes += $m.Bytes; $qtd += $m.Arquivos
    }
    Add-Item 'Cache de aplicativos' $bytes $qtd 'padrao'

    $adLogs = [long]0; $adTotal = [long]0; $adQtd = 0
    foreach ($b in @($env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData)) {
        $p = Join-Path $b 'AnyDesk'
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $t = Measure-Pasta $p; $adTotal += $t.Bytes; $adQtd += $t.Arquivos
        foreach ($f in @('*.trace', '*.log', '*.old', '*.bak')) {
            $adLogs += (Measure-Pasta $p -Filtro $f).Bytes
        }
        foreach ($sub in @('chat', 'thumbnails', 'msg_thumbnails', 'incoming', 'video')) {
            $adLogs += (Measure-Pasta (Join-Path $p $sub)).Bytes
        }
    }
    if ($adTotal -gt 0) {
        Add-Item 'AnyDesk: logs e miniaturas' $adLogs $adQtd '-LimparAnyDesk' 'mantem ID e senha'
        Add-Item 'AnyDesk: pasta completa'    $adTotal $adQtd '-AnyDeskModo Completo' 'RESETA o ID da maquina'
    }

    $m = Measure-Pasta "$env:SystemRoot\Prefetch" -Filtro '*.pf'
    Add-Item 'Prefetch' $m.Bytes $m.Arquivos 'padrao' 'piora os proximos 3-5 boots'

    if (Test-Path 'C:\Windows.old') {
        $m = Measure-Pasta 'C:\Windows.old' -IgnorarGuarda
        Add-Item 'Windows.old' $m.Bytes $m.Arquivos '-LimpezaAgressiva' 'instalacao anterior do Windows'
    }

    $hib = "$env:SystemDrive\hiberfil.sys"
    if (Test-Path -LiteralPath $hib) {
        $t = [long](Get-Item -LiteralPath $hib -Force -ErrorAction SilentlyContinue).Length
        $temBateria = [bool](Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
        $obs = if ($temBateria) { 'notebook: NAO recomendado' } else { 'desliga hibernacao' }
        Add-Item 'hiberfil.sys' $t 1 '-DesativarHibernacao' $obs
    }

    if ($Completa) {
        Write-Info 'Analisando WinSxS via DISM (1 a 3 minutos)...'
        $saida = (& dism.exe /Online /Cleanup-Image /AnalyzeComponentStore 2>$null) -join "`n"
        $mt2 = [regex]::Match($saida, '(?im)Actual Size of Component Store\s*:\s*([\d\.,]+)\s*(MB|GB)')
        $obs = if ($mt2.Success) { "WinSxS atual: $($mt2.Groups[1].Value) $($mt2.Groups[2].Value)" } else { 'ver saida do DISM' }
        Add-Item 'WinSxS (componentes)' 0 0 '-LimpezaAgressiva' $obs
    } else {
        Add-Item 'WinSxS (componentes)' 0 0 '-LimpezaAgressiva' 'nao medido - use -EstimativaCompleta'
    }

    return $itens
}

function Show-PotencialLimpeza {
    param([object[]]$Itens, [string]$Letra = 'C')

    $comDados = @($Itens | Where-Object { $_.Bytes -gt 0 } | Sort-Object Bytes -Descending)
    if ($comDados.Count -eq 0) { Write-Ok 'Nada relevante a liberar - sistema ja esta limpo.'; return }

    Write-Host ''
    Write-Host ('     {0,-34} {1,12}  {2}' -f 'Categoria', 'Tamanho', 'Requer') -ForegroundColor White
    Write-Host ('     ' + ('-' * 72)) -ForegroundColor DarkGray

    foreach ($i in $comDados) {
        $cor = switch ($i.Quando) {
            'padrao' { 'Green' }
            default  { 'DarkYellow' }
        }
        Write-Host ('     {0,-34} {1,12}  {2}' -f $i.Categoria, $i.Tamanho, $i.Quando) -ForegroundColor $cor
        if ($i.Observacao) { Write-Host ("        ^ $($i.Observacao)") -ForegroundColor DarkGray }
    }

    $padrao = [long](($comDados | Where-Object { $_.Quando -eq 'padrao' } | Measure-Object Bytes -Sum).Sum)
    $extra  = [long](($comDados | Where-Object { $_.Quando -ne 'padrao' -and $_.Categoria -ne 'AnyDesk: pasta completa' } |
                      Measure-Object Bytes -Sum).Sum)

    Write-Host ('     ' + ('-' * 76)) -ForegroundColor DarkGray
    Write-Host ('     {0,-32} {1,12}' -f 'SUBTOTAL execucao padrao', (Format-Tamanho $padrao)) -ForegroundColor Cyan
    Write-Host ('     {0,-32} {1,12}' -f 'SUBTOTAL etapas opcionais', (Format-Tamanho $extra)) -ForegroundColor DarkYellow
    Write-Host ('     {0,-32} {1,12}' -f 'POTENCIAL TOTAL', (Format-Tamanho ($padrao + $extra))) -ForegroundColor Green

    $vol = Get-Volume -DriveLetter $Letra -ErrorAction SilentlyContinue
    if ($vol -and $vol.Size -gt 0) {
        $antes  = $vol.SizeRemaining
        $depois = $antes + $padrao + $extra
        Write-Host ''
        Write-Host ('     Disco {0}:  livre agora {1} ({2:N1}%)  ->  apos limpeza total {3} ({4:N1}%)' -f `
            $Letra, (Format-Tamanho $antes), ($antes / $vol.Size * 100),
            (Format-Tamanho $depois), ($depois / $vol.Size * 100)) -ForegroundColor Cyan
    }

    $abertos = Get-NavegadoresAbertos
    if ($abertos.Count -gt 0) {
        Write-Host ''
        Write-Aviso "Feche estes navegadores para liberar o cache deles: $($abertos.Values -join ', ')"
    }

    $script:potencialPadrao = $padrao
    $script:potencialExtra  = $extra
}

# =========================================================================
# REGIAO: LIMPEZAS DO SISTEMA
# =========================================================================

function Clear-Temporarios {
    $total = [long]0

    Write-Etapa 'TEMP do usuario...'
    $b = Remove-Files -Pasta $env:TEMP
    $total += $b; Write-Ok "TEMP usuario   : $(Format-Tamanho $b)"

    Write-Etapa 'TEMP do sistema...'
    $b = Remove-Files -Pasta "$env:SystemRoot\Temp"
    $total += $b; Write-Ok "TEMP sistema   : $(Format-Tamanho $b)"

    Write-Etapa 'Relatorios de erro e dumps de memoria...'
    $b = [long]0
    $b += Remove-Files -Pasta "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
    $b += Remove-Files -Pasta "$env:ProgramData\Microsoft\Windows\WER\ReportArchive"
    $b += Remove-Files -Pasta "$env:LOCALAPPDATA\CrashDumps"
    # Minidumps dos ultimos 30 dias FICAM: sao a unica evidencia de tela azul
    # e e' exatamente essa janela que a analise de BSOD (opcao 5 do menu) le.
    # Cada um tem 1-2 MB, entao guardar nao atrapalha a liberacao de espaco.
    $b += Remove-Files -Pasta "$env:SystemRoot\Minidump" -DiasAntigos 30
    $b += Remove-Files -Pasta "$env:SystemRoot\Logs\CBS" -DiasAntigos 7
    # MEMORY.DMP sempre sai: costuma ter varios GB e e' o que enche o disco.
    # Se o chamado for tela azul, rode a analise de BSOD ANTES da manutencao.
    $dump = "$env:SystemRoot\MEMORY.DMP"
    if (Test-Path -LiteralPath $dump) {
        $t = [long](Get-Item -LiteralPath $dump -Force -ErrorAction SilentlyContinue).Length
        if ($SomenteRelatorio) {
            $b += $t   # em simulacao tambem precisa entrar na conta
        } else {
            try {
                Remove-Item -LiteralPath $dump -Force -ErrorAction Stop
                $b += $t
                Write-Aviso "MEMORY.DMP removido ($(Format-Tamanho $t)) - dump completo de tela azul."
                Write-Info  'Os minidumps dos ultimos 30 dias foram mantidos para analise de BSOD.'
            } catch { }
        }
    }
    $total += $b; Write-Ok "Erros e dumps  : $(Format-Tamanho $b)"

    Write-Etapa 'Cache de instaladores e entrega de conteudo...'
    $b = [long]0
    $b += Remove-Files -Pasta "$env:LOCALAPPDATA\Package Cache" -DiasAntigos 90
    $b += Remove-Files -Pasta "$env:LOCALAPPDATA\Downloaded Installations" -DiasAntigos 90
    $total += $b; Write-Ok "Instaladores   : $(Format-Tamanho $b)"

    # Prefetch limpo junto com os temporarios, por decisao do operador.
    # Efeito conhecido: os proximos 3-5 boots ficam mais lentos ate o Windows
    # reconstruir os arquivos .pf. Nao afeta dados, senhas nem programas.
    Write-Etapa 'Prefetch...'
    $b = Remove-Files -Pasta "$env:SystemRoot\Prefetch" -Filtro '*.pf'
    $total += $b; Write-Ok "Prefetch       : $(Format-Tamanho $b)"
    if ($b -gt 0) {
        Write-Aviso 'Os proximos 3-5 boots podem ficar mais lentos (cache sendo refeito).'
    }

    return $total
}

function Clear-LixeiraTodosDiscos {
    $total = [long]0
    $volumes = @(Get-Volume -ErrorAction SilentlyContinue |
                 Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter })

    foreach ($v in $volumes) {
        $letra = [string]$v.DriveLetter
        $lixeira = "${letra}:\" + '$Recycle.Bin'
        $bytes = [long]0
        try {
            $soma = (Get-ChildItem -LiteralPath $lixeira -Recurse -Force -File -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum
            if ($soma) { $bytes = [long]$soma }
        } catch { }

        if ($SomenteRelatorio) {
            Write-Simul "Lixeira ${letra}: $(Format-Tamanho $bytes) seriam liberados."
            $total += $bytes
            continue
        }
        try {
            Clear-RecycleBin -DriveLetter $letra -Force -Confirm:$false -ErrorAction Stop
            $total += $bytes
            Write-Ok "Lixeira ${letra}: $(Format-Tamanho $bytes)"
        } catch {
            Write-Info "Lixeira ${letra}: ja vazia ou inacessivel."
        }
    }
    return $total
}

function Clear-Miniaturas {
    $pasta = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
    $total = [long]0
    foreach ($filtro in @('thumbcache_*.db', 'iconcache_*.db')) {
        $total += Remove-Files -Pasta $pasta -Filtro $filtro
    }
    if ($total -gt 0) {
        Write-Ok "Cache de miniaturas: $(Format-Tamanho $total)"
    } else {
        Write-Aviso 'Arquivos em uso pelo Explorer. Serao refeitos no proximo logon.'
    }
    return $total
}

function Clear-WindowsUpdate {
    $total = [long]0
    if ($SomenteRelatorio) {
        $soma = (Get-ChildItem "$env:SystemRoot\SoftwareDistribution\Download" -Recurse -File -ErrorAction SilentlyContinue |
                 Measure-Object Length -Sum).Sum
        Write-Simul "Cache do Windows Update: $(Format-Tamanho ([long]$soma))"
        return [long]$soma
    }

    Write-Etapa 'Parando wuauserv, bits e cryptsvc...'
    $servicos = @('wuauserv', 'bits', 'dosvc')
    $estadoOriginal = @{}
    foreach ($s in $servicos) {
        $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
        if ($svc) {
            $estadoOriginal[$s] = $svc.Status
            Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
        }
    }
    try {
        Write-Ok 'Servicos pausados.'
        $total += Remove-Files -Pasta "$env:SystemRoot\SoftwareDistribution\Download"
        Write-Ok "Windows Update : $(Format-Tamanho $total)"

        # Cache do Delivery Optimization (pode ter varios GB)
        try {
            $doAntes = (Get-DeliveryOptimizationPerfSnap -ErrorAction SilentlyContinue)
            Delete-DeliveryOptimizationCache -Force -ErrorAction Stop
            Write-Ok 'Cache do Delivery Optimization removido.'
        } catch { }
    } finally {
        foreach ($s in $servicos) {
            if ($estadoOriginal.ContainsKey($s) -and $estadoOriginal[$s] -eq 'Running') {
                Start-Service -Name $s -ErrorAction SilentlyContinue
            }
        }
        Write-Ok 'Servicos restaurados ao estado original.'
    }
    return $total
}

function Clear-CacheAplicativos {
    <# Caches de apps comuns em escritorio, incluindo Java/PjeOffice. #>
    $total = [long]0

    $alvos = [ordered]@{
        'Java Deployment'  = "$env:LOCALAPPDATA\Sun\Java\Deployment\cache"
        'Java logs'        = "$env:APPDATA\Sun\Java\Deployment\log"
        'PjeOffice logs'   = "$env:USERPROFILE\.pjeoffice-pro\logs"
        'Shodo logs'       = "$env:USERPROFILE\.shodo\logs"
        'Teams cache'      = "$env:APPDATA\Microsoft\Teams\Cache"
        'Teams GPUCache'   = "$env:APPDATA\Microsoft\Teams\GPUCache"
        'Teams novo'       = "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Default\Cache"
        'Office cache'     = "$env:LOCALAPPDATA\Microsoft\Office\16.0\OfficeFileCache"
        'Adobe cache'      = "$env:LOCALAPPDATA\Adobe\Acrobat\DC\Cache"
        'Spotify cache'    = "$env:LOCALAPPDATA\Spotify\Data"
        'Discord cache'    = "$env:APPDATA\discord\Cache"
        'Miniaturas Win'   = "$env:LOCALAPPDATA\Microsoft\Windows\Caches"
        'Fontes cache'     = "$env:LOCALAPPDATA\FontCache"
    }

    foreach ($nome in $alvos.Keys) {
        $caminho = $alvos[$nome]
        if (-not (Test-Path -LiteralPath $caminho)) { continue }
        $dias = if ($nome -like '*logs*') { 30 } else { 0 }
        $b = Remove-Files -Pasta $caminho -DiasAntigos $dias
        if ($b -gt 0) {
            $total += $b
            Write-Ok ("{0,-18}: {1}" -f $nome, (Format-Tamanho $b))
        }
    }

    Write-Info 'Configuracoes, certificados e keystores do Java/PjeOffice preservados.'
    return $total
}

function Clear-ComponentesWindows {
    <# Etapa agressiva: WinSxS + cleanmgr. Pode levar 10-20 min. #>
    if ($SomenteRelatorio) {
        Write-Simul 'Executaria DISM /StartComponentCleanup e cleanmgr /sagerun.'
        & dism.exe /Online /Cleanup-Image /AnalyzeComponentStore | Out-Host
        return [long]0
    }

    Write-Etapa 'Compactando armazenamento de componentes (WinSxS)... pode demorar.'
    & dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase /Quiet | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'WinSxS compactado.'
        Write-Aviso '/ResetBase e irreversivel: nao sera possivel desinstalar atualizacoes antigas.'
    } else {
        Write-Aviso "DISM retornou codigo $LASTEXITCODE."
    }

    Write-Etapa 'Limpeza de disco automatizada (cleanmgr)...'
    try {
        $base = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
        Get-ChildItem $base -ErrorAction Stop | ForEach-Object {
            New-ItemProperty -Path $_.PSPath -Name 'StateFlags0077' -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Start-Process -FilePath 'cleanmgr.exe' -ArgumentList '/sagerun:77' -Wait -WindowStyle Hidden -ErrorAction Stop
        Write-Ok 'Limpeza de disco concluida.'
    } catch {
        Write-Aviso "cleanmgr indisponivel: $($_.Exception.Message)"
    }

    if (Test-Path 'C:\Windows.old') {
        Write-Aviso 'C:\Windows.old presente (instalacao anterior do Windows).'
        Write-Info  'O cleanmgr acima ja tenta remove-lo. Se persistir, use Configuracoes > Sistema > Armazenamento.'
    }

    return [long]0   # ganho medido pelo delta do volume
}

# =========================================================================
# REGIAO: REPARO DO ACESSO A %APPDATA% (Executar / ShellExecute)
#
# Sintoma: no Executar (Win+R) digitar %appdata% faz o Windows perguntar
# "Como voce deseja abrir este arquivo?" em vez de abrir a pasta.
#
# Causa: o Executar usa ShellExecute, que precisa do verbo 'open' da classe
# Directory. Quando HKCR\Directory\shell\open\command nao existe e o valor
# padrao de HKCR\Directory\shell e 'none', nao sobra verbo para abrir pasta.
# O duplo clique no Explorer continua funcionando porque usa outro caminho
# interno (IShellFolder), por isso o problema passa despercebido.
#
# Ferramentas de desenvolvedor (VS Code, Git, WSL, Antigravity, Codex...)
# costumam encher Directory\shell de verbos proprios; se o padrao ficar
# vazio, o shell ainda pode eleger o PRIMEIRO EM ORDEM ALFABETICA como
# padrao - por isso mantemos 'none' e recriamos apenas o 'open'.
# =========================================================================

function Test-AcessoAppData {
    $diag = [ordered]@{}
    $diag['APPDATA (sessao)']      = $env:APPDATA
    $diag['Pasta existe']          = (Test-Path -LiteralPath $env:APPDATA)

    $ve = Get-ItemProperty 'HKCU:\Volatile Environment' -ErrorAction SilentlyContinue
    $diag['Volatile APPDATA']      = if ($ve) { $ve.APPDATA } else { '(ausente)' }

    $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders')
    if ($k) {
        $diag['User Shell Folders'] = $k.GetValue('AppData', $null, 'DoNotExpandEnvironmentNames')
        $k.Close()
    }

    $dirOpen = Test-Path 'Registry::HKEY_CLASSES_ROOT\Directory\shell\open\command'
    $fldOpen = Test-Path 'Registry::HKEY_CLASSES_ROOT\Folder\shell\open\command'
    $diag['Directory\shell\open']  = if ($dirOpen) { 'OK' } else { 'AUSENTE  <-- causa do erro no Executar' }
    $diag['Folder\shell\open']     = if ($fldOpen) { 'OK' } else { 'AUSENTE' }

    $shellDefault = (Get-ItemProperty 'Registry::HKEY_CLASSES_ROOT\Directory\shell' -ErrorAction SilentlyContinue).'(default)'
    $diag['Directory\shell padrao'] = if ($null -eq $shellDefault -or $shellDefault -eq '') { "(vazio)  <-- risco: verbo de terceiro pode virar padrao" } else { $shellDefault }

    # Espaco no caminho do perfil agrava o problema no ShellExecute
    if ($env:APPDATA -match '\s') {
        $diag['Aviso caminho'] = 'Perfil contem espacos - use aspas ou shell:AppData'
    }
    return $diag
}

function Repair-AcessoAppData {
    <# Recria o verbo 'open' da classe Directory e cria atalhos garantidos. #>

    Write-Etapa 'Diagnostico do acesso a %appdata%...'
    $diag = Test-AcessoAppData
    foreach ($chave in $diag.Keys) { Write-Info ("{0,-24}: {1}" -f $chave, $diag[$chave]) }

    $precisaReparo = -not (Test-Path 'Registry::HKEY_CLASSES_ROOT\Directory\shell\open\command')

    if ($SomenteRelatorio) {
        if ($precisaReparo) { Write-Simul 'Recriaria HKCR\Directory\shell\open\command.' }
        else { Write-Simul 'Verbo open ja presente - nada a reparar.' }
        return [long]0
    }

    if ($precisaReparo) {
        # Backup antes de tocar em HKCR
        $pastaReg = Join-Path $script:pastaExec 'backup-registro'
        New-Item -ItemType Directory -Path $pastaReg -Force -ErrorAction SilentlyContinue | Out-Null
        & reg.exe export 'HKCR\Directory' (Join-Path $pastaReg 'HKCR_Directory.reg') /y 2>$null | Out-Null
        & reg.exe export 'HKCR\Folder'    (Join-Path $pastaReg 'HKCR_Folder.reg')    /y 2>$null | Out-Null

        try {
            $cmdPath = 'Registry::HKEY_CLASSES_ROOT\Directory\shell\open\command'
            New-Item -Path $cmdPath -Force -ErrorAction Stop | Out-Null
            # ExpandString e o tipo correto: precisa expandir %SystemRoot% e %1
            $key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey('Directory\shell\open\command', $true)
            $key.SetValue('', '%SystemRoot%\Explorer.exe "%1"', [Microsoft.Win32.RegistryValueKind]::ExpandString)
            $key.Close()
            Write-Ok 'Verbo open recriado em HKCR\Directory\shell\open\command'

            # Garante que nenhum verbo de terceiro vire o padrao
            Set-ItemProperty -Path 'Registry::HKEY_CLASSES_ROOT\Directory\shell' -Name '(default)' -Value 'none' -ErrorAction SilentlyContinue
            Write-Ok "Valor padrao de Directory\shell fixado em 'none'."
            $script:precisaReiniciar = $true
        } catch {
            Write-Falha "Nao foi possivel reparar: $($_.Exception.Message)"
        }
    } else {
        Write-Ok 'Verbo open da classe Directory ja esta presente.'
    }

    # Reforca as variaveis de ambiente do usuario, se estiverem faltando
    foreach ($par in @(@{N='APPDATA'; V='%USERPROFILE%\AppData\Roaming'},
                       @{N='LOCALAPPDATA'; V='%USERPROFILE%\AppData\Local'})) {
        $atual = [Environment]::GetEnvironmentVariable($par.N, 'User')
        if ([string]::IsNullOrWhiteSpace($atual) -and [string]::IsNullOrWhiteSpace((Get-ItemProperty 'HKCU:\Volatile Environment' -ErrorAction SilentlyContinue).($par.N))) {
            [Environment]::SetEnvironmentVariable($par.N, $par.V, 'User')
            Write-Ok "Variavel $($par.N) recriada."
        }
    }

    # Atalhos que funcionam mesmo com o shell quebrado
    try {
        $pastaAtalhos = Join-Path $env:USERPROFILE 'Desktop\Pastas do Sistema'
        New-Item -ItemType Directory -Path $pastaAtalhos -Force -ErrorAction SilentlyContinue | Out-Null
        $ws = New-Object -ComObject WScript.Shell
        $mapa = [ordered]@{
            'AppData Roaming' = $env:APPDATA
            'AppData Local'   = $env:LOCALAPPDATA
            'Temp do usuario' = $env:TEMP
            'Inicializar'     = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        }
        foreach ($nome in $mapa.Keys) {
            if (-not (Test-Path -LiteralPath $mapa[$nome])) { continue }
            $lnk = $ws.CreateShortcut((Join-Path $pastaAtalhos "$nome.lnk"))
            $lnk.TargetPath       = "$env:SystemRoot\explorer.exe"
            $lnk.Arguments        = '"' + $mapa[$nome] + '"'
            $lnk.IconLocation     = "$env:SystemRoot\system32\shell32.dll,3"
            $lnk.Description      = "Abre $($mapa[$nome])"
            $lnk.Save()
        }
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ws) | Out-Null
        Write-Ok "Atalhos criados em: $pastaAtalhos"
    } catch { Write-Aviso "Nao foi possivel criar atalhos: $($_.Exception.Message)" }

    Write-Host ''
    Write-Info 'Alternativas que SEMPRE funcionam no Executar (Win+R):'
    Write-Info '   shell:AppData          -> AppData\Roaming'
    Write-Info '   shell:Local AppData    -> AppData\Local'
    Write-Info '   shell:Startup          -> pasta Inicializar'
    Write-Info '   explorer %appdata%     -> forca o Explorer como executor'
    Write-Info '   "%appdata%" (com aspas) -> resolve caminho com espacos'

    return [long]0
}

# =========================================================================
# REGIAO: ANYDESK
#
# ATENCAO: %APPDATA%\AnyDesk guarda user.conf/service.conf, ou seja o ID do
# AnyDesk, a senha de acesso nao supervisionado e o historico de conexoes.
# Apagar a pasta inteira RESETA O ID DA MAQUINA - se voce usa AnyDesk para
# atender esse cliente, vai perder o acesso configurado.
# Por isso o padrao e 'SomenteLogs' (limpa ad.trace, chat e miniaturas,
# preservando ID e senha) e a pasta e copiada para o log antes de apagar.
# =========================================================================

# =========================================================================
# REGIAO: CERTIFICADOS DIGITAIS   (veio de ListarCertificados.ps1)
# =========================================================================

function Show-CertificadosInstalados {
    <#
      Lista os certificados das lojas pessoais do usuario e da maquina, com
      validade e se tem chave privada - que e' o que diz se o certificado
      serve para assinar. Somente leitura.
      Certificado A3 (token) so aparece com o token conectado e o middleware
      carregado: ausencia aqui nao significa que o certificado nao exista.
    #>
    param(
        [string]$Loja = 'My',
        [string]$Local = '',              # vazio = CurrentUser e LocalMachine
        [int]$DiasParaVencer = 30
    )

    function Get-StatusValidade {
        param([datetime]$DataExpiracao, [int]$Limite)
        $hoje = Get-Date
        $dias = ($DataExpiracao - $hoje).Days
        if ($DataExpiracao -lt $hoje)  { return @{ Status = 'EXPIRADO';       Cor = 'Red';    Dias = $dias } }
        elseif ($dias -le $Limite)     { return @{ Status = 'VENCE EM BREVE'; Cor = 'Yellow'; Dias = $dias } }
        else                           { return @{ Status = 'Valido';         Cor = 'Green';  Dias = $dias } }
    }
    function Get-CN {
        param([string]$Nome)
        if ($Nome -match 'CN=([^,]+)') { return $Matches[1].Trim() }
        return $Nome
    }
    function Get-CPFCNPJ {
        param([string]$Subject)
        if ($Subject -match ':(\d{14})\b') {
            $n = $Matches[1]
            return 'CNPJ ' + $n.Substring(0,2) + '.' + $n.Substring(2,3) + '.' + $n.Substring(5,3) + '/' + $n.Substring(8,4) + '-' + $n.Substring(12,2)
        }
        if ($Subject -match ':(\d{11})\b') {
            $n = $Matches[1]
            return 'CPF ' + $n.Substring(0,3) + '.' + $n.Substring(3,3) + '.' + $n.Substring(6,3) + '-' + $n.Substring(9,2)
        }
        return ''
    }

    $locais     = if ($Local) { @($Local) } else { @('CurrentUser', 'LocalMachine') }
    $totalGeral = 0
    $comChaveGeral = 0

    foreach ($loc in $locais) {
        $caminho = "Cert:\$loc\$Loja"
        Write-Etapa "Certificados em $loc\$Loja"

        try {
            $certificados = @(Get-ChildItem -Path $caminho -ErrorAction Stop)
        } catch {
            Write-Aviso ("Nao foi possivel acessar '$caminho': " + $_.Exception.Message)
            continue
        }

        if ($certificados.Count -eq 0) {
            Write-Info "Nenhum certificado nesta loja."
            continue
        }

        $lista = foreach ($cert in $certificados) {
            $sv = Get-StatusValidade -DataExpiracao $cert.NotAfter -Limite $DiasParaVencer
            $temChave = $false
            try { $temChave = $cert.HasPrivateKey } catch { }
            [PSCustomObject]@{
                Nome          = Get-CN $cert.Subject
                Identificador = Get-CPFCNPJ $cert.Subject
                Emissor       = Get-CN $cert.Issuer
                ValidoDe      = $cert.NotBefore.ToString('dd/MM/yyyy')
                ValidoAte     = $cert.NotAfter.ToString('dd/MM/yyyy')
                Dias          = $sv.Dias
                Status        = $sv.Status
                ChavePrivada  = $temChave
                Thumbprint    = $cert.Thumbprint
                Cor           = $sv.Cor
            }
        }
        $lista = @($lista)

        foreach ($item in ($lista | Sort-Object { $_.Status -ne 'Valido' }, ValidoAte)) {
            Write-Host ''
            Write-Dest  ("Nome       : " + $item.Nome)
            if ($item.Identificador) { Write-Info ("Documento  : " + $item.Identificador) }
            Write-Info  ("Emissor    : " + $item.Emissor)
            Write-Info  ("Valido de  : " + $item.ValidoDe + "  ate  " + $item.ValidoAte)
            Write-Host  ("     Status     : " + $item.Status + " (" + $item.Dias + " dias)") -ForegroundColor $item.Cor
            if ($item.ChavePrivada) {
                Write-Host '     Chave priv.: SIM - pode assinar documentos' -ForegroundColor Green
            } else {
                Write-Host '     Chave priv.: nao - somente a parte publica (nao assina)' -ForegroundColor DarkGray
            }
            Write-Host  ("     Thumbprint : " + $item.Thumbprint) -ForegroundColor DarkGray
        }

        $comChave = @($lista | Where-Object { $_.ChavePrivada }).Count
        $vencidos = @($lista | Where-Object { $_.Status -eq 'EXPIRADO' }).Count
        $aVencer  = @($lista | Where-Object { $_.Status -eq 'VENCE EM BREVE' }).Count

        Write-Host ''
        Write-Ok ("$loc : $($lista.Count) certificado(s)  |  com chave privada: $comChave")
        if ($vencidos -gt 0) { Write-Aviso "$vencidos vencido(s) nesta loja." }
        if ($aVencer -gt 0) {
            Write-Aviso "$aVencer vence(m) nos proximos $DiasParaVencer dias."
            Add-Alerta "$aVencer certificado(s) vencendo em ate $DiasParaVencer dias em $loc."
        }

        $totalGeral += $lista.Count
        $comChaveGeral += $comChave
    }

    Write-Host ''
    Write-Ok "Total: $totalGeral certificado(s), $comChaveGeral com chave privada."
    Write-Info 'Token A3 so aparece com o token conectado e o middleware instalado.'
    Write-Info 'Gerenciar a mao: certmgr.msc (usuario) ou certlm.msc (maquina).'
    return [long]0
}

function Install-VisualCRedist {
    <#
      Instala os redistribuiveis Visual C++ que faltam (veio de InstalarVisualC.ps1).
      Confere a assinatura da Microsoft antes de executar cada instalador.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Verificaria e instalaria os redistribuiveis Visual C++ que faltam.'; return [long]0 }



    # =========================================================================
    # Cabecalho
    # =========================================================================

    Write-Etapa 'Redistribuiveis Visual C++ para sistemas juridicos'


    # =========================================================================
    # Definicao dos pacotes necessarios
    # =========================================================================

    $pacotes = @(
        [PSCustomObject]@{
            Nome    = 'Visual C++ 2005 SP1'
            Ano     = '2005'
            Arq     = 'x86'
            Padroes = @('2005')
            URL     = 'https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE'
            Arquivo = 'vcredist_2005_x86.exe'
            Params  = '/q:a /r:n'
        }
        [PSCustomObject]@{
            Nome    = 'Visual C++ 2005 SP1'
            Ano     = '2005'
            Arq     = 'x64'
            Padroes = @('2005')
            URL     = 'https://download.microsoft.com/download/6/B/B/6BB661D6-A8AE-4819-B79F-236472F6070C/vcredist_x64.EXE'
            Arquivo = 'vcredist_2005_x64.exe'
            Params  = '/q:a /r:n'
        }
        [PSCustomObject]@{
            Nome    = 'Visual C++ 2008 SP1'
            Ano     = '2008'
            Arq     = 'x86'
            Padroes = @('2008')
            URL     = 'https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe'
            Arquivo = 'vcredist_2008_x86.exe'
            Params  = '/q'
        }
        [PSCustomObject]@{
            Nome    = 'Visual C++ 2008 SP1'
            Ano     = '2008'
            Arq     = 'x64'
            Padroes = @('2008')
            URL     = 'https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe'
            Arquivo = 'vcredist_2008_x64.exe'
            Params  = '/q'
        }
        [PSCustomObject]@{
            Nome    = 'Visual C++ 2010 SP1'
            Ano     = '2010'
            Arq     = 'x86'
            Padroes = @('2010')
            URL     = 'https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe'
            Arquivo = 'vcredist_2010_x86.exe'
            Params  = '/quiet /norestart'
        }
        [PSCustomObject]@{
            Nome    = 'Visual C++ 2010 SP1'
            Ano     = '2010'
            Arq     = 'x64'
            Padroes = @('2010')
            URL     = 'https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe'
            Arquivo = 'vcredist_2010_x64.exe'
            Params  = '/quiet /norestart'
        }
        [PSCustomObject]@{
            Nome    = 'Visual C++ 2012 Update 4'
            Ano     = '2012'
            Arq     = 'x86'
            Padroes = @('2012')
            URL     = 'https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe'
            Arquivo = 'vcredist_2012_x86.exe'
            Params  = '/quiet /norestart'
        }
        [PSCustomObject]@{
            Nome    = 'Visual C++ 2012 Update 4'
            Ano     = '2012'
            Arq     = 'x64'
            Padroes = @('2012')
            URL     = 'https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe'
            Arquivo = 'vcredist_2012_x64.exe'
            Params  = '/quiet /norestart'
        }
        [PSCustomObject]@{
            Nome    = 'Visual C++ 2013 Update 5'
            Ano     = '2013'
            Arq     = 'x86'
            Padroes = @('2013')
            URL     = 'https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x86.exe'
            Arquivo = 'vcredist_2013_x86.exe'
            Params  = '/install /quiet /norestart'
        }
        [PSCustomObject]@{
            Nome    = 'Visual C++ 2013 Update 5'
            Ano     = '2013'
            Arq     = 'x64'
            Padroes = @('2013')
            URL     = 'https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe'
            Arquivo = 'vcredist_2013_x64.exe'
            Params  = '/install /quiet /norestart'
        }
        [PSCustomObject]@{
            Nome    = 'Visual C++ 2015-2022'
            Ano     = '2015-2022'
            Arq     = 'x86'
            Padroes = @('2015', '2017', '2019', '2022', '2015-2022')
            URL     = 'https://aka.ms/vs/17/release/vc_redist.x86.exe'
            Arquivo = 'vcredist_2015_2022_x86.exe'
            Params  = '/install /quiet /norestart'
        }
        [PSCustomObject]@{
            Nome    = 'Visual C++ 2015-2022'
            Ano     = '2015-2022'
            Arq     = 'x64'
            Padroes = @('2015', '2017', '2019', '2022', '2015-2022')
            URL     = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'
            Arquivo = 'vcredist_2015_2022_x64.exe'
            Params  = '/install /quiet /norestart'
        }
    )

    # =========================================================================
    # ETAPA 1 - Listar redistribuiveis ja instalados
    # =========================================================================

    Write-Etapa '1. Listando redistribuiveis Visual C++ ja instalados...'
    Write-Host ''

    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    $instalados = [System.Collections.Generic.List[PSObject]]::new()
    $nomesUnicos = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($regPath in $regPaths) {
        $itens = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue |
            Get-ItemProperty -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match 'Microsoft Visual C\+\+' }
        foreach ($item in $itens) {
            $chave = "$($item.DisplayName)|$($item.DisplayVersion)"
            if ($nomesUnicos.Add($chave)) {
                $instalados.Add($item)
            }
        }
    }

    if ($instalados.Count -gt 0) {
        $instalados | Sort-Object DisplayName | ForEach-Object {
            $arqLabel = if ($_.DisplayName -match '\(x64\)' -or $_.DisplayName -match '- x64') { 'x64' }
                        elseif ($_.DisplayName -match '\(x86\)' -or $_.DisplayName -match '- x86') { 'x86' }
                        else { '   ' }
            Write-Host ("   {0,-6}  {1}" -f "[$arqLabel]", $_.DisplayName) -ForegroundColor White
            if ($_.DisplayVersion) {
                Write-Host ("          Versao: {0}" -f $_.DisplayVersion) -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Aviso 'Nenhum redistribuivel Visual C++ encontrado.'
    }

    # Funcao de verificacao de instalacao
    function Test-VCInstalado {
        param([string[]]$Padroes, [string]$Arq)
        foreach ($regPath in $regPaths) {
            $itens = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue |
                Get-ItemProperty -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -match 'Microsoft Visual C\+\+' }
            foreach ($item in $itens) {
                $nome = $item.DisplayName
                # Pacotes antigos (2005/2008) nomeiam so a versao x64; a x86 vem
                # sem sufixo nenhum. Sem este tratamento a x86 nunca era vista
                # como instalada e o script rebaixava e reinstalava toda vez.
                $marcaX64 = ($nome -match [regex]::Escape('(x64)') -or $nome -match '[\s-]x64[\s\.]' -or $nome -match 'x64$')
                $marcaX86 = ($nome -match [regex]::Escape('(x86)') -or $nome -match '[\s-]x86[\s\.]' -or $nome -match 'x86$')

                if ($Arq -eq 'x64') {
                    if (-not $marcaX64) { continue }
                } else {
                    # x86 = tem marca x86, ou nao tem marca alguma de arquitetura
                    if ($marcaX64) { continue }
                }
                foreach ($p in $Padroes) {
                    if ($nome -match [regex]::Escape($p)) { return $true }
                }
            }
        }
        return $false
    }

    # =========================================================================
    # ETAPA 2 - Verificar quais versoes essenciais estao faltando
    # =========================================================================

    Write-Etapa '2. Verificando versoes essenciais necessarias...'
    Write-Host ''

    $faltando = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($pkg in $pacotes) {
        $estaInstalado = Test-VCInstalado -Padroes $pkg.Padroes -Arq $pkg.Arq
        if ($estaInstalado) {
            Write-Ok "$($pkg.Nome) ($($pkg.Arq)) - ja instalado"
        } else {
            Write-Aviso "$($pkg.Nome) ($($pkg.Arq)) - FALTANDO"
            $faltando.Add($pkg)
        }
    }

    if ($faltando.Count -eq 0) {
        Write-Host ''
        Write-Ok 'Todos os redistribuiveis necessarios ja estao instalados.'
        Write-Host ''
        Write-Host ''
            return [long]0
    }

    Write-Host ''
    Write-Aviso "$($faltando.Count) pacote(s) serao baixados e instalados."

    # =========================================================================
    # ETAPAS 3 e 4 - Baixar e instalar os pacotes faltando
    # =========================================================================

    Write-Etapa "3/4. Baixando e instalando $($faltando.Count) pacote(s)..."

    $tmpDir = $env:TEMP
    $resumoInstalados  = [System.Collections.Generic.List[string]]::new()
    $resumoFalhas      = [System.Collections.Generic.List[string]]::new()
    $num = 0

    foreach ($pkg in $faltando) {
        $num++
        $destino = Join-Path $tmpDir $pkg.Arquivo
        $label   = "$($pkg.Nome) ($($pkg.Arq))"

        Write-Host ''
        Write-Host ("   [{0}/{1}]  {2}" -f $num, $faltando.Count, $label) -ForegroundColor Cyan

        # ----- Download -----
        $downloadOk = $false
        Write-Info "Baixando de: $($pkg.URL)"

        # Tentativa 1: BITS Transfer (mostra progresso nativo)
        try {
            Import-Module BitsTransfer -ErrorAction Stop
            Start-BitsTransfer -Source $pkg.URL -Destination $destino `
                -Description "Baixando $label" -Priority Normal -ErrorAction Stop
            $downloadOk = $true
            Write-Ok 'Download concluido.'
        } catch {
            Write-Aviso "BITS indisponivel, usando WebRequest..."
            # Tentativa 2: Invoke-WebRequest com progresso manual
            try {
                $ProgressPreference = 'SilentlyContinue'
                Invoke-WebRequest -Uri $pkg.URL -OutFile $destino `
                    -UseBasicParsing -ErrorAction Stop
                $ProgressPreference = 'Continue'
                $downloadOk = $true
                Write-Ok 'Download concluido.'
            } catch {
                Write-Falha "Erro no download: $_"
                $resumoFalhas.Add("$label  (falha no download)")
                continue
            }
        }

        if (-not $downloadOk -or -not (Test-Path $destino)) {
            Write-Falha 'Arquivo nao encontrado apos o download.'
            $resumoFalhas.Add("$label  (arquivo nao baixado)")
            continue
        }

        $tamanhoMB = [math]::Round((Get-Item $destino).Length / 1MB, 1)
        Write-Info "Arquivo: $($pkg.Arquivo)  ($tamanhoMB MB)"

        # ----- Conferir a assinatura digital antes de executar -----
        # O arquivo veio da internet e vai rodar como Administrador. Se o
        # download for interceptado ou o link redirecionado, sem esta checagem
        # o script executaria um binario qualquer com privilegio total.
        $assinaturaOk = $false
        try {
            $sig = Get-AuthenticodeSignature -FilePath $destino -ErrorAction Stop
            if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate -and
                $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation') {
                $assinaturaOk = $true
                Write-Ok 'Assinatura digital conferida: Microsoft Corporation.'
            } else {
                $quem = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'sem assinatura' }
                Write-Falha "Assinatura invalida ou nao e da Microsoft (status: $($sig.Status))."
                Write-Info  "Assinante: $quem"
            }
        } catch {
            Write-Falha "Nao foi possivel verificar a assinatura: $_"
        }

        if (-not $assinaturaOk) {
            Write-Aviso 'Instalacao ABORTADA por seguranca. Arquivo descartado.'
            Remove-Item -Path $destino -Force -ErrorAction SilentlyContinue
            $resumoFalhas.Add("$label  (assinatura digital nao confere)")
            continue
        }

        # ----- Instalacao -----
        Write-Info "Instalando silenciosamente..."
        try {
            $proc = Start-Process -FilePath $destino `
                -ArgumentList $pkg.Params `
                -Wait -PassThru -NoNewWindow -ErrorAction Stop

            switch ($proc.ExitCode) {
                0    {
                    Write-Ok "Instalado com sucesso."
                    $resumoInstalados.Add($label)
                }
                3010 {
                    Write-Ok "Instalado com sucesso. (reinicio necessario)"
                    $resumoInstalados.Add("$label  [reinicio necessario]")
                    $script:precisaReiniciar = $true
                }
                1638 {
                    Write-Ok "Versao mais recente ja instalada (codigo 1638)."
                    $resumoInstalados.Add("$label  [versao mais recente ja presente]")
                }
                default {
                    Write-Falha "Instalacao encerrada com codigo: $($proc.ExitCode)"
                    $resumoFalhas.Add("$label  (codigo de saida: $($proc.ExitCode))")
                }
            }
        } catch {
            Write-Falha "Erro ao executar instalador: $_"
            $resumoFalhas.Add("$label  (erro ao executar)")
        }

        # Remover arquivo temporario
        Remove-Item -Path $destino -Force -ErrorAction SilentlyContinue
    }

    # =========================================================================
    # ETAPA 5 - Relatorio final
    # =========================================================================

    Write-Host ''
    Write-Host '   RELATORIO FINAL                              ' -ForegroundColor Green
    Write-Host ''

    $jaInstalados = $pacotes.Count - $faltando.Count
    Write-Host "   Ja instalados antes  : $jaInstalados de $($pacotes.Count)" -ForegroundColor White
    Write-Host "   Instalados agora     : $($resumoInstalados.Count)" -ForegroundColor White
    Write-Host "   Falhas               : $($resumoFalhas.Count)" -ForegroundColor White
    Write-Host ''

    if ($resumoInstalados.Count -gt 0) {
        Write-Host '   Instalados nesta execucao:' -ForegroundColor Green
        foreach ($linha in $resumoInstalados) {
            Write-Host "   + $linha" -ForegroundColor Green
        }
        Write-Host ''
    }

    if ($resumoFalhas.Count -gt 0) {
        Write-Host '   Falhas:' -ForegroundColor Red
        foreach ($linha in $resumoFalhas) {
            Write-Host "   x $linha" -ForegroundColor Red
        }
        Write-Host ''
        Write-Aviso 'Para os pacotes com falha, verifique a conexao com a internet e execute novamente.'
        Write-Host ''
    }

    if ($script:precisaReiniciar) {
        Write-Host '   IMPORTANTE: Reinicie o computador para concluir a instalacao.' -ForegroundColor Yellow
        Write-Host ''
    }

    if ($resumoFalhas.Count -eq 0 -and $resumoInstalados.Count -ge 0) {
        Write-Host '   Todos os redistribuiveis Visual C++ necessarios estao instalados.' -ForegroundColor Green
        Write-Host ''
    }

    Write-Host ''
    return [long]0
}

function Set-JavaJuridico {
    <#
      Veio de ConfigurarJava.ps1.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Configuraria o Java 8 para os sistemas juridicos (security level, exception.sites, cache).'; return [long]0 }
    # ConfigurarJava.ps1
    # Configura Java 8 para sistemas juridicos brasileiros (PJe, PROJUDI, eProc, Shodo, Shomei)

    $resumo = [System.Collections.Generic.List[string]]::new()


    function Add-Resumo  { param([string]$l) $script:resumo.Add($l) }

    # Escreve arquivo de texto sem BOM (Java nao suporta BOM em .properties)
    function Write-TextFile {
        param([string]$Caminho, [object]$Linhas)
        $enc = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllLines($Caminho, [string[]]$Linhas, $enc)
    }

    # =========================================================================
    # Cabecalho
    # =========================================================================

    Write-Host ''
    Write-Host '  Java 8 - Configuracao para Sistemas Juridicos ' -ForegroundColor Cyan
    Write-Host ''

    # =========================================================================
    # ETAPA 1 - Verificar Java 8
    # =========================================================================

    Write-Etapa '1. Verificando instalacao do Java 8...'

    $javaHome = $null

    # Busca no registro (64-bit e 32-bit)
    $regRaizes = @(
        'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment',
        'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment'
    )
    foreach ($raiz in $regRaizes) {
        if (-not (Test-Path $raiz -ErrorAction SilentlyContinue)) { continue }
        Get-ChildItem -Path $raiz -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.PSChildName -like '1.8*' -and -not $javaHome) {
                $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if ($p.JavaHome -and (Test-Path "$($p.JavaHome)\bin\java.exe")) {
                    $javaHome = $p.JavaHome
                }
            }
        }
        if ($javaHome) { break }
    }

    # Busca em caminhos comuns de instalacao
    if (-not $javaHome) {
        foreach ($base in @('C:\Program Files\Java', 'C:\Program Files (x86)\Java')) {
            if (-not (Test-Path $base)) { continue }
            $dir = Get-ChildItem -Path $base -Directory -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -like 'jre1.8*' -or $_.Name -like 'jdk1.8*' } |
                   Sort-Object Name -Descending |
                   Select-Object -First 1
            if ($dir -and (Test-Path "$($dir.FullName)\bin\java.exe")) {
                $javaHome = $dir.FullName
                break
            }
        }
    }

    if (-not $javaHome) {
        Write-Falha 'Java 8 (JRE 1.8.x) nao encontrado neste computador.'
        Write-Info  'Baixe e instale em: https://www.java.com'
        Write-Info  'Execute este script novamente apos a instalacao.'
        Write-Host ''
            return [long]0
    }

    $javaBin  = "$javaHome\bin\java.exe"
    $verRaw   = & "$javaBin" -version 2>&1
    $verLinha = ($verRaw | Select-Object -First 1).ToString()
    Write-Ok "Versao encontrada: $verLinha"
    Write-Info "Diretorio: $javaHome"
    Add-Resumo "Java 8 encontrado: $verLinha"
    Add-Resumo "Diretorio Java: $javaHome"

    # =========================================================================
    # ETAPA 2 - Localizar deployment.properties
    # =========================================================================

    Write-Etapa '2. Localizando arquivo deployment.properties...'

    $possiveis = @(
        "$env:USERPROFILE\AppData\LocalLow\Sun\Java\Deployment\deployment.properties",
        "$env:APPDATA\Sun\Java\Deployment\deployment.properties",
        "$env:USERPROFILE\.java\deployment\deployment.properties",
        'C:\Windows\Sun\Java\Deployment\deployment.properties'
    )

    $deployProps = $null
    $deployDir   = $null

    foreach ($candidato in $possiveis) {
        if (Test-Path $candidato) {
            $deployProps = $candidato
            $deployDir   = Split-Path -Parent $candidato
            Write-Ok "Encontrado: $deployProps"
            break
        }
    }

    if (-not $deployProps) {
        $deployDir   = "$env:USERPROFILE\AppData\LocalLow\Sun\Java\Deployment"
        $deployProps = "$deployDir\deployment.properties"
        if (-not (Test-Path $deployDir)) {
            New-Item -ItemType Directory -Path $deployDir -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Write-TextFile -Caminho $deployProps -Linhas @()
        Write-Aviso "Nao encontrado em nenhum local padrao."
        Write-Ok   "Criado novo arquivo em: $deployProps"
    }

    Add-Resumo "deployment.properties: $deployProps"

    # =========================================================================
    # ETAPA 3 - Backup do deployment.properties
    # =========================================================================

    Write-Etapa '3. Criando backup do deployment.properties...'

    $ts         = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupPath = "$deployProps.bak.$ts"

    try {
        Copy-Item -Path $deployProps -Destination $backupPath -Force -ErrorAction Stop
        Write-Ok "Backup criado: $backupPath"
        Add-Resumo "Backup: $backupPath"
    } catch {
        Write-Aviso "Nao foi possivel criar backup: $_"
    }

    # =========================================================================
    # ETAPA 4 - Configurar nivel de seguranca MEDIUM
    # =========================================================================

    Write-Etapa '4. Configurando nivel de seguranca do Java...'

    # MEDIUM foi removido do Java a partir do 8u20: os unicos niveis validos sao
    # HIGH e VERY_HIGH. Gravar MEDIUM faz o Java ignorar e cair de volta em HIGH.
    # Quem realmente libera os sistemas juridicos e' o exception.sites (etapa 5).
    $chaveNivel  = 'deployment.security.level'
    $chaveLocked = 'deployment.security.level.locked'
    $chaveExpira = 'deployment.expiration.check.enabled'
    $chaveWebJava = 'deployment.webjava.enabled'

    $linhasDP   = [System.IO.File]::ReadAllLines($deployProps)
    $novaDP     = [System.Collections.Generic.List[string]]::new()
    $achouNivel = $false

    foreach ($linha in $linhasDP) {
        # Qualquer chave .locked trava o painel do Java: removida do arquivo.
        if ($linha -match '^\s*deployment\..*\.locked\s*=') {
            Write-Aviso ('Removendo bloqueio: ' + ($linha -split '=')[0].Trim())
            continue
        }
        if ($linha -match "^\s*$chaveNivel\s*=") {
            $novaDP.Add("$chaveNivel=HIGH")
            $achouNivel = $true
        } elseif ($linha -match "^\s*$chaveExpira\s*=" -or $linha -match "^\s*$chaveWebJava\s*=") {
            continue
        } else {
            $novaDP.Add($linha)
        }
    }
    if (-not $achouNivel) { $novaDP.Add("$chaveNivel=HIGH") }

    # Evita o aviso "Java desatualizado" que trava o usuario, e garante applets.
    $novaDP.Add("$chaveExpira=false")
    $novaDP.Add("$chaveWebJava=true")

    Write-TextFile -Caminho $deployProps -Linhas $novaDP

    if ($achouNivel) {
        Write-Ok 'deployment.security.level atualizado para HIGH.'
    } else {
        Write-Ok 'deployment.security.level=HIGH adicionado.'
    }
    Write-Info 'Bloqueios (.locked) removidos e verificacao de expiracao desativada.'
    Add-Resumo 'Seguranca: deployment.security.level=HIGH (bloqueios removidos)'

    # =========================================================================
    # ETAPA 5 - Configurar excecoes de sites
    # =========================================================================

    Write-Etapa '5. Configurando excecoes de sites para sistemas juridicos...'

    $urlsNecessarias = [ordered]@{
        'https://127.0.0.1:9000'         = 'Shodo'
        'https://127.0.0.1:9003'         = 'Shomei'
        'http://127.0.0.1'               = 'PJe / PROJUDI local'
        'https://pje.jus.br'             = 'PJe nacional'
        'https://projudi.tjgo.jus.br'    = 'PROJUDI TJGO'
        'https://projudi.tjam.jus.br'    = 'PROJUDI TJAM'
        'https://projudi.tjrr.jus.br'    = 'PROJUDI TJRR'
        'https://projudi.tjap.jus.br'    = 'PROJUDI TJAP'
        'https://projudi.tjba.jus.br'    = 'PROJUDI TJBA'
        'https://projudi.tjpa.jus.br'    = 'PROJUDI TJPA'
        'https://projudi.tjmt.jus.br'    = 'PROJUDI TJMT'
        'https://projudi.tjms.jus.br'    = 'PROJUDI TJMS'
        'https://projudi.tjto.jus.br'    = 'PROJUDI TJTO'
        'https://projudi.tjpi.jus.br'    = 'PROJUDI TJPI'
        'https://projudi.tjma.jus.br'    = 'PROJUDI TJMA'
        'https://projudi.tjal.jus.br'    = 'PROJUDI TJAL'
        'https://projudi.tjse.jus.br'    = 'PROJUDI TJSE'
        'https://projudi.tjpb.jus.br'    = 'PROJUDI TJPB'
        'https://projudi.tjrn.jus.br'    = 'PROJUDI TJRN'
        'https://projudi.tjce.jus.br'    = 'PROJUDI TJCE'
        'https://projudi.tjpe.jus.br'    = 'PROJUDI TJPE'
        'https://projudi.tjac.jus.br'    = 'PROJUDI TJAC'
        'https://projudi.tjro.jus.br'    = 'PROJUDI TJRO'
        'https://projudi.tjrj.jus.br'    = 'PROJUDI TJRJ'
        'https://projudi.tjes.jus.br'    = 'PROJUDI TJES'
        'https://projudi.tjmg.jus.br'    = 'PROJUDI TJMG'
        'https://projudi.tjsp.jus.br'    = 'PROJUDI TJSP'
        'https://projudi.tjpr.jus.br'    = 'PROJUDI TJPR'
        'https://projudi.tjsc.jus.br'    = 'PROJUDI TJSC'
        'https://projudi.tjrs.jus.br'    = 'PROJUDI TJRS'
        'https://projudi.tjdft.jus.br'   = 'PROJUDI TJDFT'
        'https://eproc.jfrs.jus.br'      = 'eProc JFRS'
        'https://eproc1.trf4.jus.br'     = 'eProc TRF4 (1)'
        'https://eproc2.trf4.jus.br'     = 'eProc TRF4 (2)'
    }

    # Determina caminho do exception.sites a partir do deployment.properties
    $chaveExcecoes = 'deployment.user.security.exception.sites'
    $pathExcecoes  = $null

    $dpAtual = [System.IO.File]::ReadAllLines($deployProps)
    foreach ($linha in $dpAtual) {
        if ($linha -match "^$chaveExcecoes\s*=\s*(.+)$") {
            $pathExcecoes = ($Matches[1].Trim()) -replace '/', '\'
            break
        }
    }

    if (-not $pathExcecoes) {
        $pathExcecoes = "$deployDir\security\exception.sites"
    }

    # Cria o diretorio se nao existir
    $dirExcecoes = Split-Path -Parent $pathExcecoes
    if (-not (Test-Path $dirExcecoes)) {
        New-Item -ItemType Directory -Path $dirExcecoes -Force -ErrorAction SilentlyContinue | Out-Null
    }

    # Le URLs ja existentes no arquivo
    $urlsExistentes = @()
    if (Test-Path $pathExcecoes) {
        $urlsExistentes = [System.IO.File]::ReadAllLines($pathExcecoes) |
                          Where-Object { $_.Trim() -ne '' } |
                          ForEach-Object { $_.Trim() }
    }

    $conjExistentes = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($u in $urlsExistentes) { [void]$conjExistentes.Add($u) }

    $listaFinal = [System.Collections.Generic.List[string]]::new()
    foreach ($u in $urlsExistentes) { $listaFinal.Add($u) }

    $qtdAdicionados = 0
    $qtdJaExistiam  = 0

    foreach ($url in $urlsNecessarias.Keys) {
        $label = $urlsNecessarias[$url]
        if ($conjExistentes.Contains($url)) {
            Write-Aviso "Ja existe:  $url  ($label)"
            $qtdJaExistiam++
        } else {
            $listaFinal.Add($url)
            Write-Ok   "Adicionado: $url  ($label)"
            $qtdAdicionados++
        }
    }

    Write-TextFile -Caminho $pathExcecoes -Linhas $listaFinal

    # Garante que deployment.properties aponta para o exception.sites
    $pathExcecoesJava = $pathExcecoes -replace '\\', '/'
    $dpAtual2   = [System.IO.File]::ReadAllLines($deployProps)
    $dpLista2   = [System.Collections.Generic.List[string]]::new()
    $achouChave = $false
    foreach ($linha in $dpAtual2) {
        if ($linha -match "^$chaveExcecoes\s*=") {
            $dpLista2.Add("$chaveExcecoes=$pathExcecoesJava")
            $achouChave = $true
        } else {
            $dpLista2.Add($linha)
        }
    }
    if (-not $achouChave) { $dpLista2.Add("$chaveExcecoes=$pathExcecoesJava") }
    Write-TextFile -Caminho $deployProps -Linhas $dpLista2

    Write-Info "Arquivo exception.sites: $pathExcecoes"
    Write-Info "Adicionados: $qtdAdicionados  |  Ja existiam: $qtdJaExistiam  |  Total na lista: $($listaFinal.Count)"
    Add-Resumo "Excecoes: $qtdAdicionados URL(s) adicionada(s), $qtdJaExistiam ja existiam"
    Add-Resumo "exception.sites: $pathExcecoes"

    # =========================================================================
    # ETAPA 6 - Limpar cache do Java
    # =========================================================================

    Write-Etapa '6. Limpando cache do Java...'

    $dirsCache = @(
        "$env:USERPROFILE\AppData\LocalLow\Sun\Java\Deployment\cache",
        "$env:APPDATA\Sun\Java\Deployment\cache"
    )

    $totalBytes  = [long]0
    $cacheLimpos = 0

    foreach ($dir in $dirsCache) {
        if (-not (Test-Path $dir)) { continue }
        try {
            $arquivos = Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue
            $bytes    = ($arquivos | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            if ($bytes) { $totalBytes += [long]$bytes }
            Remove-Item -Path "$dir\*" -Recurse -Force -ErrorAction SilentlyContinue
            $cacheLimpos++
            $tamanho = if ($bytes -ge 1MB) { '{0:N1} MB' -f ($bytes / 1MB) } `
                       elseif ($bytes -ge 1KB) { '{0:N0} KB' -f ($bytes / 1KB) } `
                       else { "$bytes bytes" }
            Write-Ok "Cache limpo: $dir  ($tamanho)"
        } catch {
            Write-Aviso "Nao foi possivel limpar cache em: $dir"
        }
    }

    if ($cacheLimpos -eq 0) {
        Write-Info 'Pasta de cache nao encontrada ou ja estava vazia.'
        Add-Resumo 'Cache Java: nenhum arquivo encontrado'
    } else {
        $totalStr = if ($totalBytes -ge 1MB) { '{0:N1} MB' -f ($totalBytes / 1MB) } `
                    elseif ($totalBytes -ge 1KB) { '{0:N0} KB' -f ($totalBytes / 1KB) } `
                    else { "$totalBytes bytes" }
        Add-Resumo "Cache Java limpo: $totalStr removidos"
    }

    # =========================================================================
    # RESUMO FINAL
    # =========================================================================

    Write-Host ''
    Write-Host '   Configuracao concluida com sucesso!          ' -ForegroundColor Green
    Write-Host ''

    foreach ($linha in $resumo) {
        Write-Host "  $linha" -ForegroundColor Gray
    }

    Write-Host ''
    Write-Host '  Proximos passos recomendados:' -ForegroundColor Cyan
    Write-Host '  1. Feche todos os navegadores abertos' -ForegroundColor White
    Write-Host '  2. Acesse o sistema juridico normalmente' -ForegroundColor White
    Write-Host '  3. Se aparecer aviso de seguranca Java, clique em Executar' -ForegroundColor White
    Write-Host '  4. Se ainda houver problemas, verifique o token/certificado' -ForegroundColor White
    Write-Host ''
    Write-Host ''
    return [long]0
}

function Remove-ImpressoraEDriver {
    <#
      Veio de ReinstalarImpressora.ps1.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Listaria as impressoras para remocao de impressora e driver.'; return [long]0 }
    # ReinstalarImpressora.ps1
    # Remove e reinstala driver de impressora com limpeza completa




    # =========================================================================
    # Cabecalho
    # =========================================================================

    Write-Host ''
    Write-Host '   Remocao e Limpeza de Driver de Impressora    ' -ForegroundColor Cyan
    Write-Host ''

    # Verificar privilegios de administrador

    # =========================================================================
    # ETAPA 1 - Listar impressoras instaladas
    # =========================================================================

    Write-Etapa '1. Listando impressoras instaladas...'
    Write-Host ''

    $impressoras = @(Get-Printer -ErrorAction SilentlyContinue | Sort-Object Name)

    if ($impressoras.Count -eq 0) {
        Write-Aviso 'Nenhuma impressora encontrada no sistema.'
        Write-Host ''
            return [long]0
    }

    $i = 1
    foreach ($imp in $impressoras) {
        $tipo = if ($imp.Type -eq 'Connection') { 'Rede' } else { 'Local' }
        Write-Host ("   [{0,2}]  {1}" -f $i, $imp.Name) -ForegroundColor White
        Write-Host ("         Driver : {0}" -f $imp.DriverName) -ForegroundColor Gray
        Write-Host ("         Porta  : {0}  |  Tipo: {1}" -f $imp.PortName, $tipo) -ForegroundColor Gray
        Write-Host ''
        $i++
    }

    # Selecao da impressora
    $selecao = $null
    do {
        $entrada = Read-Host '   Digite o numero da impressora a remover (0 para cancelar)'
        if ($entrada -eq '0') {
            Write-Info 'Operacao cancelada pelo usuario.'
            return [long]0
        }
        if ($entrada -match '^\d+$') {
            $num = [int]$entrada
            if ($num -ge 1 -and $num -le $impressoras.Count) {
                $selecao = $num
            } else {
                Write-Aviso "Numero invalido. Digite entre 1 e $($impressoras.Count)."
            }
        } else {
            Write-Aviso 'Digite apenas o numero correspondente.'
        }
    } while ($null -eq $selecao)

    $impressoraSel = $impressoras[$selecao - 1]
    $nomeImpressora = $impressoraSel.Name
    $nomeDriver     = $impressoraSel.DriverName
    $nomePorta      = $impressoraSel.PortName

    Write-Host ''
    Write-Host '   Impressora selecionada:' -ForegroundColor Cyan
    Write-Host "   Nome   : $nomeImpressora" -ForegroundColor White
    Write-Host "   Driver : $nomeDriver"     -ForegroundColor White
    Write-Host "   Porta  : $nomePorta"      -ForegroundColor White
    Write-Host ''

    $confirma = Read-Host '   Confirma a remocao completa? Esta operacao nao pode ser desfeita. (S/N)'
    if ($confirma -notmatch '^[Ss]$') {
        Write-Info 'Operacao cancelada pelo usuario.'
            return [long]0
    }

    # Verificar se outras impressoras usam o mesmo driver
    $outrasComDriver = @(Get-Printer | Where-Object {
        $_.DriverName -eq $nomeDriver -and $_.Name -ne $nomeImpressora
    })

    $removerDriver = $true
    if ($outrasComDriver.Count -gt 0) {
        Write-Host ''
        Write-Aviso "O driver '$nomeDriver' esta em uso por outras impressoras:"
        foreach ($outra in $outrasComDriver) { Write-Info "  - $($outra.Name)" }
        Write-Aviso 'O driver NAO sera removido para nao afetar as demais impressoras.'
        $removerDriver = $false
    }

    # =========================================================================
    # ETAPA 2 - Coletar informacoes do driver no registro
    # =========================================================================

    Write-Etapa '2. Coletando informacoes do driver no registro antes da remocao...'

    $arquivosDriver = [System.Collections.Generic.List[string]]::new()

    $regAmbientes = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3\$nomeDriver",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-4\$nomeDriver",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows NT x86\Drivers\Version-3\$nomeDriver"
    )

    foreach ($regPath in $regAmbientes) {
        if (-not (Test-Path -LiteralPath $regPath -ErrorAction SilentlyContinue)) { continue }
        $props = Get-ItemProperty -LiteralPath $regPath -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        Write-Ok "Driver localizado: $regPath"
        foreach ($propNome in @('DriverPath', 'DataFile', 'ConfigFile', 'HelpFile')) {
            $val = $props.$propNome
            if ($val -and $val.Trim() -ne '') { $arquivosDriver.Add($val.Trim()) }
        }
        if ($props.DependentFiles) {
            foreach ($dep in $props.DependentFiles) {
                if ($dep -and $dep.Trim() -ne '') { $arquivosDriver.Add($dep.Trim()) }
            }
        }
    }

    if ($arquivosDriver.Count -gt 0) {
        Write-Info "$($arquivosDriver.Count) arquivo(s) de driver mapeados para limpeza posterior."
    } else {
        Write-Aviso 'Nenhum arquivo de driver encontrado no registro (sera feita limpeza generica).'
    }

    # =========================================================================
    # ETAPA 3 - Remover a impressora
    # =========================================================================

    Write-Etapa "3. Removendo a impressora '$nomeImpressora'..."

    $impressoraRemovida = $false
    try {
        Remove-Printer -Name $nomeImpressora -ErrorAction Stop
        Write-Ok "Impressora '$nomeImpressora' removida."
        $impressoraRemovida = $true
    } catch {
        Write-Aviso "Falha pelo cmdlet: $_"
        Write-Info  'Tentando remocao via WMI...'
        try {
            $wmiPrinter = Get-WmiObject -Class Win32_Printer |
                Where-Object { $_.Name -eq $nomeImpressora }
            if ($wmiPrinter) {
                $wmiPrinter.Delete() | Out-Null
                Write-Ok "Impressora removida via WMI."
                $impressoraRemovida = $true
            } else {
                Write-Falha 'Impressora nao encontrada via WMI.'
            }
        } catch {
            Write-Falha "Erro na remocao via WMI: $_"
        }
    }

    # =========================================================================
    # ETAPA 4 - Remover o driver
    # =========================================================================

    $driverRemovido = $false

    if ($removerDriver) {
        Write-Etapa "4. Removendo driver '$nomeDriver' do sistema..."

        # Tentativa 1: cmdlet padrao
        try {
            Remove-PrinterDriver -Name $nomeDriver -ErrorAction Stop
            Write-Ok "Driver removido pelo cmdlet padrao."
            $driverRemovido = $true
        } catch {
            Write-Aviso "Metodo 1 falhou: $_"
        }

        # Tentativa 2: com RemoveFromDriverStore
        if (-not $driverRemovido) {
            try {
                Remove-PrinterDriver -Name $nomeDriver -RemoveFromDriverStore -ErrorAction Stop
                Write-Ok "Driver removido com RemoveFromDriverStore."
                $driverRemovido = $true
            } catch {
                Write-Aviso "Metodo 2 falhou: $_"
            }
        }

        # Tentativa 3: via WMI
        if (-not $driverRemovido) {
            Write-Info 'Tentando remocao via WMI...'
            try {
                $wmiDrivers = Get-WmiObject -Class Win32_PrinterDriver |
                    Where-Object { $_.Name -like "$nomeDriver*" }
                if ($wmiDrivers) {
                    $wmiDrivers | ForEach-Object { $_.Delete() | Out-Null }
                    Write-Ok 'Driver removido via WMI.'
                    $driverRemovido = $true
                } else {
                    Write-Aviso 'Driver nao localizado via WMI.'
                }
            } catch {
                Write-Aviso "Metodo WMI falhou: $_"
            }
        }

        if (-not $driverRemovido) {
            Write-Aviso 'Remocao automatica do driver nao foi possivel.'
            Write-Info  'A limpeza manual de arquivos e registro sera realizada a seguir.'
        }
    } else {
        Write-Etapa '4. Remocao de driver pulada (em uso por outras impressoras).'
    }

    # =========================================================================
    # ETAPA 5 - Parar Spooler e limpar fila de impressao
    # =========================================================================

    Write-Etapa '5. Parando Spooler e limpando fila de impressao...'

    try {
        Stop-Service -Name Spooler -Force -ErrorAction Stop
        Write-Ok 'Servico Spooler parado.'
    } catch {
        Write-Falha "Erro ao parar Spooler: $_"
    }

    $spoolPrinters = "$env:SystemRoot\System32\spool\PRINTERS"
    if (Test-Path $spoolPrinters) {
        $filaItens = @(Get-ChildItem -Path $spoolPrinters -ErrorAction SilentlyContinue)
        if ($filaItens.Count -gt 0) {
            # A fila e' unica para o Windows todo: isso descarta documentos
            # pendentes de TODAS as impressoras e de todos os usuarios.
            Write-Aviso "$($filaItens.Count) documento(s) na fila de impressao (de todas as impressoras)."
            Write-Info  'Limpar a fila descarta esses documentos - eles teriam que ser reenviados.'
            $respFila = Read-Host '   Limpar a fila de impressao? (S/N)'
            if ($respFila -match '^[Ss]') {
                Remove-Item -Path "$spoolPrinters\*" -Force -ErrorAction SilentlyContinue
                Write-Ok "Fila de impressao limpa ($($filaItens.Count) arquivo(s) removidos)."
            } else {
                Write-Info 'Fila de impressao mantida.'
            }
        } else {
            Write-Info 'Fila de impressao ja estava vazia.'
        }
    }

    # =========================================================================
    # ETAPA 6 - Limpar arquivos residuais do driver em spool\drivers
    # =========================================================================

    Write-Etapa '6. Limpando arquivos residuais do driver em spool\drivers...'

    $spoolDirs = @(
        "$env:SystemRoot\System32\spool\drivers\x64\3",
        "$env:SystemRoot\System32\spool\drivers\x64\4",
        "$env:SystemRoot\System32\spool\drivers\W32X86\3"
    )

    $arquivosRemovidos   = 0
    $arquivosNaoRemovidos = 0

    foreach ($arquivo in $arquivosDriver) {
        $caminhoFinal = $null
        if ([System.IO.Path]::IsPathRooted($arquivo)) {
            $caminhoFinal = $arquivo
        } else {
            foreach ($dir in $spoolDirs) {
                $candidato = Join-Path $dir $arquivo
                if (Test-Path $candidato) { $caminhoFinal = $candidato; break }
            }
        }
        if (-not $caminhoFinal -or -not (Test-Path $caminhoFinal)) { continue }
        try {
            Remove-Item -LiteralPath $caminhoFinal -Force -ErrorAction Stop
            Write-Ok "Removido: $(Split-Path $caminhoFinal -Leaf)"
            $arquivosRemovidos++
        } catch {
            Write-Aviso "Nao foi possivel remover: $(Split-Path $caminhoFinal -Leaf)"
            $arquivosNaoRemovidos++
        }
    }

    if ($arquivosDriver.Count -eq 0) {
        Write-Info 'Nenhum arquivo especifico mapeado; arquivos ja foram removidos pelo sistema.'
    } elseif ($arquivosRemovidos -eq 0 -and $arquivosNaoRemovidos -eq 0) {
        Write-Info 'Arquivos do driver ja removidos automaticamente na etapa anterior.'
    } else {
        Write-Info "Resultado: $arquivosRemovidos removido(s), $arquivosNaoRemovidos nao removido(s)."
    }

    # =========================================================================
    # ETAPA 7 - Limpar entradas residuais no registro
    # =========================================================================

    Write-Etapa '7. Limpando entradas residuais no registro...'

    $regLimpos = 0

    # Entrada da impressora em Print\Printers
    $regImpressora = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers\$nomeImpressora"
    if (Test-Path -LiteralPath $regImpressora -ErrorAction SilentlyContinue) {
        try {
            Remove-Item -LiteralPath $regImpressora -Recurse -Force -ErrorAction Stop
            Write-Ok "Registro da impressora removido: Print\Printers\$nomeImpressora"
            $regLimpos++
        } catch {
            Write-Aviso "Nao foi possivel remover registro da impressora: $_"
        }
    } else {
        Write-Info 'Entrada de impressora no registro ja removida.'
    }

    # Entrada no hive SOFTWARE (presente em algumas versoes)
    $regSoftware = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\$nomeImpressora"
    if (Test-Path -LiteralPath $regSoftware -ErrorAction SilentlyContinue) {
        try {
            Remove-Item -LiteralPath $regSoftware -Recurse -Force -ErrorAction Stop
            Write-Ok 'Entrada adicional removida do registro (SOFTWARE hive).'
            $regLimpos++
        } catch {
            Write-Aviso "Nao foi possivel remover entrada SOFTWARE: $_"
        }
    }

    # Entradas do driver nos ambientes de impressao
    if ($removerDriver) {
        foreach ($regPath in $regAmbientes) {
            if (-not (Test-Path -LiteralPath $regPath -ErrorAction SilentlyContinue)) { continue }
            try {
                Remove-Item -LiteralPath $regPath -Recurse -Force -ErrorAction Stop
                Write-Ok "Registro do driver removido: ...$(($regPath -split 'Environments')[1])"
                $regLimpos++
            } catch {
                Write-Aviso "Nao foi possivel remover entrada de driver: $regPath"
            }
        }
    }

    if ($regLimpos -eq 0) {
        Write-Info 'Nenhuma entrada residual encontrada no registro.'
    }

    # =========================================================================
    # ETAPA 8 - Reiniciar servico Spooler
    # =========================================================================

    Write-Etapa '8. Reiniciando servico Spooler...'

    try {
        Start-Service -Name Spooler -ErrorAction Stop
        Start-Sleep -Seconds 2
        $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        if ($spooler -and $spooler.Status -eq 'Running') {
            Write-Ok 'Servico Spooler reiniciado e em execucao.'
        } else {
            Write-Aviso "Servico Spooler status: $($spooler.Status). Verifique em services.msc."
        }
    } catch {
        Write-Falha "Erro ao iniciar Spooler: $_"
        Write-Info  'Inicie manualmente: services.msc > Spooler > Iniciar'
    }

    # =========================================================================
    # Relatorio final e orientacoes
    # =========================================================================

    Write-Host ''
    Write-Host '   LIMPEZA CONCLUIDA - COMO REINSTALAR          ' -ForegroundColor Green
    Write-Host ''
    Write-Host '   Impressora removida  : ' -NoNewline -ForegroundColor White
    Write-Host $nomeImpressora -ForegroundColor Yellow
    Write-Host '   Driver               : ' -NoNewline -ForegroundColor White
    if ($removerDriver -and $driverRemovido) {
        Write-Host "$nomeDriver  [removido]" -ForegroundColor Green
    } elseif ($removerDriver -and -not $driverRemovido) {
        Write-Host "$nomeDriver  [limpeza manual realizada]" -ForegroundColor Yellow
    } else {
        Write-Host "$nomeDriver  [mantido - em uso por outras impressoras]" -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host '   Para reinstalar a impressora:' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '   1. Acesse o site do fabricante e busque o driver usando:' -ForegroundColor White
    Write-Host "         Nome da impressora : $nomeImpressora" -ForegroundColor Yellow
    Write-Host "         Nome do driver     : $nomeDriver"     -ForegroundColor Yellow
    Write-Host ''
    Write-Host '   2. Baixe o driver para Windows 10/11 64-bit' -ForegroundColor White
    Write-Host ''
    Write-Host '   3. Execute o instalador como Administrador' -ForegroundColor White
    Write-Host ''
    Write-Host '   4. Ou adicione via Painel de Controle:' -ForegroundColor White
    Write-Host '      Dispositivos e Impressoras > Adicionar Impressora' -ForegroundColor Gray
    Write-Host ''
    Write-Host ''
    return [long]0
}

function Repair-Webcam {
    <#
      Veio de RepararWebcam.ps1.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Diagnosticaria e repararia a webcam (drivers, servicos, permissoes).'; return [long]0 }
    # RepararWebcam.ps1
    # Detecta e resolve automaticamente todos os problemas comuns de webcam

    $resolvidoHW    = $false
    $etapaResolvida = ''
    $acoesTomadas   = [System.Collections.Generic.List[string]]::new()



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
    Write-Host '   Reparo Automatico de Webcam / Camera         ' -ForegroundColor Cyan
    Write-Host ''


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
    Write-Host '   RELATORIO FINAL                              ' -ForegroundColor $corFinal
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
    Write-Host ''
    return [long]0
}

function Repair-Audio {
    <#
      Veio de RepararAudio.ps1.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Diagnosticaria e repararia audio e microfone (drivers, servicos, permissoes).'; return [long]0 }
    # RepararAudio.ps1
    # Detecta e resolve automaticamente problemas de audio e microfone no Windows

    $resolvidoHW    = $false
    $etapaResolvida = ''
    $acoesTomadas   = [System.Collections.Generic.List[string]]::new()



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
    Write-Host '   Reparo Automatico de Audio e Microfone       ' -ForegroundColor Cyan
    Write-Host ''


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
    Write-Host '   RELATORIO FINAL                              ' -ForegroundColor $corFinal
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
    Write-Host ''
    return [long]0
}

function Repair-PermissoesPowerShell {
    <#
      Veio de CorrigirPermissoesPowerShell.ps1.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Ajustaria a ExecutionPolicy e desbloquearia .ps1 marcados como da internet.'; return [long]0 }
    # CorrigirPermissoesPowerShell.ps1
    # Resolve todos os tipos de bloqueio de execucao do PowerShell no Windows
    #
    # COMO EXECUTAR SE AINDA ESTIVER BLOQUEADO:
    #   powershell.exe -ExecutionPolicy Bypass -File CorrigirPermissoesPowerShell.ps1




    # Relatorio

    $relatorio = [System.Collections.Generic.List[PSObject]]::new()

    function Add-Rel {
        param([string]$Etapa, [string]$Status, [string]$Msg)
        $relatorio.Add([PSCustomObject]@{ Etapa = $Etapa; Status = $Status; Msg = $Msg })
    }

    # =========================================================================
    # Cabecalho
    # =========================================================================

    Write-Host ''
    Write-Host '   Corrigir Permissoes de Execucao do PowerShell      ' -ForegroundColor Cyan
    Write-Host '   ExecutionPolicy | Registry | Zone.Identifier | GPO ' -ForegroundColor Cyan
    Write-Host ''

    # =========================================================================
    # ETAPA 2 - Verificar privilegios de Administrador
    # =========================================================================

    Write-Etapa '1/10  Verificando privilegios de Administrador...'
    Write-Host ''

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )

    if ($isAdmin) {
        Write-Ok 'Executando como Administrador. Todas as correcoes serao aplicadas.'
        Add-Rel '1. Administrador' 'OK' 'Script executando com privilegios de Administrador'
    } else {
        Write-Aviso 'NAO esta sendo executado como Administrador.'
        Write-Info  'Correcoes no HKLM e para todos os usuarios exigem privilegios elevados.'
        Write-Info  'Execute novamente: clique direito no PowerShell > Executar como Administrador'
        Add-Rel '1. Administrador' 'AVISO' 'Sem privilegios de Admin. Algumas correcoes podem nao ser aplicadas.'
    }

    # =========================================================================
    # ETAPA 1 - Corrigir ExecutionPolicy em todos os escopos
    # =========================================================================

    Write-Etapa '2/10  Corrigindo ExecutionPolicy em todos os escopos...'
    Write-Host ''

    # RemoteSigned e nao Unrestricted: libera todo script criado na propria
    # maquina e continua exigindo assinatura no que vier da internet. Deixar
    # Unrestricted numa maquina de cliente derruba essa protecao para sempre,
    # e o toolkit ja roda com -ExecutionPolicy Bypass quando precisa.
    $politicaAlvo = 'RemoteSigned'

    $politicaAntes = Get-ExecutionPolicy -ErrorAction SilentlyContinue
    Write-Info "Politica efetiva atual: $politicaAntes"
    Write-Info "Politica que sera aplicada: $politicaAlvo"
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
            if ($politicaAtual -in @($politicaAlvo, 'Unrestricted', 'Bypass')) {
                Write-Ok ($escopo.Nome.PadRight(18) + ": ja permite execucao ($politicaAtual).")
                $escoposOk++
            } else {
                if ($escopo.GPO) {
                    Write-Aviso ($escopo.Nome.PadRight(18) + ': controlado por GPO (valor atual: ' + $politicaAtual + '). Ignorando.')
                    $escoposGPO++
                } else {
                    Set-ExecutionPolicy -ExecutionPolicy $politicaAlvo -Scope $escopo.Nome -Force -ErrorAction Stop
                    Write-Ok ($escopo.Nome.PadRight(18) + ": corrigido para $politicaAlvo (era: " + $politicaAtual + ').')
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
        Add-Rel '2. ExecutionPolicy' 'OK' "Todos os escopos definidos como $politicaAlvo"
    } elseif ($escoposGPO -gt 0 -and $escoposErro -eq 0) {
        Add-Rel '2. ExecutionPolicy' 'AVISO' "$escoposOk escopo(s) corrigidos | $escoposGPO escopo(s) bloqueados por GPO"
    } else {
        Add-Rel '2. ExecutionPolicy' 'AVISO' "$escoposOk OK | $escoposGPO GPO | $escoposErro erro(s)"
    }

    # =========================================================================
    # ETAPA 6 - Verificar bloqueio por GPO antes de editar registro
    # =========================================================================

    Write-Etapa '3/10  Verificando bloqueio por GPO...'
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
        Add-Rel '3. GPO' 'OK' 'Nenhuma politica de grupo bloqueando o PowerShell'
    } else {
        Add-Rel '3. GPO' 'AVISO' 'GPO ativa detectada. Administrador do dominio deve liberar via GPMC.'
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
        Set-ItemProperty $regHKLM64 -Name 'ExecutionPolicy' -Value $politicaAlvo -Type String -Force
        Write-Ok "HKLM 64 bits: ExecutionPolicy definida como $politicaAlvo (era: $valorAtual)."
        Add-Rel '4. HKLM 64 bits' 'OK' ("ExecutionPolicy=$politicaAlvo aplicado")
    } catch {
        Write-Falha ('HKLM 64 bits: erro - ' + $_.Exception.Message)
        Add-Rel '4. HKLM 64 bits' 'ERRO' $_.Exception.Message
    }

    # =========================================================================
    # ETAPA 7 - Corrigir registro HKLM (32 bits / WOW6432Node)
    # =========================================================================

    Write-Etapa '5/10  Corrigindo registro HKLM - PowerShell 32 bits (WOW6432Node)...'
    Write-Host ''

    $regHKLM32 = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'

    try {
        if (-not (Test-Path $regHKLM32)) {
            New-Item $regHKLM32 -Force | Out-Null
            Write-Info 'Chave HKLM 32 bits criada.'
        }
        $valorAtual32 = (Get-ItemProperty $regHKLM32 -ErrorAction SilentlyContinue).ExecutionPolicy
        Set-ItemProperty $regHKLM32 -Name 'ExecutionPolicy' -Value $politicaAlvo -Type String -Force
        Write-Ok "HKLM 32 bits: ExecutionPolicy definida como $politicaAlvo (era: $valorAtual32)."
        Add-Rel '5. HKLM 32 bits' 'OK' ("ExecutionPolicy=$politicaAlvo aplicado (WOW6432Node)")
    } catch {
        Write-Falha ('HKLM 32 bits: erro - ' + $_.Exception.Message)
        Add-Rel '5. HKLM 32 bits' 'ERRO' $_.Exception.Message
    }

    # =========================================================================
    # ETAPA 5 - Corrigir registro HKCU (usuario atual)
    # =========================================================================

    Write-Etapa '6/10  Corrigindo registro HKCU - usuario atual...'
    Write-Host ''

    $regHKCU = 'HKCU:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'

    try {
        if (-not (Test-Path $regHKCU)) {
            New-Item $regHKCU -Force | Out-Null
            Write-Info 'Chave HKCU criada.'
        }
        $valorAtualHKCU = (Get-ItemProperty $regHKCU -ErrorAction SilentlyContinue).ExecutionPolicy
        Set-ItemProperty $regHKCU -Name 'ExecutionPolicy' -Value $politicaAlvo -Type String -Force
        Write-Ok "HKCU: ExecutionPolicy definida como $politicaAlvo (era: $valorAtualHKCU)."
        Add-Rel '6. HKCU' 'OK' ("ExecutionPolicy=$politicaAlvo aplicado para o usuario atual")
    } catch {
        Write-Falha ('HKCU: erro - ' + $_.Exception.Message)
        Add-Rel '6. HKCU' 'ERRO' $_.Exception.Message
    }

    # =========================================================================
    # ETAPA 3 - Desbloquear arquivos .ps1 com Zone.Identifier
    # =========================================================================

    Write-Etapa '7/10  Desbloqueando arquivos .ps1 com Zone.Identifier (bloqueio de internet)...'
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
        Add-Rel '7. Zone.Identifier' 'OK' 'Nenhum arquivo bloqueado encontrado'
    } elseif ($totalDesbloqueados -eq $totalBloqueados) {
        Write-Ok "Zone.Identifier: $totalDesbloqueados de $totalBloqueados arquivo(s) desbloqueado(s) com sucesso."
        Add-Rel '7. Zone.Identifier' 'OK' "$totalDesbloqueados arquivo(s) desbloqueados de $totalBloqueados encontrados"
    } else {
        $falhas = $totalBloqueados - $totalDesbloqueados
        Write-Aviso "$totalDesbloqueados desbloqueados, $falhas ainda bloqueados (possivelmente em uso)."
        Add-Rel '7. Zone.Identifier' 'AVISO' "$falhas arquivo(s) nao puderam ser desbloqueados"
    }

    # =========================================================================
    # ETAPA 8 - Limpar cache do PowerShell (PSReadline e analise de modulos)
    # =========================================================================

    Write-Etapa '8/10  Limpando cache do PowerShell...'
    Write-Host ''

    $totalCacheLimpo = 0

    foreach ($usuario in $usuarios) {
        # PSReadline NAO entra aqui: essa pasta guarda o HISTORICO de comandos do
        # usuario (ConsoleHost_history.txt), nao cache. Apagar nao ajuda em nada
        # a destravar a execucao de scripts e o usuario perde o historico dele.
        $cachePaths = @(
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

    Write-Host '   RELATORIO - PERMISSOES DE EXECUCAO DO POWERSHELL   ' -ForegroundColor Cyan
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
        $corPol = if ($p.ExecutionPolicy -in @('RemoteSigned','Unrestricted','Bypass')) { 'Green' } elseif ($p.ExecutionPolicy -eq 'Undefined') { 'Gray' } else { 'Yellow' }
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
    Write-Host ''
    return [long]0
}

function Set-AmbientePJe {
    <#
      Veio de ConfigurarPJe.ps1.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Configuraria o ambiente PJe (Java, exception.sites, Shodo/Shomei) para todos os usuarios.'; return [long]0 }
    # ConfigurarPJe.ps1
    # Configura completamente o ambiente PJe em uma maquina Windows
    # Java security, exception.sites, cache, servicos Shodo/Shomei, conectividade




    # Funcoes de manipulacao de arquivos Java (sem BOM)

    $encodingUTF8SemBOM = New-Object System.Text.UTF8Encoding $false

    function Ler-Linhas {
        param([string]$Caminho)
        if (Test-Path $Caminho) {
            return [System.IO.File]::ReadAllLines($Caminho)
        }
        return @()
    }

    function Escrever-Linhas {
        param([string]$Caminho, [string[]]$Linhas)
        [System.IO.File]::WriteAllLines($Caminho, $Linhas, $encodingUTF8SemBOM)
    }

    function Atualizar-Properties {
        param(
            [string]$Caminho,
            [hashtable]$Propriedades,
            [string[]]$Remover = @()
        )
        $linhasExistentes = Ler-Linhas $Caminho
        $linhasFinais = [System.Collections.Generic.List[string]]::new()

        foreach ($linha in $linhasExistentes) {
            $incluir = $true
            foreach ($chave in $Propriedades.Keys) {
                if ($linha -match ('^\s*' + [regex]::Escape($chave) + '\s*=')) {
                    $incluir = $false
                    break
                }
            }
            # Chaves a remover: a linha some do arquivo e NAO e' regravada.
            # Gravar 'deployment.security.level.locked=' vazio NAO desbloqueia:
            # a simples presenca da chave e' o que trava o painel Java.
            if ($incluir) {
                foreach ($chave in $Remover) {
                    if ($linha -match ('^\s*' + [regex]::Escape($chave) + '\s*=')) {
                        $incluir = $false
                        break
                    }
                }
            }
            if ($incluir) { $linhasFinais.Add($linha) }
        }

        foreach ($chave in $Propriedades.Keys) {
            $linhasFinais.Add($chave + '=' + $Propriedades[$chave])
        }

        Escrever-Linhas $Caminho $linhasFinais.ToArray()
    }

    function Atualizar-ExceptionSites {
        param([string]$Caminho, [string[]]$UrlsNecessarias)
        $urlsExistentes = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        foreach ($linha in (Ler-Linhas $Caminho)) {
            $l = $linha.Trim()
            if ($l -ne '') { $urlsExistentes.Add($l) | Out-Null }
        }
        $adicionadas = 0
        foreach ($url in $UrlsNecessarias) {
            if ($urlsExistentes.Add($url)) { $adicionadas++ }
        }
        Escrever-Linhas $Caminho ([string[]]$urlsExistentes)
        return $adicionadas
    }

    # Relatorio de etapas

    $relatorio = [System.Collections.Generic.List[PSObject]]::new()

    function Add-Rel {
        param([string]$Etapa, [string]$Status, [string]$Msg)
        $relatorio.Add([PSCustomObject]@{ Etapa = $Etapa; Status = $Status; Msg = $Msg })
    }

    # =========================================================================
    # URLs de excecao obrigatorias para o PJe
    # =========================================================================

    $urlsExcecao = @(
        'https://127.0.0.1:9000'            # Shodo
        'https://127.0.0.1:9003'            # Shomei
        'http://127.0.0.1'                  # PJe local
        'https://pje.jus.br'
        # PJe - instancias especificas
        'https://pje1g.tjba.jus.br'
        'https://pje2g.tjba.jus.br'
        'https://pje.trt5.jus.br'
        'https://pje.trf1.jus.br'
        'https://pje.trf2.jus.br'
        'https://pje.trf3.jus.br'
        'https://pje.trf4.jus.br'
        'https://pje.trf5.jus.br'
        'https://pje.tst.jus.br'
        'https://pje.csjt.jus.br'
        # PROJUDI - formato real: projudi.tj<uf>.jus.br (sem prefixo de estado)
        'https://projudi.tjac.jus.br'
        'https://projudi.tjal.jus.br'
        'https://projudi.tjam.jus.br'
        'https://projudi.tjap.jus.br'
        'https://projudi.tjba.jus.br'
        'https://projudi.tjce.jus.br'
        'https://projudi.tjdft.jus.br'
        'https://projudi.tjes.jus.br'
        'https://projudi.tjgo.jus.br'
        'https://projudi.tjma.jus.br'
        'https://projudi.tjmg.jus.br'
        'https://projudi.tjms.jus.br'
        'https://projudi.tjmt.jus.br'
        'https://projudi.tjpa.jus.br'
        'https://projudi.tjpb.jus.br'
        'https://projudi.tjpe.jus.br'
        'https://projudi.tjpi.jus.br'
        'https://projudi.tjpr.jus.br'
        'https://projudi.tjrj.jus.br'
        'https://projudi.tjrn.jus.br'
        'https://projudi.tjro.jus.br'
        'https://projudi.tjrr.jus.br'
        'https://projudi.tjrs.jus.br'
        'https://projudi.tjsc.jus.br'
        'https://projudi.tjse.jus.br'
        'https://projudi.tjsp.jus.br'
        'https://projudi.tjto.jus.br'
    )

    # =========================================================================
    # Cabecalho
    # =========================================================================

    Write-Host ''
    Write-Host '   Configuracao do Ambiente PJe                       ' -ForegroundColor Cyan
    Write-Host '   Java  |  exception.sites  |  Shodo  |  Shomei     ' -ForegroundColor Cyan
    Write-Host ''

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    if ($isAdmin) {
        Write-Ok 'Executando como Administrador (acesso a todos os perfis).'
    } else {
        Write-Aviso 'Sem privilegios de Administrador. Apenas o usuario atual sera configurado.'
        Write-Info  'Execute como Administrador para configurar todos os usuarios.'
    }

    # =========================================================================
    # ETAPA 1 - Verificar Java 8
    # =========================================================================

    Write-Etapa '1/9  Verificando instalacao do Java 8...'
    Write-Host ''

    $java8Encontrado = $false
    $java8Versao     = ''
    $java8Path       = ''

    $regCaminhos = @(
        'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment',
        'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment'
    )

    foreach ($regBase in $regCaminhos) {
        $jreKey = Get-ItemProperty "$regBase\1.8" -ErrorAction SilentlyContinue
        if ($jreKey) {
            $javaHome = $jreKey.JavaHome
            $javaExe  = Join-Path $javaHome 'bin\java.exe'
            if (Test-Path $javaExe) {
                $java8Encontrado = $true
                $java8Path       = $javaExe
                $java8Versao     = if ($jreKey.FullVersion) { $jreKey.FullVersion } else { '1.8.x' }
                break
            }
        }
    }

    if (-not $java8Encontrado) {
        $buscaFS = @('C:\Program Files\Java', 'C:\Program Files (x86)\Java')
        foreach ($dir in $buscaFS) {
            if (Test-Path $dir) {
                $jre8 = Get-ChildItem $dir -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^jre1\.8' } |
                    Sort-Object Name -Descending | Select-Object -First 1
                if ($jre8) {
                    $javaExe = Join-Path $jre8.FullName 'bin\java.exe'
                    if (Test-Path $javaExe) {
                        $java8Encontrado = $true
                        $java8Path       = $javaExe
                        $java8Versao     = $jre8.Name
                        break
                    }
                }
            }
        }
    }

    if ($java8Encontrado) {
        Write-Ok "Java 8 encontrado: $java8Versao"
        Write-Info "Caminho: $java8Path"
        Add-Rel '1. Java 8' 'OK' "Versao $java8Versao encontrada em $java8Path"
    } else {
        Write-Falha 'Java 8 NAO encontrado neste computador.'
        Write-Info  'O PJe requer Java 8 (JRE 1.8). Instale e execute este script novamente.'
        Write-Info  'Download: https://www.java.com/pt-BR/download/'
        Add-Rel '1. Java 8' 'ERRO' 'Java 8 nao encontrado. Instale e execute novamente.'
        Write-Host ''
        Write-Host '   Configuracao encerrada: Java 8 e obrigatorio para o PJe.' -ForegroundColor Red
        Write-Host ''
            return [long]0
    }

    # =========================================================================
    # ETAPA 2-5 - Configurar Java para cada usuario do sistema
    # =========================================================================

    $nomesIgnorados  = '^(Public|All Users|Default|Default User|defaultuser0|desktop\.ini)$'
    $usuarios        = @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch $nomesIgnorados })

    $usuariosConfig  = 0
    $usuariosSemDir  = 0
    $totalBackups    = 0
    $totalCacheLimpo = 0

    Write-Etapa '2-5/9  Configurando Java para todos os usuarios do sistema...'
    Write-Host ''
    Write-Info ("$($usuarios.Count) perfil(is) de usuario encontrado(s) em C:\Users.")
    Write-Host ''

    foreach ($usuario in $usuarios) {
        $deployDir   = Join-Path $usuario.FullName 'AppData\LocalLow\Sun\Java\Deployment'
        $deployProps = Join-Path $deployDir 'deployment.properties'
        $excepSites  = Join-Path $deployDir 'exception.sites'
        $cacheDir    = Join-Path $deployDir 'cache'

        Write-Dest ("   --- Usuario: $($usuario.Name) ---")

        # Garantir que a pasta Deployment existe
        if (-not (Test-Path $deployDir)) {
            try {
                New-Item -Path $deployDir -ItemType Directory -Force | Out-Null
                Write-Info 'Pasta Deployment criada.'
            } catch {
                Write-Aviso ("Sem acesso a pasta do usuario $($usuario.Name). Ignorando.")
                $usuariosSemDir++
                Write-Host ''
                continue
            }
        }

        # ETAPA 2 - Backup do deployment.properties
        if (Test-Path $deployProps) {
            $ts     = Get-Date -Format 'yyyyMMdd_HHmmss'
            $backup = $deployProps + '.bak_' + $ts
            try {
                Copy-Item $deployProps $backup -Force
                Write-Ok "Backup criado: deployment.properties.bak_$ts"
                $totalBackups++
            } catch {
                Write-Aviso 'Nao foi possivel criar backup do deployment.properties.'
            }
        } else {
            Write-Info 'deployment.properties nao existia. Sera criado.'
        }

        # ETAPA 3 - Configurar nivel de seguranca e apontar exception.sites
        $excepSitesPath = $usuario.FullName.Replace('\', '/') + '/AppData/LocalLow/Sun/Java/Deployment/exception.sites'

        # MEDIUM foi removido do Java a partir do 8u20: os niveis validos sao
        # HIGH e VERY_HIGH. Gravar MEDIUM faz o Java ignorar e voltar para HIGH.
        # O que realmente libera os sistemas juridicos e' o exception.sites.
        $props = @{
            'deployment.security.level'                = 'HIGH'
            'deployment.user.security.exception.sites' = $excepSitesPath
            'deployment.expiration.check.enabled'      = 'false'
            'deployment.webjava.enabled'               = 'true'
        }
        # Chaves .locked travam o painel do Java: precisam SUMIR do arquivo.
        $remover = @(
            'deployment.security.level.locked'
            'deployment.user.security.exception.sites.locked'
            'deployment.expiration.check.enabled.locked'
            'deployment.webjava.enabled.locked'
        )

        try {
            Atualizar-Properties $deployProps $props -Remover $remover
            Write-Ok 'deployment.properties: security.level=HIGH + exception.sites configurado.'
        } catch {
            Write-Aviso ('Erro ao atualizar deployment.properties: ' + $_.Exception.Message)
        }

        # ETAPA 4 - Adicionar excecoes de sites no exception.sites
        try {
            $adicionadas = Atualizar-ExceptionSites $excepSites $urlsExcecao
            if ($adicionadas -gt 0) {
                Write-Ok "exception.sites: $adicionadas URL(s) nova(s) adicionada(s) ($($urlsExcecao.Count) total configuradas)."
            } else {
                Write-Ok "exception.sites: todas as $($urlsExcecao.Count) URLs ja estavam presentes."
            }
        } catch {
            Write-Aviso ('Erro ao atualizar exception.sites: ' + $_.Exception.Message)
        }

        # ETAPA 5 - Limpar cache do Java
        if (Test-Path $cacheDir) {
            try {
                $itensCache = @(Get-ChildItem $cacheDir -Recurse -Force -ErrorAction SilentlyContinue)
                Remove-Item $cacheDir -Recurse -Force -ErrorAction SilentlyContinue
                Write-Ok ("Cache do Java removido ($($itensCache.Count) item(ns) eliminados).")
                $totalCacheLimpo++
            } catch {
                Write-Aviso ('Erro ao limpar cache Java: ' + $_.Exception.Message)
            }
        } else {
            Write-Info 'Cache do Java ja estava vazio.'
        }

        $usuariosConfig++
        Write-Host ''
    }

    Add-Rel '2. Backup props' 'OK' "$totalBackups backup(s) criado(s) com timestamp"
    Add-Rel '3. Security HIGH' 'OK' "deployment.properties atualizado em $usuariosConfig usuario(s) (locks removidos)"
    Add-Rel '4. exception.sites' 'OK' "$($urlsExcecao.Count) URLs configuradas em $usuariosConfig usuario(s)"
    Add-Rel '5. Cache Java' 'OK' "Cache limpo em $totalCacheLimpo usuario(s)"

    if ($usuariosSemDir -gt 0) {
        Write-Aviso "$usuariosSemDir usuario(s) ignorado(s) por falta de permissao de acesso."
    }

    # =========================================================================
    # ETAPA 6 - Verificar servico Shodo
    # =========================================================================

    Write-Etapa '6/9  Verificando servico Shodo...'
    Write-Host ''

    $servicoShodo = Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'shodo' -or $_.DisplayName -match 'shodo' } |
        Select-Object -First 1

    if ($servicoShodo) {
        Write-Info ("Servico encontrado: '$($servicoShodo.Name)' - Status: $($servicoShodo.Status)")
        if ($servicoShodo.Status -eq 'Running') {
            Write-Ok 'Shodo esta em execucao.'
            Add-Rel '6. Shodo' 'OK' "Servico '$($servicoShodo.Name)' em execucao"
        } else {
            Write-Aviso "Shodo esta parado. Tentando iniciar..."
            try {
                Start-Service -Name $servicoShodo.Name -ErrorAction Stop
                Start-Sleep -Milliseconds 1500
                $novoStatus = (Get-Service -Name $servicoShodo.Name).Status
                if ($novoStatus -eq 'Running') {
                    Write-Ok 'Shodo iniciado com sucesso.'
                    Add-Rel '6. Shodo' 'OK' "Servico iniciado (estava parado)"
                } else {
                    Write-Aviso "Shodo nao iniciou (status: $novoStatus)."
                    Add-Rel '6. Shodo' 'AVISO' "Nao foi possivel iniciar o servico (status: $novoStatus)"
                }
            } catch {
                Write-Falha ('Erro ao iniciar Shodo: ' + $_.Exception.Message)
                Add-Rel '6. Shodo' 'ERRO' ('Falha ao iniciar: ' + $_.Exception.Message)
            }
        }
    } else {
        Write-Aviso 'Servico Shodo NAO encontrado neste computador.'
        Write-Info  'O Shodo e necessario para assinatura digital no PJe.'
        Write-Info  'Instale o Shodo e execute este script novamente para verificar.'
        Add-Rel '6. Shodo' 'AVISO' 'Servico nao instalado. Instale o Shodo para assinatura digital.'
    }

    # =========================================================================
    # ETAPA 7 - Verificar servico Shomei
    # =========================================================================

    Write-Etapa '7/9  Verificando servico Shomei...'
    Write-Host ''

    $servicoShomei = Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'shomei' -or $_.DisplayName -match 'shomei' } |
        Select-Object -First 1

    if ($servicoShomei) {
        Write-Info ("Servico encontrado: '$($servicoShomei.Name)' - Status: $($servicoShomei.Status)")
        if ($servicoShomei.Status -eq 'Running') {
            Write-Ok 'Shomei esta em execucao.'
            Add-Rel '7. Shomei' 'OK' "Servico '$($servicoShomei.Name)' em execucao"
        } else {
            Write-Aviso 'Shomei esta parado. Tentando iniciar...'
            try {
                Start-Service -Name $servicoShomei.Name -ErrorAction Stop
                Start-Sleep -Milliseconds 1500
                $novoStatus = (Get-Service -Name $servicoShomei.Name).Status
                if ($novoStatus -eq 'Running') {
                    Write-Ok 'Shomei iniciado com sucesso.'
                    Add-Rel '7. Shomei' 'OK' "Servico iniciado (estava parado)"
                } else {
                    Write-Aviso "Shomei nao iniciou (status: $novoStatus)."
                    Add-Rel '7. Shomei' 'AVISO' "Nao foi possivel iniciar o servico (status: $novoStatus)"
                }
            } catch {
                Write-Falha ('Erro ao iniciar Shomei: ' + $_.Exception.Message)
                Add-Rel '7. Shomei' 'ERRO' ('Falha ao iniciar: ' + $_.Exception.Message)
            }
        }
    } else {
        Write-Aviso 'Servico Shomei NAO encontrado neste computador.'
        Write-Info  'O Shomei e necessario para assinatura digital no PJe.'
        Write-Info  'Instale o Shomei e execute este script novamente para verificar.'
        Add-Rel '7. Shomei' 'AVISO' 'Servico nao instalado. Instale o Shomei para assinatura digital.'
    }

    # =========================================================================
    # ETAPA 8 - Testar conectividade com o PJe
    # =========================================================================

    Write-Etapa '8/9  Testando conectividade com pje.jus.br...'
    Write-Host ''

    [Net.ServicePointManager]::SecurityProtocol = (
        [Net.SecurityProtocolType]::Tls12 -bor
        [Net.SecurityProtocolType]::Tls11 -bor
        [Net.SecurityProtocolType]::Tls
    )

    $urlTeste   = 'https://pje.jus.br'
    $conectOk   = $false
    $conectDetalhe = ''

    try {
        $req = [System.Net.HttpWebRequest]::Create($urlTeste)
        $req.Timeout          = 12000
        $req.AllowAutoRedirect = $true
        $req.UserAgent        = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        $resp = $req.GetResponse()
        $httpCode = [int]$resp.StatusCode
        $resp.Close()
        $conectOk     = $true
        $conectDetalhe = "HTTP $httpCode"
    } catch [System.Net.WebException] {
        $webEx = $_.Exception
        if ($webEx.Response) {
            $httpCode = [int]$webEx.Response.StatusCode
            if ($httpCode -ge 200) {
                $conectOk     = $true
                $conectDetalhe = "HTTP $httpCode (site acessivel)"
            } else {
                $conectDetalhe = "HTTP $httpCode"
            }
        } elseif ($webEx.Message -match 'SSL|certificate|TLS') {
            $conectDetalhe = 'Erro de certificado SSL. Verifique certificados raiz do Windows.'
        } elseif ($webEx.Message -match 'proxy|407') {
            $conectDetalhe = 'Bloqueado por proxy.'
        } elseif ($webEx.Message -match 'timed out|timeout') {
            $conectDetalhe = 'Timeout (servidor nao respondeu em 12s).'
        } else {
            $conectDetalhe = $webEx.Message
            if ($conectDetalhe.Length -gt 80) { $conectDetalhe = $conectDetalhe.Substring(0, 77) + '...' }
        }
    } catch {
        $conectDetalhe = $_.Exception.Message
        if ($conectDetalhe.Length -gt 80) { $conectDetalhe = $conectDetalhe.Substring(0, 77) + '...' }
    }

    if ($conectOk) {
        Write-Ok "pje.jus.br acessivel. $conectDetalhe"
        Add-Rel '8. Conectividade' 'OK' "pje.jus.br acessivel ($conectDetalhe)"
    } else {
        Write-Aviso "pje.jus.br com problema: $conectDetalhe"
        Write-Info  'Verifique conexao com a internet, proxy ou VPN.'
        Add-Rel '8. Conectividade' 'AVISO' "pje.jus.br inacessivel: $conectDetalhe"
    }

    # =========================================================================
    # ETAPA 9 - Relatorio final colorido
    # =========================================================================

    Write-Etapa '9/9  Relatorio final...'
    Write-Host ''

    Write-Host '   RELATORIO DE CONFIGURACAO DO AMBIENTE PJe          ' -ForegroundColor Cyan
    Write-Host ''

    $erros  = @($relatorio | Where-Object { $_.Status -eq 'ERRO' })
    $avisos = @($relatorio | Where-Object { $_.Status -eq 'AVISO' })
    $oks    = @($relatorio | Where-Object { $_.Status -eq 'OK' })

    foreach ($item in $relatorio) {
        $cor    = if ($item.Status -eq 'OK') { 'Green' } elseif ($item.Status -eq 'AVISO') { 'Yellow' } else { 'Red' }
        $prefixo = if ($item.Status -eq 'OK') { '[OK]   ' } elseif ($item.Status -eq 'AVISO') { '[!]    ' } else { '[ERRO] ' }
        Write-Host ('   ' + $prefixo + $item.Etapa.PadRight(22) + '  ') -ForegroundColor $cor -NoNewline
        Write-Host $item.Msg
    }

    Write-Host ''
    $corRel = if ($erros.Count -gt 0) { 'Red' } elseif ($avisos.Count -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ('   Resumo: ' + $oks.Count + ' OK  |  ' + $avisos.Count + ' Aviso(s)  |  ' + $erros.Count + ' Erro(s)') -ForegroundColor $corRel
    Write-Host ''

    if ($oks.Count -eq $relatorio.Count) {
        Write-Host '   Ambiente PJe configurado com sucesso!' -ForegroundColor Green
    }
    if ($avisos.Count -gt 0 -or $erros.Count -gt 0) {
        Write-Host '   Verifique os itens acima com [!] ou [ERRO] e resolva antes de usar o PJe.' -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Dest '   Configuracoes aplicadas para todos os usuarios:'
    Write-Info ("   Usuarios processados : $usuariosConfig")
    Write-Info ("   Backups criados      : $totalBackups")
    Write-Info ("   URLs no exception.sites : $($urlsExcecao.Count)  (Shodo, Shomei, PJe, PROJUDI - 27 estados)")
    Write-Info ("   Cache Java limpo em  : $totalCacheLimpo usuario(s)")

    Write-Host ''
    Write-Host ''
    return [long]0
}

function Clear-CertificadosVencidos {
    <#
      Veio de LimparCertificadosVencidos.ps1.

      DECISAO DO IVAN (29/07/2026): esta ferramenta NAO PERGUNTA NADA. Quando
      ele escolhe a opcao, e para apagar. Perguntar a cada certificado tornava
      a limpeza mais demorada que fazer a mao no certmgr, que era o problema
      que a ferramenta existia para resolver.

      Regra, sem excecao e sem confirmacao:
        FICA  - ICP-Brasil ou ICP-Portugal VALIDO;
        SAI   - todo VENCIDO (inclusive ICP, inclusive com chave privada);
        SAI   - todo NAO RECONHECIDO como ICP, mesmo dentro da validade.

      Portugal entra na mesma regra do Brasil: Cartao de Cidadao e demais
      certificados ICP-PT validos FICAM. So saem se estiverem vencidos.

      O backup continua acontecendo, mas em silencio - backup nao e pergunta.
      Limite conhecido e aceito: o .cer guarda so a parte publica, entao
      certificado A1 removido nao volta. Como o que sai e' vencido ou nao-ICP,
      o custo real disso e' baixo; o que tem valor (ICP dentro da validade)
      nunca e' tocado.

      COR: por pedido dele, nada de fonte clara nesta ferramenta. Tudo em tom
      escuro (Dark*), que e o que se le no console de fundo claro que ele usa.
      Nao usar Black nem DarkBlue: somem no console de fundo escuro.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Listaria os certificados da loja Pessoal e o que poderia ser removido.'; return [long]0 }
    # LimparCertificadosVencidos.ps1
    # Limpa certificados indesejados da loja Pessoal (CurrentUser\My) do Windows
    # Mantem ICP-Brasil e ICP-Portugal validos; apaga vencidos e nao-ICP

    # --- saida em tom escuro, so para esta ferramenta ---------------------
    function Write-CertSecao { param([string]$t) Write-Host ''; Write-Host ('   ' + $t) -ForegroundColor DarkCyan }
    function Write-CertEtapa { param([string]$t) Write-Host ('  >> ' + $t) -ForegroundColor DarkCyan }
    function Write-CertOk    { param([string]$t) Write-Host ('     [OK] ' + $t) -ForegroundColor DarkGreen }
    function Write-CertAviso { param([string]$t) Write-Host ('     [!]  ' + $t) -ForegroundColor DarkYellow }
    function Write-CertFalha { param([string]$t) Write-Host ('     [X]  ' + $t) -ForegroundColor DarkRed }
    function Write-CertInfo  { param([string]$t) Write-Host ('     ' + $t) -ForegroundColor DarkGray }




    # Funcoes de classificacao de certificados

    function Test-ICPBrasil {
        param([string]$Subject, [string]$Issuer)
        $texto = $Subject + ' ' + $Issuer
        if ($texto -match 'ICP-Brasil') { return $true }
        # Cartao de Cidadao: aceita tanto com acentos (Cart[a~]o) quanto sem (Cartao)
        if ($texto -match 'Cart.o de Cidad.o') { return $true }
        $marcadores = @(
            # ICP-Brasil
            'AC OAB', 'OAB ',
            'SyngularID', 'SYNGULARID',
            'Certisign', 'CERTISIGN',
            'Serpro', 'SERPRO',
            'Serasa', 'SERASA',
            'SafeID', 'SAFEID',
            'VALID ', 'Valid ', 'VALID,', 'Valid,', 'Valid S',
            'AC Raiz', 'Autoridade Certificadora Raiz',
            'Autoridade Certificadora',
            'Soluti', 'SOLUTI',
            'Safeweb', 'SAFEWEB',
            'AC CAIXA', 'Caixa Economica',
            'FENACOR', 'Casa da Moeda',
            'e-CPF', 'e-CNPJ',
            'RFB e-CPF', 'RFB e-CNPJ',
            'Receita Federal', 'RECEITA FEDERAL',
            'ITI ', 'Imprensa Oficial',
            'DocuSign Brazil',
            # ICP-Portugal
            'CC Portuguese', 'Portuguese Citizen Card',
            'Portuguese Authentication Authority',
            'SCEE',
            'Multicert', 'MULTICERT',
            'DigitalSign', 'DIGITALSIGN',
            'DSTgroup', 'DST group', 'DST Group',
            'ECEE',
            'Camerfirma Portugal', 'CAMERFIRMA',
            'EC de Autenticacao do Cidadao',
            'Entidade de Certificacao Electronica do Estado',
            'AMA - Agencia para a Modernizacao Administrativa'
        )
        foreach ($m in $marcadores) {
            if ($texto -match [regex]::Escape($m)) { return $true }
        }
        return $false
    }

    function Get-NomeCert {
        param([string]$Subject)
        if ($Subject -match 'CN=([^,]+)') {
            $cn = $Matches[1].Trim()
            $cn = $cn -replace ':\d{11,14}.*$', ''    # Remove :CPF ou :CNPJ
            $cn = $cn -replace '\s*\(.*?\)\s*$', ''   # Remove (e-CPF A1) etc.
            return $cn.Trim()
        }
        return $Subject
    }

    function Get-IdentificadorCert {
        param([string]$Subject)
        if ($Subject -match ':(\d{14})\b') {
            $n = $Matches[1]
            return 'CNPJ ' + $n.Substring(0,2) + '.' + $n.Substring(2,3) + '.' + $n.Substring(5,3) + '/' + $n.Substring(8,4) + '-' + $n.Substring(12,2)
        }
        if ($Subject -match ':(\d{11})\b') {
            $n = $Matches[1]
            return 'CPF ' + $n.Substring(0,3) + '.' + $n.Substring(3,3) + '.' + $n.Substring(6,3) + '-' + $n.Substring(9,2)
        }
        if ($Subject -match '(\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2})') { return 'CNPJ ' + $Matches[1] }
        if ($Subject -match '(\d{3}\.\d{3}\.\d{3}-\d{2})')       { return 'CPF '  + $Matches[1] }
        return ''
    }

    function Get-TipoICPBrasil {
        param([string]$Subject, [string]$Issuer, [string]$Identificador)
        $texto = $Subject + ' ' + $Issuer
        if ($texto -match 'OAB') { return 'OAB' }
        # Tipos ICP-Portugal
        if ($texto -match 'Cart.o de Cidad.o|Portuguese Citizen Card|CC Portuguese') { return 'Cidadao PT' }
        if ($texto -match 'SCEE|Multicert|DigitalSign|DSTgroup|ECEE|Camerfirma Portugal|Portuguese Auth') { return 'ICP-PT' }
        # Tipos ICP-Brasil
        if ($Identificador -match '^CNPJ') { return 'eCNPJ' }
        if ($Identificador -match '^CPF')  { return 'eCPF'  }
        return 'ICP-Brasil'
    }

    function Get-EmissorResumido {
        param([string]$Issuer)
        if ($Issuer -match 'CN=([^,]+)') { return $Matches[1].Trim() }
        return $Issuer
    }

    # =========================================================================
    # Cabecalho
    # =========================================================================

    Write-Host ''
    Write-Host '   Limpeza de Certificados - Loja Pessoal (My)        ' -ForegroundColor DarkCyan
    Write-Host '   Apaga vencidos e nao-ICP. Nao pergunta nada.       ' -ForegroundColor DarkCyan
    Write-Host ''
    Write-CertInfo 'FICA: ICP-Brasil e ICP-Portugal dentro da validade.'
    Write-CertInfo 'SAI : todo vencido, e todo certificado que nao e ICP.'
    Write-CertInfo 'Portugal segue a mesma regra do Brasil: so sai se estiver vencido.'

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    if ($isAdmin) {
        Write-CertOk 'Executando como Administrador.'
    } else {
        Write-CertOk 'Executando como usuario padrao (suficiente para a loja Pessoal).'
    }

    # =========================================================================
    # ETAPA 1 - Ler a loja CurrentUser\My
    # =========================================================================

    Write-CertEtapa '1/5  Lendo loja CurrentUser\My (aba Pessoal do certmgr)...'
    Write-Host ''

    $StoreName     = [System.Security.Cryptography.X509Certificates.StoreName]::My
    $StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    $OpenFlags     = [System.Security.Cryptography.X509Certificates.OpenFlags]

    $loja = [System.Security.Cryptography.X509Certificates.X509Store]::new($StoreName, $StoreLocation)

    try {
        $loja.Open($OpenFlags::ReadOnly)
    } catch {
        Write-CertFalha ('Nao foi possivel abrir a loja CurrentUser\My: ' + $_.Exception.Message)
            return [long]0
    }

    $certsBrutos = @($loja.Certificates)
    $loja.Close()

    if ($certsBrutos.Count -eq 0) {
        Write-CertOk 'A loja Pessoal esta vazia. Nenhuma acao necessaria.'
            return [long]0
    }

    Write-CertOk ("$($certsBrutos.Count) certificado(s) encontrado(s) na loja Pessoal.")

    $hoje = Get-Date

    # =========================================================================
    # ETAPA 2 - Classificar cada certificado nas tres categorias
    # =========================================================================

    Write-CertEtapa '2/5  Classificando certificados...'
    Write-Host ''

    # Duas listas, so. Nao existe mais categoria "sob consulta".
    #   MANTER  = ICP (Brasil ou Portugal) dentro da validade;
    #   REMOVER = todo o resto - vencido de qualquer origem, e nao-ICP.
    #
    # O que faz esta regra ser segura o bastante para rodar sem perguntar:
    # todo certificado ICP-Brasil traz "O=ICP-Brasil" no proprio emissor
    # (conferido em 29/07/2026 na maquina do Ivan), entao "nao reconhecido"
    # significa de fato "nao e ICP", e nao "emissor que faltou na lista".

    $manter  = [System.Collections.Generic.List[PSObject]]::new()
    $remover = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($cert in $certsBrutos) {
        $subject      = $cert.Subject
        $issuer       = $cert.Issuer
        $nome         = Get-NomeCert $subject
        $identificador = Get-IdentificadorCert $subject
        $emissor      = Get-EmissorResumido $issuer
        $vencimento   = $cert.NotAfter
        $vencido      = $vencimento -lt $hoje
        $diasRestantes = [math]::Round(($vencimento - $hoje).TotalDays, 0)
        $isICP        = Test-ICPBrasil $subject $issuer
        $tipo         = if ($isICP) { Get-TipoICPBrasil $subject $issuer $identificador } else { 'Desconhecido' }
        $temChave     = $false
        try { $temChave = $cert.HasPrivateKey } catch {}

        $obj = [PSCustomObject]@{
            Thumbprint    = $cert.Thumbprint
            NumeroSerie   = $cert.SerialNumber
            Nome          = $nome
            Identificador = $identificador
            Tipo          = $tipo
            Emissor       = $emissor
            Vencimento    = $vencimento
            Vencido       = $vencido
            DiasRestantes = $diasRestantes
            ICPBrasil     = $isICP
            ChavePrivada  = $temChave
            Certificado   = $cert
        }

        if ($isICP -and -not $vencido) {
            $manter.Add($obj)
        } else {
            $motivo = if ($isICP)        { 'ICP vencido'     }
                      elseif ($vencido)  { 'Nao-ICP vencido' }
                      else               { 'Nao e ICP'       }
            $obj | Add-Member -NotePropertyName 'Motivo' -NotePropertyValue $motivo
            $remover.Add($obj)
        }
    }

    $comChave = @($remover | Where-Object { $_.ChavePrivada })

    Write-CertOk    ('Ficam  (ICP dentro da validade) : ' + $manter.Count)
    Write-CertAviso ('Saem   (vencidos e nao-ICP)     : ' + $remover.Count)
    if ($comChave.Count -gt 0) {
        Write-CertAviso ('   destes, com chave privada A1 : ' + $comChave.Count)
    }

    # =========================================================================
    # ETAPA 3 - Exibir o que fica e o que sai
    # =========================================================================

    Write-CertEtapa '3/5  Lista completa...'

    # --- Ficam ---
    Write-Host ''
    Write-Host '   ============================================================' -ForegroundColor DarkGreen
    Write-Host '   FICAM  >>  ICP-Brasil / ICP-Portugal dentro da validade     ' -ForegroundColor DarkGreen
    Write-Host '   ============================================================' -ForegroundColor DarkGreen
    Write-Host ''

    if ($manter.Count -eq 0) {
        Write-CertInfo 'Nenhum certificado ICP valido na loja.'
    } else {
        foreach ($c in ($manter | Sort-Object Vencimento)) {
            $diasInfo = if ($c.DiasRestantes -le 30) {
                '  [expira em ' + $c.DiasRestantes + ' dias]'
            } else {
                ''
            }
            Write-Host ('   [' + $c.Tipo.PadRight(9) + '] ') -ForegroundColor DarkGreen -NoNewline
            Write-Host ($c.Nome + $diasInfo) -ForegroundColor DarkGreen
            if ($c.Identificador) {
                Write-Host ('   ' + ''.PadRight(12) + ' Ident.: ' + $c.Identificador) -ForegroundColor DarkGray
            }
            Write-Host ('   ' + ''.PadRight(12) + ' Emiss.: ' + $c.Emissor) -ForegroundColor DarkGray
            Write-Host ('   ' + ''.PadRight(12) + ' Valido: ' + $c.Vencimento.ToString('dd/MM/yyyy')) -ForegroundColor DarkGray
            Write-Host ('   ' + ''.PadRight(12) + ' Thumb : ' + $c.Thumbprint) -ForegroundColor DarkCyan
            Write-Host ''
        }
    }

    # --- Saem ---
    Write-Host '   ============================================================' -ForegroundColor DarkRed
    Write-Host '   SAEM   >>  Vencidos (de qualquer origem) e nao-ICP          ' -ForegroundColor DarkRed
    Write-Host '   ============================================================' -ForegroundColor DarkRed
    Write-Host ''

    if ($remover.Count -eq 0) {
        Write-CertInfo 'Nada a remover.'
    } else {
        foreach ($c in ($remover | Sort-Object Motivo, Nome)) {
            Write-Host ('   [' + $c.Motivo.PadRight(15) + '] ') -ForegroundColor DarkRed -NoNewline
            Write-Host $c.Nome -ForegroundColor DarkYellow
            if ($c.Identificador) {
                Write-Host ('   ' + ''.PadRight(18) + ' Ident.: ' + $c.Identificador) -ForegroundColor DarkGray
            }
            Write-Host ('   ' + ''.PadRight(18) + ' Emiss.: ' + $c.Emissor) -ForegroundColor DarkGray
            $rotuloData = if ($c.Vencido) {
                ' Venceu: ' + $c.Vencimento.ToString('dd/MM/yyyy') + '  (ha ' + [math]::Abs($c.DiasRestantes) + ' dias)'
            } else {
                ' Validade: ' + $c.Vencimento.ToString('dd/MM/yyyy') + '  (na validade, mas nao e ICP)'
            }
            Write-Host ('   ' + ''.PadRight(18) + $rotuloData) -ForegroundColor DarkRed
            Write-Host ('   ' + ''.PadRight(18) + ' Thumb : ' + $c.Thumbprint) -ForegroundColor DarkCyan
            if ($c.ChavePrivada) {
                Write-Host ('   ' + ''.PadRight(18) + ' Tem chave privada (A1) - a remocao e permanente') -ForegroundColor DarkRed
            }
            Write-Host ''
        }
    }

    # =========================================================================
    # ETAPA 4 - Verificar se ha algo a fazer
    # =========================================================================

    if ($remover.Count -eq 0) {
        Write-Host ''
        Write-CertOk 'Nenhum certificado para remover. Loja ja esta limpa.'
        Write-Host ''
            return [long]0
    }

    # =========================================================================
    # ETAPA 5/6 - Backup CSV antes de qualquer remocao
    # =========================================================================

    Write-CertEtapa '4/5  Exportando backup para a Area de Trabalho...'
    Write-Host ''

    $desktop    = [Environment]::GetFolderPath('Desktop')
    $backupDir  = Join-Path $desktop ('CertificadosBackup_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $csvPath    = Join-Path $backupDir 'certificados.csv'
    $backupOk   = $false

    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $linhasCSV = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($c in $certsBrutos) {
        $s = $c.Subject
        $i = $c.Issuer
        $linhasCSV.Add([PSCustomObject]@{
            Categoria     = if (Test-ICPBrasil $s $i) { if ($c.NotAfter -lt $hoje) { 'ICP Vencido' } else { 'ICP Valido' } } else { 'Nao e ICP' }
            Nome          = Get-NomeCert $s
            Identificador = Get-IdentificadorCert $s
            Tipo          = if (Test-ICPBrasil $s $i) { Get-TipoICPBrasil $s $i (Get-IdentificadorCert $s) } else { 'Desconhecido' }
            Emissor       = Get-EmissorResumido $i
            Vencimento    = $c.NotAfter.ToString('dd/MM/yyyy HH:mm:ss')
            Vencido       = if ($c.NotAfter -lt $hoje) { 'Sim' } else { 'Nao' }
            Thumbprint    = $c.Thumbprint
            NumeroSerie   = $c.SerialNumber
            Loja          = 'CurrentUser\My'
        })
    }

    # O backup nao pergunta nada e nao interrompe: se falhar, avisa e segue.
    # Ele existe para deixar rastro do que havia na loja, nao para servir de
    # portao de confirmacao.
    try {
        $linhasCSV | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
        $backupOk = $true
        Write-CertOk ("Lista salva: $csvPath")
        Write-CertInfo ("$($linhasCSV.Count) certificado(s) registrado(s) no arquivo CSV.")
    } catch {
        Write-CertAviso 'Nao foi possivel salvar o CSV. Seguindo assim mesmo.'
        Write-CertInfo  ('Erro: ' + $_.Exception.Message)
    }

    # Exportar o certificado em si (.cer) - permite reimportar a parte publica
    $cerExportados = 0
    foreach ($c in $certsBrutos) {
        try {
            $nomeArq = ($c.Thumbprint + '.cer')
            $bytes   = $c.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            [System.IO.File]::WriteAllBytes((Join-Path $backupDir $nomeArq), $bytes)
            $cerExportados++
        } catch {}
    }
    if ($cerExportados -gt 0) {
        Write-CertOk ("$cerExportados arquivo(s) .cer exportado(s) em: $backupDir")
    }

    Write-Host ''
    Write-CertAviso 'LIMITE DO BACKUP: o .cer guarda apenas a parte PUBLICA do certificado.'
    Write-CertInfo  'A chave privada (A1) nao entra no backup e nao volta depois de removida.'
    Write-CertInfo  'O que sai daqui e vencido ou nao-ICP; ICP dentro da validade nunca sai.'

    # =========================================================================
    # ETAPA 5 - Remover. Sem pergunta nenhuma: a lista acima ja e a decisao.
    # =========================================================================
    #
    # Aqui existia Select-CertsParaRemover, com menu [1/2/3] por categoria e
    # mais um S/N para cada certificado com chave privada. Saiu inteira em
    # 29/07/2026: escolher a opcao no menu JA E a confirmacao.

    Write-CertEtapa '5/5  Removendo certificados e gerando relatorio...'
    Write-Host ''

    $removidosOK    = [System.Collections.Generic.List[PSObject]]::new()
    $removidosErro  = [System.Collections.Generic.List[PSObject]]::new()

    function Remove-CertDaLoja {
        param([PSObject]$CertObj, [string]$Motivo)
        try {
            $lojaRW = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                [System.Security.Cryptography.X509Certificates.StoreName]::My,
                [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
            )
            $lojaRW.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $lojaRW.Remove($CertObj.Certificado)
            $lojaRW.Close()
            $removidosOK.Add([PSCustomObject]@{ Nome = $CertObj.Nome; Tipo = $CertObj.Tipo; Motivo = $Motivo; Thumb = $CertObj.Thumbprint })
            Write-CertOk ('Removido [' + $Motivo + ']: ' + $CertObj.Nome)
        } catch {
            $removidosErro.Add([PSCustomObject]@{ Nome = $CertObj.Nome; Erro = $_.Exception.Message })
            Write-CertFalha ('Erro ao remover: ' + $CertObj.Nome + ' - ' + $_.Exception.Message)
        }
    }

    foreach ($c in ($remover | Sort-Object Motivo, Nome)) {
        Remove-CertDaLoja $c $c.Motivo
    }

    # =========================================================================
    # Relatorio final
    # =========================================================================

    $totalRemovidos = $removidosOK.Count
    $totalErros     = $removidosErro.Count

    Write-Host ''
    Write-Host '   RELATORIO FINAL                                     ' -ForegroundColor DarkCyan
    Write-Host ''

    Write-CertSecao 'Resultado da analise:'
    Write-Host ('   ICP validos (mantidos)        : ' + $manter.Count) -ForegroundColor DarkGreen
    Write-Host ('   Marcados para remocao         : ' + $remover.Count) -ForegroundColor $(if ($remover.Count -gt 0) { 'DarkYellow' } else { 'DarkGray' })

    Write-CertSecao 'Resultado das remocoes:'
    Write-Host ('   Removidos com sucesso         : ' + $totalRemovidos) -ForegroundColor $(if ($totalRemovidos -gt 0) { 'DarkGreen' } else { 'DarkGray' })
    Write-Host ('   Erros ao remover              : ' + $totalErros) -ForegroundColor $(if ($totalErros -gt 0) { 'DarkRed' } else { 'DarkGray' })

    if ($removidosOK.Count -gt 0) {
        Write-CertSecao 'Certificados removidos:'
        foreach ($r in $removidosOK) {
            Write-Host ('   [' + $r.Motivo.PadRight(15) + '] ' + $r.Nome) -ForegroundColor DarkGreen
            Write-Host ('   ' + ''.PadRight(19) + ' Thumb: ' + $r.Thumb) -ForegroundColor DarkCyan
        }
    }

    if ($removidosErro.Count -gt 0) {
        Write-CertSecao 'Erros (certificados que nao puderam ser removidos):'
        foreach ($e in $removidosErro) {
            Write-Host ('   ' + $e.Nome + ' : ' + $e.Erro) -ForegroundColor DarkRed
        }
        Write-CertInfo 'Certificado em uso por outro programa pode nao ser removivel.'
        Write-CertInfo 'Feche os programas (PJeOffice, navegador, Java) e rode de novo.'
        Add-Alerta ('Limpeza de certificados: ' + $totalErros + ' nao puderam ser removidos.')
    }

    Write-Host ''
    if ($backupOk) {
        Write-Host ('   Backup : ' + $backupDir) -ForegroundColor DarkCyan
        Write-Host '   (lista em CSV + .cer da parte publica; chave privada NAO incluida)' -ForegroundColor DarkGray
    }

    Write-Host ''
    Write-Host '   Para verificar manualmente: Win+R  >  certmgr.msc  >  Pessoal' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host ''
    return [long]0
}

function Repair-ProxyECertificados {
    <#
      Veio de CorrigirProxy.ps1.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Verificaria proxy, TLS e certificados raiz, e testaria os sistemas juridicos.'; return [long]0 }
    # CorrigirProxy.ps1
    # Detecta e corrige problemas de proxy e certificados de rede




    function Garantir-Chave {
        param([string]$Caminho)
        if (-not (Test-Path $Caminho)) {
            New-Item -Path $Caminho -Force | Out-Null
        }
    }

    function Definir-DWORD {
        param([string]$Caminho, [string]$Nome, [int]$Valor)
        Garantir-Chave $Caminho
        Set-ItemProperty -Path $Caminho -Name $Nome -Value $Valor -Type DWord -Force
    }

    # =========================================================================
    # Cabecalho
    # =========================================================================

    Write-Host ''
    Write-Host '   Corrigir Proxy e Certificados de Rede              ' -ForegroundColor Cyan
    Write-Host ''

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    if (-not $isAdmin) {
        Write-Falha 'Este script requer privilegios de Administrador.'
        Write-Info  'Execute o PowerShell como Administrador e tente novamente.'
            return [long]0
    }
    Write-Ok 'Executando como Administrador.'

    # Rastrear acoes realizadas para o relatorio final
    $acoesRealizadas  = [System.Collections.Generic.List[string]]::new()
    $problemaEncontrado = $false

    # =========================================================================
    # ETAPA 1 - Verificar configuracoes de proxy atuais
    # =========================================================================

    Write-Etapa '1/9  Verificando configuracoes de proxy atuais...'
    Write-Host ''

    $regProxy = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

    $proxyAtivo      = (Get-ItemProperty -Path $regProxy -Name 'ProxyEnable'    -ErrorAction SilentlyContinue).ProxyEnable
    $proxyServidor   = (Get-ItemProperty -Path $regProxy -Name 'ProxyServer'    -ErrorAction SilentlyContinue).ProxyServer
    $proxyExcecoes   = (Get-ItemProperty -Path $regProxy -Name 'ProxyOverride'  -ErrorAction SilentlyContinue).ProxyOverride
    $proxyAutoConfig = (Get-ItemProperty -Path $regProxy -Name 'AutoConfigURL'  -ErrorAction SilentlyContinue).AutoConfigURL

    $proxyHKLM       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
    $proxyAtivoSist  = (Get-ItemProperty -Path $proxyHKLM -Name 'ProxyEnable'   -ErrorAction SilentlyContinue).ProxyEnable
    $proxyServSist   = (Get-ItemProperty -Path $proxyHKLM -Name 'ProxyServer'   -ErrorAction SilentlyContinue).ProxyServer

    Write-Dest '   --- Proxy do usuario (HKCU) ---'
    if ($proxyAtivo -eq 1) {
        Write-Aviso 'Proxy do usuario: ATIVO'
        $problemaEncontrado = $true
        if ($proxyServidor) { Write-Dest ("   Servidor    : " + $proxyServidor) }
        if ($proxyExcecoes) { Write-Dest ("   Excecoes    : " + $proxyExcecoes) }
    } else {
        Write-Ok 'Proxy do usuario: inativo.'
    }
    if ($proxyAutoConfig) {
        Write-Aviso ('Auto-config (PAC) configurado: ' + $proxyAutoConfig)
        $problemaEncontrado = $true
    }

    Write-Host ''
    Write-Dest '   --- Proxy do sistema (HKLM) ---'
    if ($proxyAtivoSist -eq 1) {
        Write-Aviso 'Proxy do sistema: ATIVO'
        $problemaEncontrado = $true
        if ($proxyServSist) { Write-Dest ("   Servidor    : " + $proxyServSist) }
    } else {
        Write-Ok 'Proxy do sistema: inativo.'
    }

    # Proxy WinHTTP
    Write-Host ''
    Write-Dest '   --- Proxy WinHTTP (netsh) ---'
    $winHttpProxy = netsh winhttp show proxy 2>$null
    if ($winHttpProxy) {
        $linhaProxy = $winHttpProxy | Where-Object { $_ -match 'Servidor Proxy|Proxy Server|Direct Access' }
        foreach ($linha in $linhaProxy) {
            $textoLinha = $linha.Trim()
            if ($textoLinha -match 'Direct Access|Acesso direto') {
                Write-Ok "WinHTTP: $textoLinha"
            } else {
                Write-Aviso "WinHTTP: $textoLinha"
                $problemaEncontrado = $true
            }
        }
        if (-not $linhaProxy) {
            $winHttpProxy | Where-Object { $_.Trim() } | ForEach-Object { Write-Info $_.Trim() }
        }
    }

    # =========================================================================
    # ETAPA 2 - Perguntar se deseja limpar configuracoes de proxy
    # =========================================================================

    Write-Etapa '2/9  Limpeza das configuracoes de proxy...'
    Write-Host ''

    $limparProxy = $false
    if ($proxyAtivo -eq 1 -or $proxyAutoConfig -or $proxyAtivoSist -eq 1) {
        Write-Aviso 'Proxy ativo detectado. Recomenda-se limpar para restaurar acesso direto.'
        Write-Host ''
        $resp = Read-Host '   Deseja limpar as configuracoes de proxy? (S/N)'
        if ($resp -match '^[Ss]') {
            $limparProxy = $true
        } else {
            Write-Info 'Limpeza de proxy ignorada pelo usuario.'
        }
    } else {
        Write-Ok 'Nenhum proxy ativo. Etapa ignorada.'
        $resp2 = Read-Host '   Deseja limpar/resetar o proxy mesmo assim (preventivo)? (S/N)'
        if ($resp2 -match '^[Ss]') { $limparProxy = $true }
    }

    if ($limparProxy) {
        Write-Host ''
        Write-Acao 'Limpando ProxyEnable no registro do usuario (HKCU)...'
        Set-ItemProperty -Path $regProxy -Name 'ProxyEnable' -Value 0 -Type DWord -Force
        Remove-ItemProperty -Path $regProxy -Name 'ProxyServer'    -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $regProxy -Name 'ProxyOverride'  -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $regProxy -Name 'AutoConfigURL'  -ErrorAction SilentlyContinue
        Write-Ok 'Proxy do usuario (HKCU) limpo.'
        $acoesRealizadas.Add('Proxy do usuario (HKCU) desativado e limpo')

        Write-Acao 'Limpando proxy no registro do sistema (HKLM)...'
        Set-ItemProperty -Path $proxyHKLM -Name 'ProxyEnable' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $proxyHKLM -Name 'ProxyServer'   -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $proxyHKLM -Name 'AutoConfigURL' -ErrorAction SilentlyContinue
        Write-Ok 'Proxy do sistema (HKLM) limpo.'
        $acoesRealizadas.Add('Proxy do sistema (HKLM) desativado e limpo')

        Write-Acao 'Resetando proxy WinHTTP para acesso direto...'
        netsh winhttp reset proxy | Out-Null
        Write-Ok 'WinHTTP resetado para acesso direto.'
        $acoesRealizadas.Add('Proxy WinHTTP resetado para acesso direto (netsh)')

        # Notificar o sistema sobre mudanca de proxy (equivalente a clicar OK nas configuracoes de IE)
        try {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class WinInet {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int lpdwBufferLength);
    public const int INTERNET_OPTION_SETTINGS_CHANGED   = 39;
    public const int INTERNET_OPTION_REFRESH            = 37;
}
'@ -ErrorAction SilentlyContinue
            [WinInet]::InternetSetOption([IntPtr]::Zero, [WinInet]::INTERNET_OPTION_SETTINGS_CHANGED, [IntPtr]::Zero, 0) | Out-Null
            [WinInet]::InternetSetOption([IntPtr]::Zero, [WinInet]::INTERNET_OPTION_REFRESH, [IntPtr]::Zero, 0) | Out-Null
            Write-Ok 'Notificacao de alteracao de proxy enviada ao sistema.'
        } catch {}
    }

    # =========================================================================
    # ETAPA 3 - Habilitar TLS 1.0, TLS 1.1, TLS 1.2 e TLS 1.3
    # =========================================================================

    Write-Etapa '3/9  Verificando e habilitando protocolos TLS...'
    Write-Host ''

    $baseSchannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

    $buildNum = $null
    try {
        $buildNum = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).CurrentBuildNumber
    } catch {}

    # TLS 1.0 e 1.1 sao protocolos obsoletos. Sao habilitados apenas no lado
    # CLIENTE, que e o que a maquina usa para acessar sistemas judiciais antigos.
    # Habilitar no lado SERVIDOR nao ajuda em nada nessas maquinas e so deixaria
    # a maquina aceitando conexoes por protocolo fraco.
    $protocolos = @(
        @{ Nome = 'TLS 1.0'; Chave = 'TLS 1.0';  Habilitar = $true;  Servidor = $false }
        @{ Nome = 'TLS 1.1'; Chave = 'TLS 1.1';  Habilitar = $true;  Servidor = $false }
        @{ Nome = 'TLS 1.2'; Chave = 'TLS 1.2';  Habilitar = $true;  Servidor = $true  }
        @{ Nome = 'TLS 1.3'; Chave = 'TLS 1.3';  Habilitar = ($buildNum -ge 18362); Servidor = $true }
    )

    foreach ($proto in $protocolos) {
        $caminho    = $baseSchannel + '\' + $proto.Chave
        $caminhoCliente  = $caminho + '\Client'
        $caminhoServidor = $caminho + '\Server'

        if (-not $proto.Habilitar) {
            Write-Info "$($proto.Nome): nao aplicavel nesta versao do Windows (build $buildNum). Ignorado."
            continue
        }

        $clienteEnabled  = (Get-ItemProperty -Path $caminhoCliente  -Name 'Enabled'          -ErrorAction SilentlyContinue).Enabled
        $clienteDisabled = (Get-ItemProperty -Path $caminhoCliente  -Name 'DisabledByDefault' -ErrorAction SilentlyContinue).DisabledByDefault
        $servidorEnabled = (Get-ItemProperty -Path $caminhoServidor -Name 'Enabled'          -ErrorAction SilentlyContinue).Enabled

        $clienteOk  = ($clienteEnabled -eq 1 -and $clienteDisabled -eq 0)
        $servidorOk = (-not $proto.Servidor) -or ($servidorEnabled -eq 1)

        if ($clienteOk -and $servidorOk) {
            Write-Ok "$($proto.Nome): ja habilitado."
        } else {
            $lado = if ($proto.Servidor) { 'cliente e servidor' } else { 'somente cliente' }
            Write-Acao "Habilitando $($proto.Nome) ($lado)..."
            Definir-DWORD -Caminho $caminhoCliente  -Nome 'Enabled'          -Valor 1
            Definir-DWORD -Caminho $caminhoCliente  -Nome 'DisabledByDefault' -Valor 0
            if ($proto.Servidor) {
                Definir-DWORD -Caminho $caminhoServidor -Nome 'Enabled'          -Valor 1
                Definir-DWORD -Caminho $caminhoServidor -Nome 'DisabledByDefault' -Valor 0
            }
            Write-Ok "$($proto.Nome): habilitado com sucesso ($lado)."
            $acoesRealizadas.Add("$($proto.Nome) habilitado no SCHANNEL ($lado)")
        }
    }

    # .NET Framework - habilitar TLS forte para aplicacoes Java/juridicas
    Write-Host ''
    Write-Dest '   --- .NET Framework (SchUseStrongCrypto) ---'
    $dotNetCaminhos = @(
        'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
        'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727'
    )
    foreach ($dotNetCaminho in $dotNetCaminhos) {
        $valor = (Get-ItemProperty -Path $dotNetCaminho -Name 'SchUseStrongCrypto' -ErrorAction SilentlyContinue).SchUseStrongCrypto
        $versao = Split-Path $dotNetCaminho -Leaf
        if ($valor -eq 1) {
            Write-Ok "SchUseStrongCrypto OK: $versao"
        } else {
            Definir-DWORD -Caminho $dotNetCaminho -Nome 'SchUseStrongCrypto' -Valor 1
            Write-Ok "SchUseStrongCrypto habilitado: $versao"
            $acoesRealizadas.Add("SchUseStrongCrypto habilitado para .NET $versao")
        }
    }

    # =========================================================================
    # ETAPA 4 - Atualizar certificados raiz via Windows Update
    # =========================================================================

    Write-Etapa '4/9  Atualizando certificados raiz do Windows...'
    Write-Host ''

    $sstTemp = "$env:TEMP\roots_wu.sst"
    if (Test-Path $sstTemp) { Remove-Item $sstTemp -Force -ErrorAction SilentlyContinue }

    Write-Acao 'Baixando certificados raiz do Windows Update (certutil -generateSSTFromWU)...'
    Write-Info 'Isso pode levar alguns segundos. Requer acesso a internet.'

    $saida = certutil -generateSSTFromWU $sstTemp 2>&1
    $sucesso = Test-Path $sstTemp

    if ($sucesso) {
        Write-Ok 'Arquivo SST baixado com sucesso.'
        Write-Acao 'Importando certificados raiz para a loja do sistema...'
        $saidaImport = certutil -addstore -f root $sstTemp 2>&1
        $errosImport = $saidaImport | Where-Object { $_ -match 'Erro|Error|FAILED' }
        if ($errosImport) {
            Write-Aviso 'Alguns certificados nao puderam ser importados (normal para certificados ja existentes).'
        } else {
            Write-Ok 'Certificados raiz importados com sucesso.'
            $acoesRealizadas.Add('Certificados raiz atualizados via Windows Update (certutil)')
        }
        Remove-Item $sstTemp -Force -ErrorAction SilentlyContinue
    } else {
        Write-Aviso 'Nao foi possivel baixar certificados do Windows Update.'
        Write-Info  'Verifique a conexao com a internet e tente novamente manualmente:'
        Write-Info  '  certutil -generateSSTFromWU %TEMP%\roots.sst'
        Write-Info  '  certutil -addstore -f root %TEMP%\roots.sst'
    }

    # Sincronizar via mecanismo automatico do Windows (authroot.stl)
    Write-Acao 'Sinalizando o sistema para resincronizar a lista de certificados confiados...'
    try {
        certutil -setreg chain\ChainCacheResyncFiletime '@now' 2>&1 | Out-Null
        Write-Ok 'Cache de cadeia de certificados sinalizado para resincronizacao.'
        $acoesRealizadas.Add('Cache de cadeia de certificados marcado para resincronizacao (certutil)')
    } catch {
        Write-Info 'Resincronizacao de cache nao disponivel (opcional).'
    }

    # =========================================================================
    # ETAPA 5 - Limpar cache SSL do Windows
    # =========================================================================

    Write-Etapa '5/9  Limpando cache SSL do Windows...'
    Write-Host ''

    # Limpar cache de URL do certutil (OCSP, CRL, AIA)
    Write-Acao 'Limpando cache de URL do certutil (OCSP/CRL)...'
    certutil -urlcache * delete 2>&1 | Out-Null
    Write-Ok 'Cache de URL do certutil limpo.'
    $acoesRealizadas.Add('Cache de URL do certutil (OCSP/CRL) limpo')

    # Limpar o CryptnetUrlCache - e' AQUI que ficam CRL/OCSP/AIA em cache.
    # (Fica em LocalLow, nao no INetCache do navegador.)
    $cryptCache = Join-Path $env:USERPROFILE 'AppData\LocalLow\Microsoft\CryptnetUrlCache'
    if (Test-Path -LiteralPath $cryptCache) {
        $arquivosCrypt = @(Get-ChildItem -LiteralPath $cryptCache -Recurse -File -ErrorAction SilentlyContinue)
        if ($arquivosCrypt.Count -gt 0) {
            Write-Acao "Limpando $($arquivosCrypt.Count) arquivo(s) do CryptnetUrlCache..."
            Remove-Item -Path (Join-Path $cryptCache '*') -Recurse -Force -ErrorAction SilentlyContinue
            Write-Ok 'CryptnetUrlCache limpo.'
            $acoesRealizadas.Add("CryptnetUrlCache limpo ($($arquivosCrypt.Count) arquivos removidos)")
        } else {
            Write-Ok 'CryptnetUrlCache ja estava vazio.'
        }
    } else {
        Write-Info 'CryptnetUrlCache nao encontrado neste perfil.'
    }

    # O estado SSL do Windows fica no cache de cadeia, ja tratado pelo certutil
    # acima. Nao usamos ClearMyTracksByProcess aqui: os flags dele apagam
    # historico/cookies do IE-Edge e nao tem relacao com estado SSL.

    # =========================================================================
    # ETAPA 6 - Verificar certificados expirados ou invalidos
    # =========================================================================

    Write-Etapa '6/9  Verificando certificados na loja do usuario...'
    Write-Host ''

    $StoreName     = [System.Security.Cryptography.X509Certificates.StoreName]
    $StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]
    $OpenFlags     = [System.Security.Cryptography.X509Certificates.OpenFlags]

    $hoje             = Get-Date
    $certExpirados    = [System.Collections.Generic.List[PSObject]]::new()
    $certQuaseExpir   = [System.Collections.Generic.List[PSObject]]::new()

    $lojas = @(
        @{ Nome = 'Pessoal (My)';       Loja = $StoreName::My;       Local = $StoreLocation::CurrentUser  }
        @{ Nome = 'Raiz confiavel';     Loja = $StoreName::Root;     Local = $StoreLocation::CurrentUser  }
        @{ Nome = 'Autoridades interm.'; Loja = $StoreName::CertificationAuthority; Local = $StoreLocation::CurrentUser }
        @{ Nome = 'Raiz (sistema)';     Loja = $StoreName::Root;     Local = $StoreLocation::LocalMachine }
    )

    foreach ($entrada in $lojas) {
        $loja = [System.Security.Cryptography.X509Certificates.X509Store]::new($entrada.Loja, $entrada.Local)
        try {
            $loja.Open($OpenFlags::ReadOnly)
            $certs = $loja.Certificates

            $expiradosLoja  = @($certs | Where-Object { $_.NotAfter -lt $hoje })
            $quaseExpLoja   = @($certs | Where-Object { $_.NotAfter -ge $hoje -and $_.NotAfter -lt $hoje.AddDays(30) })

            if ($expiradosLoja.Count -gt 0 -or $quaseExpLoja.Count -gt 0) {
                Write-Aviso ("Loja '$($entrada.Nome)': $($expiradosLoja.Count) expirado(s), $($quaseExpLoja.Count) a expirar em 30 dias.")
                foreach ($c in $expiradosLoja) { $certExpirados.Add([PSCustomObject]@{ Loja = $entrada.Nome; Assunto = $c.Subject; Expirou = $c.NotAfter }) }
                foreach ($c in $quaseExpLoja)  { $certQuaseExpir.Add([PSCustomObject]@{ Loja = $entrada.Nome; Assunto = $c.Subject; Expira  = $c.NotAfter }) }
            } else {
                Write-Ok ("Loja '$($entrada.Nome)': $($certs.Count) certificado(s), nenhum expirado.")
            }
            $loja.Close()
        } catch {
            Write-Info ("Nao foi possivel abrir loja '$($entrada.Nome)': " + $_.Exception.Message)
        }
    }

    if ($certExpirados.Count -gt 0) {
        Write-Host ''
        Write-Aviso "Certificados EXPIRADOS encontrados ($($certExpirados.Count)):"
        foreach ($c in ($certExpirados | Select-Object -First 10)) {
            $assuntoResumido = if ($c.Assunto.Length -gt 70) { $c.Assunto.Substring(0, 67) + '...' } else { $c.Assunto }
            Write-Dest ("   [" + $c.Expirou.ToString('dd/MM/yyyy') + "]  " + $assuntoResumido)
        }
        Write-Info  'Certificados pessoais expirados podem ser removidos via: certmgr.msc'
        $problemaEncontrado = $true
    }

    if ($certQuaseExpir.Count -gt 0) {
        Write-Host ''
        Write-Info "Certificados proximos do vencimento ($($certQuaseExpir.Count)):"
        foreach ($c in $certQuaseExpir) {
            Write-Dest ("   [expira " + $c.Expira.ToString('dd/MM/yyyy') + "]  " + ($c.Assunto -replace 'CN=',''))
        }
    }

    # =========================================================================
    # ETAPA 7 - Resetar configuracoes de proxy do IE/Edge no registro
    # =========================================================================

    Write-Etapa '7/9  Resetando configuracoes de proxy do IE/Edge (registro e WinHTTP)...'
    Write-Host ''

    # Limpar ConnectionSettings binario do IE (proxy por conexao)
    $regConexoes = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
    $defaultConn = (Get-ItemProperty -Path $regConexoes -Name 'DefaultConnectionSettings' -ErrorAction SilentlyContinue).DefaultConnectionSettings

    if ($defaultConn) {
        # Byte 8 (indice 8) contem flags de proxy: bit 2 = proxy ativo (valor 2 ou 3 = proxy ativo, 1 = direto)
        # Forcar para acesso direto definindo o byte de flags como 1
        $bytesConn = [byte[]]$defaultConn
        if ($bytesConn.Count -ge 9) {
            $flagAtual = $bytesConn[8]
            if (($flagAtual -band 2) -ne 0) {
                Write-Acao 'Limpando configuracao de proxy por conexao (DefaultConnectionSettings)...'
                $bytesConn[8] = ($flagAtual -band 0xFD) -bor 1  # Desativa bit de proxy, ativa bit direto
                Set-ItemProperty -Path $regConexoes -Name 'DefaultConnectionSettings' -Value $bytesConn -Force
                Write-Ok 'DefaultConnectionSettings atualizado para acesso direto.'
                $acoesRealizadas.Add('DefaultConnectionSettings do IE/Edge resetado para acesso direto')
            } else {
                Write-Ok 'DefaultConnectionSettings ja configurado sem proxy ativo.'
            }
        }
    }

    # Garantir que WinHTTP esta sincronizado com as configuracoes do IE
    Write-Acao 'Verificando sincronizacao WinHTTP com configuracoes do IE/Edge...'
    $winHttpAtual = netsh winhttp show proxy 2>$null
    $temProxyWinHttp = $winHttpAtual | Where-Object { $_ -match ':\d+' }

    if ($temProxyWinHttp) {
        Write-Acao 'Importando configuracoes de proxy do IE para WinHTTP...'
        netsh winhttp import proxy source=ie 2>&1 | Out-Null
        Write-Ok 'WinHTTP sincronizado com as configuracoes do IE.'
        $acoesRealizadas.Add('WinHTTP sincronizado com configuracoes do IE/Edge')
    } else {
        Write-Ok 'WinHTTP ja esta com acesso direto. Nenhuma acao necessaria.'
    }

    # Certificar que o servico WinHTTP Web Proxy Auto-Discovery esta funcionando
    $wpadService = Get-Service -Name 'WinHttpAutoProxySvc' -ErrorAction SilentlyContinue
    if ($wpadService) {
        if ($wpadService.Status -ne 'Running') {
            Write-Acao 'Iniciando servico WinHTTP Web Proxy Auto-Discovery...'
            try {
                Set-Service -Name 'WinHttpAutoProxySvc' -StartupType Manual -ErrorAction SilentlyContinue
                Start-Service -Name 'WinHttpAutoProxySvc' -ErrorAction SilentlyContinue
                Write-Ok 'Servico WinHTTP Auto-Discovery iniciado.'
                $acoesRealizadas.Add('Servico WinHTTP Web Proxy Auto-Discovery iniciado')
            } catch {
                Write-Info 'Servico WinHTTP Auto-Discovery nao pode ser iniciado (normal se proxy nao for usado).'
            }
        } else {
            Write-Ok 'Servico WinHTTP Auto-Discovery: em execucao.'
        }
    }

    # =========================================================================
    # ETAPA 8 - Testar conectividade com sites juridicos
    # =========================================================================

    Write-Etapa '8/9  Testando conectividade com sistemas juridicos...'
    Write-Host ''

    $sitesJuridicos = @(
        @{ URL = 'https://pje.jus.br';                Nome = 'PJe Nacional'    }
        @{ URL = 'https://projudi.tjgo.jus.br';        Nome = 'PROJUDI TJGO'   }
        @{ URL = 'https://eproc.jfrs.jus.br';          Nome = 'eProc JFRS'     }
    )

    $resultadosConect = [System.Collections.Generic.List[PSObject]]::new()

    # Garantir que o processo atual usa TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = (
        [Net.SecurityProtocolType]::Tls12 -bor
        [Net.SecurityProtocolType]::Tls11 -bor
        [Net.SecurityProtocolType]::Tls
    )

    foreach ($site in $sitesJuridicos) {
        $url  = $site.URL
        $nome = $site.Nome
        Write-Info "Testando $nome ($url)..."

        $status   = 'FALHA'
        $detalhe  = ''
        $corItem  = 'Red'
        $httpCode = $null

        try {
            $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Timeout          = 12000
            $req.AllowAutoRedirect = $true
            $req.UserAgent        = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120'
            $resp = $req.GetResponse()
            $httpCode = [int]$resp.StatusCode
            $resp.Close()
            $status  = 'OK'
            $detalhe = "HTTP $httpCode"
            $corItem = 'Green'
        } catch [System.Net.WebException] {
            $webEx = $_.Exception
            if ($webEx.Response) {
                $httpCode = [int]$webEx.Response.StatusCode
                # Resposta HTTP recebida = servidor acessivel, mesmo com erro de autenticacao
                if ($httpCode -ge 200) {
                    $status  = 'OK'
                    $detalhe = "HTTP $httpCode (site acessivel)"
                    $corItem = 'Green'
                } else {
                    $status  = 'AVISO'
                    $detalhe = "HTTP $httpCode"
                    $corItem = 'Yellow'
                }
            } elseif ($webEx.Message -match 'SSL|certificate|certificado|TLS') {
                $status  = 'ERRO SSL'
                $detalhe = 'Erro de certificado/TLS - verifique certificados raiz'
                $corItem = 'Red'
            } elseif ($webEx.Message -match 'proxy|407') {
                $status  = 'ERRO PROXY'
                $detalhe = 'Bloqueado por proxy - verifique as configuracoes'
                $corItem = 'Red'
            } elseif ($webEx.Message -match 'timed out|tempo|timeout') {
                $status  = 'TIMEOUT'
                $detalhe = 'Servidor nao respondeu em 12 segundos'
                $corItem = 'Yellow'
            } else {
                $detalhe = $webEx.Message -replace '.*---> ', '' | Select-Object -First 1
                if ($detalhe.Length -gt 80) { $detalhe = $detalhe.Substring(0, 77) + '...' }
                $corItem = 'Yellow'
                $status  = 'AVISO'
            }
        } catch {
            $detalhe = $_.Exception.Message
            if ($detalhe.Length -gt 80) { $detalhe = $detalhe.Substring(0, 77) + '...' }
        }

        $resultadosConect.Add([PSCustomObject]@{
            Nome    = $nome
            URL     = $url
            Status  = $status
            Detalhe = $detalhe
            Cor     = $corItem
        })

        $prefixo = if ($status -eq 'OK') { '   [OK] ' } elseif ($status -match 'AVISO|TIMEOUT') { '   [!]  ' } else { '   [X]  ' }
        $corPref = if ($status -eq 'OK') { 'Green' } elseif ($status -match 'AVISO|TIMEOUT') { 'Yellow' } else { 'Red' }
        Write-Host $prefixo -ForegroundColor $corPref -NoNewline
        Write-Host ($nome.PadRight(20) + "  " + $status.PadRight(12) + "  " + $detalhe)
    }

    # =========================================================================
    # ETAPA 9 - Relatorio final
    # =========================================================================

    Write-Etapa '9/9  Relatorio final...'
    Write-Host ''

    $corRelatorio = if ($acoesRealizadas.Count -eq 0 -and -not $problemaEncontrado) { 'Green' } else { 'Yellow' }

    Write-Host '   RELATORIO DE CORRECOES DE PROXY E CERTIFICADOS     ' -ForegroundColor $corRelatorio
    Write-Host ''

    if ($acoesRealizadas.Count -gt 0) {
        Write-Host '   Acoes realizadas nesta execucao:' -ForegroundColor White
        $num = 1
        foreach ($acao in $acoesRealizadas) {
            Write-Host ('   ' + $num + '. ' + $acao) -ForegroundColor Green
            $num++
        }
    } else {
        Write-Host '   Nenhuma alteracao necessaria. Sistema ja estava configurado corretamente.' -ForegroundColor Green
    }

    Write-Host ''
    Write-Host '   Resultado dos testes de conectividade:' -ForegroundColor White
    foreach ($r in $resultadosConect) {
        Write-Host ('   ' + $r.Status.PadRight(12) + '  ' + $r.Nome.PadRight(20) + '  ' + $r.Detalhe) -ForegroundColor $r.Cor
    }

    if ($certExpirados.Count -gt 0) {
        Write-Host ''
        Write-Host ('   Atencao: ' + $certExpirados.Count + ' certificado(s) expirado(s) encontrado(s). Use certmgr.msc para gerenciar.') -ForegroundColor Yellow
    }

    $requerReinicio = $acoesRealizadas | Where-Object { $_ -match 'TLS|SCHANNEL|SchUseStrongCrypto' }
    if ($requerReinicio) {
        Write-Host ''
        Write-Host '   IMPORTANTE: As alteracoes de TLS entram em vigor apos reiniciar o computador.' -ForegroundColor Yellow
        Write-Host '   Reinicie o sistema para garantir que todos os programas usem os novos protocolos.' -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host ''
    return [long]0
}

function Show-AnaliseBSOD {
    <#
      Analisa telas azuis dos ultimos 30 dias (veio de AnalisarBSOD.ps1).
      Somente leitura. O relatorio e publicado pelo motor em TXT temporario.
    #>
    # AnalisarBSOD.ps1
    # Analisa e identifica causas de Tela Azul (BSOD) no Windows
    # Somente leitura: nao altera nada na maquina.

    $dataLimite = (Get-Date).AddDays(-30)



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
    Write-Host '   Analisador de BSOD - Tela Azul do Windows   ' -ForegroundColor Cyan
    Write-Host ("   Periodo     : ultimos 30 dias") -ForegroundColor DarkGray
    Write-Host ''

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    if (-not $isAdmin) {
        Write-Falha 'Este script requer privilegios de Administrador.'
        Write-Info  'Execute o PowerShell como Administrador e tente novamente.'
            return [long]0
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
                $tamanho = [math]::Round($_.Length / 1KB, 0).ToString('N0') + ' KB'
                Write-Dest ("   " + $_.LastWriteTime.ToString('dd/MM/yyyy HH:mm') + "  " + $tamanho.PadLeft(8) + "  " + $_.Name)
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
        $tamanhoGB  = [math]::Round($memDmpInfo.Length / 1GB, 2).ToString('N2') + ' GB'
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
            Write-Host ("   " + $g.Name + "  x" + ([string]$g.Count).PadRight(3) + "  " + $nomeCode + "  ultima: " + $ultimaVez.ToString('dd/MM/yyyy HH:mm')) -ForegroundColor $cor
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
                Write-Dest ("   " + $_.DataDriver.ToString('dd/MM/yyyy') + "  " + $_.Dispositivo)
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
        $tamanhoGB = if ($disco.Size) { [math]::Round($disco.Size / 1GB, 0).ToString('N0') + ' GB' } else { 'desconhecido' }
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
            Write-Dest ("   " + $slot.PadRight(10) + "  " + ([string]$capGB).PadLeft(4) + " GB  " + $veloc + "  " + $fabric)
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
        Write-Host ("   " + "Data/Hora".PadRight(20) + "  " + "Tipo".PadRight(18) + "  " + "Codigo".PadRight(14) + "  Nome") -ForegroundColor Cyan
        Write-Host ("   " + ('-' * 20) + "  " + ('-' * 18) + "  " + ('-' * 14) + "  " + ('-' * 30)) -ForegroundColor DarkGray
        foreach ($item in $linhaOrdenada) {
            Write-Host ("   " + $item.Data.ToString('dd/MM/yyyy HH:mm:ss').PadRight(20) + "  " + $item.Tipo.PadRight(18) + "  " + $item.Codigo.PadRight(14) + "  " + $item.Nome) -ForegroundColor $item.Cor
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
                Write-Dest ("   Semana de " + $primeiraData.ToString('dd/MM/yyyy').PadRight(12) + ": " + $semana.Count + " evento(s)")
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
    Write-Host '   RESUMO DO DIAGNOSTICO                        ' -ForegroundColor $corResumo
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
    Write-Host ''
    return [long]0
}

# =========================================================================
# REGIAO: DLL FALTANDO
# =========================================================================

function Get-PacoteDaDLL {
    <#
      Diz de qual pacote vem uma DLL. A mensagem "falta X.dll" quase nunca e
      arquivo de sistema corrompido: e' redistribuivel que nao foi instalado.
      Por isso SFC e DISM nao resolvem esse tipo de erro.
    #>
    param([string]$Nome)

    $n = $Nome.ToLower()

    # Universal C Runtime: veio com o VC++ 2015 em diante
    if ($n -like 'api-ms-win-crt-*' -or $n -eq 'ucrtbase.dll') {
        return @{ Pacote = 'Visual C++ 2015-2022 (Universal C Runtime)'; Ferramenta = 'visualc'
                  Obs = 'No Windows 7/8 tambem exige a atualizacao KB2999226.' }
    }
    # Visual C++ por versao
    $mapaVC = [ordered]@{
        '140' = 'Visual C++ 2015-2022'; '120' = 'Visual C++ 2013'; '110' = 'Visual C++ 2012'
        '100' = 'Visual C++ 2010';      '90'  = 'Visual C++ 2008'; '80'  = 'Visual C++ 2005'
        '71'  = 'Visual C++ 2003';      '70'  = 'Visual C++ 2002'
    }
    foreach ($ver in $mapaVC.Keys) {
        if ($n -match "^(msvcr|msvcp|vcruntime|concrt|vccorlib|mfc|mfcm|atl)$ver(_\d+)?\.dll$") {
            return @{ Pacote = $mapaVC[$ver]; Ferramenta = 'visualc'; Obs = '' }
        }
    }
    # DirectX antigo (jogos e alguns sistemas graficos)
    if ($n -match '^(d3dx9|d3dx10|d3dx11|xinput1_|x3daudio|xactengine|xapofx|d3dcompiler_4)') {
        return @{ Pacote = 'DirectX End-User Runtime (junho/2010)'; Ferramenta = ''
                  Obs = 'Baixar em microsoft.com/download/details.aspx?id=35 - o DirectX do Windows nao inclui essas DLLs antigas.' }
    }
    # Visual Basic 6: comum em sistema juridico antigo
    if ($n -match '^(msvbvm50|msvbvm60)\.dll$') {
        return @{ Pacote = 'Visual Basic 6 Runtime'; Ferramenta = ''
                  Obs = 'Normalmente vem junto com o instalador do proprio sistema.' }
    }
    if ($n -match '^(mscomctl|comdlg32|richtx32|msflxgrd|tabctl32|mscomct2)\.ocx$') {
        return @{ Pacote = 'Controles OCX do Visual Basic 6'; Ferramenta = ''
                  Obs = 'Precisa copiar para SysWOW64 e registrar com: regsvr32 <arquivo>' }
    }
    # .NET
    if ($n -match '^(mscoree|mscorlib|system\.|clr)') {
        return @{ Pacote = '.NET Framework'; Ferramenta = ''
                  Obs = 'Instalar o .NET Framework 4.8 (ou o 3.5 via Recursos do Windows).' }
    }
    # Java
    if ($n -match '^(jvm|msvcr100|deploy|jp2iexp)\.dll$') {
        return @{ Pacote = 'Java Runtime'; Ferramenta = 'java'; Obs = '' }
    }
    return $null
}

function Get-DLLsComErroRecente {
    <#
      Varre o log de eventos atras de falhas que citam .dll ou .ocx.
      Evita depender do cliente lembrar o nome exato que apareceu na tela.
        Application Error (1000) : "Nome do modulo com falha: X.dll"
        SideBySide (33,58,59,78) : manifesto/VC++ errado
        Application Hang (1002)  : travamento
    #>
    param([int]$Dias = 60)

    $resultado = [System.Collections.Generic.List[PSObject]]::new()
    $inicio = (Get-Date).AddDays(-$Dias)

    try {
        $eventos = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Application'; StartTime = $inicio } -MaxEvents 400 -ErrorAction SilentlyContinue |
            Where-Object { $_.ProviderName -in @('Application Error', 'SideBySide', 'Application Hang') })
    } catch { return $resultado }

    foreach ($ev in $eventos) {
        $msg = $ev.Message
        if (-not $msg) { continue }
        # pega qualquer nome de arquivo .dll/.ocx citado na mensagem
        foreach ($m in [regex]::Matches($msg, '(?i)\b([A-Za-z0-9_\-\.]+\.(dll|ocx))\b')) {
            $arq = $m.Groups[1].Value
            # ignora o proprio executavel e modulos do sistema que nao ajudam
            if ($arq -match '(?i)^(ntdll|kernelbase|kernel32|combase|user32|shell32)\.dll$') { continue }
            $ja = $resultado | Where-Object { $_.Arquivo -eq $arq }
            if ($ja) {
                $ja.Ocorrencias++
                if ($ev.TimeCreated -gt $ja.Ultima) { $ja.Ultima = $ev.TimeCreated }
            } else {
                $resultado.Add([PSCustomObject]@{
                    Arquivo     = $arq
                    Ocorrencias = 1
                    Ultima      = $ev.TimeCreated
                    Origem      = $ev.ProviderName
                })
            }
        }
    }
    return ($resultado | Sort-Object Ocorrencias -Descending)
}

function Show-RedistribuiveisInstalados {
    $regs = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
              'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    $lista = [System.Collections.Generic.List[string]]::new()
    foreach ($r in $regs) {
        Get-ChildItem -Path $r -ErrorAction SilentlyContinue |
            Get-ItemProperty -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match 'Visual C\+\+|\.NET Framework|DirectX' } |
            ForEach-Object { [void]$lista.Add($_.DisplayName) }
    }
    $unicos = @($lista | Sort-Object -Unique)
    if ($unicos.Count -eq 0) {
        Write-Aviso 'Nenhum redistribuivel Visual C++ / .NET encontrado nesta maquina.'
    } else {
        Write-Info "$($unicos.Count) pacote(s) instalado(s):"
        foreach ($u in $unicos) { Write-Info "   $u" }
    }
}

function Repair-DLLFaltando {
    <#
      Ajuda no erro "nao foi possivel iniciar o programa porque falta X.dll".
      Descobre de onde a DLL deveria vir, verifica se ela existe na maquina,
      confere a arquitetura, olha a quarentena do antivirus e oferece instalar
      o pacote correto. SFC e DISM nao resolvem esse tipo de erro: a DLL nao e'
      arquivo do Windows, e' de redistribuivel.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Identificaria de qual pacote vem a DLL faltando.'; return [long]0 }

    Write-Etapa 'DLL faltando - identificar e resolver'
    Write-Info 'Este erro quase nunca e arquivo do Windows corrompido: a DLL vem'
    Write-Info 'de um redistribuivel que nao foi instalado. Por isso SFC/DISM nao resolvem.'

    if ($SemInteracao) { Write-Aviso 'Modo desatendido: esta ferramenta precisa de interacao.'; return [long]0 }

    # --- Como descobrir o nome ---
    Write-Host ''
    Write-Host '     [1] Procurar sozinho no log de eventos (ultimos 60 dias)' -ForegroundColor White
    Write-Host '     [2] Digitar o nome que apareceu na mensagem de erro' -ForegroundColor White
    Write-Host '     [3] So listar os redistribuiveis instalados' -ForegroundColor White
    Write-Host '     [0] Cancelar' -ForegroundColor DarkGray
    Write-Host ''
    $opc = (Read-Host '  Opcao').Trim()
    if ($opc -eq '0' -or $opc -eq '') { Write-Info 'Cancelado.'; return [long]0 }

    if ($opc -eq '3') {
        Write-Etapa 'Redistribuiveis instalados'
        Show-RedistribuiveisInstalados
        return [long]0
    }

    $nome = ''

    if ($opc -eq '1') {
        Write-Etapa 'Procurando falhas recentes no log de eventos...'
        $achados = @(Get-DLLsComErroRecente -Dias 60)
        if ($achados.Count -eq 0) {
            Write-Info 'Nenhuma falha citando .dll nos ultimos 60 dias.'
            Write-Info 'Use a opcao 2 e digite o nome que aparece na mensagem.'
            return [long]0
        }
        Write-Ok "$($achados.Count) arquivo(s) citado(s) em falhas recentes:"
        Write-Host ''
        $i = 1
        foreach ($a in ($achados | Select-Object -First 12)) {
            Write-Host ("     [{0,2}] {1,-34} {2} ocorrencia(s)   ultima: {3}" -f `
                $i, $a.Arquivo, $a.Ocorrencias, $a.Ultima.ToString('dd/MM/yyyy')) -ForegroundColor White
            $i++
        }
        Write-Host ''
        $sel = (Read-Host '  Numero do arquivo (ENTER para cancelar)').Trim()
        if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le [math]::Min(12, $achados.Count)) {
            $nome = $achados[[int]$sel - 1].Arquivo
        } else { Write-Info 'Cancelado.'; return [long]0 }
    } else {
        Write-Host ''
        Write-Info 'Exemplos: VCRUNTIME140.dll, MSVCP140.dll, msvcr100.dll, MSCOMCTL.OCX'
        $nome = (Read-Host '  Nome do arquivo').Trim().Trim('"').Trim("'")
        if (-not $nome) { Write-Info 'Nada informado. Cancelado.'; return [long]0 }
        if ($nome -notmatch '\.(dll|ocx|exe)$') { $nome = $nome + '.dll' }
        $nome = Split-Path $nome -Leaf     # aceita caminho completo colado do erro
    }

    Write-Host ''
    Write-Dest ("Arquivo: $nome")

    # --- 1) A DLL existe na maquina? ---
    Write-Etapa 'Procurando o arquivo no sistema...'
    $locais = @(
        "$env:SystemRoot\System32"
        "$env:SystemRoot\SysWOW64"
        "$env:SystemRoot"
    )
    $achados = [System.Collections.Generic.List[string]]::new()
    foreach ($d in $locais) {
        $c = Join-Path $d $nome
        if (Test-Path -LiteralPath $c) {
            $v = ''
            try { $v = (Get-Item -LiteralPath $c).VersionInfo.FileVersion } catch { }
            $achados.Add(("$c" + $(if ($v) { "   (versao $v)" } else { '' })))
        }
    }

    if ($achados.Count -gt 0) {
        Write-Ok 'O arquivo EXISTE nesta maquina:'
        foreach ($a in $achados) { Write-Info "   $a" }

        # System32 = 64 bits, SysWOW64 = 32 bits (nomes trocados, mas e' isso).
        # Programa de 32 bits so enxerga SysWOW64; de 64 bits so System32.
        $tem64 = @($achados | Where-Object { $_ -match 'System32' }).Count -gt 0
        $tem32 = @($achados | Where-Object { $_ -match 'SysWOW64' }).Count -gt 0
        Write-Host ''
        Write-Dest 'Arquitetura:'
        Write-Info ("   64 bits (System32) : " + $(if ($tem64) { 'presente' } else { 'AUSENTE' }))
        Write-Info ("   32 bits (SysWOW64) : " + $(if ($tem32) { 'presente' } else { 'AUSENTE' }))
        if ($tem64 -and -not $tem32) {
            Write-Aviso 'So existe a versao 64 bits. Programa de 32 bits vai continuar acusando falta.'
            Write-Info  'Instale tambem o redistribuivel x86 (a ferramenta instala os dois).'
        } elseif ($tem32 -and -not $tem64) {
            Write-Aviso 'So existe a versao 32 bits. Programa de 64 bits vai continuar acusando falta.'
            Write-Info  'Instale tambem o redistribuivel x64.'
        }

        Write-Host ''
        Write-Aviso 'Se o erro continua mesmo com o arquivo presente:'
        Write-Info  '  - versao errada (o programa espera outra versao do mesmo pacote)'
        Write-Info  '  - falta a outra arquitetura (ver acima)'
        Write-Info  '  - a DLL usada e a que esta na pasta do programa, e ela corrompeu'
        Write-Info  '    -> reinstalar o programa resolve'
    } else {
        Write-Falha 'O arquivo NAO foi encontrado em System32 nem em SysWOW64.'
    }

    # --- 2) O antivirus colocou em quarentena? ---
    Write-Etapa 'Verificando se o antivirus colocou o arquivo em quarentena...'
    try {
        $q = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
        $suspeito = @($q | Where-Object { $_.Resources -match [regex]::Escape($nome) })
        if ($suspeito.Count -gt 0) {
            Write-Aviso 'O Windows Defender tem deteccao envolvendo este arquivo.'
            Write-Info  'Pode ser falso positivo: confira em Seguranca do Windows > Historico de protecao.'
            Add-Alerta "Defender tem deteccao envolvendo $nome - verificar quarentena."
        } else {
            Write-Ok 'Nenhuma deteccao do Defender para este arquivo.'
        }
    } catch { Write-Info 'Nao foi possivel consultar o historico do Defender.' }

    # --- 3) De qual pacote vem? ---
    Write-Etapa 'Identificando a origem do arquivo...'
    $info = Get-PacoteDaDLL -Nome $nome

    if (-not $info) {
        Write-Aviso 'Este arquivo nao esta na lista de pacotes conhecidos.'
        Write-Info  'Provavelmente pertence ao proprio programa que mostrou o erro.'
        Write-Info  'Caminho recomendado: reinstalar esse programa (nao baixar a DLL avulsa'
        Write-Info  "de site de DLL - e' fonte comum de malware)."
        return [long]0
    }

    Write-Ok ("Vem do pacote: " + $info.Pacote)
    if ($info.Obs) { Write-Info $info.Obs }

    # --- 4) Resolver ---
    if ($info.Ferramenta -eq 'visualc') {
        Write-Host ''
        Write-Info 'Da para resolver agora instalando os redistribuiveis Visual C++.'
        $r = Read-Host '  Instalar os redistribuiveis que faltam? (S/N)'
        if ($r -match '^[Ss]') {
            Install-VisualCRedist | Out-Null
            Write-Host ''
            Write-Info 'Feche e abra o programa que mostrou o erro para testar.'
        } else {
            Write-Info 'Voce pode rodar depois pela opcao "Visual C++ Redistribuiveis" do menu.'
        }
    } elseif ($info.Ferramenta -eq 'java') {
        Write-Info 'Use a opcao "Configurar Java (Juridico)" do menu apos instalar o Java.'
    } else {
        Write-Info 'Instale o pacote indicado acima e teste o programa novamente.'
    }

    Write-Host ''
    Write-Aviso 'Nunca baixe a DLL avulsa de sites de download de DLL.'
    Write-Info  'Sempre instale o pacote oficial que contem o arquivo.'
    return [long]0
}

function Get-ArquivosNaoReparados {
    <#
      Extrai do CBS.log os arquivos que o SFC encontrou corrompidos e NAO
      conseguiu reparar. E' a informacao que falta quando o SFC diz apenas
      "encontrou arquivos corrompidos mas nao conseguiu corrigir alguns".
    #>
    $cbs = "$env:SystemRoot\Logs\CBS\CBS.log"
    $lista = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-Path -LiteralPath $cbs)) { return $lista }
    try {
        $linhas = @(Get-Content -LiteralPath $cbs -Tail 4000 -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match 'Cannot repair member file' })
        foreach ($l in $linhas) {
            # formato: Cannot repair member file [l:24]'winload.efi' of ...
            $m = [regex]::Match($l, "Cannot repair member file \[l:\d+\]'([^']+)'")
            if ($m.Success) {
                $arq = $m.Groups[1].Value
                if (-not $lista.Contains($arq)) { [void]$lista.Add($arq) }
            }
        }
    } catch { }
    return $lista
}

function Get-FontesInstalacao {
    <# Procura install.wim/install.esd em unidades montadas (ISO, DVD, pendrive). #>
    $fontes = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($v in @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter })) {
        $letra = [string]$v.DriveLetter
        foreach ($arq in @('install.wim', 'install.esd')) {
            $c = "${letra}:\sources\$arq"
            if (Test-Path -LiteralPath $c -ErrorAction SilentlyContinue) {
                $fontes.Add([PSCustomObject]@{
                    Caminho = $c
                    Tipo    = $(if ($arq -like '*.wim') { 'wim' } else { 'esd' })
                    Rotulo  = $(if ($v.FileSystemLabel) { $v.FileSystemLabel } else { "unidade $letra" })
                })
            }
        }
    }
    return $fontes
}

function Repair-SistemaAvancado {
    <#
      Para quando o SFC acusa corrupcao e NAO consegue reparar - normalmente
      porque o proprio repositorio de componentes esta danificado ou o
      RestoreHealth nao consegue baixar os arquivos (sem internet, WSUS,
      Windows Update quebrado).
      Aqui: mostra QUAIS arquivos falharam, repara usando uma ISO/DVD do
      Windows como fonte, e permite reparar um arquivo especifico.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Mostraria os arquivos nao reparados e ofereceria reparo com fonte alternativa.'; return [long]0 }

    Write-Etapa 'Reparo avancado de arquivos do sistema'

    # --- 1) O que o SFC nao conseguiu reparar ---
    Write-Etapa 'Lendo o CBS.log (resultado da ultima varredura do SFC)...'
    $falhos = @(Get-ArquivosNaoReparados)
    if ($falhos.Count -gt 0) {
        Write-Falha "$($falhos.Count) arquivo(s) que o SFC NAO conseguiu reparar:"
        foreach ($f in ($falhos | Select-Object -First 30)) { Write-Info "   $f" }
        if ($falhos.Count -gt 30) { Write-Info "   ... e mais $($falhos.Count - 30)" }
        Add-Alerta "$($falhos.Count) arquivo(s) do sistema seguem corrompidos apos o SFC."
    } else {
        Write-Ok 'O CBS.log nao lista arquivos que tenham falhado no reparo.'
        Write-Info 'Se voce ainda nao rodou o SFC, use antes a opcao "Reparar Sistema (SFC/DISM)".'
    }

    if ($SemInteracao) { return [long]0 }

    # --- 2) Reparar usando ISO/DVD como fonte ---
    Write-Host ''
    Write-Info 'Quando o RestoreHealth falha (sem internet, WSUS bloqueando, ou o proprio'
    Write-Info 'repositorio danificado), da para reparar usando a midia do Windows.'
    Write-Host ''
    Write-Host '     [1] Reparar usando ISO/DVD do Windows como fonte' -ForegroundColor White
    Write-Host '     [2] Reparar um arquivo especifico (sfc /scanfile)' -ForegroundColor White
    Write-Host '     [3] Limpar e reconstruir o repositorio de componentes' -ForegroundColor White
    Write-Host '     [0] Sair' -ForegroundColor DarkGray
    Write-Host ''
    $opc = (Read-Host '  Opcao').Trim()

    switch ($opc) {

        '1' {
            Write-Etapa 'Procurando midia do Windows montada...'
            $fontes = @(Get-FontesInstalacao)
            $origem = ''

            if ($fontes.Count -gt 0) {
                Write-Ok "$($fontes.Count) fonte(s) encontrada(s):"
                $i = 1
                foreach ($f in $fontes) {
                    Write-Host ("     [$i] $($f.Caminho)   ($($f.Rotulo))") -ForegroundColor White
                    $i++
                }
                Write-Host '     [M] Informar outro caminho (arquivo .iso, .wim ou .esd)' -ForegroundColor White
                Write-Host ''
                $s = (Read-Host '  Opcao').Trim()
                if ($s -match '^\d+$' -and [int]$s -ge 1 -and [int]$s -le $fontes.Count) {
                    $sel = $fontes[[int]$s - 1]
                    $origem = "$($sel.Tipo):$($sel.Caminho):1"
                }
            } else {
                Write-Info 'Nenhuma ISO/DVD do Windows montado no momento.'
            }

            if (-not $origem) {
                Write-Host ''
                Write-Info 'Informe o caminho da midia. Pode ser:'
                Write-Info '   um .iso   (eu monto para voce)'
                Write-Info '   um install.wim ou install.esd'
                Write-Info '   a letra do DVD/pendrive, ex.: E:'
                $cam = (Read-Host '  Caminho (ENTER para cancelar)').Trim().Trim('"')
                if (-not $cam) { Write-Info 'Cancelado.'; return [long]0 }

                if ($cam -match '\.iso$') {
                    if (-not (Test-Path -LiteralPath $cam)) { Write-Falha 'Arquivo .iso nao encontrado.'; return [long]0 }
                    Write-Acao 'Montando a ISO...'
                    try {
                        $img = Mount-DiskImage -ImagePath $cam -PassThru -ErrorAction Stop
                        Start-Sleep -Seconds 2
                        $letra = ($img | Get-Volume).DriveLetter
                        Write-Ok "ISO montada em ${letra}:"
                        foreach ($a in @('install.wim', 'install.esd')) {
                            $c = "${letra}:\sources\$a"
                            if (Test-Path -LiteralPath $c) {
                                $origem = $(if ($a -like '*.wim') { "wim:$c`:1" } else { "esd:$c`:1" })
                                break
                            }
                        }
                        if (-not $origem) { Write-Falha 'A ISO nao tem sources\install.wim nem install.esd.' }
                    } catch { Write-Falha "Nao foi possivel montar a ISO: $($_.Exception.Message)" }
                } elseif ($cam -match '\.(wim|esd)$') {
                    if (-not (Test-Path -LiteralPath $cam)) { Write-Falha 'Arquivo nao encontrado.'; return [long]0 }
                    $tipo = $(if ($cam -match '\.wim$') { 'wim' } else { 'esd' })
                    $origem = "$tipo`:$cam`:1"
                } else {
                    $letra = $cam.TrimEnd('\', ':')
                    foreach ($a in @('install.wim', 'install.esd')) {
                        $c = "${letra}:\sources\$a"
                        if (Test-Path -LiteralPath $c) {
                            $origem = $(if ($a -like '*.wim') { "wim:$c`:1" } else { "esd:$c`:1" })
                            break
                        }
                    }
                    if (-not $origem) { Write-Falha "Nao achei sources\install.wim em ${letra}:" }
                }
            }

            if (-not $origem) { return [long]0 }

            Write-Host ''
            Write-Dest ("Fonte: $origem")
            Write-Aviso 'A edicao e a versao da midia precisam bater com a instalada,'
            Write-Info  'senao o DISM recusa a fonte. Confira com: winver'
            Write-Info  'Pode levar de 10 a 30 minutos. Nao feche a janela.'
            Write-Host ''
            $c = Read-Host '  Iniciar o reparo? (S/N)'
            if ($c -notmatch '^[Ss]') { Write-Info 'Cancelado.'; return [long]0 }

            Write-Etapa 'DISM /RestoreHealth com fonte local...'
            # /LimitAccess: nao tenta o Windows Update, usa so a midia
            & dism.exe /Online /Cleanup-Image /RestoreHealth /Source:$origem /LimitAccess 2>&1 |
                ForEach-Object { if ($_.ToString().Trim()) { Write-Host "     $_" -ForegroundColor DarkGray } }

            if ($LASTEXITCODE -eq 0) {
                Write-Ok 'DISM concluido com sucesso.'
                Write-Etapa 'Rodando SFC novamente para aplicar o reparo...'
                & "$env:SystemRoot\System32\sfc.exe" /scannow
                $script:precisaReiniciar = $true
                Write-Ok 'Reparo concluido. Reinicie o computador.'
            } else {
                Write-Falha "DISM retornou codigo $LASTEXITCODE."
                Write-Info 'Causa comum: edicao/versao da midia diferente da instalada.'
                Write-Info 'Confira a versao com winver e use uma ISO da mesma versao.'
            }
        }

        '2' {
            Write-Host ''
            Write-Info 'Informe o caminho completo do arquivo, ex.:'
            Write-Info '   C:\Windows\System32\opencl.dll'
            $arq = (Read-Host '  Caminho').Trim().Trim('"')
            if (-not $arq) { Write-Info 'Cancelado.'; return [long]0 }
            Write-Etapa "Verificando e reparando $arq ..."
            & "$env:SystemRoot\System32\sfc.exe" "/scanfile=$arq"
            if ($LASTEXITCODE -eq 0) { Write-Ok 'Comando concluido. Confira a mensagem acima.' }
            else { Write-Aviso "sfc retornou codigo $LASTEXITCODE." }
        }

        '3' {
            Write-Host ''
            Write-Aviso 'StartComponentCleanup /ResetBase remove as versoes antigas dos'
            Write-Info  'componentes: libera espaco, mas depois disso NAO da mais para'
            Write-Info  'desinstalar as atualizacoes ja instaladas.'
            $c = Read-Host '  Continuar? (S/N)'
            if ($c -notmatch '^[Ss]') { Write-Info 'Cancelado.'; return [long]0 }
            Write-Etapa 'DISM StartComponentCleanup /ResetBase - pode demorar...'
            & dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase 2>&1 |
                ForEach-Object { if ($_.ToString().Trim()) { Write-Host "     $_" -ForegroundColor DarkGray } }
            if ($LASTEXITCODE -eq 0) { Write-Ok 'Repositorio de componentes reconstruido.' }
            else { Write-Aviso "DISM retornou codigo $LASTEXITCODE." }
        }

        default { Write-Info 'Nada feito.' }
    }

    return [long]0
}

# =========================================================================
# REGIAO: RELATORIO DE ATENDIMENTO, DESFAZER E TESTE DE MEMORIA
# =========================================================================

function New-RelatorioAtendimento {
    <#
      Documento para ENTREGAR AO ESCRITORIO - nao e o log tecnico.
      Resume o que foi feito no atendimento, como a maquina esta e o que
      precisa de atencao. Serve de comprovante do servico e, quando o disco
      morre dois meses depois, prova que o alerta foi dado.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Geraria o relatorio de atendimento para o cliente.'; return [long]0 }

    Write-Etapa 'Relatorio de atendimento para o cliente'

    $linhas = [System.Collections.Generic.List[string]]::new()
    $add = { param([string]$t) $linhas.Add($t) }

    & $add ('=' * 78)
    & $add '                      RELATORIO DE ATENDIMENTO TECNICO'
    & $add '                        SuporteADV - suporte.adv.br'
    & $add ('=' * 78)
    & $add ''
    & $add ("Computador : $env:COMPUTERNAME")
    & $add ("Usuario    : $env:USERNAME")
    & $add ("Data       : " + (Get-Date -Format 'dd/MM/yyyy HH:mm'))
    & $add ''

    # --- Identificacao da maquina ---
    & $add ('-' * 78)
    & $add 'EQUIPAMENTO'
    & $add ('-' * 78)
    try {
        $cs  = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cs)  { & $add ("  Modelo          : $($cs.Manufacturer) $($cs.Model)") }
        if ($cpu) { & $add ("  Processador     : $($cpu.Name.Trim())") }
        if ($cs)  { & $add ("  Memoria RAM     : " + [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) + " GB") }
        if ($os)  {
            & $add ("  Sistema         : $($os.Caption) ($($os.OSArchitecture))")
            $boot = $os.LastBootUpTime
            if ($boot) { & $add ("  Ligado desde    : " + $boot.ToString('dd/MM/yyyy HH:mm')) }
        }
    } catch { }

    # --- Discos ---
    & $add ''
    & $add ('-' * 78)
    & $add 'ARMAZENAMENTO'
    & $add ('-' * 78)
    # Espaco cheio e disco com defeito sao problemas diferentes: o primeiro se
    # resolve liberando espaco, o segundo exige trocar o disco. Nao misturar.
    $espacoCritico = $false
    $falhaSMART    = $false
    try {
        foreach ($v in @(Get-Volume -ErrorAction SilentlyContinue |
                         Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter })) {
            $tot = [math]::Round($v.Size / 1GB, 1)
            $liv = [math]::Round($v.SizeRemaining / 1GB, 1)
            $pct = if ($v.Size -gt 0) { [math]::Round(($v.SizeRemaining / $v.Size) * 100) } else { 0 }
            $obs = if ($pct -lt 10) { '   ATENCAO: espaco critico' } elseif ($pct -lt 20) { '   pouco espaco' } else { '' }
            & $add ("  Disco $($v.DriveLetter): $liv GB livres de $tot GB ($pct%)$obs")
            if ($pct -lt 10) { $espacoCritico = $true }
        }
        foreach ($d in @(Get-CimInstance -ClassName MSStorageDriver_FailurePredictStatus -Namespace root\wmi -ErrorAction SilentlyContinue)) {
            if ($d.PredictFailure) {
                & $add '  ALERTA: o proprio disco esta prevendo falha (SMART).'
                & $add '          Recomendamos backup imediato e substituicao.'
                $falhaSMART = $true
            }
        }
        if (-not $falhaSMART) { & $add '  Saude dos discos (SMART): sem alerta de falha.' }
    } catch { }

    # --- Seguranca ---
    & $add ''
    & $add ('-' * 78)
    & $add 'SEGURANCA'
    & $add ('-' * 78)
    try {
        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mp) {
            & $add ("  Antivirus ativo        : " + $(if ($mp.AMServiceEnabled) { 'sim' } else { 'NAO' }))
            & $add ("  Protecao em tempo real : " + $(if ($mp.RealTimeProtectionEnabled) { 'sim' } else { 'NAO' }))
            if ($mp.AntivirusSignatureLastUpdated) {
                & $add ("  Assinaturas de         : " + $mp.AntivirusSignatureLastUpdated.ToString('dd/MM/yyyy'))
            }
            if (-not $mp.RealTimeProtectionEnabled) {
                & $add '  ATENCAO: a protecao em tempo real esta desligada.'
            }
        }
        $fw = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Enabled })
        if ($fw.Count -gt 0) { & $add ("  ATENCAO: firewall desligado em: " + (($fw | ForEach-Object { $_.Name }) -join ', ')) }
        else { & $add '  Firewall               : ativo' }
    } catch { }

    # --- Certificados que vencem ---
    try {
        $hoje = Get-Date
        $venc = @(Get-ChildItem 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
                  Where-Object { $_.NotAfter -lt $hoje.AddDays(60) })
        if ($venc.Count -gt 0) {
            & $add ''
            & $add ('-' * 78)
            & $add 'CERTIFICADO DIGITAL'
            & $add ('-' * 78)
            foreach ($c in $venc) {
                $nome = if ($c.Subject -match 'CN=([^,]+)') { $Matches[1] } else { $c.Subject }
                $dias = ($c.NotAfter - $hoje).Days
                $situacao = if ($dias -lt 0) { "VENCIDO ha $([math]::Abs($dias)) dias" } else { "vence em $dias dias" }
                & $add ("  $nome")
                & $add ("     $situacao (em " + $c.NotAfter.ToString('dd/MM/yyyy') + ")")
            }
            & $add '  Providencie a renovacao junto a Autoridade Certificadora.'
        }
    } catch { }

    # --- O que foi feito hoje ---
    & $add ''
    & $add ('-' * 78)
    & $add 'SERVICOS EXECUTADOS NESTE ATENDIMENTO'
    & $add ('-' * 78)
    $fezAlgo = $false
    try {
        $baseLogs = 'C:\ProgramData\SuporteTI\Logs'
        if (Test-Path -LiteralPath $baseLogs) {
            $hojeStr = Get-Date -Format 'yyyy-MM-dd'
            $pastas = @(Get-ChildItem -LiteralPath $baseLogs -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -like "*$hojeStr*" } | Sort-Object CreationTime)
            foreach ($p in $pastas) {
                $log = Join-Path $p.FullName 'manutencao.log'
                $hora = $p.CreationTime.ToString('HH:mm')
                $desc = 'Manutencao'
                if (Test-Path -LiteralPath $log) {
                    $cab = @(Get-Content -LiteralPath $log -TotalCount 40 -ErrorAction SilentlyContinue |
                             Where-Object { $_ -match 'FERRAMENTA:' })
                    if ($cab.Count -gt 0) { $desc = ($cab[0] -replace '.*FERRAMENTA:\s*', '').Trim() }
                    else { $desc = 'Manutencao completa' }
                }
                & $add ("  $hora  -  $desc")
                $fezAlgo = $true
            }
        }
    } catch { }
    if (-not $fezAlgo) {
        & $add '  (nenhuma execucao registrada hoje nesta maquina)'
    }

    # --- Recomendacoes ---
    & $add ''
    & $add ('-' * 78)
    & $add 'RECOMENDACOES'
    & $add ('-' * 78)
    $rec = [System.Collections.Generic.List[string]]::new()
    if ($falhaSMART) {
        $rec.Add('URGENTE: o disco esta prevendo falha. Fazer backup dos dados e substituir o disco.')
    }
    if ($espacoCritico) {
        $rec.Add('Liberar espaco em disco (abaixo de 10% livre o Windows fica lento e pode falhar ao atualizar).')
    }
    try {
        $mp2 = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mp2 -and -not $mp2.RealTimeProtectionEnabled) { $rec.Add('Religar a protecao em tempo real do antivirus.') }
    } catch { }
    if ($script:precisaReiniciar) { $rec.Add('Reiniciar o computador para concluir as alteracoes.') }
    if ($rec.Count -eq 0) { $rec.Add('Nenhuma pendencia. Manter as atualizacoes do Windows em dia.') }
    foreach ($r in $rec) { & $add ("  - $r") }

    & $add ''
    & $add ('=' * 78)
    & $add '  Documento gerado automaticamente pelo sistema de manutencao SuporteADV.'
    & $add ('=' * 78)

    # --- Salvar ---
    $nomeArq = 'Atendimento_' + $env:COMPUTERNAME + '_' + (Get-Date -Format 'yyyy-MM-dd_HHmm') + '.txt'
    $destino = Join-Path ([Environment]::GetFolderPath('Desktop')) $nomeArq
    try {
        [System.IO.File]::WriteAllLines($destino, $linhas.ToArray(), (New-Object System.Text.UTF8Encoding($true)))
        Write-Ok "Relatorio salvo na Area de Trabalho:"
        Write-Info "   $destino"
        try { Start-Process 'notepad.exe' -ArgumentList $destino -ErrorAction SilentlyContinue } catch { }
        Write-Info 'Este arquivo pode ser entregue ao cliente por e-mail ou impresso.'
    } catch {
        Write-Falha "Nao foi possivel salvar: $($_.Exception.Message)"
        foreach ($l in $linhas) { Write-Host "     $l" -ForegroundColor Gray }
    }
    return [long]0
}

function Undo-UltimaManutencao {
    <#
      Caminho de volta guiado. Os backups ja existiam (ponto de restauracao,
      .reg, RESTAURAR.cmd, quarentena, AnyDesk), mas espalhados: era preciso
      saber onde procurar. Aqui tudo aparece numa lista so.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Listaria os backups disponiveis para reverter.'; return [long]0 }

    Write-Etapa 'Desfazer alteracoes de um atendimento'

    $baseLogs = 'C:\ProgramData\SuporteTI\Logs'
    if (-not (Test-Path -LiteralPath $baseLogs)) {
        Write-Info 'Nenhuma execucao registrada nesta maquina.'
        return [long]0
    }

    $pastas = @(Get-ChildItem -LiteralPath $baseLogs -Directory -ErrorAction SilentlyContinue |
                Sort-Object CreationTime -Descending | Select-Object -First 12)
    if ($pastas.Count -eq 0) { Write-Info 'Nenhuma pasta de log encontrada.'; return [long]0 }

    Write-Info 'Execucoes registradas (mais recentes primeiro):'
    Write-Host ''
    $i = 1
    foreach ($p in $pastas) {
        $itens = [System.Collections.Generic.List[string]]::new()
        if (Test-Path -LiteralPath (Join-Path $p.FullName 'RESTAURAR.cmd')) { $itens.Add('registro/inicializacao') }
        if (Test-Path -LiteralPath (Join-Path $p.FullName 'backup-anydesk'))  { $itens.Add('AnyDesk') }
        if (@(Get-ChildItem -LiteralPath $p.FullName -Filter '*.reg' -ErrorAction SilentlyContinue).Count -gt 0) { $itens.Add('.reg') }
        $temQue = if ($itens.Count) { ($itens -join ', ') } else { 'sem backup para reverter' }
        Write-Host ("     [{0,2}] {1}   ({2})" -f $i, $p.CreationTime.ToString('dd/MM/yyyy HH:mm'), $temQue) -ForegroundColor White
        $i++
    }

    if ($SemInteracao) { return [long]0 }

    Write-Host ''
    Write-Info 'Voce tambem pode usar a Restauracao do Sistema do Windows, que desfaz'
    Write-Info 'tudo de uma vez (a manutencao completa cria um ponto antes de comecar).'
    Write-Host ''
    Write-Host '     [numero] escolher uma execucao   [R] abrir a Restauracao do Sistema   [0] sair' -ForegroundColor DarkGray
    Write-Host ''
    $sel = (Read-Host '  Opcao').Trim()

    if ($sel -match '^[Rr]$') {
        try { Start-Process 'rstrui.exe' -ErrorAction Stop; Write-Ok 'Restauracao do Sistema aberta.' }
        catch { Write-Aviso 'Nao foi possivel abrir. Use: Windows + R > rstrui' }
        return [long]0
    }
    if ($sel -notmatch '^\d+$' -or [int]$sel -lt 1 -or [int]$sel -gt $pastas.Count) {
        Write-Info 'Cancelado.'
        return [long]0
    }

    $alvo = $pastas[[int]$sel - 1]
    Write-Host ''
    Write-Dest ("Pasta: " + $alvo.FullName)

    $restCmd = Join-Path $alvo.FullName 'RESTAURAR.cmd'
    $bkpAny  = Join-Path $alvo.FullName 'backup-anydesk'

    Write-Host ''
    if (Test-Path -LiteralPath $restCmd) {
        Write-Host '     [1] Restaurar registro e programas de inicializacao (RESTAURAR.cmd)' -ForegroundColor White
    }
    if (Test-Path -LiteralPath $bkpAny) {
        Write-Host '     [2] Restaurar a pasta do AnyDesk (ID e senha antigos)' -ForegroundColor White
    }
    Write-Host '     [3] Abrir a pasta no Explorer' -ForegroundColor White
    Write-Host '     [0] Voltar' -ForegroundColor DarkGray
    Write-Host ''
    $acao = (Read-Host '  Opcao').Trim()

    switch ($acao) {
        '1' {
            if (-not (Test-Path -LiteralPath $restCmd)) { Write-Aviso 'Este atendimento nao tem RESTAURAR.cmd.'; break }
            Write-Aviso 'Isto devolve as chaves de registro e a inicializacao ao estado anterior.'
            $c = Read-Host '  Confirma? (S/N)'
            if ($c -match '^[Ss]') {
                Start-Process 'cmd.exe' -ArgumentList '/c', "`"$restCmd`"" -Wait -Verb RunAs -ErrorAction SilentlyContinue
                Write-Ok 'Restauracao executada. Reinicie para aplicar por completo.'
                $script:precisaReiniciar = $true
            } else { Write-Info 'Cancelado.' }
        }
        '2' {
            if (-not (Test-Path -LiteralPath $bkpAny)) { Write-Aviso 'Este atendimento nao tem backup do AnyDesk.'; break }
            Write-Aviso 'O AnyDesk precisa estar FECHADO para restaurar.'
            $c = Read-Host '  Confirma? (S/N)'
            if ($c -match '^[Ss]') {
                $proc = Get-Process -Name 'AnyDesk' -ErrorAction SilentlyContinue
                if ($proc) { Write-Aviso 'AnyDesk aberto - feche e tente de novo.'; break }
                foreach ($par in @(@{ O = 'APPDATA'; D = (Join-Path $env:APPDATA 'AnyDesk') },
                                   @{ O = 'LOCALAPPDATA'; D = (Join-Path $env:LOCALAPPDATA 'AnyDesk') })) {
                    $origem = Join-Path $bkpAny $par.O
                    if (Test-Path -LiteralPath $origem) {
                        try {
                            Copy-Item -LiteralPath $origem -Destination $par.D -Recurse -Force -ErrorAction Stop
                            Write-Ok ("Restaurado: " + $par.D)
                        } catch { Write-Falha ("Falha em " + $par.D + ": " + $_.Exception.Message) }
                    }
                }
            } else { Write-Info 'Cancelado.' }
        }
        '3' {
            try { Start-Process 'explorer.exe' -ArgumentList $alvo.FullName -ErrorAction Stop }
            catch { Write-Info ("Abra a mao: " + $alvo.FullName) }
        }
        default { Write-Info 'Nada feito.' }
    }
    return [long]0
}

function Test-MemoriaRAM {
    <#
      Mostra a memoria instalada e agenda o teste do Windows. Vale quando a
      tela azul volta depois do reparo: RAM defeituosa e disco ruim sao os
      dois suspeitos que sobram.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Mostraria a memoria instalada e ofereceria agendar o teste.'; return [long]0 }

    Write-Etapa 'Memoria RAM - informacoes e teste'

    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($cs) { Write-Info ("Total instalado : " + [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) + " GB") }
        $pentes = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue)
        Write-Info ("Pentes          : " + $pentes.Count)
        foreach ($p in $pentes) {
            $gb  = [math]::Round($p.Capacity / 1GB, 1)
            $vel = if ($p.Speed) { "$($p.Speed) MHz" } else { 'velocidade nao informada' }
            $fab = if ($p.Manufacturer) { $p.Manufacturer.Trim() } else { 'fabricante nao informado' }
            Write-Info ("   $($p.DeviceLocator): $gb GB  $vel  $fab")
        }
    } catch { Write-Aviso "Nao foi possivel ler os dados da memoria: $($_.Exception.Message)" }

    # Resultado de teste anterior, se houver
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results' } `
                -MaxEvents 3 -ErrorAction SilentlyContinue)
        if ($ev.Count -gt 0) {
            Write-Host ''
            Write-Dest 'Testes de memoria ja realizados:'
            foreach ($e in $ev) {
                Write-Info ("   " + $e.TimeCreated.ToString('dd/MM/yyyy HH:mm') + " - " + ($e.Message -split "`n")[0].Trim())
            }
        } else {
            Write-Host ''
            Write-Info 'Nenhum teste de memoria registrado nesta maquina.'
        }
    } catch { }

    if ($SemInteracao) { return [long]0 }

    Write-Host ''
    Write-Aviso 'O teste do Windows roda ANTES do sistema iniciar e leva de 15 a 40 minutos.'
    Write-Info  'O computador REINICIA para executa-lo. Salve tudo antes.'
    Write-Info  'Ao terminar, o Windows volta sozinho e o resultado aparece aqui nesta tela.'
    Write-Host ''
    $c = Read-Host '  Agendar o teste para o proximo reinicio? (S/N)'
    if ($c -match '^[Ss]') {
        try {
            Start-Process 'mdsched.exe' -ErrorAction Stop
            Write-Ok 'Ferramenta de diagnostico de memoria aberta.'
            Write-Info 'Escolha "Reiniciar agora" ou "Verificar na proxima vez".'
        } catch {
            Write-Aviso 'Nao foi possivel abrir. Use: Windows + R > mdsched'
        }
    } else {
        Write-Info 'Nada agendado.'
    }
    return [long]0
}

# =========================================================================
# REGIAO: REDE DE COMPARTILHAMENTO (servidor, cliente e diagnostico)
# =========================================================================
#
# Postura de seguranca destas ferramentas - escritorio de advocacia guarda
# processo sob sigilo, entao o padrao aqui e' compartilhamento AUTENTICADO:
#   - SMB1 NUNCA e' habilitado (e' o buraco do WannaCry/EternalBlue).
#   - Regras de firewall so no perfil PRIVADO. Nunca no publico.
#   - Nao compartilha raiz de disco (C:\).
#   - Acesso por usuario e senha, com a credencial salva nos clientes para
#     nao incomodar o advogado no dia a dia. Acesso anonimo existe como
#     opcao, mas com aviso do custo.

# Grupos de regra do firewall: o nome que aparece na tela e traduzido, mas o
# identificador interno nao muda. Usamos o interno e caimos no texto so se
# preciso.
$script:GrupoFWCompartilhamento = '@FirewallAPI.dll,-28502'
$script:GrupoFWDescoberta       = '@FirewallAPI.dll,-32752'

function Enable-RegrasFirewallRede {
    param([string]$Grupo, [string]$RegexNome, [string]$Rotulo)
    $ok = 0
    try {
        $regras = @(Get-NetFirewallRule -Group $Grupo -ErrorAction SilentlyContinue |
                    Where-Object { $_.Profile -match 'Private|Any' })
        if ($regras.Count -eq 0) {
            $regras = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayGroup -match $RegexNome -and $_.Profile -match 'Private|Any' })
        }
        foreach ($r in $regras) {
            if ($r.Enabled -ne 'True') {
                try { Enable-NetFirewallRule -Name $r.Name -ErrorAction Stop; $ok++ } catch { }
            }
        }
        $total = @(Get-NetFirewallRule -Group $Grupo -ErrorAction SilentlyContinue |
                   Where-Object { $_.Enabled -eq 'True' }).Count
        if ($ok -gt 0) { Write-Ok "$Rotulo : $ok regra(s) habilitada(s) no perfil Privado." }
        else { Write-Ok "$Rotulo : ja estava liberado ($total regras ativas)." }
    } catch {
        Write-Aviso "$Rotulo : nao foi possivel ajustar - $($_.Exception.Message)"
    }
}

function Set-ServicosRede {
    <# Servicos sem os quais a maquina nao aparece na rede nem serve arquivo. #>
    $servicos = @(
        @{ Nome = 'LanmanServer';      Tipo = 'Automatic'; Desc = 'Servidor (compartilhar arquivos)' }
        @{ Nome = 'LanmanWorkstation'; Tipo = 'Automatic'; Desc = 'Estacao de trabalho (acessar rede)' }
        @{ Nome = 'FDResPub';          Tipo = 'Automatic'; Desc = 'Publicacao de recursos (aparecer na rede)' }
        @{ Nome = 'fdPHost';           Tipo = 'Automatic'; Desc = 'Descoberta de dispositivos' }
        @{ Nome = 'SSDPSRV';           Tipo = 'Manual';    Desc = 'Descoberta SSDP' }
        @{ Nome = 'upnphost';          Tipo = 'Manual';    Desc = 'Host de dispositivo UPnP' }
    )
    foreach ($s in $servicos) {
        $sv = Get-Service -Name $s.Nome -ErrorAction SilentlyContinue
        if (-not $sv) { Write-Info "$($s.Desc): servico nao existe nesta versao."; continue }
        try {
            if ($sv.StartType -ne $s.Tipo) {
                Set-Service -Name $s.Nome -StartupType $s.Tipo -ErrorAction Stop
            }
            if ($sv.Status -ne 'Running') {
                Start-Service -Name $s.Nome -ErrorAction Stop
                Write-Ok "$($s.Desc): iniciado."
            } else {
                Write-Ok "$($s.Desc): em execucao."
            }
        } catch {
            Write-Aviso "$($s.Desc): $($_.Exception.Message)"
        }
    }
}

function Set-PerfilRedePrivado {
    <#
      Perfil Publico bloqueia descoberta e compartilhamento por design. E' a
      causa numero 1 de "a maquina sumiu da rede".
    #>
    $mudou = $false
    foreach ($p in @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)) {
        if ($p.NetworkCategory -eq 'Public') {
            try {
                Set-NetConnectionProfile -InterfaceIndex $p.InterfaceIndex -NetworkCategory Private -ErrorAction Stop
                Write-Ok "Rede '$($p.Name)' ($($p.InterfaceAlias)): Publica -> PRIVADA."
                $mudou = $true
            } catch {
                Write-Falha "Nao foi possivel mudar '$($p.Name)' para privada: $($_.Exception.Message)"
            }
        } elseif ($p.NetworkCategory -eq 'DomainAuthenticated') {
            Write-Info "Rede '$($p.Name)': autenticada em dominio (as politicas do dominio mandam)."
        } else {
            Write-Ok "Rede '$($p.Name)' ($($p.InterfaceAlias)): ja e privada."
        }
    }
    return $mudou
}

function Test-SMB1Perigoso {
    <# SMB1 e' o vetor do WannaCry. Nunca ligar; avisar se estiver ligado. #>
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($f -and $f.State -eq 'Enabled') {
            Write-Falha 'SMB1 esta HABILITADO nesta maquina.'
            Write-Info  'SMB1 e o protocolo explorado pelo WannaCry. Deve ser desligado.'
            Write-Info  'Desligar: Painel de Controle > Programas > Ativar ou desativar recursos'
            Write-Info  '          do Windows > desmarcar "Suporte a Compartilhamento de Arquivos SMB 1.0".'
            Add-Alerta 'SMB1 habilitado - risco de seguranca conhecido. Desativar.'
            return $true
        }
        Write-Ok 'SMB1 (protocolo antigo e inseguro): desabilitado, como deve ser.'
    } catch { }
    return $false
}

function Get-IPsLocais {
    return @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and
                            $_.PrefixOrigin -ne 'WellKnown' })
}

function Set-MaquinaServidor {
    <#
      Prepara a maquina para servir arquivos na rede do escritorio e cria os
      compartilhamentos. Nao instala nada: usa o compartilhamento do proprio
      Windows, que e o suficiente para o porte de um escritorio.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Configuraria esta maquina como servidor de arquivos da rede.'; return [long]0 }

    Write-Titulo 'CONFIGURAR ESTA MAQUINA COMO SERVIDOR DE ARQUIVOS'
    Write-Info 'Esta maquina passa a hospedar as pastas que os outros computadores acessam.'
    Write-Info 'Ela precisa ficar LIGADA para os demais enxergarem os arquivos.'

    # --- 1. Diagnostico inicial -----------------------------------------
    Write-Etapa '1/7  Situacao atual'
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    Write-Info ("Nome desta maquina : " + $env:COMPUTERNAME)
    if ($cs) {
        if ($cs.PartOfDomain) {
            Write-Aviso "Esta maquina esta no DOMINIO $($cs.Domain)."
            Write-Info  'Num dominio quem manda sao as politicas de grupo (GPO). Ajustes locais'
            Write-Info  'podem ser revertidos no proximo gpupdate. Fale com o administrador.'
        } else {
            Write-Info ("Grupo de trabalho  : " + $cs.Workgroup)
        }
    }
    $ips = @(Get-IPsLocais)
    foreach ($ip in $ips) {
        $fixo = if ($ip.PrefixOrigin -eq 'Manual') { 'IP FIXO' } else { 'IP automatico (DHCP)' }
        Write-Info ("Endereco IP        : $($ip.IPAddress)  ($fixo)")
    }
    Test-SMB1Perigoso | Out-Null

    if ($SemInteracao) { Write-Aviso 'Modo desatendido: esta ferramenta precisa de interacao.'; return [long]0 }

    # IP fixo importa: se o IP muda, as unidades mapeadas nos clientes quebram.
    $temFixo = @($ips | Where-Object { $_.PrefixOrigin -eq 'Manual' }).Count -gt 0
    if (-not $temFixo -and $ips.Count -gt 0) {
        Write-Host ''
        Write-Aviso 'O IP desta maquina e automatico (DHCP).'
        Write-Info  'Servidor com IP que muda faz a unidade de rede dos outros PCs parar de'
        Write-Info  'funcionar do nada. Recomendado: reservar o IP no roteador, ou fixar aqui.'
        Write-Info  'Os clientes tambem podem se conectar pelo NOME da maquina, que nao muda -'
        Write-Info  'e o que esta ferramenta configura por padrao.'
    }

    Write-Host ''
    $ok = Read-Host '  Continuar e configurar esta maquina como servidor? (S/N)'
    if ($ok -notmatch '^[Ss]') { Write-Info 'Cancelado. Nada foi alterado.'; return [long]0 }

    # --- 2. Perfil de rede ----------------------------------------------
    Write-Etapa '2/7  Perfil da rede'
    Set-PerfilRedePrivado | Out-Null

    # --- 3. Servicos ------------------------------------------------------
    Write-Etapa '3/7  Servicos de rede'
    Set-ServicosRede

    # --- 4. Firewall ------------------------------------------------------
    Write-Etapa '4/7  Firewall (somente no perfil Privado)'
    Enable-RegrasFirewallRede -Grupo $script:GrupoFWCompartilhamento `
        -RegexNome 'Compartilhamento de Arquivo e Impressora|File and Printer Sharing' `
        -Rotulo 'Compartilhamento de arquivos e impressoras'
    Enable-RegrasFirewallRede -Grupo $script:GrupoFWDescoberta `
        -RegexNome 'Descoberta de Rede|Network Discovery' `
        -Rotulo 'Descoberta de rede'
    Write-Info 'As regras foram habilitadas SO no perfil Privado - em rede publica'
    Write-Info '(hotel, aeroporto) a maquina continua fechada.'

    # --- 5. Grupo de trabalho --------------------------------------------
    Write-Etapa '5/7  Grupo de trabalho'
    if ($cs -and -not $cs.PartOfDomain) {
        Write-Info ("Atual: " + $cs.Workgroup)
        Write-Info 'Todos os computadores do escritorio devem usar o MESMO grupo de trabalho.'
        $novoWg = (Read-Host '  Grupo de trabalho (ENTER para manter)').Trim()
        if ($novoWg -and $novoWg -ne $cs.Workgroup) {
            if ($novoWg -notmatch '^[A-Za-z0-9\-]{1,15}$') {
                Write-Aviso 'Nome invalido (use ate 15 letras/numeros, sem espaco). Mantido o atual.'
            } else {
                try {
                    Add-Computer -WorkgroupName $novoWg -ErrorAction Stop
                    Write-Ok "Grupo de trabalho alterado para $novoWg."
                    Write-Aviso 'Precisa REINICIAR para o grupo de trabalho valer.'
                    $script:precisaReiniciar = $true
                } catch {
                    Write-Falha "Nao foi possivel alterar: $($_.Exception.Message)"
                }
            }
        }
    }

    # --- 6. Conta de acesso ----------------------------------------------
    Write-Etapa '6/7  Como os outros computadores vao se autenticar'
    Write-Host ''
    Write-Host '     [1] Com usuario e senha (RECOMENDADO)' -ForegroundColor Green
    Write-Host '         Cria uma conta so para a rede. A senha fica salva nos computadores' -ForegroundColor DarkGray
    Write-Host '         do escritorio, entao ninguem digita nada no dia a dia - mas o acesso' -ForegroundColor DarkGray
    Write-Host '         e identificado e pode ser revogado.' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '     [2] Sem senha (qualquer um na rede acessa)' -ForegroundColor Yellow
    Write-Host '         Mais simples, porem QUALQUER dispositivo conectado a rede - inclusive' -ForegroundColor DarkGray
    Write-Host '         visitante no Wi-Fi - le os arquivos. Em escritorio de advocacia isso' -ForegroundColor DarkGray
    Write-Host '         significa processo sob sigilo exposto. Exige tambem afrouxar a' -ForegroundColor DarkGray
    Write-Host '         seguranca do SMB nos clientes.' -ForegroundColor DarkGray
    Write-Host ''
    $modo = (Read-Host '  Opcao').Trim()

    $usuarioRede = ''
    if ($modo -eq '2') {
        Write-Host ''
        Write-Falha 'Voce escolheu acesso sem senha.'
        Write-Info  'Confirme que a rede do escritorio e fechada (sem Wi-Fi de visitante).'
        $c2 = Read-Host '  Tem certeza? (S/N)'
        if ($c2 -notmatch '^[Ss]') { Write-Info 'Voltando para o modo com senha.'; $modo = '1' }
    }

    if ($modo -ne '2') {
        $modo = '1'
        Write-Host ''
        Write-Info 'Nome da conta que os outros PCs usarao (ex.: rede, arquivos, escritorio).'
        $usuarioRede = (Read-Host '  Nome do usuario [rede]').Trim()
        if (-not $usuarioRede) { $usuarioRede = 'rede' }

        $existe = Get-LocalUser -Name $usuarioRede -ErrorAction SilentlyContinue
        if ($existe) {
            Write-Ok "A conta '$usuarioRede' ja existe nesta maquina."
            Write-Info 'A senha atual dela sera usada nos clientes.'
        } else {
            Write-Host ''
            Write-Info "A conta '$usuarioRede' sera criada. Escolha uma senha."
            Write-Info 'Anote: ela sera digitada uma vez em cada computador do escritorio.'
            $senha1 = Read-Host '  Senha' -AsSecureString
            $senha2 = Read-Host '  Repita a senha' -AsSecureString
            $p1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($senha1))
            $p2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($senha2))
            if (-not $p1 -or $p1 -ne $p2) {
                Write-Falha 'As senhas nao conferem (ou ficou em branco). Conta nao criada.'
                Write-Info  'Rode a ferramenta de novo.'
                return [long]0
            }
            try {
                New-LocalUser -Name $usuarioRede -Password $senha1 -FullName 'Acesso a rede do escritorio' `
                    -Description 'Conta usada pelos computadores para acessar as pastas compartilhadas' `
                    -PasswordNeverExpires -UserMayNotChangePassword -ErrorAction Stop | Out-Null
                Write-Ok "Conta '$usuarioRede' criada."
                # Conta de rede nao deve aparecer na tela de login nem ser admin.
                try {
                    $regLogin = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
                    if (-not (Test-Path $regLogin)) { New-Item -Path $regLogin -Force | Out-Null }
                    Set-ItemProperty -Path $regLogin -Name $usuarioRede -Value 0 -Type DWord -Force
                    Write-Ok 'Conta ocultada da tela de login (so serve para acesso pela rede).'
                } catch { }
            } catch {
                Write-Falha "Nao foi possivel criar a conta: $($_.Exception.Message)"
                Write-Info  'Se a senha foi recusada, a politica local exige senha mais forte.'
                return [long]0
            }
        }
    } else {
        # Acesso anonimo: desliga o compartilhamento protegido por senha.
        try {
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'everyoneincludesanonymous' -Value 1 -Type DWord -Force
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Value 0 -Type DWord -Force
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RestrictNullSessAccess' -Value 0 -Type DWord -Force
            Write-Ok 'Compartilhamento protegido por senha DESLIGADO nesta maquina.'
            Add-Alerta 'Compartilhamento sem senha ativado - qualquer dispositivo na rede acessa as pastas.'
        } catch {
            Write-Aviso "Nao foi possivel liberar o acesso sem senha: $($_.Exception.Message)"
        }
    }

    # --- 7. Compartilhar a pasta -----------------------------------------
    Write-Etapa '7/7  Pasta compartilhada'

    # Pasta padrao: fica no disco de dados com mais espaco livre. Documento de
    # escritorio so cresce, e deixar fora do C: facilita reinstalar o Windows
    # sem perder nada. Se so existe o C:, usa ele mesmo.
    $pastaPadrao = 'C:\Compartilhado'
    try {
        $melhor = @(Get-Volume -ErrorAction SilentlyContinue |
                    Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and
                                   $_.DriveLetter -ne 'C' -and $_.SizeRemaining -gt 5GB } |
                    Sort-Object SizeRemaining -Descending | Select-Object -First 1)
        if ($melhor) { $pastaPadrao = "$($melhor.DriveLetter):\Compartilhado" }
    } catch { }

    Write-Host ''
    Write-Info 'Pasta que sera compartilhada com o escritorio.'
    Write-Info ("Sugestao: $pastaPadrao")
    Write-Info '(ENTER aceita a sugestao; ou digite outro caminho, ex.: D:\Documentos)'
    $pasta = (Read-Host "  Pasta [$pastaPadrao]").Trim().Trim('"')
    if (-not $pasta) { $pasta = $pastaPadrao }

    # Compartilhar raiz de disco expoe o Windows inteiro.
    if ($pasta -match '^[A-Za-z]:\\?$') {
        Write-Falha 'Nao compartilhe a raiz de um disco (C:\, D:\...).'
        Write-Info  'Isso expoe o Windows inteiro na rede. Crie uma pasta especifica.'
        return [long]0
    }
    if ($pasta -match '(?i)^C:\\(Windows|Program Files|Users)\\?$') {
        Write-Falha 'Esta pasta e do sistema e nao deve ser compartilhada.'
        return [long]0
    }

    if (-not (Test-Path -LiteralPath $pasta)) {
        Write-Info "A pasta $pasta ainda nao existe."
        $cr = Read-Host '  Criar agora? (S/N) [S]'
        if (-not $cr -or $cr -match '^[Ss]') {
            try { New-Item -ItemType Directory -Path $pasta -Force -ErrorAction Stop | Out-Null; Write-Ok "Pasta criada: $pasta" }
            catch { Write-Falha "Nao foi possivel criar: $($_.Exception.Message)"; return [long]0 }
        } else { Write-Info 'Cancelado.'; return [long]0 }
    } else {
        Write-Ok "Pasta encontrada: $pasta"
    }

    # Nome na rede: por padrao o proprio nome da pasta, que e o que o pessoal
    # do escritorio ja reconhece.
    $nomePadrao = Split-Path $pasta -Leaf
    if (-not $nomePadrao -or $nomePadrao -match '[\\/\[\]:|<>+=;,?*"]') { $nomePadrao = 'Compartilhado' }
    $nomeCompart = (Read-Host "  Nome que aparecera na rede [$nomePadrao]").Trim()
    if (-not $nomeCompart) { $nomeCompart = $nomePadrao }
    if ($nomeCompart -match '[\\/\[\]:|<>+=;,?*"]') {
        Write-Falha 'Nome de compartilhamento invalido.'
        return [long]0
    }

    Write-Host ''
    Write-Host '     [1] Leitura e gravacao (o escritorio edita os arquivos)' -ForegroundColor White
    Write-Host '     [2] Somente leitura (ninguem altera nada pela rede)' -ForegroundColor White
    $perm = (Read-Host '  Opcao [1]').Trim()
    $somenteLeitura = ($perm -eq '2')

    $jaExiste = Get-SmbShare -Name $nomeCompart -ErrorAction SilentlyContinue
    if ($jaExiste) {
        Write-Aviso "Ja existe um compartilhamento chamado '$nomeCompart' apontando para:"
        Write-Info  ("   " + $jaExiste.Path)
        $sub = Read-Host '  Substituir? (S/N)'
        if ($sub -match '^[Ss]') {
            try { Remove-SmbShare -Name $nomeCompart -Force -ErrorAction Stop; Write-Ok 'Compartilhamento anterior removido.' }
            catch { Write-Falha "Nao foi possivel remover: $($_.Exception.Message)"; return [long]0 }
        } else { Write-Info 'Cancelado.'; return [long]0 }
    }

    # Nome dos grupos internos muda com o idioma do Windows (Administradores x
    # Administrators, Todos x Everyone). Resolver pelo SID, que e' fixo.
    function Resolve-NomePorSID {
        param([string]$SID)
        try {
            return (New-Object System.Security.Principal.SecurityIdentifier($SID)).Translate(
                    [System.Security.Principal.NTAccount]).Value
        } catch { return $null }
    }
    $grpAdmin = Resolve-NomePorSID 'S-1-5-32-544'   # Administradores
    $grpTodos = Resolve-NomePorSID 'S-1-1-0'        # Todos / Everyone

    try {
        if ($modo -eq '2') {
            # Sem senha: acesso para todos (inclusive convidado).
            $quemShare = if ($grpTodos) { $grpTodos } else { 'Everyone' }
            if ($somenteLeitura) { New-SmbShare -Name $nomeCompart -Path $pasta -ReadAccess $quemShare -ErrorAction Stop | Out-Null }
            else { New-SmbShare -Name $nomeCompart -Path $pasta -ChangeAccess $quemShare -ErrorAction Stop | Out-Null }
        } else {
            # Com senha: a conta de rede acessa; administradores mantem controle.
            $param = @{ Name = $nomeCompart; Path = $pasta; ErrorAction = 'Stop' }
            if ($somenteLeitura) { $param['ReadAccess'] = $usuarioRede } else { $param['ChangeAccess'] = $usuarioRede }
            if ($grpAdmin) { $param['FullAccess'] = $grpAdmin }
            New-SmbShare @param | Out-Null
        }
        Write-Ok "Compartilhamento '$nomeCompart' criado."
    } catch {
        Write-Falha "Nao foi possivel compartilhar: $($_.Exception.Message)"
        return [long]0
    }

    # Permissao NTFS: o Windows aplica a mais restritiva entre share e NTFS,
    # entao sem isso o acesso e negado mesmo com o compartilhamento liberado.
    try {
        $direito = if ($somenteLeitura) { 'ReadAndExecute' } else { 'Modify' }
        $candidatos = if ($modo -eq '2') {
            @($grpTodos, 'Everyone', 'Todos') | Where-Object { $_ }
        } else {
            @("$env:COMPUTERNAME\$usuarioRede", $usuarioRede)
        }
        $aplicado = $false
        foreach ($nome in $candidatos) {
            try {
                $acl = Get-Acl -LiteralPath $pasta
                $regra = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $nome, $direito, 'ContainerInherit,ObjectInherit', 'None', 'Allow')
                $acl.AddAccessRule($regra)
                Set-Acl -LiteralPath $pasta -AclObject $acl -ErrorAction Stop
                Write-Ok "Permissao da pasta ajustada: $direito para $nome."
                $aplicado = $true
                break
            } catch { }
        }
        if (-not $aplicado) {
            Write-Aviso 'Compartilhamento criado, mas a permissao da pasta nao pode ser ajustada.'
            Write-Info  'Ajuste a mao: botao direito na pasta > Propriedades > Seguranca.'
        }
    } catch {
        Write-Aviso "Permissao da pasta: $($_.Exception.Message)"
    }

    # --- Instrucoes para os clientes -------------------------------------
    Write-Host ''
    Write-Titulo 'PRONTO - COMO CONECTAR OS OUTROS COMPUTADORES'
    $caminhoRede = "\\$env:COMPUTERNAME\$nomeCompart"
    Write-Dest ("Caminho da rede : " + $caminhoRede)
    foreach ($ip in @(Get-IPsLocais)) {
        Write-Info ("Ou pelo IP      : \\$($ip.IPAddress)\$nomeCompart")
    }
    if ($modo -ne '2') {
        Write-Info ("Usuario         : " + $usuarioRede)
        Write-Info  'Senha           : a que voce acabou de definir'
    } else {
        Write-Info  'Sem usuario e senha (acesso liberado na rede)'
    }
    Write-Host ''
    Write-Info 'Em cada computador do escritorio, rode este mesmo menu e escolha'
    Write-Info '"Conectar a Rede/Servidor" - ele pergunta esse caminho e ja deixa a'
    Write-Info 'unidade de rede fixa, com a senha salva.'
    Write-Host ''
    Write-Aviso 'Esta maquina precisa ficar LIGADA para os outros acessarem os arquivos.'
    Write-Info  'E backup: compartilhar pasta nao e backup. Os arquivos continuam num disco so.'
    Add-Alerta "Servidor de arquivos configurado: $caminhoRede"
    return [long]0
}

function Set-MaquinaClienteRede {
    <#
      Prepara um computador do escritorio para enxergar e usar o servidor:
      perfil de rede, servicos, firewall, grupo de trabalho e a unidade de
      rede fixa com a credencial salva.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Configuraria esta maquina para acessar o servidor de arquivos.'; return [long]0 }

    Write-Titulo 'CONECTAR ESTA MAQUINA A REDE DO ESCRITORIO'

    Write-Etapa '1/5  Perfil da rede'
    Set-PerfilRedePrivado | Out-Null

    Write-Etapa '2/5  Servicos de rede'
    Set-ServicosRede

    Write-Etapa '3/5  Firewall (somente no perfil Privado)'
    Enable-RegrasFirewallRede -Grupo $script:GrupoFWDescoberta `
        -RegexNome 'Descoberta de Rede|Network Discovery' -Rotulo 'Descoberta de rede'
    Enable-RegrasFirewallRede -Grupo $script:GrupoFWCompartilhamento `
        -RegexNome 'Compartilhamento de Arquivo e Impressora|File and Printer Sharing' `
        -Rotulo 'Compartilhamento de arquivos e impressoras'

    Test-SMB1Perigoso | Out-Null

    if ($SemInteracao) { Write-Aviso 'Modo desatendido: o resto desta ferramenta precisa de interacao.'; return [long]0 }

    # --- Grupo de trabalho ---
    Write-Etapa '4/5  Grupo de trabalho'
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs -and $cs.PartOfDomain) {
        Write-Info "Maquina em dominio ($($cs.Domain)) - grupo de trabalho nao se aplica."
    } elseif ($cs) {
        Write-Info ("Atual: " + $cs.Workgroup + "   (deve ser igual ao do servidor)")
        $wg = (Read-Host '  Grupo de trabalho (ENTER para manter)').Trim()
        if ($wg -and $wg -ne $cs.Workgroup) {
            if ($wg -notmatch '^[A-Za-z0-9\-]{1,15}$') {
                Write-Aviso 'Nome invalido. Mantido o atual.'
            } else {
                try {
                    Add-Computer -WorkgroupName $wg -ErrorAction Stop
                    Write-Ok "Grupo de trabalho alterado para $wg."
                    Write-Aviso 'Precisa REINICIAR para valer.'
                    $script:precisaReiniciar = $true
                } catch { Write-Falha "Nao foi possivel alterar: $($_.Exception.Message)" }
            }
        }
    }

    # --- Unidade de rede ---
    Write-Etapa '5/5  Unidade de rede'
    Write-Host ''
    Write-Info 'Informe o caminho do servidor, como ele apareceu no final da configuracao.'
    Write-Info 'Ex.: \\SERVIDOR\Documentos   ou   \\192.168.0.10\Documentos'
    $caminho = (Read-Host '  Caminho (ENTER para pular)').Trim().Trim('"')
    if (-not $caminho) { Write-Info 'Unidade de rede nao configurada. O resto ja esta pronto.'; return [long]0 }

    if ($caminho -notmatch '^\\\\[^\\]+\\[^\\]+') {
        Write-Falha 'Caminho invalido. Use o formato \\NOME\Pasta'
        return [long]0
    }

    $servidor = ($caminho -split '\\')[2]
    Write-Etapa "Testando o servidor $servidor ..."
    $alcancou = $false
    try {
        $t = Test-NetConnection -ComputerName $servidor -Port 445 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        if ($t -and $t.TcpTestSucceeded) { Write-Ok "Servidor $servidor respondeu na porta de compartilhamento (445)."; $alcancou = $true }
        else {
            Write-Falha "Nao consegui falar com $servidor na porta 445."
            Write-Info  'Verifique: o servidor esta ligado? Esta na mesma rede? O firewall dele foi liberado?'
            Write-Info  'Rode a opcao de configurar servidor naquela maquina antes desta etapa.'
        }
    } catch { Write-Aviso 'Nao foi possivel testar a conexao.' }

    if (-not $alcancou) {
        $ir = Read-Host '  Tentar mapear mesmo assim? (S/N)'
        if ($ir -notmatch '^[Ss]') { Write-Info 'Cancelado.'; return [long]0 }
    }

    # Credencial
    Write-Host ''
    Write-Info 'Usuario e senha criados no servidor (ex.: rede).'
    Write-Info 'Deixe o usuario em branco se o servidor foi configurado sem senha.'
    $usu = (Read-Host '  Usuario').Trim()
    $temCred = $false
    if ($usu) {
        $pw = Read-Host '  Senha' -AsSecureString
        $pwTexto = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))
        # Salva no Gerenciador de Credenciais do Windows: reconecta sozinho
        # depois de reiniciar, sem pedir senha ao advogado.
        $alvo = if ($usu -match '\\') { $usu } else { "$servidor\$usu" }
        try {
            & cmdkey.exe /add:$servidor /user:$alvo /pass:$pwTexto | Out-Null
            Write-Ok 'Credencial salva no Gerenciador de Credenciais do Windows.'
            $temCred = $true
        } catch { Write-Aviso 'Nao foi possivel salvar a credencial.' }
    }

    # Letra da unidade
    $usadas = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $sugerida = @('Z','Y','X','W','V','U','T','S','R','Q','P') | Where-Object { $usadas -notcontains $_ } | Select-Object -First 1
    Write-Host ''
    Write-Info ("Letras em uso: " + ($usadas -join ', '))
    $letra = (Read-Host "  Letra para a unidade de rede [$sugerida]").Trim().TrimEnd(':').ToUpper()
    if (-not $letra) { $letra = $sugerida }
    if ($letra -notmatch '^[D-Z]$') { Write-Falha 'Letra invalida.'; return [long]0 }
    if ($usadas -contains $letra) {
        Write-Aviso "A letra $letra ja esta em uso."
        $sub = Read-Host '  Substituir? (S/N)'
        if ($sub -match '^[Ss]') {
            & net use "${letra}:" /delete /y 2>&1 | Out-Null
        } else { Write-Info 'Cancelado.'; return [long]0 }
    }

    # /persistent:yes reconecta ao ligar o computador
    try {
        $saida = if ($temCred) {
            & net use "${letra}:" $caminho /persistent:yes 2>&1
        } else {
            & net use "${letra}:" $caminho /persistent:yes 2>&1
        }
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Unidade ${letra}: conectada a $caminho"
            Write-Info 'Ela reconecta sozinha toda vez que o computador ligar.'
            try { Start-Process 'explorer.exe' -ArgumentList "${letra}:\" -ErrorAction SilentlyContinue } catch { }
        } else {
            Write-Falha 'Nao foi possivel mapear a unidade.'
            foreach ($l in @($saida)) { if ($l.ToString().Trim()) { Write-Info ("   " + $l) } }
            Write-Info 'Causas comuns: usuario/senha errados, servidor desligado, ou o nome'
            Write-Info 'do compartilhamento diferente do que foi criado no servidor.'
        }
    } catch {
        Write-Falha "Erro ao mapear: $($_.Exception.Message)"
    }

    Write-Host ''
    Write-Info 'Para conferir depois: abra o Explorer e veja a unidade na lateral,'
    Write-Info 'ou use a opcao de diagnostico de rede deste menu.'
    return [long]0
}

function Test-RedeCompartilhamento {
    <#
      Diagnostico somente-leitura de compartilhamento. Percorre as causas que
      derrubam rede de escritorio, na ordem em que costumam acontecer.
    #>
    Write-Titulo 'DIAGNOSTICO DA REDE DE COMPARTILHAMENTO'

    $problemas = [System.Collections.Generic.List[string]]::new()

    # 1. Identificacao
    Write-Etapa '1/8  Identificacao da maquina'
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    Write-Info ("Nome        : " + $env:COMPUTERNAME)
    if ($cs) {
        if ($cs.PartOfDomain) { Write-Info ("Dominio     : " + $cs.Domain) }
        else { Write-Info ("Grupo trab. : " + $cs.Workgroup) }
    }
    foreach ($ip in @(Get-IPsLocais)) {
        $orig = if ($ip.PrefixOrigin -eq 'Manual') { 'fixo' } else { 'DHCP' }
        Write-Info ("IP          : $($ip.IPAddress)  ($orig, $($ip.InterfaceAlias))")
    }

    # 2. Perfil de rede
    Write-Etapa '2/8  Perfil da rede'
    foreach ($p in @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)) {
        if ($p.NetworkCategory -eq 'Public') {
            Write-Falha "Rede '$($p.Name)': PUBLICA - bloqueia descoberta e compartilhamento."
            $problemas.Add('Perfil de rede publico (mudar para privado)')
        } else {
            Write-Ok "Rede '$($p.Name)': $($p.NetworkCategory)"
        }
    }

    # 3. Servicos
    Write-Etapa '3/8  Servicos'
    foreach ($s in @('LanmanServer','LanmanWorkstation','FDResPub','fdPHost')) {
        $sv = Get-Service -Name $s -ErrorAction SilentlyContinue
        if (-not $sv) { continue }
        if ($sv.Status -ne 'Running') {
            Write-Falha "$s : $($sv.Status) (deveria estar rodando)"
            $problemas.Add("Servico $s parado")
        } else {
            Write-Ok "$s : em execucao ($($sv.StartType))"
        }
    }

    # 4. Firewall
    Write-Etapa '4/8  Firewall'
    foreach ($g in @(@{ G = $script:GrupoFWCompartilhamento; N = 'Compartilhamento de arquivos' },
                     @{ G = $script:GrupoFWDescoberta;       N = 'Descoberta de rede' })) {
        $regras = @(Get-NetFirewallRule -Group $g.G -ErrorAction SilentlyContinue |
                    Where-Object { $_.Profile -match 'Private|Any' })
        $on = @($regras | Where-Object { $_.Enabled -eq 'True' }).Count
        if ($regras.Count -gt 0 -and $on -eq 0) {
            Write-Falha "$($g.N): bloqueado pelo firewall no perfil privado."
            $problemas.Add("Firewall bloqueando: $($g.N)")
        } else {
            Write-Ok "$($g.N): $on regra(s) ativa(s) no perfil privado."
        }
    }

    # 5. SMB
    Write-Etapa '5/8  Protocolo SMB'
    Test-SMB1Perigoso | Out-Null
    try {
        $srv = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($srv) {
            if (-not $srv.EnableSMB2Protocol) {
                Write-Falha 'SMB2/SMB3 desabilitado - compartilhamento moderno nao funciona.'
                $problemas.Add('SMB2/SMB3 desabilitado')
            } else { Write-Ok 'SMB2/SMB3: habilitado.' }
        }
        $cli = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
        if ($cli -and $cli.EnableInsecureGuestLogons) {
            Write-Aviso 'Logon de convidado inseguro esta PERMITIDO neste cliente.'
            Write-Info  'Necessario para alguns NAS e para compartilhamento sem senha,'
            Write-Info  'mas deixa a conexao sem assinatura (sujeita a interceptacao).'
        }
    } catch { }

    # 6. Compartilhamentos locais
    Write-Etapa '6/8  Pastas compartilhadas nesta maquina'
    $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\$$' })
    if ($shares.Count -eq 0) {
        Write-Info 'Nenhuma pasta compartilhada (esta maquina nao e servidor de arquivos).'
    } else {
        foreach ($sh in $shares) {
            Write-Ok ("\\$env:COMPUTERNAME\$($sh.Name)  ->  $($sh.Path)")
            try {
                foreach ($a in @(Get-SmbShareAccess -Name $sh.Name -ErrorAction SilentlyContinue)) {
                    Write-Info ("     $($a.AccountName): $($a.AccessRight) ($($a.AccessControlType))")
                    if ($a.AccountName -match '(?i)^(Everyone|Todos)$' -and $a.AccessRight -eq 'Full') {
                        $problemas.Add("Compartilhamento '$($sh.Name)' com acesso total para Todos")
                    }
                }
            } catch { }
            if (-not (Test-Path -LiteralPath $sh.Path)) {
                Write-Falha "   A pasta de origem nao existe mais: $($sh.Path)"
                $problemas.Add("Compartilhamento '$($sh.Name)' aponta para pasta inexistente")
            }
        }
    }

    # 7. Unidades de rede
    Write-Etapa '7/8  Unidades de rede mapeadas'
    $mapeadas = @(Get-CimInstance Win32_NetworkConnection -ErrorAction SilentlyContinue)
    if ($mapeadas.Count -eq 0) {
        Write-Info 'Nenhuma unidade de rede mapeada nesta maquina.'
    } else {
        foreach ($m in $mapeadas) {
            $estado = if ($m.ConnectionState -eq 'Connected') { 'conectada' } else { $m.ConnectionState }
            if ($m.ConnectionState -eq 'Connected') {
                Write-Ok ("$($m.LocalName)  ->  $($m.RemoteName)   ($estado)")
            } else {
                Write-Falha ("$($m.LocalName)  ->  $($m.RemoteName)   ($estado)")
                $problemas.Add("Unidade $($m.LocalName) desconectada")
            }
        }
    }

    # 8. Teste de alcance
    Write-Etapa '8/8  Teste de conexao com o servidor'
    if (-not $SemInteracao) {
        Write-Info 'Informe o nome ou IP do servidor para testar (ENTER para pular).'
        $alvo = (Read-Host '  Servidor').Trim().TrimStart('\')
        if ($alvo) {
            $alvo = ($alvo -split '\\')[0]
            $pingOk = Test-Connection -ComputerName $alvo -Count 2 -Quiet -ErrorAction SilentlyContinue
            if ($pingOk) { Write-Ok "$alvo responde ao ping." }
            else { Write-Aviso "$alvo nao responde ao ping (pode ser so o firewall dele bloqueando ICMP)." }

            try {
                $t = Test-NetConnection -ComputerName $alvo -Port 445 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                if ($t -and $t.TcpTestSucceeded) {
                    Write-Ok "Porta 445 (compartilhamento) aberta em $alvo."
                    try {
                        $lista = & net view "\\$alvo" 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            Write-Ok 'Pastas compartilhadas visiveis:'
                            foreach ($l in @($lista)) { if ($l -match '\S' -and $l -notmatch 'comando|command') { Write-Info ("   " + $l) } }
                        } else {
                            Write-Aviso 'Servidor alcancado, mas nao foi possivel listar as pastas.'
                            Write-Info  'Normalmente e credencial: usuario/senha errados ou nao salvos.'
                            $problemas.Add("Sem credencial valida para $alvo")
                        }
                    } catch { }
                } else {
                    Write-Falha "Porta 445 fechada ou inalcancavel em $alvo."
                    Write-Info  'O servidor pode estar desligado, em outra rede, ou com o firewall fechado.'
                    $problemas.Add("Servidor $alvo inalcancavel na porta 445")
                }
            } catch { Write-Aviso 'Nao foi possivel testar a porta 445.' }
        }
    }

    # --- Conclusao ---
    Write-Host ''
    if ($problemas.Count -eq 0) {
        Write-Ok 'Nenhum problema encontrado na configuracao de rede desta maquina.'
    } else {
        Write-Falha "$($problemas.Count) ponto(s) a corrigir:"
        foreach ($p in $problemas) { Write-Info ("   - " + $p) }
        Write-Host ''
        Write-Info 'Para corrigir: use "Configurar Servidor de Arquivos" na maquina que'
        Write-Info 'guarda os documentos, e "Conectar a Rede/Servidor" nas demais.'
        foreach ($p in $problemas) { Add-Alerta ("Rede: " + $p) }
    }
    return [long]0
}

function Get-ConexoesReais {
    <#
      Devolve so as conexoes que valem: as que tem gateway. Adaptador de
      Hyper-V, WSL, VirtualBox e VPN aparece com IP mas sem gateway, e so
      confunde a leitura na hora do atendimento.
    #>
    $reais = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($c in @(Get-NetIPConfiguration -ErrorAction SilentlyContinue)) {
        if ($c.NetAdapter.Status -ne 'Up') { continue }
        $gw = if ($c.IPv4DefaultGateway) { @($c.IPv4DefaultGateway)[0].NextHop } else { $null }
        $ip = @($c.IPv4Address)[0]
        $virtual = ($c.InterfaceDescription -match '(?i)(hyper-v|virtual|vmware|virtualbox|loopback|tap-|tunnel|wintun|wireguard)')
        $reais.Add([PSCustomObject]@{
            Alias     = $c.InterfaceAlias
            Descricao = $c.InterfaceDescription
            Indice    = $c.InterfaceIndex
            IP        = if ($ip) { $ip.IPAddress } else { $null }
            Prefixo   = if ($ip) { $ip.PrefixLength } else { $null }
            Origem    = if ($ip) { $ip.PrefixOrigin } else { $null }
            Gateway   = $gw
            DNS       = @($c.DNSServer | Where-Object { $_.AddressFamily -eq 2 } |
                          ForEach-Object { $_.ServerAddresses })
            Virtual   = $virtual
            Vale      = ($null -ne $gw -and -not $virtual)
        })
    }
    return $reais
}

function Get-FaixaRede {
    <# Faixa da rede a partir de IP + mascara: e' o que precisa bater entre
       as maquinas para elas se enxergarem. #>
    param([string]$IP, [int]$Prefixo)
    try {
        $bytes = ([System.Net.IPAddress]::Parse($IP)).GetAddressBytes()
        [Array]::Reverse($bytes)
        $ipNum = [BitConverter]::ToUInt32($bytes, 0)
        $mask  = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $Prefixo))
        $rede  = $ipNum -band $mask
        $b = [BitConverter]::GetBytes($rede)
        [Array]::Reverse($b)
        return (([System.Net.IPAddress]$b).ToString() + "/$Prefixo")
    } catch { return '' }
}

function Get-InfoWiFi {
    <# Dados do Wi-Fi conectado. Vazio se a maquina so tem cabo. #>
    $info = @{}
    try {
        $saida = & netsh wlan show interfaces 2>&1
        if ($LASTEXITCODE -ne 0) { return $info }
        foreach ($l in @($saida)) {
            $t = $l.ToString()
            if ($t -match '(?i)^\s*SSID\s*:\s*(.+)$' -and $t -notmatch '(?i)BSSID') { $info['SSID'] = $Matches[1].Trim() }
            elseif ($t -match '(?i)^\s*BSSID\s*:\s*(.+)$')                          { $info['BSSID'] = $Matches[1].Trim() }
            elseif ($t -match '(?i)^\s*(Sinal|Signal)\s*:\s*(.+)$')                 { $info['Sinal'] = $Matches[2].Trim() }
            elseif ($t -match '(?i)^\s*(R.dio|Radio type|Tipo de r.dio)\s*:\s*(.+)$') { $info['Radio'] = $Matches[2].Trim() }
            elseif ($t -match '(?i)^\s*(Canal|Channel)\s*:\s*(.+)$')                { $info['Canal'] = $Matches[2].Trim() }
            elseif ($t -match '(?i)^\s*(Autentica..o|Authentication)\s*:\s*(.+)$')  { $info['Auth'] = $Matches[2].Trim() }
            elseif ($t -match '(?i)^\s*(Estado|State)\s*:\s*(.+)$')                 { $info['Estado'] = $Matches[2].Trim() }
        }
    } catch { }
    return $info
}

function Show-QualRede {
    <#
      Cartao de identidade da rede desta maquina. Feito para ser rodado em cada
      computador e comparado: se a FAIXA ou o GATEWAY diferem, as maquinas nao
      se enxergam, por mais que as duas tenham internet.
    #>
    Write-Titulo 'EM QUAL REDE ESTE COMPUTADOR ESTA'

    $conexoes = @(Get-ConexoesReais)
    $validas  = @($conexoes | Where-Object { $_.Vale })

    if ($validas.Count -eq 0) {
        Write-Falha 'Este computador NAO esta conectado a nenhuma rede.'
        Write-Info  'Sem gateway definido: cabo desconectado, Wi-Fi desligado ou DHCP falhou.'
        Write-Info  'Use a opcao de resolver problemas de conexao deste menu.'
        Add-Alerta 'Computador sem conexao de rede.'
        return [long]0
    }

    $wifi = Get-InfoWiFi

    foreach ($c in $validas) {
        Write-Host ''
        # Wi-Fi ou cabo
        $ehWifi = $false
        try {
            $ad = Get-NetAdapter -InterfaceIndex $c.Indice -ErrorAction SilentlyContinue
            if ($ad -and ($ad.MediaType -match '802.11' -or $ad.InterfaceDescription -match '(?i)(wi-?fi|wireless|802\.11)')) { $ehWifi = $true }
        } catch { }

        if ($ehWifi) {
            Write-Dest '  >>> CONEXAO SEM FIO (Wi-Fi)'
            if ($wifi['SSID']) {
                Write-Host ''
                Write-Host ("      Rede Wi-Fi : " + $wifi['SSID']) -ForegroundColor Yellow
                if ($wifi['Sinal']) { Write-Info ("      Sinal      : " + $wifi['Sinal']) }
                if ($wifi['Radio']) { Write-Info ("      Padrao     : " + $wifi['Radio']) }
                if ($wifi['Canal']) { Write-Info ("      Canal      : " + $wifi['Canal']) }
                if ($wifi['Auth'])  { Write-Info ("      Seguranca  : " + $wifi['Auth']) }

                # Rede de visitante costuma ter isolamento de cliente ligado:
                # a maquina navega, mas nao enxerga as outras.
                if ($wifi['SSID'] -match '(?i)(visitante|guest|convidado|cliente|public)') {
                    Write-Host ''
                    Write-Falha '      ESTA E UMA REDE DE VISITANTES.'
                    Write-Info  '      Rede de visitante normalmente isola os dispositivos: a maquina'
                    Write-Info  '      navega na internet mas NAO enxerga as outras do escritorio.'
                    Write-Info  '      Conecte na rede principal do escritorio.'
                    Add-Alerta ("Maquina conectada na rede de visitantes: " + $wifi['SSID'])
                }
                # Sinal fraco derruba conexao com pasta compartilhada no meio do uso
                if ($wifi['Sinal'] -match '(\d+)%') {
                    $pct = [int]$Matches[1]
                    if ($pct -lt 40) {
                        Write-Aviso ("      Sinal fraco ($pct%) - a conexao pode cair ao usar arquivos em rede.")
                        Add-Alerta "Sinal Wi-Fi fraco ($pct%)."
                    }
                }
            }
        } else {
            Write-Dest '  >>> CONEXAO POR CABO'
            Write-Host ''
            try {
                $ad = Get-NetAdapter -InterfaceIndex $c.Indice -ErrorAction SilentlyContinue
                if ($ad) {
                    Write-Info ("      Placa      : " + $ad.InterfaceDescription)
                    Write-Info ("      Velocidade : " + $ad.LinkSpeed)
                    if ($ad.LinkSpeed -match '^(\d+)\s*Mbps' -and [int]$Matches[1] -le 100) {
                        Write-Aviso '      Link em 100 Mbps ou menos - cabo ou porta antiga.'
                        Write-Info  '      Copiar arquivo grande pela rede vai ficar lento.'
                    }
                }
            } catch { }
        }

        Write-Info ("      Adaptador  : " + $c.Alias)

        # --- O que precisa bater entre as maquinas ---
        $faixa = Get-FaixaRede -IP $c.IP -Prefixo $c.Prefixo
        Write-Host ''
        Write-Host '      ---- Identidade da rede (compare entre os computadores) ----' -ForegroundColor Cyan
        Write-Host ("      FAIXA DA REDE : " + $faixa) -ForegroundColor Yellow
        Write-Host ("      GATEWAY       : " + $c.Gateway) -ForegroundColor Yellow
        Write-Info ("      IP desta maq. : " + $c.IP + "  (" + $(if ($c.Origem -eq 'Manual') { 'fixo' } else { 'automatico' }) + ")")
        Write-Info ("      DNS           : " + $(if ($c.DNS.Count) { $c.DNS -join ', ' } else { '-' }))
    }

    # --- Adaptadores virtuais, so para nao confundir ---
    $virtuais = @($conexoes | Where-Object { -not $_.Vale -and $_.IP })
    if ($virtuais.Count -gt 0) {
        Write-Host ''
        Write-Info 'Outros adaptadores nesta maquina (virtuais - IGNORE na comparacao):'
        foreach ($v in $virtuais) {
            Write-Host ("      $($v.Alias): $($v.IP)  - $($v.Descricao)") -ForegroundColor DarkGray
        }
        Write-Info 'Sao do Hyper-V, WSL, VPN ou maquina virtual. Nao servem para o'
        Write-Info 'compartilhamento entre os computadores do escritorio.'
    }

    # --- A regra ---
    Write-Host ''
    Write-Titulo 'PARA OS COMPUTADORES SE ENXERGAREM'
    Write-Info 'Rode esta opcao em CADA computador do escritorio e compare:'
    Write-Host ''
    Write-Host '   1. A FAIXA DA REDE tem de ser a mesma em todos.' -ForegroundColor White
    Write-Host '   2. O GATEWAY tem de ser o mesmo em todos.' -ForegroundColor White
    Write-Host ''
    Write-Info 'Se um PC esta em 192.168.0.x e outro em 192.168.15.x, eles NAO se'
    Write-Info 'enxergam - mesmo os dois tendo internet normal. Isso acontece quando:'
    Write-Info '   - um esta no Wi-Fi de visitantes e outro na rede principal;'
    Write-Info '   - alguem ligou um roteador extra e criou uma segunda rede;'
    Write-Info '   - um esta no cabo e outro num repetidor mal configurado;'
    Write-Info '   - alguem esta com VPN ligada.'
    Write-Host ''
    Write-Info 'Mesma faixa e mesmo gateway, e ainda assim nao se enxergam? Ai o'
    Write-Info 'problema e firewall, perfil de rede ou isolamento no roteador -'
    Write-Info 'use o diagnostico da rede local.'
    return [long]0
}

function Repair-ProblemasConexao {
    <#
      Diagnostica a conexao em camadas, de baixo para cima: cabo/Wi-Fi, IP,
      gateway, DNS e internet. Assim o problema aparece na camada certa em vez
      de virar "a internet caiu".
    #>
    Write-Titulo 'RESOLVER PROBLEMAS DE CONEXAO'

    $achados = [System.Collections.Generic.List[string]]::new()
    $sugestoes = [System.Collections.Generic.List[string]]::new()

    # --- 1. Camada fisica -------------------------------------------------
    Write-Etapa '1/7  Placa de rede e cabo/Wi-Fi'
    $adaptadores = @(Get-NetAdapter -ErrorAction SilentlyContinue |
                     Where-Object { $_.InterfaceDescription -notmatch '(?i)(hyper-v|virtual|vmware|virtualbox|loopback|tap-|wintun)' })
    if ($adaptadores.Count -eq 0) {
        Write-Falha 'Nenhuma placa de rede fisica encontrada.'
        $achados.Add('Nenhuma placa de rede fisica')
    }
    foreach ($a in $adaptadores) {
        if ($a.Status -eq 'Up') {
            Write-Ok "$($a.Name): conectado ($($a.LinkSpeed))"
        } elseif ($a.Status -eq 'Disabled') {
            Write-Falha "$($a.Name): DESATIVADA no Windows."
            $achados.Add("Placa '$($a.Name)' desativada")
            $sugestoes.Add("Ativar a placa '$($a.Name)'")
        } else {
            $ehWifi = ($a.MediaType -match '802.11' -or $a.InterfaceDescription -match '(?i)(wi-?fi|wireless)')
            if ($ehWifi) {
                Write-Falha "$($a.Name): sem conexao (Wi-Fi desconectado)."
                $sugestoes.Add('Conectar no Wi-Fi do escritorio')
            } else {
                Write-Falha "$($a.Name): sem link - CABO DESCONECTADO ou porta do switch morta."
                $sugestoes.Add('Conferir o cabo de rede nas duas pontas e a porta do switch')
            }
            $achados.Add("'$($a.Name)' sem conexao")
        }
    }

    # --- 2. Endereco IP ---------------------------------------------------
    Write-Etapa '2/7  Endereco IP'
    $conexoes = @(Get-ConexoesReais)
    $validas  = @($conexoes | Where-Object { $_.Vale })
    $apipa    = @($conexoes | Where-Object { $_.IP -like '169.254.*' })

    if ($apipa.Count -gt 0) {
        foreach ($a in $apipa) {
            Write-Falha "$($a.Alias): IP $($a.IP) - o DHCP NAO respondeu."
        }
        Write-Info 'IP 169.254.x.x significa que o Windows nao conseguiu endereco do roteador.'
        Write-Info 'Causas: roteador desligado, cabo ruim, DHCP cheio, ou porta bloqueada.'
        $achados.Add('DHCP nao respondeu (IP 169.254.x.x)')
        $sugestoes.Add('Renovar o IP; se nao resolver, reiniciar o roteador')
    }
    if ($validas.Count -eq 0 -and $apipa.Count -eq 0) {
        Write-Falha 'Nenhuma conexao com gateway definido.'
        $achados.Add('Sem gateway')
    }
    foreach ($c in $validas) {
        $faixa = Get-FaixaRede -IP $c.IP -Prefixo $c.Prefixo
        Write-Ok "$($c.Alias): $($c.IP)/$($c.Prefixo)  faixa $faixa  gateway $($c.Gateway)"
    }

    # Mais de um gateway = rotas competindo, causa classica de rede instavel
    $comGw = @($conexoes | Where-Object { $_.Gateway })
    if ($comGw.Count -gt 1) {
        Write-Host ''
        Write-Aviso "$($comGw.Count) conexoes com gateway ao mesmo tempo:"
        foreach ($g in $comGw) { Write-Info ("   $($g.Alias): gateway $($g.Gateway)") }
        Write-Info 'Duas rotas competindo deixam a rede instavel e podem impedir o acesso'
        Write-Info 'as pastas compartilhadas. Comum quando o cabo e o Wi-Fi estao ligados'
        Write-Info 'juntos, ou com VPN ativa.'
        $achados.Add('Mais de um gateway ativo')
        $sugestoes.Add('Desligar o Wi-Fi quando usar cabo (ou desconectar a VPN)')
    }

    # --- 3. Gateway -------------------------------------------------------
    Write-Etapa '3/7  Comunicacao com o roteador'
    $gwOk = $false
    foreach ($c in $validas) {
        $r = Test-Connection -ComputerName $c.Gateway -Count 2 -Quiet -ErrorAction SilentlyContinue
        if ($r) { Write-Ok "Roteador $($c.Gateway) respondeu."; $gwOk = $true }
        else {
            Write-Falha "Roteador $($c.Gateway) NAO respondeu."
            $achados.Add("Gateway $($c.Gateway) sem resposta")
            $sugestoes.Add('Verificar se o roteador esta ligado e o cabo conectado')
        }
    }

    # --- 4. DNS -----------------------------------------------------------
    Write-Etapa '4/7  Resolucao de nomes (DNS)'
    $dnsOk = $false
    foreach ($nome in @('www.google.com', 'pje.jus.br')) {
        try {
            $res = Resolve-DnsName -Name $nome -Type A -ErrorAction Stop -QuickTimeout
            if ($res) { Write-Ok "$nome resolveu para $(@($res | Where-Object { $_.IPAddress })[0].IPAddress)"; $dnsOk = $true }
        } catch {
            Write-Falha "$nome NAO resolveu."
        }
    }
    if (-not $dnsOk) {
        $achados.Add('DNS nao resolve nomes')
        $sugestoes.Add('Limpar o cache DNS; se persistir, trocar o DNS para 8.8.8.8')
        Write-Info 'Sem DNS o navegador nao abre site nenhum, mesmo com a rede funcionando.'
    }

    # --- 5. Internet ------------------------------------------------------
    Write-Etapa '5/7  Acesso a internet'
    $netOk = $false
    foreach ($alvo in @('1.1.1.1', '8.8.8.8')) {
        $r = Test-Connection -ComputerName $alvo -Count 3 -ErrorAction SilentlyContinue
        if ($r) {
            $ms = [math]::Round(($r | Measure-Object -Property ResponseTime -Average).Average)
            $perdidos = 3 - @($r).Count
            Write-Ok "$alvo respondeu - latencia $ms ms$(if ($perdidos -gt 0) { ", $perdidos pacote(s) perdido(s)" })"
            $netOk = $true
            if ($ms -gt 150) {
                Write-Aviso 'Latencia alta - conexao lenta ou congestionada.'
                $achados.Add("Latencia alta ($ms ms)")
            }
            if ($perdidos -gt 0) {
                Write-Aviso 'Perda de pacotes - cabo, conector ou Wi-Fi com interferencia.'
                $achados.Add('Perda de pacotes')
            }
        } else {
            Write-Falha "$alvo nao respondeu."
        }
    }
    if (-not $netOk) {
        $achados.Add('Sem acesso a internet')
        if ($gwOk) {
            Write-Info 'O roteador responde mas a internet nao: o problema esta no link do'
            Write-Info 'provedor, nao na rede interna. As pastas compartilhadas continuam'
            Write-Info 'funcionando normalmente.'
            $sugestoes.Add('Falar com o provedor - a rede interna esta boa')
        }
    }

    # --- 6. Proxy ---------------------------------------------------------
    Write-Etapa '6/7  Proxy'
    try {
        $rp = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $pe = (Get-ItemProperty -Path $rp -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
        $ps = (Get-ItemProperty -Path $rp -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
        $pac = (Get-ItemProperty -Path $rp -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL
        if ($pe -eq 1 -or $pac) {
            Write-Aviso "Proxy configurado: $(if ($ps) { $ps } else { $pac })"
            Write-Info 'Proxy indevido bloqueia sites e sistemas de tribunal.'
            $achados.Add('Proxy configurado')
            $sugestoes.Add('Se o escritorio nao usa proxy, limpar pela opcao de corrigir proxy')
        } else { Write-Ok 'Sem proxy configurado.' }
    } catch { }

    # --- 7. Servidores DNS ------------------------------------------------
    # DNS configurado mas inalcancavel deixa tudo lento: cada consulta espera
    # o tempo limite antes de tentar o proximo servidor.
    Write-Etapa '7/7  Servidores DNS configurados'
    $dnsTestados = 0
    foreach ($c in $validas) {
        foreach ($d in $c.DNS) {
            if ($d -match '^127\.' -or $d -like '169.254.*') { continue }
            $dnsTestados++
            $inicio = Get-Date
            $resp = $false
            try {
                $r = Resolve-DnsName -Name 'www.google.com' -Server $d -Type A -ErrorAction Stop -QuickTimeout
                if ($r) { $resp = $true }
            } catch { }
            $ms = [int]((Get-Date) - $inicio).TotalMilliseconds
            if ($resp) {
                if ($ms -gt 800) {
                    Write-Aviso "DNS $d responde, mas devagar ($ms ms) - navegacao fica arrastada."
                    $achados.Add("DNS $d lento ($ms ms)")
                    $sugestoes.Add('Trocar o DNS para 8.8.8.8 e 1.1.1.1')
                } else {
                    Write-Ok "DNS $d respondeu ($ms ms)."
                }
            } else {
                Write-Falha "DNS $d NAO responde."
                Write-Info  'Cada consulta espera o tempo limite antes de tentar outro servidor:'
                Write-Info  'e o que faz "a internet ficar lenta" mesmo com a conexao boa.'
                $achados.Add("DNS $d inalcancavel")
                $sugestoes.Add('Trocar o DNS para 8.8.8.8 e 1.1.1.1, ou deixar automatico')
            }
        }
    }
    if ($dnsTestados -eq 0) { Write-Info 'Nenhum servidor DNS configurado para testar.' }

    # --- Resultado ---------------------------------------------------------
    Write-Host ''
    if ($achados.Count -eq 0) {
        Write-Titulo 'CONEXAO SAUDAVEL'
        Write-Ok 'Placa, IP, roteador, DNS e internet: tudo funcionando.'
        Write-Info 'Se mesmo assim o cliente nao acessa a pasta compartilhada, o problema'
        Write-Info 'nao e a conexao - use o diagnostico da rede local.'
        return [long]0
    }

    Write-Titulo 'PROBLEMAS ENCONTRADOS'
    foreach ($a in $achados) { Write-Falha $a; Add-Alerta ("Conexao: " + $a) }
    if ($sugestoes.Count -gt 0) {
        Write-Host ''
        Write-Dest 'O que fazer:'
        foreach ($s in ($sugestoes | Select-Object -Unique)) { Write-Info ("   - " + $s) }
    }

    if ($SomenteRelatorio -or $SemInteracao) { return [long]0 }

    # --- Correcoes ---------------------------------------------------------
    Write-Host ''
    Write-Host '     [1] Tentar corrigir agora (limpar DNS, renovar IP, reiniciar a placa)' -ForegroundColor White
    Write-Host '     [2] So limpar o cache DNS (rapido, nao derruba a conexao)' -ForegroundColor White
    Write-Host '     [0] Nao corrigir agora' -ForegroundColor DarkGray
    Write-Host ''
    $opc = (Read-Host '  Opcao').Trim()

    if ($opc -eq '2') {
        try { Clear-DnsClientCache -ErrorAction Stop; Write-Ok 'Cache DNS limpo.' }
        catch { & ipconfig /flushdns | Out-Null; Write-Ok 'Cache DNS limpo.' }
        return [long]0
    }
    if ($opc -ne '1') { Write-Info 'Nada foi alterado.'; return [long]0 }

    # Reiniciar placa derruba sessao remota: avisar.
    $remoto = @(Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $_.ProcessName -match '(?i)^(anydesk|teamviewer|rustdesk)' })
    if ($remoto.Count -gt 0 -or ($env:SESSIONNAME -match '(?i)^RDP')) {
        Write-Host ''
        Write-Falha 'ACESSO REMOTO ATIVO NESTA MAQUINA.'
        Write-Info  'Reiniciar a placa de rede DERRUBA a sua conexao com o cliente.'
        $c = Read-Host '  Continuar mesmo assim? (S/N)'
        if ($c -notmatch '^[Ss]') { Write-Info 'Cancelado. Limpando so o cache DNS.';
            try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch { }
            Write-Ok 'Cache DNS limpo.'
            return [long]0 }
    }

    Write-Etapa 'Limpando cache DNS...'
    try { Clear-DnsClientCache -ErrorAction Stop; Write-Ok 'Cache DNS limpo.' }
    catch { & ipconfig /flushdns | Out-Null; Write-Ok 'Cache DNS limpo.' }

    Write-Etapa 'Renovando endereco IP...'
    try {
        & ipconfig /release 2>&1 | Out-Null
        & ipconfig /renew 2>&1 | Out-Null
        Write-Ok 'IP renovado.'
    } catch { Write-Aviso "Falha ao renovar: $($_.Exception.Message)" }

    Write-Etapa 'Reiniciando a placa de rede...'
    foreach ($a in @($adaptadores | Where-Object { $_.Status -eq 'Up' })) {
        try {
            Restart-NetAdapter -Name $a.Name -ErrorAction Stop
            Write-Ok "Placa '$($a.Name)' reiniciada."
            Start-Sleep -Seconds 5
        } catch { Write-Aviso "Nao foi possivel reiniciar '$($a.Name)': $($_.Exception.Message)" }
    }

    Write-Etapa 'Conferindo o resultado...'
    Start-Sleep -Seconds 3
    $depois = @(Get-ConexoesReais | Where-Object { $_.Vale })
    if ($depois.Count -gt 0) {
        foreach ($d in $depois) { Write-Ok "$($d.Alias): $($d.IP)  gateway $($d.Gateway)" }
        $t = Test-Connection -ComputerName '1.1.1.1' -Count 2 -Quiet -ErrorAction SilentlyContinue
        if ($t) { Write-Ok 'Internet respondendo.' }
        else { Write-Aviso 'Ainda sem internet. Se o roteador responde, o problema e do provedor.' }
    } else {
        Write-Falha 'Ainda sem endereco valido.'
        Write-Info  'Proximos passos: trocar o cabo, testar outra porta do switch, e'
        Write-Info  'reiniciar o roteador. Se nada resolver, use a opcao de corrigir'
        Write-Info  'rede no modo profundo (reset de TCP/IP e Winsock).'
    }
    return [long]0
}

function Initialize-MaquinaEscritorio {
    <#
      Roteiro de maquina nova. Nao acrescenta capacidade: encadeia, na ordem
      certa, o que hoje sao oito opcoes espalhadas pelo menu, e marca o que ja
      foi feito. O ganho e' nao esquecer passo - o erro classico e' entregar a
      maquina e descobrir depois que faltou o certificado ou a unidade de rede.

      Cada etapa pergunta antes e pode ser pulada: maquina de estagiario nao
      precisa de certificado; maquina que nao usa PJe nao precisa de Java.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Percorreria o roteiro de preparacao de maquina nova.'; return [long]0 }

    Write-Titulo 'PREPARAR MAQUINA PARA O ESCRITORIO'
    Write-Info 'Roteiro para computador novo, formatado, ou que trocou de usuario.'
    Write-Info 'Cada etapa pergunta antes - pule o que nao se aplica a esta maquina.'

    if ($SemInteracao) { Write-Aviso 'Modo desatendido: o roteiro precisa de interacao.'; return [long]0 }

    $feito  = [System.Collections.Generic.List[string]]::new()
    $pulado = [System.Collections.Generic.List[string]]::new()

    function Perguntar-Etapa {
        param([string]$Titulo, [string]$Porque)
        Write-Host ''
        Write-Host ('  ' + ('-' * 66)) -ForegroundColor DarkCyan
        Write-Host ("  $Titulo") -ForegroundColor Cyan
        Write-Host ('  ' + ('-' * 66)) -ForegroundColor DarkCyan
        if ($Porque) { Write-Info $Porque }
        $r = Read-Host '  Fazer agora? (S/N) [S]'
        return (-not $r -or $r -match '^[Ss]')
    }

    # --- 0. Retrato inicial ------------------------------------------------
    Write-Etapa 'Situacao da maquina antes de comecar'
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($cs) { Write-Info ("Modelo    : $($cs.Manufacturer) $($cs.Model)") }
    if ($os) { Write-Info ("Sistema   : $($os.Caption) build $($os.BuildNumber)") }
    Write-Info ("Nome      : $env:COMPUTERNAME")
    if ($cs -and -not $cs.PartOfDomain) { Write-Info ("Grupo trab: $($cs.Workgroup)") }
    foreach ($c in @(Get-ConexoesReais | Where-Object { $_.Vale })) {
        Write-Info ("Rede      : $($c.IP)  faixa $(Get-FaixaRede -IP $c.IP -Prefixo $c.Prefixo)")
    }

    # --- 1. Nome da maquina ------------------------------------------------
    if (Perguntar-Etapa 'ETAPA 1 de 8 - Nome do computador' `
        'Nome claro (ex.: RECEPCAO, DR-CARLOS) facilita achar na rede depois.') {
        Write-Info ("Nome atual: $env:COMPUTERNAME")
        $novo = (Read-Host '  Nome novo (ENTER para manter)').Trim()
        if ($novo -and $novo -ne $env:COMPUTERNAME) {
            if ($novo -notmatch '^[A-Za-z0-9\-]{1,15}$') {
                Write-Falha 'Nome invalido: ate 15 letras/numeros, sem espaco nem acento.'
            } else {
                try {
                    Rename-Computer -NewName $novo -Force -ErrorAction Stop
                    Write-Ok "Nome alterado para $novo. Vale apos reiniciar."
                    $script:precisaReiniciar = $true
                    $feito.Add("nome do computador -> $novo")
                } catch { Write-Falha "Nao foi possivel renomear: $($_.Exception.Message)" }
            }
        } else { Write-Info 'Nome mantido.' }
    } else { $pulado.Add('nome do computador') }

    # --- 2. Visual C++ ------------------------------------------------------
    if (Perguntar-Etapa 'ETAPA 2 de 8 - Redistribuiveis Visual C++' `
        'Sistema juridico antigo nao abre sem eles. Melhor instalar antes do que descobrir depois.') {
        Install-VisualCRedist | Out-Null
        $feito.Add('redistribuiveis Visual C++')
    } else { $pulado.Add('Visual C++') }

    # --- 3. Java + PJe ------------------------------------------------------
    if (Perguntar-Etapa 'ETAPA 3 de 8 - Java e ambiente PJe' `
        'So faz sentido se este usuario vai peticionar ou assinar pelo PJe.') {
        Set-AmbientePJe | Out-Null
        $feito.Add('ambiente PJe e Java')
    } else { $pulado.Add('Java e PJe') }

    # --- 4. Certificado -----------------------------------------------------
    if (Perguntar-Etapa 'ETAPA 4 de 8 - Certificado digital' `
        'A1: importar do .pfx. A3: conectar o token e conferir se aparece.') {
        Write-Host ''
        Write-Host '     [1] Importar certificado A1 de um arquivo .pfx' -ForegroundColor White
        Write-Host '     [2] So conferir o que ja esta instalado (token A3)' -ForegroundColor White
        Write-Host '     [0] Pular' -ForegroundColor DarkGray
        $op = (Read-Host '  Opcao').Trim()
        if ($op -eq '1') {
            $arq = (Read-Host '  Caminho do arquivo .pfx').Trim().Trim('"')
            if ($arq -and (Test-Path -LiteralPath $arq)) {
                $pw = Read-Host '  Senha do arquivo' -AsSecureString
                try {
                    Import-PfxCertificate -FilePath $arq -CertStoreLocation 'Cert:\CurrentUser\My' `
                        -Password $pw -Exportable -ErrorAction Stop | Out-Null
                    Write-Ok 'Certificado importado para a loja Pessoal do usuario.'
                    Write-Info 'Importado como exportavel, para permitir backup futuro.'
                    $feito.Add('certificado A1 importado')
                } catch {
                    Write-Falha "Nao foi possivel importar: $($_.Exception.Message)"
                    Write-Info  'Senha errada, ou arquivo corrompido.'
                }
            } elseif ($arq) { Write-Falha 'Arquivo nao encontrado.' }
            Show-CertificadosInstalados | Out-Null
        } elseif ($op -eq '2') {
            Show-CertificadosInstalados | Out-Null
            $feito.Add('certificados conferidos')
        } else { $pulado.Add('certificado digital') }
    } else { $pulado.Add('certificado digital') }

    # --- 5. Rede do escritorio ---------------------------------------------
    if (Perguntar-Etapa 'ETAPA 5 de 8 - Rede e pasta compartilhada' `
        'Coloca a maquina no grupo de trabalho e mapeia a unidade do servidor.') {
        Set-MaquinaClienteRede | Out-Null
        $feito.Add('rede e unidade do servidor')
    } else { $pulado.Add('rede do escritorio') }

    # --- 6. Impressora ------------------------------------------------------
    if (Perguntar-Etapa 'ETAPA 6 de 8 - Impressora' `
        'Conecta a impressora compartilhada de outra maquina da rede.') {
        Write-Info 'Informe o caminho da impressora compartilhada.'
        Write-Info 'Ex.: \\SERVIDOR\HP-Recepcao   (deixe em branco para pular)'
        $imp = (Read-Host '  Impressora').Trim().Trim('"')
        if ($imp -match '^\\\\[^\\]+\\.+') {
            try {
                Add-Printer -ConnectionName $imp -ErrorAction Stop
                Write-Ok "Impressora conectada: $imp"
                $feito.Add("impressora $imp")
                $r = Read-Host '  Definir como impressora padrao? (S/N) [S]'
                if (-not $r -or $r -match '^[Ss]') {
                    try {
                        $pr = Get-CimInstance Win32_Printer -Filter "Name='$($imp -replace '\\','\\\\')'" -ErrorAction SilentlyContinue
                        if ($pr) { Invoke-CimMethod -InputObject $pr -MethodName SetDefaultPrinter | Out-Null; Write-Ok 'Definida como padrao.' }
                    } catch { Write-Info 'Defina como padrao manualmente se necessario.' }
                }
            } catch {
                Write-Falha "Nao foi possivel conectar: $($_.Exception.Message)"
                Write-Info  'Confira se a impressora esta compartilhada e se o driver esta disponivel.'
            }
        } else { Write-Info 'Impressora nao configurada.'; $pulado.Add('impressora') }
    } else { $pulado.Add('impressora') }

    # --- 7. Ajustes de uso --------------------------------------------------
    if (Perguntar-Etapa 'ETAPA 7 de 8 - Ajustes de uso do Windows' `
        'Miniaturas ligadas, efeitos leves e plano de energia - o que o escritorio espera.') {
        Set-EfeitosVisuais | Out-Null
        Set-DesempenhoEnergia | Out-Null
        $feito.Add('ajustes de exibicao e energia')
    } else { $pulado.Add('ajustes de uso') }

    # --- 8. Retrato final e proximos passos ---------------------------------
    if (Perguntar-Etapa 'ETAPA 8 de 8 - Registrar como a maquina ficou' `
        'Gera a ficha da rede para voce guardar na pasta deste cliente.') {
        Export-FichaRede | Out-Null
        $feito.Add('ficha da rede gerada')
    } else { $pulado.Add('ficha da rede') }

    # --- Resumo --------------------------------------------------------------
    Write-Host ''
    Write-Titulo 'MAQUINA PREPARADA'
    if ($feito.Count -gt 0) {
        Write-Dest 'Feito nesta passagem:'
        foreach ($f in $feito) { Write-Ok $f }
    }
    if ($pulado.Count -gt 0) {
        Write-Host ''
        Write-Dest 'Pulado (confira se realmente nao se aplica):'
        foreach ($p in $pulado) { Write-Info ("   - " + $p) }
    }

    Write-Host ''
    Write-Dest 'Antes de entregar a maquina, confira a mao:'
    Write-Info  '   - o usuario consegue abrir a pasta da rede e SALVAR um arquivo nela;'
    Write-Info  '   - o certificado assina de verdade (peca para ele assinar um teste);'
    Write-Info  '   - a impressora imprime uma pagina de teste;'
    Write-Info  '   - se for usar audiencia por video, rode a opcao "Pronto para a Audiencia".'
    if ($script:precisaReiniciar) {
        Write-Host ''
        Write-Aviso 'REINICIE a maquina para concluir - o nome so vale apos reiniciar.'
    }
    Add-Alerta 'Maquina preparada para o escritorio - conferir os itens manuais.'
    return [long]0
}

function Test-CapturaEmUso {
    <#
      Descobre se algum programa esta SEGURANDO a camera ou o microfone agora.
      O Windows registra o uso em ConsentStore: quando LastUsedTimeStop vale 0,
      o aplicativo esta com o dispositivo aberto neste momento.
      Camera presa pelo Teams em segundo plano e' a causa numero 1 de "a camera
      nao funciona" cinco minutos antes da audiencia.
    #>
    param([ValidateSet('webcam','microphone')][string]$Dispositivo)

    $emUso = [System.Collections.Generic.List[string]]::new()
    foreach ($raiz in @("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$Dispositivo",
                        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$Dispositivo")) {
        foreach ($grupo in @('', '\NonPackaged')) {
            $p = "$raiz$grupo"
            if (-not (Test-Path -LiteralPath $p)) { continue }
            foreach ($k in @(Get-ChildItem -LiteralPath $p -ErrorAction SilentlyContinue)) {
                $v = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                if ($null -ne $v.LastUsedTimeStop -and $v.LastUsedTimeStop -eq 0) {
                    $nome = $k.PSChildName -replace '#', '\'
                    # nome amigavel: so o executavel
                    if ($nome -match '([^\\]+\.exe)$') { $nome = $Matches[1] }
                    if (-not $emUso.Contains($nome)) { [void]$emUso.Add($nome) }
                }
            }
        }
    }
    return $emUso
}

function Test-QualidadeChamada {
    <#
      Mede o que realmente derruba videoconferencia: perda de pacote e JITTER
      (variacao da latencia). Uma conexao de 30 ms com jitter alto trava a voz;
      uma de 80 ms estavel funciona bem. Ping medio sozinho nao diz nada.
    #>
    param([string]$Alvo = '8.8.8.8', [int]$Amostras = 20)

    $r = Test-Connection -ComputerName $Alvo -Count $Amostras -ErrorAction SilentlyContinue
    if (-not $r) {
        return [PSCustomObject]@{ Ok = $false; Perda = 100; Media = 0; Jitter = 0 }
    }
    $t = @($r | ForEach-Object { $_.ResponseTime })
    $recebidos = $t.Count
    $perda = [math]::Round((($Amostras - $recebidos) / $Amostras) * 100)
    $media = ($t | Measure-Object -Average).Average
    $jitter = 0
    if ($recebidos -gt 1) {
        $soma = ($t | ForEach-Object { [math]::Pow($_ - $media, 2) } | Measure-Object -Sum).Sum
        $jitter = [math]::Sqrt($soma / $recebidos)
    }
    return [PSCustomObject]@{
        Ok     = $true
        Perda  = $perda
        Media  = [math]::Round($media)
        Jitter = [math]::Round($jitter, 1)
    }
}

function Test-ProntoParaAudiencia {
    <#
      Verificacao pre-audiencia. Feita para rodar NA VESPERA ou minutos antes,
      e devolver um veredicto - nao uma lista de dados para o operador
      interpretar sob pressao.

      As opcoes de reparar audio e webcam consertam DEPOIS que deu errado.
      Esta existe para o problema aparecer enquanto ainda ha tempo.
    #>
    Write-Titulo 'PRONTO PARA A AUDIENCIA?'
    Write-Info 'Verificacao de camera, microfone, som e qualidade da conexao.'
    Write-Info 'Rode na vespera, ou pelo menos 15 minutos antes da audiencia.'

    $bloqueia = [System.Collections.Generic.List[string]]::new()
    $ressalva = [System.Collections.Generic.List[string]]::new()

    # --- 1. CAMERA --------------------------------------------------------
    Write-Etapa '1/6  Camera'
    # A webcam costuma expor tambem o microfone dela: sem excluir o endpoint de
    # audio, o mesmo aparelho aparece duas ou tres vezes na lista de cameras.
    $cams = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $_.Class -notin @('AudioEndpoint','MEDIA') -and
        $_.FriendlyName -notmatch '(?i)^microfone|^microphone' -and
        (($_.Class -in @('Camera','Image')) -or
         ($_.FriendlyName -match '(?i)(webcam|camera)' -and $_.FriendlyName -notmatch '(?i)(virtual|scanner|fax)')) } |
        Sort-Object FriendlyName -Unique)
    $camOk = @($cams | Where-Object { $_.Status -eq 'OK' })

    if ($cams.Count -eq 0) {
        Write-Falha 'Nenhuma camera encontrada nesta maquina.'
        $bloqueia.Add('Sem camera: notebook com camera desativada na BIOS, ou webcam nao conectada')
    } elseif ($camOk.Count -eq 0) {
        foreach ($c in $cams) { Write-Falha "$($c.FriendlyName): $($c.Status)" }
        $bloqueia.Add('Camera com defeito - use a opcao de reparar webcam')
    } else {
        foreach ($c in $camOk) { Write-Ok "$($c.FriendlyName): funcionando" }
    }

    # Permissao
    try {
        $pc = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam' -Name Value -ErrorAction SilentlyContinue).Value
        $pn = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged' -Name Value -ErrorAction SilentlyContinue).Value
        if ($pc -eq 'Deny' -or $pn -eq 'Deny') {
            Write-Falha 'Acesso a camera BLOQUEADO nas configuracoes de privacidade.'
            $bloqueia.Add('Permissao de camera negada - use a opcao de reparar webcam')
        } else { Write-Ok 'Permissao de camera: liberada.' }
    } catch { }

    # Em uso por outro programa
    $camUso = @(Test-CapturaEmUso -Dispositivo 'webcam')
    if ($camUso.Count -gt 0) {
        Write-Falha ("CAMERA EM USO por: " + ($camUso -join ', '))
        Write-Info  'Enquanto outro programa segurar a camera, o sistema da audiencia'
        Write-Info  'nao consegue abrir. Feche esse programa ANTES de entrar.'
        $bloqueia.Add("Fechar o programa que esta usando a camera: " + ($camUso -join ', '))
    } else {
        Write-Ok 'Camera livre - nenhum programa segurando.'
    }

    # --- 2. MICROFONE -----------------------------------------------------
    Write-Etapa '2/6  Microfone'
    $mics = @(Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
              Where-Object { $_.PNPClass -eq 'AudioEndpoint' -and $_.Name -match '(?i)(microfone|microphone)' })
    if ($mics.Count -eq 0) {
        # segunda tentativa pelo registro de captura
        $reg = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture'
        $ativos = @(Get-ChildItem -LiteralPath $reg -ErrorAction SilentlyContinue | Where-Object {
            (Get-ItemProperty -LiteralPath $_.PSPath -Name DeviceState -ErrorAction SilentlyContinue).DeviceState -eq 1 })
        if ($ativos.Count -gt 0) { Write-Ok "$($ativos.Count) dispositivo(s) de captura ativo(s)." }
        else {
            Write-Falha 'Nenhum microfone ativo encontrado.'
            $bloqueia.Add('Sem microfone - conferir se esta conectado e habilitado')
        }
    } else {
        foreach ($m in $mics) { Write-Ok "$($m.Name): $($m.Status)" }
    }

    try {
        $pm = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone' -Name Value -ErrorAction SilentlyContinue).Value
        $pmn = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged' -Name Value -ErrorAction SilentlyContinue).Value
        if ($pm -eq 'Deny' -or $pmn -eq 'Deny') {
            Write-Falha 'Acesso ao microfone BLOQUEADO nas configuracoes de privacidade.'
            $bloqueia.Add('Permissao de microfone negada - use a opcao de reparar audio')
        } else { Write-Ok 'Permissao de microfone: liberada.' }
    } catch { }

    $micUso = @(Test-CapturaEmUso -Dispositivo 'microphone')
    if ($micUso.Count -gt 0) {
        Write-Aviso ("Microfone em uso por: " + ($micUso -join ', '))
        Write-Info  'Se nao for o programa da audiencia, feche antes de entrar.'
        $ressalva.Add("Microfone em uso por: " + ($micUso -join ', '))
    } else { Write-Ok 'Microfone livre.' }

    # --- 3. SOM (SAIDA) ---------------------------------------------------
    Write-Etapa '3/6  Som (para ouvir o juiz)'
    $reg = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render'
    $saidas = @(Get-ChildItem -LiteralPath $reg -ErrorAction SilentlyContinue | Where-Object {
        (Get-ItemProperty -LiteralPath $_.PSPath -Name DeviceState -ErrorAction SilentlyContinue).DeviceState -eq 1 })
    if ($saidas.Count -eq 0) {
        Write-Falha 'Nenhum dispositivo de som ativo.'
        $bloqueia.Add('Sem saida de som - use a opcao de reparar audio')
    } else {
        Write-Ok "$($saidas.Count) dispositivo(s) de som ativo(s)."
    }
    $svc = Get-Service -Name 'AudioSrv' -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') {
        Write-Falha 'Servico de audio do Windows parado.'
        $bloqueia.Add('Servico de audio parado - use a opcao de reparar audio')
    }

    # Volume e mudo nao sao lidos de forma confiavel por script. Em vez de
    # fingir que verificamos, oferecemos a conferencia visual de 10 segundos.
    Write-Info 'Volume e "mudo" precisam de conferencia visual - o script nao le'
    Write-Info 'isso de forma confiavel. A tela de som sera aberta no final.'

    # --- 4. QUALIDADE DA CONEXAO ------------------------------------------
    Write-Etapa '4/6  Qualidade da conexao (o que trava a voz)'
    Write-Info 'Medindo 20 amostras... aguarde.'
    $q = Test-QualidadeChamada -Alvo '8.8.8.8' -Amostras 20

    if (-not $q.Ok) {
        Write-Falha 'Sem resposta da internet.'
        $bloqueia.Add('Sem internet - resolver antes da audiencia')
    } else {
        Write-Info ("Latencia media : " + $q.Media + " ms")
        Write-Info ("Jitter         : " + $q.Jitter + " ms   (variacao da latencia)")
        Write-Info ("Perda          : " + $q.Perda + "%")
        Write-Host ''

        if ($q.Perda -ge 5) {
            Write-Falha "Perda de $($q.Perda)% dos pacotes - a chamada vai cortar."
            $bloqueia.Add("Perda de pacotes em $($q.Perda)% - trocar cabo, ou sair do Wi-Fi para o cabo")
        } elseif ($q.Perda -gt 0) {
            Write-Aviso "Perda de $($q.Perda)% - pode haver cortes pontuais."
            $ressalva.Add("Perda de $($q.Perda)% dos pacotes")
        } else { Write-Ok 'Sem perda de pacotes.' }

        if ($q.Jitter -gt 30) {
            Write-Falha "Jitter de $($q.Jitter) ms - a voz vai picotar."
            Write-Info  "Jitter alto e' pior que latencia alta para videoconferencia."
            $bloqueia.Add("Jitter de $($q.Jitter) ms - preferir cabo, e tirar downloads/streaming da rede")
        } elseif ($q.Jitter -gt 15) {
            Write-Aviso "Jitter de $($q.Jitter) ms - conexao instavel, pode picotar."
            $ressalva.Add("Jitter de $($q.Jitter) ms")
        } else { Write-Ok 'Conexao estavel (jitter baixo).' }

        if ($q.Media -gt 150) {
            Write-Aviso "Latencia de $($q.Media) ms - vai haver atraso perceptivel na fala."
            $ressalva.Add("Latencia alta ($($q.Media) ms)")
        }
    }

    # --- 5. COMO ESTA CONECTADO -------------------------------------------
    Write-Etapa '5/6  Tipo de conexao e energia'
    $wifi = Get-InfoWiFi
    if ($wifi['SSID']) {
        Write-Info ("Wi-Fi: " + $wifi['SSID'] + $(if ($wifi['Sinal']) { "   sinal " + $wifi['Sinal'] } else { '' }))
        if ($wifi['Sinal'] -match '(\d+)%') {
            $pct = [int]$Matches[1]
            if ($pct -lt 50) {
                Write-Aviso "Sinal de $pct% - risco de queda no meio da audiencia."
                Write-Info  'Aproxime-se do roteador, ou use cabo de rede.'
                $ressalva.Add("Sinal Wi-Fi fraco ($pct%) - preferir cabo")
            } else { Write-Ok "Sinal Wi-Fi bom ($pct%)." }
        }
        Write-Info 'Cabo de rede sempre e mais estavel que Wi-Fi para audiencia.'
    } else {
        Write-Ok 'Conexao por cabo - o mais estavel para videoconferencia.'
    }

    # Bateria: notebook no modo economia reduz desempenho de video
    try {
        $bat = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($bat) {
            if ($bat.BatteryStatus -eq 1) {
                Write-Aviso ("Notebook NA BATERIA (" + $bat.EstimatedChargeRemaining + "%).")
                Write-Info  'Conecte na tomada: economia de energia derruba o desempenho do video.'
                $ressalva.Add('Notebook na bateria - conectar na tomada')
            } else { Write-Ok 'Notebook na tomada.' }
        }
    } catch { }

    # --- 6. PROGRAMA DA AUDIENCIA ------------------------------------------
    Write-Etapa '6/6  Programa de videoconferencia'
    $apps = [System.Collections.Generic.List[string]]::new()
    $caminhos = @{
        'Microsoft Teams'       = @("$env:LOCALAPPDATA\Microsoft\Teams\current\Teams.exe",
                                    "$env:ProgramFiles\WindowsApps")
        'Zoom'                  = @("$env:APPDATA\Zoom\bin\Zoom.exe", "$env:ProgramFiles\Zoom\bin\Zoom.exe")
        'Google Chrome'         = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
                                    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe")
        'Microsoft Edge'        = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe")
    }
    foreach ($nome in $caminhos.Keys) {
        foreach ($c in $caminhos[$nome]) {
            if (Test-Path -LiteralPath $c) { if (-not $apps.Contains($nome)) { [void]$apps.Add($nome) }; break }
        }
    }
    # Teams novo (empacotado)
    if (Get-AppxPackage -Name 'MSTeams' -ErrorAction SilentlyContinue) { if (-not $apps.Contains('Microsoft Teams')) { [void]$apps.Add('Microsoft Teams') } }

    if ($apps.Count -gt 0) {
        Write-Ok ("Instalado(s): " + ($apps -join ', '))
        Write-Info 'Audiencia por navegador (Meet, PJe, Zoom web) funciona no Chrome e Edge.'
    } else {
        Write-Aviso 'Nenhum programa de videoconferencia identificado.'
        $ressalva.Add('Confirmar por qual sistema sera a audiencia e se ele abre')
    }

    # --- VEREDICTO ----------------------------------------------------------
    Write-Host ''
    if ($bloqueia.Count -gt 0) {
        Write-Host ('  ' + ('=' * 66)) -ForegroundColor Red
        Write-Host '     NAO ENTRE ASSIM NA AUDIENCIA' -ForegroundColor Red
        Write-Host ('  ' + ('=' * 66)) -ForegroundColor Red
        Write-Host ''
        Write-Dest 'Resolver antes de entrar:'
        foreach ($b in $bloqueia) { Write-Falha $b }
        Add-Alerta 'Maquina NAO esta pronta para audiencia.'
    } elseif ($ressalva.Count -gt 0) {
        Write-Host ('  ' + ('=' * 66)) -ForegroundColor Yellow
        Write-Host '     PRONTO, COM RESSALVAS' -ForegroundColor Yellow
        Write-Host ('  ' + ('=' * 66)) -ForegroundColor Yellow
        Write-Host ''
        Write-Info 'A audiencia deve funcionar, mas ajuste o que der:'
        foreach ($r in $ressalva) { Write-Aviso $r }
    } else {
        Write-Host ('  ' + ('=' * 66)) -ForegroundColor Green
        Write-Host '     PRONTO PARA A AUDIENCIA' -ForegroundColor Green
        Write-Host ('  ' + ('=' * 66)) -ForegroundColor Green
        Write-Host ''
        Write-Ok 'Camera, microfone, som e conexao verificados.'
    }

    Write-Host ''
    Write-Info 'Falta a conferencia que nenhum script faz: fale e veja se o'
    Write-Info 'indicador do microfone se mexe, e ouca um som de teste.'

    if (-not $SemInteracao -and -not $SomenteRelatorio) {
        Write-Host ''
        $c = Read-Host '  Abrir a tela de som para testar microfone e volume? (S/N) [S]'
        if (-not $c -or $c -match '^[Ss]') {
            try { Start-Process 'mmsys.cpl' -ErrorAction Stop; Write-Ok 'Tela de som aberta.' }
            catch { try { Start-Process 'control.exe' -ArgumentList 'mmsys.cpl' -ErrorAction SilentlyContinue } catch { } }
            Write-Info 'Na aba Gravacao, fale: a barra ao lado do microfone tem de se mexer.'
            Write-Info 'Na aba Reproducao, botao Testar toca um som em cada caixa.'
        }
    }
    return [long]0
}

function Backup-CertificadoA1 {
    <#
      Exporta o certificado A1 (o que fica guardado no computador) para um
      arquivo .pfx, que e' a unica forma de reinstala-lo depois.

      Por que importa: A1 vive no disco. Se o HD morre, ou o Windows e'
      reinstalado sem exportar antes, o advogado fica sem assinar ate comprar
      outro certificado - dias parado e custo cheio, porque a AC nao reemite.

      A3 (token/cartao) NAO e' exportavel por design: a chave privada nunca
      sai do hardware. Isso e' protecao, nao defeito - a ferramenta detecta e
      explica em vez de falhar sem dizer o motivo.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Listaria os certificados e exportaria os A1 para .pfx.'; return [long]0 }

    Write-Titulo 'BACKUP DO CERTIFICADO DIGITAL (A1)'
    Write-Info 'Certificado A1 fica guardado no computador. Sem uma copia exportada,'
    Write-Info 'perder o disco significa comprar outro certificado.'

    # --- Levantamento -----------------------------------------------------
    Write-Etapa '1/3  Certificados com chave privada nesta maquina'
    $todos = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($loc in @('CurrentUser', 'LocalMachine')) {
        try {
            foreach ($c in @(Get-ChildItem "Cert:\$loc\My" -ErrorAction SilentlyContinue)) {
                if (-not $c.HasPrivateKey) { continue }
                $nome = if ($c.Subject -match 'CN=([^,]+)') { $Matches[1].Trim() } else { $c.Subject }
                # A3 fica em provider de hardware; A1 em provider de software.
                $tipo = 'A1'
                $provider = ''
                try {
                    if ($c.PrivateKey -and $c.PrivateKey.CspKeyContainerInfo) {
                        $provider = $c.PrivateKey.CspKeyContainerInfo.ProviderName
                    } else {
                        $k = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
                        if ($k -and $k.Key) { $provider = $k.Key.Provider.Provider }
                    }
                } catch { }
                if ($provider -match '(?i)(smart ?card|token|etoken|safenet|gemalto|watchdata|feitian|epass|starsign|athena|scard)') { $tipo = 'A3' }
                $todos.Add([PSCustomObject]@{
                    Cert     = $c
                    Nome     = $nome
                    Local    = $loc
                    Tipo     = $tipo
                    Provider = $provider
                    Expira   = $c.NotAfter
                    Venceu   = ($c.NotAfter -lt (Get-Date))
                })
            }
        } catch { }
    }

    if ($todos.Count -eq 0) {
        Write-Aviso 'Nenhum certificado com chave privada encontrado nesta maquina.'
        Write-Info  'Se o cliente usa token (A3), conecte-o e rode de novo - mas A3 nao'
        Write-Info  'e exportavel de qualquer forma.'
        return [long]0
    }

    $i = 1
    $exportaveis = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($t in $todos) {
        $st = if ($t.Venceu) { ' [VENCIDO]' } else { " (vence " + $t.Expira.ToString('dd/MM/yyyy') + ")" }
        if ($t.Tipo -eq 'A3') {
            Write-Host ("     [--] $($t.Nome)$st") -ForegroundColor DarkGray
            Write-Host ("          A3 (token/cartao) - nao pode ser exportado") -ForegroundColor DarkGray
        } else {
            # Certificado do titular traz CPF/CNPJ no nome. Sem isso e' quase
            # sempre certificado tecnico (localhost, servidor, IIS) e nao
            # interessa ao backup do advogado.
            $doc = ''
            if ($t.Cert.Subject -match ':(\d{11})\b') {
                $nn = $Matches[1]
                $doc = 'CPF ' + $nn.Substring(0,3) + '.' + $nn.Substring(3,3) + '.' + $nn.Substring(6,3) + '-' + $nn.Substring(9,2)
            } elseif ($t.Cert.Subject -match ':(\d{14})\b') {
                $nn = $Matches[1]
                $doc = 'CNPJ ' + $nn.Substring(0,2) + '.' + $nn.Substring(2,3) + '.' + $nn.Substring(5,3) + '/' + $nn.Substring(8,4) + '-' + $nn.Substring(12,2)
            }
            $cor = if ($doc) { 'White' } else { 'DarkGray' }
            Write-Host ("     [{0,2}] {1}{2}" -f $i, $t.Nome, $st) -ForegroundColor $cor
            if ($doc) {
                Write-Info ("          $doc   -   A1 em $($t.Local)")
            } else {
                Write-Host ("          sem CPF/CNPJ - certificado tecnico, provavelmente nao e do advogado") -ForegroundColor DarkGray
                Write-Host ("          A1 em $($t.Local)") -ForegroundColor DarkGray
            }
            $t | Add-Member -NotePropertyName Indice -NotePropertyValue $i -Force
            $t | Add-Member -NotePropertyName Documento -NotePropertyValue $doc -Force
            $exportaveis.Add($t)
            $i++
        }
    }

    $qtdA3 = @($todos | Where-Object { $_.Tipo -eq 'A3' }).Count
    if ($qtdA3 -gt 0) {
        Write-Host ''
        Write-Info "$qtdA3 certificado(s) A3 (token) encontrado(s) - nao aparecem na lista"
        Write-Info 'porque a chave privada nunca sai do token. Isso e protecao, nao'
        Write-Info 'defeito: se o token quebrar, a renovacao e feita na Autoridade'
        Write-Info 'Certificadora. Oriente o cliente a guardar bem o token e a senha.'
    }

    if ($exportaveis.Count -eq 0) {
        Write-Host ''
        Write-Ok 'Nao ha certificado A1 para exportar nesta maquina.'
        return [long]0
    }

    if ($SemInteracao) { Write-Aviso 'Modo desatendido: a exportacao precisa de senha.'; return [long]0 }

    # --- Escolha ----------------------------------------------------------
    Write-Etapa '2/3  Qual exportar'
    Write-Host ''
    $sel = (Read-Host '  Numero (ou T para todos, ENTER para cancelar)').Trim()
    $alvos = [System.Collections.Generic.List[PSObject]]::new()
    if ($sel -match '^[Tt]$') { foreach ($e in $exportaveis) { $alvos.Add($e) } }
    elseif ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $exportaveis.Count) {
        $alvos.Add($exportaveis[[int]$sel - 1])
    } else { Write-Info 'Cancelado.'; return [long]0 }

    # --- Senha e destino --------------------------------------------------
    Write-Etapa '3/3  Senha de protecao e destino'
    Write-Host ''
    Write-Falha 'IMPORTANTE - o arquivo .pfx E O CERTIFICADO INTEIRO.'
    Write-Info  'Quem tiver o arquivo e a senha pode assinar como o titular. Trate como'
    Write-Info  'a propria identidade digital dele:'
    Write-Info  '   - NAO deixe o arquivo na maquina do cliente depois de copiar;'
    Write-Info  '   - NAO envie por e-mail nem WhatsApp;'
    Write-Info  '   - entregue em pendrive ou guarde em cofre digital do escritorio;'
    Write-Info  '   - a senha vai junto com a responsabilidade: quem escolhe e o cliente.'
    Write-Host ''
    Write-Info 'A senha sera pedida sempre que o certificado for reinstalado.'
    Write-Info 'Se ela for perdida, o arquivo nao serve para nada.'
    Write-Host ''

    $s1 = Read-Host '  Senha para o arquivo' -AsSecureString
    $s2 = Read-Host '  Repita a senha' -AsSecureString
    $p1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s1))
    $p2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s2))
    if (-not $p1) { Write-Falha 'Senha em branco nao e aceita.'; return [long]0 }
    if ($p1 -ne $p2) { Write-Falha 'As senhas nao conferem.'; return [long]0 }
    if ($p1.Length -lt 8) {
        Write-Aviso 'Senha curta. Este arquivo vale a identidade digital do titular.'
        $c = Read-Host '  Usar assim mesmo? (S/N)'
        if ($c -notmatch '^[Ss]') { Write-Info 'Cancelado.'; return [long]0 }
    }

    Write-Host ''
    $padrao = Join-Path ([Environment]::GetFolderPath('Desktop')) 'CertificadoBackup'
    Write-Info "Pasta de destino (ENTER para $padrao)"
    $destino = (Read-Host '  Destino').Trim().Trim('"')
    if (-not $destino) { $destino = $padrao }
    if (-not (Test-Path -LiteralPath $destino)) {
        try { New-Item -ItemType Directory -Path $destino -Force -ErrorAction Stop | Out-Null }
        catch { Write-Falha "Nao foi possivel criar $destino"; return [long]0 }
    }

    # --- Exportacao -------------------------------------------------------
    Write-Host ''
    $okCount = 0
    foreach ($a in $alvos) {
        $limpo = ($a.Nome -replace '[^A-Za-z0-9 \-]', '').Trim()
        if ($limpo.Length -gt 40) { $limpo = $limpo.Substring(0, 40) }
        if (-not $limpo) { $limpo = 'certificado' }
        $arq = Join-Path $destino ($limpo + '_' + (Get-Date -Format 'yyyy-MM-dd') + '.pfx')

        try {
            Export-PfxCertificate -Cert $a.Cert -FilePath $arq -Password $s1 -ChainOption BuildChain -ErrorAction Stop | Out-Null
            if (Test-Path -LiteralPath $arq) {
                Write-Ok "Exportado: $($a.Nome)"
                Write-Info ("   arquivo: " + $arq)
                $okCount++
            }
        } catch {
            $msg = $_.Exception.Message
            Write-Falha "Nao foi possivel exportar '$($a.Nome)'."
            if ($msg -match '(?i)(not exportable|nao.*export|0x8009000B|key)') {
                Write-Info 'A chave privada esta marcada como NAO EXPORTAVEL.'
                Write-Info 'Isso e definido na instalacao do certificado e nao tem volta:'
                Write-Info 'so a Autoridade Certificadora consegue reemitir. Se este e o'
                Write-Info 'unico certificado do cliente, avise-o de que nao ha copia'
                Write-Info 'possivel e que perder o disco significa comprar outro.'
            } else {
                Write-Info ("Erro: " + $msg)
            }
        }
    }

    if ($okCount -gt 0) {
        Write-Host ''
        Write-Titulo 'BACKUP CONCLUIDO'
        Write-Ok "$okCount certificado(s) exportado(s) em: $destino"
        Write-Host ''
        Write-Falha 'AGORA, ANTES DE SAIR DA MAQUINA:'
        Write-Info  '   1. copie a pasta para pendrive ou para o cofre do escritorio;'
        Write-Info  '   2. APAGUE a pasta desta maquina;'
        Write-Info  '   3. confirme com o cliente que ele guardou a senha.'
        Write-Host ''
        Write-Info 'Teste de verdade: reinstalar o .pfx numa maquina de teste comprova'
        Write-Info 'que a copia presta. Backup nunca testado nao e backup.'
        Add-Alerta "Certificado exportado para $destino - copiar e APAGAR da maquina."
        try { Start-Process 'explorer.exe' -ArgumentList $destino -ErrorAction SilentlyContinue } catch { }
    }
    return [long]0
}

function Export-FichaRede {
    <#
      Ficha tecnica da rede do escritorio, para o Ivan guardar por cliente.
      Somente leitura. Evita redescobrir a topologia a cada visita.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Geraria a ficha tecnica da rede deste escritorio.'; return [long]0 }

    Write-Titulo 'FICHA DA REDE DO ESCRITORIO'
    Write-Info 'Levantamento da rede para voce guardar e consultar nas proximas visitas.'

    $L = [System.Collections.Generic.List[string]]::new()
    $add = { param([string]$t) $L.Add($t) }

    & $add ('=' * 78)
    & $add '                    FICHA TECNICA DA REDE - SuporteADV'
    & $add ('=' * 78)
    & $add ''
    & $add ("Levantado em : " + (Get-Date -Format 'dd/MM/yyyy HH:mm'))
    & $add ("Maquina      : " + $env:COMPUTERNAME)
    & $add ''

    # --- Identificacao ---
    Write-Etapa '1/6  Identificacao'
    & $add ('-' * 78)
    & $add 'ESTA MAQUINA'
    & $add ('-' * 78)
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    & $add ("  Nome           : " + $env:COMPUTERNAME)
    if ($cs) {
        & $add ("  Fabricante     : $($cs.Manufacturer) $($cs.Model)")
        & $add ("  Memoria        : " + [math]::Round($cs.TotalPhysicalMemory/1GB,1) + " GB")
        if ($cs.PartOfDomain) { & $add ("  Dominio        : " + $cs.Domain) }
        else { & $add ("  Grupo trabalho : " + $cs.Workgroup) }
    }
    if ($os) { & $add ("  Sistema        : $($os.Caption) build $($os.BuildNumber)") }
    Write-Ok $env:COMPUTERNAME

    # --- Rede ---
    Write-Etapa '2/6  Conexao de rede'
    & $add ''
    & $add ('-' * 78)
    & $add 'REDE'
    & $add ('-' * 78)
    foreach ($c in @(Get-ConexoesReais | Where-Object { $_.Vale })) {
        $faixa = Get-FaixaRede -IP $c.IP -Prefixo $c.Prefixo
        $tipo = 'cabo'
        try {
            $ad = Get-NetAdapter -InterfaceIndex $c.Indice -ErrorAction SilentlyContinue
            if ($ad -and ($ad.MediaType -match '802.11' -or $ad.InterfaceDescription -match '(?i)(wi-?fi|wireless)')) { $tipo = 'Wi-Fi' }
        } catch { }
        & $add ("  Conexao        : $($c.Alias)  ($tipo)")
        & $add ("  FAIXA DA REDE  : $faixa      <<< tem de ser igual em todas as maquinas")
        & $add ("  GATEWAY        : $($c.Gateway)      <<< tem de ser igual em todas")
        & $add ("  IP desta maq.  : $($c.IP)  (" + $(if ($c.Origem -eq 'Manual') { 'FIXO' } else { 'DHCP - risco de mudar' }) + ")")
        & $add ("  DNS            : " + $(if ($c.DNS.Count) { $c.DNS -join ', ' } else { '-' }))
        Write-Ok "$($c.Alias): $faixa via $($c.Gateway)"
    }
    $wifi = Get-InfoWiFi
    if ($wifi['SSID']) {
        & $add ("  Rede Wi-Fi     : " + $wifi['SSID'] + $(if ($wifi['Sinal']) { "   sinal " + $wifi['Sinal'] } else { '' }))
    }

    # --- Compartilhamentos ---
    Write-Etapa '3/6  Pastas compartilhadas'
    & $add ''
    & $add ('-' * 78)
    & $add 'PASTAS COMPARTILHADAS NESTA MAQUINA'
    & $add ('-' * 78)
    $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\$$' })
    if ($shares.Count -eq 0) {
        & $add '  (nenhuma - esta maquina nao e servidor de arquivos)'
        Write-Info 'Nenhuma'
    } else {
        foreach ($s in $shares) {
            & $add ("  \\$env:COMPUTERNAME\$($s.Name)")
            & $add ("     pasta real : " + $s.Path)
            try {
                foreach ($a in @(Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue)) {
                    & $add ("     acesso     : $($a.AccountName) = $($a.AccessRight)")
                }
            } catch { }
            try {
                $t = [long](Get-ChildItem -LiteralPath $s.Path -Recurse -File -Force -ErrorAction SilentlyContinue |
                            Measure-Object -Property Length -Sum).Sum
                & $add ("     tamanho    : " + (Format-Tamanho $t))
            } catch { }
            Write-Ok "\\$env:COMPUTERNAME\$($s.Name)"
        }
    }

    # --- Unidades mapeadas ---
    Write-Etapa '4/6  Unidades de rede'
    & $add ''
    & $add ('-' * 78)
    & $add 'UNIDADES DE REDE MAPEADAS NESTA MAQUINA'
    & $add ('-' * 78)
    $map = @(Get-CimInstance Win32_NetworkConnection -ErrorAction SilentlyContinue)
    if ($map.Count -eq 0) { & $add '  (nenhuma)'; Write-Info 'Nenhuma' }
    else {
        foreach ($m in $map) {
            & $add ("  $($m.LocalName)  ->  $($m.RemoteName)   [$($m.ConnectionState)]")
            Write-Ok "$($m.LocalName) -> $($m.RemoteName)"
        }
    }

    # --- Quem esta na rede ---
    Write-Etapa '5/6  Outros aparelhos na rede'
    & $add ''
    & $add ('-' * 78)
    & $add 'APARELHOS VISTOS NA REDE'
    & $add ('-' * 78)
    & $add '  (tabela ARP - aparelhos que trocaram dados com esta maquina)'
    $vistos = 0
    try {
        foreach ($n in @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                         Where-Object { $_.State -in @('Reachable','Stale') -and $_.IPAddress -notlike '169.254.*' -and
                                        $_.IPAddress -notlike '224.*' -and $_.IPAddress -notlike '239.*' -and
                                        $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' })) {
            $nome = ''
            try { $nome = ([System.Net.Dns]::GetHostEntry($n.IPAddress)).HostName } catch { }
            & $add ("  $($n.IPAddress.PadRight(16))  $($n.LinkLayerAddress)  $nome")
            $vistos++
        }
    } catch { }
    if ($vistos -eq 0) { & $add '  (nenhum registrado no momento)' }
    Write-Ok "$vistos aparelho(s)"

    # --- Backups ---
    Write-Etapa '6/6  Backup e protecoes'
    & $add ''
    & $add ('-' * 78)
    & $add 'BACKUP E PROTECOES'
    & $add ('-' * 78)
    $tb = @(Get-ScheduledTask -TaskPath '\SuporteADV\' -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like 'Backup*' })
    if ($tb.Count -eq 0) {
        & $add '  BACKUP: NAO CONFIGURADO NESTA MAQUINA   <<< risco'
        Write-Falha 'Sem backup configurado'
        Add-Alerta 'Servidor sem backup configurado.'
    } else {
        foreach ($t in $tb) {
            $inf = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
            & $add ("  BACKUP: $($t.TaskName)")
            & $add ("     descricao : " + $t.Description)
            if ($inf) {
                & $add ("     ultima    : " + $(if ($inf.LastRunTime -and $inf.LastRunTime.Year -gt 1999) { $inf.LastRunTime.ToString('dd/MM/yyyy HH:mm') } else { 'nunca' }) +
                        "   resultado: " + $(if ($inf.LastTaskResult -eq 0) { 'OK' } else { $inf.LastTaskResult }))
            }
            Write-Ok $t.TaskName
        }
    }
    $ips = @(Get-ConexoesReais | Where-Object { $_.Vale -and $_.Origem -ne 'Manual' })
    if ($ips.Count -gt 0 -and $shares.Count -gt 0) {
        & $add '  ATENCAO: servidor com IP automatico - se mudar, as unidades quebram.'
    }
    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($smb1 -and $smb1.State -eq 'Enabled') { & $add '  ATENCAO: SMB1 habilitado - risco de seguranca conhecido.' }
    } catch { }

    # --- Falhas do proprio toolkit ---
    # O cliente raramente avisa que uma ferramenta deu erro. Aqui elas
    # aparecem, para o Ivan descobrir na visita em vez de nunca.
    $arqFalhas = 'C:\ProgramData\SuporteTI\falhas.txt'
    if (Test-Path -LiteralPath $arqFalhas) {
        $recentes = @(Get-Content -LiteralPath $arqFalhas -ErrorAction SilentlyContinue |
                      Select-Object -Last 15)
        if ($recentes.Count -gt 0) {
            & $add ''
            & $add ('-' * 78)
            & $add 'FALHAS REGISTRADAS DAS FERRAMENTAS'
            & $add ('-' * 78)
            foreach ($r in $recentes) { & $add ("  " + $r) }
            & $add '  (historico completo em C:\ProgramData\SuporteTI\falhas.txt)'
            Write-Aviso "$($recentes.Count) falha(s) de ferramenta registrada(s) nesta maquina."
        }
    }

    & $add ''
    & $add ('=' * 78)
    & $add '  Rode esta ficha em CADA computador do escritorio e guarde junto.'
    & $add '  A faixa da rede e o gateway precisam ser iguais em todos.'
    & $add ('=' * 78)

    # --- Salvar ---
    $nome = 'RedeEscritorio_' + $env:COMPUTERNAME + '_' + (Get-Date -Format 'yyyy-MM-dd') + '.txt'
    $destino = Join-Path ([Environment]::GetFolderPath('Desktop')) $nome
    try {
        [System.IO.File]::WriteAllLines($destino, $L.ToArray(), (New-Object System.Text.UTF8Encoding($true)))
        Write-Host ''
        Write-Ok "Ficha salva: $destino"
        try { Start-Process 'notepad.exe' -ArgumentList $destino -ErrorAction SilentlyContinue } catch { }
        Write-Info 'Guarde uma copia na sua pasta do cliente. Na proxima visita voce ja'
        Write-Info 'chega sabendo a topologia, sem redescobrir tudo.'
    } catch {
        Write-Falha "Nao foi possivel salvar: $($_.Exception.Message)"
        foreach ($l in $L) { Write-Host "     $l" -ForegroundColor Gray }
    }
    return [long]0
}

function Set-MonitoramentoRede {
    <#
      Verificacao agendada que registra quando algo sai do lugar. Nao envia
      e-mail nem depende de servico externo: grava um historico local que o
      Ivan le quando chega, e deixa um alerta visivel na Area de Trabalho
      quando encontra problema.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Configuraria o monitoramento agendado do servidor.'; return [long]0 }

    Write-Titulo 'MONITORAMENTO DO SERVIDOR'
    Write-Info 'Verificacao automatica que registra quando algo sai do lugar, para voce'
    Write-Info 'saber antes do cliente ligar.'

    if ($SemInteracao) { Write-Aviso 'Modo desatendido: esta ferramenta precisa de interacao.'; return [long]0 }

    $tarefa = Get-ScheduledTask -TaskName 'Monitor SuporteADV' -TaskPath '\SuporteADV\' -ErrorAction SilentlyContinue
    if ($tarefa) {
        $inf = Get-ScheduledTaskInfo -TaskName 'Monitor SuporteADV' -TaskPath '\SuporteADV\' -ErrorAction SilentlyContinue
        Write-Etapa 'Monitoramento ja configurado'
        Write-Ok ("Ultima verificacao: " + $(if ($inf -and $inf.LastRunTime -and $inf.LastRunTime.Year -gt 1999) { $inf.LastRunTime.ToString('dd/MM/yyyy HH:mm') } else { 'nunca' }))
        $hist = 'C:\ProgramData\SuporteTI\Monitor\historico.txt'
        if (Test-Path -LiteralPath $hist) {
            Write-Host ''
            Write-Dest 'Ultimos registros:'
            Get-Content -LiteralPath $hist -Tail 15 -ErrorAction SilentlyContinue | ForEach-Object { Write-Info ("   " + $_) }
        }
        Write-Host ''
        Write-Host '     [1] Verificar agora' -ForegroundColor White
        Write-Host '     [2] Remover o monitoramento' -ForegroundColor White
        Write-Host '     [0] Sair' -ForegroundColor DarkGray
        $o = (Read-Host '  Opcao').Trim()
        if ($o -eq '1') {
            Start-ScheduledTask -TaskName 'Monitor SuporteADV' -TaskPath '\SuporteADV\' -ErrorAction SilentlyContinue
            Write-Ok 'Verificacao iniciada. Veja o historico em instantes.'
        } elseif ($o -eq '2') {
            Unregister-ScheduledTask -TaskName 'Monitor SuporteADV' -TaskPath '\SuporteADV\' -Confirm:$false -ErrorAction SilentlyContinue
            Write-Ok 'Monitoramento removido.'
        }
        return [long]0
    }

    Write-Host ''
    Write-Info 'O que sera verificado a cada execucao:'
    Write-Info '   - a maquina continua com o mesmo IP;'
    Write-Info '   - o perfil da rede continua privado;'
    Write-Info '   - os servicos de compartilhamento continuam rodando;'
    Write-Info '   - as pastas compartilhadas continuam existindo;'
    Write-Info '   - o espaco em disco;'
    Write-Info '   - a saude do disco (SMART);'
    Write-Info '   - se o backup rodou e deu certo.'
    Write-Host ''
    Write-Info 'Quando algo estiver errado, grava no historico e cria um arquivo de'
    Write-Info 'alerta na Area de Trabalho, visivel para quem usa a maquina.'
    Write-Host ''
    $c = Read-Host '  Configurar o monitoramento? (S/N) [S]'
    if ($c -and $c -notmatch '^[Ss]') { Write-Info 'Cancelado.'; return [long]0 }

    $pasta = 'C:\ProgramData\SuporteTI\Monitor'
    if (-not (Test-Path -LiteralPath $pasta)) { New-Item -ItemType Directory -Path $pasta -Force -ErrorAction SilentlyContinue | Out-Null }
    $scriptPath = Join-Path $pasta 'monitor.ps1'

    $script = @'
# Monitor do servidor - gerado pelo SuporteADV (suporte.adv.br)
# Registra o estado e alerta quando algo sai do lugar.
$ErrorActionPreference = 'SilentlyContinue'
$pasta   = 'C:\ProgramData\SuporteTI\Monitor'
$hist    = Join-Path $pasta 'historico.txt'
$estado  = Join-Path $pasta 'estado.xml'
$agora   = Get-Date -Format 'dd/MM/yyyy HH:mm'
$probs   = New-Object System.Collections.Generic.List[string]

# IP e faixa
$conf = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
$ipAtual = if ($conf) { (@($conf.IPv4Address)[0]).IPAddress } else { '' }
$gwAtual = if ($conf) { (@($conf.IPv4DefaultGateway)[0]).NextHop } else { '' }
if (-not $ipAtual) { $probs.Add('SEM CONEXAO DE REDE') }

# Perfil
foreach ($p in @(Get-NetConnectionProfile)) {
    if ($p.NetworkCategory -eq 'Public') { $probs.Add("Perfil de rede PUBLICO em '$($p.Name)'") }
}

# Servicos
foreach ($s in @('LanmanServer','LanmanWorkstation')) {
    $sv = Get-Service -Name $s
    if ($sv -and $sv.Status -ne 'Running') { $probs.Add("Servico $s parado") }
}

# Compartilhamentos
$shares = @(Get-SmbShare | Where-Object { $_.Name -notmatch '\$$' })
foreach ($sh in $shares) {
    if (-not (Test-Path -LiteralPath $sh.Path)) { $probs.Add("Pasta compartilhada sumiu: $($sh.Path)") }
}

# Disco
foreach ($v in @(Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter })) {
    if ($v.Size -gt 0) {
        $pct = [math]::Round(($v.SizeRemaining / $v.Size) * 100)
        if ($pct -lt 10) { $probs.Add("Disco $($v.DriveLetter): com apenas $pct% livre") }
    }
}

# SMART
foreach ($d in @(Get-CimInstance -ClassName MSStorageDriver_FailurePredictStatus -Namespace root\wmi)) {
    if ($d.PredictFailure) { $probs.Add('DISCO PREVENDO FALHA (SMART) - backup e troca urgentes') }
}

# Backup
$tb = @(Get-ScheduledTask -TaskPath '\SuporteADV\' | Where-Object { $_.TaskName -like 'Backup*' })
if ($shares.Count -gt 0 -and $tb.Count -eq 0) { $probs.Add('Servidor sem backup configurado') }
foreach ($t in $tb) {
    $i = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath
    if ($i) {
        if ($i.LastTaskResult -ne 0 -and $i.LastTaskResult -ne 267009) { $probs.Add("Backup '$($t.TaskName)' terminou com erro $($i.LastTaskResult)") }
        if ($i.LastRunTime -and $i.LastRunTime.Year -gt 1999 -and ((Get-Date) - $i.LastRunTime).TotalDays -gt 3) {
            $probs.Add("Backup '$($t.TaskName)' nao roda ha $([math]::Round(((Get-Date) - $i.LastRunTime).TotalDays)) dias")
        }
    }
}

# Comparar com a execucao anterior
if (Test-Path -LiteralPath $estado) {
    $ant = Import-Clixml -LiteralPath $estado
    if ($ant.IP -and $ipAtual -and $ant.IP -ne $ipAtual) { $probs.Add("O IP MUDOU: era $($ant.IP), agora e $ipAtual - unidades de rede podem ter quebrado") }
    if ($ant.GW -and $gwAtual -and $ant.GW -ne $gwAtual) { $probs.Add("A REDE MUDOU: gateway era $($ant.GW), agora e $gwAtual") }
    foreach ($nm in @($ant.Shares)) {
        if ($shares.Name -notcontains $nm) { $probs.Add("Compartilhamento '$nm' nao existe mais") }
    }
}
@{ IP = $ipAtual; GW = $gwAtual; Shares = @($shares.Name); Quando = (Get-Date) } | Export-Clixml -LiteralPath $estado

# Registrar
if ($probs.Count -eq 0) {
    Add-Content -LiteralPath $hist -Value "$agora  OK  ip=$ipAtual  compartilhamentos=$($shares.Count)"
} else {
    Add-Content -LiteralPath $hist -Value "$agora  PROBLEMA:"
    foreach ($p in $probs) { Add-Content -LiteralPath $hist -Value "            - $p" }
    # Alerta visivel para quem usa a maquina
    $aviso = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'ATENCAO - AVISAR O SUPORTE.txt'
    $txt = New-Object System.Collections.Generic.List[string]
    $txt.Add('=============================================================')
    $txt.Add('  AVISO DO SISTEMA DE MONITORAMENTO - suporte.adv.br')
    $txt.Add('=============================================================')
    $txt.Add('')
    $txt.Add("Verificado em: $agora")
    $txt.Add('')
    $txt.Add('Foram encontrados os seguintes pontos de atencao:')
    $txt.Add('')
    foreach ($p in $probs) { $txt.Add("   - $p") }
    $txt.Add('')
    $txt.Add('Entre em contato com o suporte tecnico e mostre este arquivo.')
    $txt.Add('')
    [System.IO.File]::WriteAllLines($aviso, $txt.ToArray(), (New-Object System.Text.UTF8Encoding($true)))
}

# Nao deixar o historico crescer sem fim
if (Test-Path -LiteralPath $hist) {
    $linhas = @(Get-Content -LiteralPath $hist)
    if ($linhas.Count -gt 2000) { $linhas | Select-Object -Last 1000 | Set-Content -LiteralPath $hist }
}
'@

    try {
        [System.IO.File]::WriteAllText($scriptPath, $script, (New-Object System.Text.UTF8Encoding($false)))
        Write-Ok "Rotina de monitoramento criada: $scriptPath"
    } catch {
        Write-Falha "Nao foi possivel criar: $($_.Exception.Message)"
        return [long]0
    }

    try {
        $acao = New-ScheduledTaskAction -Execute 'powershell.exe' `
                  -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
        # Ao ligar e a cada 4 horas: pega o problema logo depois que ele surge
        $g1 = New-ScheduledTaskTrigger -AtStartup
        $g2 = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddHours(8) `
                -RepetitionInterval (New-TimeSpan -Hours 4) -RepetitionDuration (New-TimeSpan -Days 3650)
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $config = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -MultipleInstances IgnoreNew

        Register-ScheduledTask -TaskName 'Monitor SuporteADV' -TaskPath '\SuporteADV\' -Action $acao `
            -Trigger $g1, $g2 -Principal $principal -Settings $config `
            -Description 'Monitoramento do servidor - SuporteADV' -ErrorAction Stop | Out-Null
        Write-Ok 'Agendado: ao ligar a maquina e a cada 4 horas.'
    } catch {
        Write-Falha "Nao foi possivel agendar: $($_.Exception.Message)"
        return [long]0
    }

    Write-Etapa 'Executando a primeira verificacao...'
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        $hist = Join-Path $pasta 'historico.txt'
        if (Test-Path -LiteralPath $hist) {
            Write-Host ''
            Write-Dest 'Resultado:'
            Get-Content -LiteralPath $hist -Tail 12 -ErrorAction SilentlyContinue | ForEach-Object { Write-Info ("   " + $_) }
        }
    } catch { Write-Aviso "Primeira execucao: $($_.Exception.Message)" }

    Write-Host ''
    Write-Titulo 'MONITORAMENTO ATIVO'
    Write-Info ("Historico : " + (Join-Path $pasta 'historico.txt'))
    Write-Info 'Quando encontrar problema, alem de registrar, cria o arquivo'
    Write-Info '"ATENCAO - AVISAR O SUPORTE.txt" na Area de Trabalho de todos.'
    Write-Host ''
    Write-Info 'Ao chegar no cliente, rode esta opcao para ver o historico - ele mostra'
    Write-Info 'o que aconteceu entre as visitas.'
    Add-Alerta 'Monitoramento do servidor ativado.'
    return [long]0
}

function Set-BackupCompartilhado {
    <#
      Copia automatica da pasta compartilhada para outro destino.

      Usa ROBOCOPY em modo espelho com historico de versoes por data: o
      robocopy vem no Windows, e testado ha decadas e sobrevive a arquivo
      aberto e caminho longo melhor que qualquer script proprio.

      NAO e substituto de backup em nuvem nem de fita. E' a copia local que
      salva o escritorio quando o disco do servidor morre - que e o cenario
      real do dia a dia.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Configuraria o backup automatico da pasta compartilhada.'; return [long]0 }

    Write-Titulo 'BACKUP DA PASTA COMPARTILHADA'
    Write-Info 'Compartilhar pasta NAO e backup: os arquivos estao num disco so.'
    Write-Info 'Se aquele disco falhar, o escritorio perde os processos.'

    if ($SemInteracao) { Write-Aviso 'Modo desatendido: esta ferramenta precisa de interacao.'; return [long]0 }

    # --- Backups ja configurados -----------------------------------------
    $tarefas = @(Get-ScheduledTask -TaskPath '\SuporteADV\' -ErrorAction SilentlyContinue |
                 Where-Object { $_.TaskName -like 'Backup*' })
    if ($tarefas.Count -gt 0) {
        Write-Etapa 'Backups ja configurados nesta maquina'
        foreach ($t in $tarefas) {
            $inf = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
            Write-Ok $t.TaskName
            if ($inf) {
                Write-Info ("   ultima execucao : " + $(if ($inf.LastRunTime -and $inf.LastRunTime.Year -gt 1999) { $inf.LastRunTime.ToString('dd/MM/yyyy HH:mm') } else { 'nunca' }))
                Write-Info ("   resultado       : " + $(if ($inf.LastTaskResult -eq 0) { 'OK' } elseif ($inf.LastTaskResult -eq 267009) { 'em execucao' } else { "codigo $($inf.LastTaskResult)" }))
                Write-Info ("   proxima         : " + $(if ($inf.NextRunTime) { $inf.NextRunTime.ToString('dd/MM/yyyy HH:mm') } else { '-' }))
            }
        }
        Write-Host ''
        Write-Host '     [1] Criar outro backup' -ForegroundColor White
        Write-Host '     [2] Executar um backup agora' -ForegroundColor White
        Write-Host '     [3] Remover um backup configurado' -ForegroundColor White
        Write-Host '     [0] Sair' -ForegroundColor DarkGray
        Write-Host ''
        $op = (Read-Host '  Opcao').Trim()

        if ($op -eq '2') {
            $i = 1
            foreach ($t in $tarefas) { Write-Host ("     [$i] $($t.TaskName)") -ForegroundColor White; $i++ }
            $s = (Read-Host '  Numero').Trim()
            if ($s -match '^\d+$' -and [int]$s -ge 1 -and [int]$s -le $tarefas.Count) {
                $alvo = $tarefas[[int]$s - 1]
                Start-ScheduledTask -TaskName $alvo.TaskName -TaskPath $alvo.TaskPath -ErrorAction SilentlyContinue
                Write-Ok 'Backup iniciado. Ele roda em segundo plano.'
                Write-Info 'Acompanhe pelo relatorio na pasta de destino.'
            }
            return [long]0
        }
        if ($op -eq '3') {
            $i = 1
            foreach ($t in $tarefas) { Write-Host ("     [$i] $($t.TaskName)") -ForegroundColor White; $i++ }
            $s = (Read-Host '  Numero').Trim()
            if ($s -match '^\d+$' -and [int]$s -ge 1 -and [int]$s -le $tarefas.Count) {
                $alvo = $tarefas[[int]$s - 1]
                Write-Aviso 'Isso remove o agendamento. Os arquivos ja copiados permanecem no destino.'
                $c = Read-Host '  Confirma? (S/N)'
                if ($c -match '^[Ss]') {
                    Unregister-ScheduledTask -TaskName $alvo.TaskName -TaskPath $alvo.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
                    Write-Ok 'Agendamento removido.'
                }
            }
            return [long]0
        }
        if ($op -ne '1') { return [long]0 }
    }

    # --- Origem ------------------------------------------------------------
    Write-Etapa '1/4  O que sera copiado'
    $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\$$' })
    $origem = ''
    if ($shares.Count -gt 0) {
        Write-Info 'Pastas compartilhadas nesta maquina:'
        $i = 1
        foreach ($s in $shares) { Write-Host ("     [$i] $($s.Path)   (compartilhada como '$($s.Name)')") -ForegroundColor White; $i++ }
        Write-Host ''
        $s = (Read-Host '  Numero, ou digite outro caminho').Trim().Trim('"')
        if ($s -match '^\d+$' -and [int]$s -ge 1 -and [int]$s -le $shares.Count) { $origem = $shares[[int]$s - 1].Path }
        elseif ($s) { $origem = $s }
    } else {
        Write-Info 'Nenhuma pasta compartilhada. Informe a pasta a proteger.'
        $origem = (Read-Host '  Pasta de origem').Trim().Trim('"')
    }
    if (-not $origem) { Write-Info 'Cancelado.'; return [long]0 }
    if (-not (Test-Path -LiteralPath $origem)) { Write-Falha "A pasta $origem nao existe."; return [long]0 }

    $tam = 0
    try {
        Write-Info 'Medindo o tamanho da pasta...'
        $tam = [long](Get-ChildItem -LiteralPath $origem -Recurse -File -Force -ErrorAction SilentlyContinue |
                      Measure-Object -Property Length -Sum).Sum
        Write-Ok ("Origem: $origem   (" + (Format-Tamanho $tam) + ")")
    } catch { Write-Ok "Origem: $origem" }

    # --- Destino -----------------------------------------------------------
    Write-Etapa '2/4  Para onde copiar'
    Write-Info 'O destino precisa ser OUTRO disco fisico, ou outra maquina.'
    Write-Aviso 'Copiar para outra pasta do MESMO disco nao protege de nada:'
    Write-Info  'se o disco morre, morrem as duas copias.'
    Write-Host ''

    $letraOrigem = ''
    if ($origem -match '^([A-Za-z]):') { $letraOrigem = $Matches[1].ToUpper() }

    $discos = @(Get-Volume -ErrorAction SilentlyContinue |
                Where-Object { $_.DriveLetter -and $_.DriveType -in @('Fixed','Removable') -and
                               $_.DriveLetter -ne $letraOrigem -and $_.SizeRemaining -gt $tam })
    if ($discos.Count -gt 0) {
        Write-Info 'Discos com espaco suficiente (fora o de origem):'
        foreach ($d in $discos) {
            $rot = if ($d.FileSystemLabel) { $d.FileSystemLabel } else { 'sem rotulo' }
            $tipo = if ($d.DriveType -eq 'Removable') { 'USB/externo' } else { 'interno' }
            Write-Host ("     $($d.DriveLetter):  $([math]::Round($d.SizeRemaining/1GB,1)) GB livres  ($rot, $tipo)") -ForegroundColor White
        }
    } else {
        Write-Aviso 'Nenhum outro disco com espaco suficiente foi encontrado.'
    }
    Write-Host ''
    Write-Info 'Informe a pasta de destino. Pode ser disco externo (E:\Backup) ou'
    Write-Info 'outra maquina da rede (\\OUTROPC\Backup).'
    $destino = (Read-Host '  Destino').Trim().Trim('"')
    if (-not $destino) { Write-Info 'Cancelado.'; return [long]0 }

    # Destino no mesmo disco = falsa sensacao de seguranca
    if ($destino -match '^([A-Za-z]):' -and $Matches[1].ToUpper() -eq $letraOrigem) {
        Write-Host ''
        Write-Falha 'O destino esta NO MESMO DISCO da origem.'
        Write-Info  'Isso protege contra apagar sem querer, mas NAO contra o disco falhar,'
        Write-Info  'que e o risco principal. Use outro disco ou outra maquina.'
        $c = Read-Host '  Continuar assim mesmo? (S/N)'
        if ($c -notmatch '^[Ss]') { Write-Info 'Cancelado.'; return [long]0 }
    }
    # Nao deixar o destino dentro da origem (copia recursiva infinita)
    if ($destino.TrimEnd('\').ToLower().StartsWith($origem.TrimEnd('\').ToLower() + '\')) {
        Write-Falha 'O destino esta DENTRO da pasta de origem. Isso faria a copia se copiar.'
        return [long]0
    }

    if (-not (Test-Path -LiteralPath $destino)) {
        $c = Read-Host '  A pasta de destino nao existe. Criar? (S/N) [S]'
        if (-not $c -or $c -match '^[Ss]') {
            try { New-Item -ItemType Directory -Path $destino -Force -ErrorAction Stop | Out-Null; Write-Ok 'Pasta de destino criada.' }
            catch { Write-Falha "Nao foi possivel criar: $($_.Exception.Message)"; return [long]0 }
        } else { return [long]0 }
    }

    # --- Quando -------------------------------------------------------------
    Write-Etapa '3/4  Quando executar'
    Write-Host ''
    Write-Host '     [1] Todo dia (recomendado para escritorio)' -ForegroundColor White
    Write-Host '     [2] De segunda a sexta' -ForegroundColor White
    Write-Host '     [3] Uma vez por semana' -ForegroundColor White
    Write-Host '     [4] Somente quando eu mandar (sem agendamento)' -ForegroundColor White
    Write-Host ''
    $quando = (Read-Host '  Opcao [1]').Trim()
    if (-not $quando) { $quando = '1' }

    $hora = '12:30'
    if ($quando -ne '4') {
        Write-Host ''
        Write-Info 'Escolha um horario em que o escritorio esteja parado, mas a maquina'
        Write-Info 'LIGADA - horario de almoco costuma funcionar melhor que de madrugada,'
        Write-Info 'porque de madrugada o servidor pode estar desligado.'
        $h = (Read-Host "  Horario (HH:MM) [$hora]").Trim()
        if ($h) {
            if ($h -match '^([01]?\d|2[0-3]):([0-5]\d)$') { $hora = $h }
            else { Write-Aviso "Horario invalido. Usando $hora." }
        }
    }

    # --- Monta o script de backup -----------------------------------------
    Write-Etapa '4/4  Criando o backup'

    $pastaScript = 'C:\ProgramData\SuporteTI\Backup'
    if (-not (Test-Path -LiteralPath $pastaScript)) {
        New-Item -ItemType Directory -Path $pastaScript -Force -ErrorAction SilentlyContinue | Out-Null
    }
    $idBackup = ($destino -replace '[^A-Za-z0-9]', '')
    if ($idBackup.Length -gt 20) { $idBackup = $idBackup.Substring(0, 20) }
    $scriptPath = Join-Path $pastaScript "backup_$idBackup.cmd"

    # /MIR espelha (inclui apagar no destino o que sumiu da origem).
    # /XF exclui o proprio relatorio: sem isso o /MIR tenta apaga-lo por ele
    #     nao existir na origem - e apagaria o historico do backup.
    # /R:2 /W:5 nao fica horas tentando um arquivo aberto pelo usuario.
    # /Z retoma copia grande do ponto onde parou.
    $nomeLog = '_relatorio_backup.txt'
    $conteudo = @"
@echo off
rem Backup automatico gerado pelo SuporteADV - suporte.adv.br
rem Origem : $origem
rem Destino: $destino
setlocal
set LOG=$destino\$nomeLog
echo. >> "%LOG%"
echo ================================================== >> "%LOG%"
echo Backup iniciado em %date% %time% >> "%LOG%"
robocopy "$origem" "$destino" /MIR /XF "$nomeLog" /R:2 /W:5 /Z /NP /NDL /TEE /LOG+:"%LOG%"
set CODIGO=%ERRORLEVEL%
echo Codigo de retorno: %CODIGO% >> "%LOG%"
if %CODIGO% LSS 8 (
  echo RESULTADO: OK - backup concluido em %date% %time% >> "%LOG%"
) else (
  echo RESULTADO: FALHA - verificar o log acima >> "%LOG%"
)
echo ================================================== >> "%LOG%"
endlocal
exit /b 0
"@
    try {
        [System.IO.File]::WriteAllText($scriptPath, $conteudo, (New-Object System.Text.UTF8Encoding($false)))
        Write-Ok "Rotina de backup criada: $scriptPath"
    } catch {
        Write-Falha "Nao foi possivel criar a rotina: $($_.Exception.Message)"
        return [long]0
    }

    # --- Agendamento --------------------------------------------------------
    if ($quando -ne '4') {
        $nomeTarefa = "Backup $idBackup"
        try {
            Unregister-ScheduledTask -TaskName $nomeTarefa -TaskPath '\SuporteADV\' -Confirm:$false -ErrorAction SilentlyContinue

            $acao = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c `"$scriptPath`""
            $gatilho = switch ($quando) {
                '2' { New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday,Tuesday,Wednesday,Thursday,Friday -At $hora }
                '3' { New-ScheduledTaskTrigger -Weekly -DaysOfWeek Friday -At $hora }
                default { New-ScheduledTaskTrigger -Daily -At $hora }
            }
            # SYSTEM roda sem ninguem logado; StartWhenAvailable recupera a
            # execucao perdida quando a maquina estava desligada na hora.
            $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $config = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd `
                        -ExecutionTimeLimit (New-TimeSpan -Hours 6) -MultipleInstances IgnoreNew

            Register-ScheduledTask -TaskName $nomeTarefa -TaskPath '\SuporteADV\' -Action $acao `
                -Trigger $gatilho -Principal $principal -Settings $config `
                -Description "Backup de $origem para $destino - SuporteADV" -ErrorAction Stop | Out-Null

            $desc = switch ($quando) { '2' { 'de segunda a sexta' } '3' { 'toda sexta-feira' } default { 'todo dia' } }
            Write-Ok "Agendado: $desc as $hora."
            Write-Info 'Roda mesmo sem ninguem logado. Se a maquina estiver desligada na'
            Write-Info 'hora marcada, ele executa assim que ela ligar.'
        } catch {
            Write-Falha "Nao foi possivel agendar: $($_.Exception.Message)"
            Write-Info  "A rotina existe em $scriptPath e pode ser executada a mao."
        }
    }

    # --- Primeira execucao ---------------------------------------------------
    Write-Host ''
    Write-Info 'A primeira copia leva mais tempo, porque copia tudo. As seguintes'
    Write-Info 'copiam apenas o que mudou.'
    $c = Read-Host '  Executar o primeiro backup agora? (S/N) [S]'
    if (-not $c -or $c -match '^[Ss]') {
        Write-Etapa 'Copiando... isso pode demorar.'
        $inicio = Get-Date
        & cmd.exe /c "`"$scriptPath`"" | Out-Null
        $dur = [math]::Round(((Get-Date) - $inicio).TotalMinutes, 1)
        $log = Join-Path $destino '_relatorio_backup.txt'
        $ok = $false
        if (Test-Path -LiteralPath $log) {
            $ult = @(Get-Content -LiteralPath $log -Tail 12 -ErrorAction SilentlyContinue)
            if (($ult -join ' ') -match 'RESULTADO: OK') { $ok = $true }
        }
        if ($ok) {
            Write-Ok "Backup concluido em $dur minuto(s)."
            try {
                $tamDest = [long](Get-ChildItem -LiteralPath $destino -Recurse -File -Force -ErrorAction SilentlyContinue |
                                  Measure-Object -Property Length -Sum).Sum
                Write-Ok ("Destino agora tem " + (Format-Tamanho $tamDest) + ".")
            } catch { }
        } else {
            Write-Aviso "Backup terminou em $dur minuto(s), mas com avisos."
            Write-Info  "Confira o relatorio: $log"
        }
    }

    Write-Host ''
    Write-Titulo 'BACKUP CONFIGURADO'
    Write-Info ("Origem  : " + $origem)
    Write-Info ("Destino : " + $destino)
    Write-Info ("Relatorio: " + (Join-Path $destino '_relatorio_backup.txt'))
    Write-Host ''
    Write-Aviso 'Limites deste backup - saiba o que ele NAO protege:'
    Write-Info  '  - E um espelho: arquivo apagado na origem some do destino na proxima'
    Write-Info  '    copia. Nao recupera algo apagado semana passada.'
    Write-Info  '  - Se o destino for disco interno na mesma maquina, incendio, roubo ou'
    Write-Info  '    ransomware levam os dois.'
    Write-Info  '  - Para o escritorio ficar realmente coberto, some a isto uma copia'
    Write-Info  '    FORA do local: nuvem, ou disco externo que sai do escritorio.'
    Write-Host ''
    Write-Info 'Teste de verdade: uma vez por mes, abra um arquivo direto do destino.'
    Write-Info 'Backup que nunca foi restaurado nao e backup comprovado.'
    Add-Alerta "Backup configurado: $origem -> $destino"
    return [long]0
}

function Protect-Servidor {
    <#
      Ataca as causas ESTRUTURAIS que derrubam a rede do escritorio. As outras
      ferramentas diagnosticam depois que o cliente ligou; esta existe para o
      chamado nao acontecer.
        1. IP fixo         - IP que muda quebra a unidade mapeada de todo mundo
        2. Nao dormir      - servidor suspenso = "sumiu tudo de manha"
        3. Placa de rede   - economia de energia derruba a conexao do nada
        4. Perfil privado  - atualizacao do Windows devolve para Publico
        5. Antivirus/lock  - lentidao e travamento com banco compartilhado
    #>
    if ($SomenteRelatorio) { Write-Simul 'Aplicaria as protecoes estruturais do servidor.'; return [long]0 }

    Write-Titulo 'BLINDAR SERVIDOR'
    Write-Info 'Rode na maquina que guarda os arquivos do escritorio.'
    Write-Info 'Corrige as causas que fazem a rede cair sozinha depois de dias ou'
    Write-Info 'semanas funcionando - o tipo de chamado que volta sempre.'

    if ($SemInteracao) { Write-Aviso 'Modo desatendido: esta ferramenta precisa de confirmacao.'; return [long]0 }

    $aplicado = [System.Collections.Generic.List[string]]::new()

    # =====================================================================
    # 1. IP FIXO
    # =====================================================================
    Write-Etapa '1/5  Endereco IP do servidor'
    $conexoes = @(Get-ConexoesReais | Where-Object { $_.Vale })
    if ($conexoes.Count -eq 0) {
        Write-Falha 'Nenhuma conexao de rede valida. Pulando esta etapa.'
    } else {
        $c = $conexoes[0]
        $faixa = Get-FaixaRede -IP $c.IP -Prefixo $c.Prefixo
        Write-Info ("Conexao : " + $c.Alias)
        Write-Info ("IP      : " + $c.IP + "/" + $c.Prefixo + "   (" + $(if ($c.Origem -eq 'Manual') { 'JA E FIXO' } else { 'automatico via DHCP' }) + ")")
        Write-Info ("Gateway : " + $c.Gateway)
        Write-Info ("DNS     : " + $(if ($c.DNS.Count) { $c.DNS -join ', ' } else { '-' }))

        if ($c.Origem -eq 'Manual') {
            Write-Ok 'O IP ja e fixo. Nada a fazer aqui.'
        } else {
            Write-Host ''
            Write-Aviso 'O IP deste servidor e automatico. Se o roteador entregar outro'
            Write-Info  'endereco, as unidades de rede de TODAS as maquinas quebram de uma vez.'
            Write-Host ''
            Write-Dest 'Duas formas de resolver:'
            Write-Info  '  A) Reserva no roteador (o mais correto): o roteador sempre entrega'
            Write-Info  '     o mesmo IP a esta maquina. Feito na interface do roteador.'
            Write-Info  '  B) IP fixo aqui na maquina: rapido, mas exige um endereco FORA da'
            Write-Info  '     faixa que o roteador distribui, senao ele pode entregar o mesmo'
            Write-Info  '     numero a outro aparelho e dar conflito.'
            Write-Host ''
            Write-Aviso 'Se voce nao sabe qual faixa o roteador distribui, prefira a opcao A.'
            Write-Host ''
            $q = Read-Host '  Fixar o IP nesta maquina agora? (S/N)'

            if ($q -match '^[Ss]') {
                # Trocar IP derruba sessao remota.
                $remoto = @(Get-Process -ErrorAction SilentlyContinue |
                            Where-Object { $_.ProcessName -match '(?i)^(anydesk|teamviewer|rustdesk)' })
                if ($remoto.Count -gt 0 -or ($env:SESSIONNAME -match '(?i)^RDP')) {
                    Write-Host ''
                    Write-Falha 'ACESSO REMOTO ATIVO. Trocar o IP DERRUBA a sua conexao.'
                    Write-Info  'Se o IP novo for igual ao atual, a queda e de segundos e volta.'
                    Write-Info  'Se for diferente, voce PERDE o acesso e alguem precisa estar no local.'
                    $q2 = Read-Host '  Continuar? (S/N)'
                    if ($q2 -notmatch '^[Ss]') { Write-Info 'Etapa cancelada.'; $q = 'N' }
                }
            }

            if ($q -match '^[Ss]') {
                Write-Host ''
                Write-Info ("Sugestao: manter o IP atual (" + $c.IP + ") - e o que os clientes ja usam.")
                Write-Info 'Ou informe outro, fora da faixa do DHCP (ex.: final .240 em diante).'
                $novoIP = (Read-Host ("  IP [" + $c.IP + "]")).Trim()
                if (-not $novoIP) { $novoIP = $c.IP }

                if ($novoIP -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
                    Write-Falha 'Endereco invalido. Etapa cancelada.'
                } elseif ((Get-FaixaRede -IP $novoIP -Prefixo $c.Prefixo) -ne $faixa) {
                    Write-Falha "O IP $novoIP nao pertence a faixa $faixa desta rede."
                    Write-Info  'Usar um IP de outra faixa deixa a maquina sem comunicacao.'
                } else {
                    # Se for outro IP, conferir se ja esta em uso
                    $livre = $true
                    if ($novoIP -ne $c.IP) {
                        Write-Info "Verificando se $novoIP esta livre..."
                        if (Test-Connection -ComputerName $novoIP -Count 2 -Quiet -ErrorAction SilentlyContinue) {
                            Write-Falha "$novoIP JA ESTA EM USO por outro aparelho. Escolha outro."
                            $livre = $false
                        } else { Write-Ok "$novoIP esta livre." }
                    }

                    if ($livre) {
                        try {
                            $dnsAtual = @($c.DNS)
                            Write-Etapa 'Aplicando IP fixo...'
                            Remove-NetIPAddress -InterfaceIndex $c.Indice -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
                            Remove-NetRoute -InterfaceIndex $c.Indice -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
                            New-NetIPAddress -InterfaceIndex $c.Indice -IPAddress $novoIP -PrefixLength $c.Prefixo `
                                -DefaultGateway $c.Gateway -ErrorAction Stop | Out-Null
                            if ($dnsAtual.Count -gt 0) {
                                Set-DnsClientServerAddress -InterfaceIndex $c.Indice -ServerAddresses $dnsAtual -ErrorAction SilentlyContinue
                            }
                            Start-Sleep -Seconds 3
                            $conf = @(Get-NetIPAddress -InterfaceIndex $c.Indice -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                                      Where-Object { $_.IPAddress -eq $novoIP })
                            if ($conf.Count -gt 0) {
                                Write-Ok "IP fixo aplicado: $novoIP/$($c.Prefixo)  gateway $($c.Gateway)"
                                $aplicado.Add("IP fixo $novoIP")
                                if (Test-Connection -ComputerName $c.Gateway -Count 2 -Quiet -ErrorAction SilentlyContinue) {
                                    Write-Ok 'Roteador continua respondendo. Rede funcionando.'
                                } else {
                                    Write-Falha 'O roteador parou de responder apos a mudanca.'
                                    Write-Info  ("Para voltar ao automatico: Set-NetIPInterface -InterfaceIndex $($c.Indice) -Dhcp Enabled")
                                }
                            } else {
                                Write-Falha 'O IP nao foi aplicado como esperado.'
                            }
                        } catch {
                            Write-Falha "Falha ao fixar o IP: $($_.Exception.Message)"
                            Write-Info  'A configuracao anterior pode ter sido removida. Para voltar ao'
                            Write-Info  ('automatico: Set-NetIPInterface -InterfaceIndex ' + $c.Indice + ' -Dhcp Enabled')
                        }
                    }
                }
            } else {
                Write-Info 'IP mantido como esta. Recomendado fazer a reserva no roteador.'
            }
        }
    }

    # =====================================================================
    # 2. NAO DORMIR
    # =====================================================================
    Write-Etapa '2/5  Impedir que o servidor durma'
    Write-Info 'Servidor que suspende de madrugada = ninguem acessa nada de manha.'
    Write-Host ''
    $q = Read-Host '  Impedir suspensao, hibernacao e desligamento de disco? (S/N) [S]'
    if (-not $q -or $q -match '^[Ss]') {
        $okEnergia = $true
        try {
            # 0 = nunca. AC = na tomada, DC = na bateria.
            & powercfg /change standby-timeout-ac 0 2>&1 | Out-Null
            & powercfg /change hibernate-timeout-ac 0 2>&1 | Out-Null
            & powercfg /change disk-timeout-ac 0 2>&1 | Out-Null
            Write-Ok 'Suspensao, hibernacao e desligamento de disco: desativados (na tomada).'
            # Monitor pode desligar - economiza e nao afeta a rede.
            Write-Info 'A tela continua podendo desligar - isso nao atrapalha o servidor.'
            $aplicado.Add('suspensao e hibernacao desativadas')
        } catch { Write-Aviso "Energia: $($_.Exception.Message)"; $okEnergia = $false }

        # Inicio rapido segura arquivos abertos e atrapalha servidor
        try {
            $reg = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
            $hf = (Get-ItemProperty -Path $reg -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled
            if ($hf -ne 0) {
                Set-ItemProperty -Path $reg -Name HiberbootEnabled -Value 0 -Type DWord -Force
                Write-Ok 'Inicializacao rapida desativada (ela mantem estado antigo apos desligar).'
                $aplicado.Add('inicializacao rapida desativada')
            } else { Write-Ok 'Inicializacao rapida ja estava desativada.' }
        } catch { }
    } else { Write-Info 'Configuracao de energia mantida.' }

    # =====================================================================
    # 3. PLACA DE REDE
    # =====================================================================
    Write-Etapa '3/5  Economia de energia da placa de rede'
    Write-Info 'O Windows desliga a placa para economizar e a conexao cai sozinha.'
    Write-Info 'E a causa mais dificil de diagnosticar, porque e intermitente.'

    $placasComEconomia = [System.Collections.Generic.List[string]]::new()
    try {
        foreach ($d in @(Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi -ErrorAction SilentlyContinue)) {
            if ($d.Enable -and $d.InstanceName -match 'PCI\\VEN_') {
                # confere se e placa de rede
                $idc = ($d.InstanceName -split '\\')[1]
                foreach ($a in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue)) {
                    if ($a.PnPDeviceID -and $idc -and $a.PnPDeviceID -match [regex]::Escape($idc)) {
                        [void]$placasComEconomia.Add($a.Name)
                    }
                }
            }
        }
    } catch { }

    Write-Host ''
    if ($placasComEconomia.Count -gt 0) {
        Write-Aviso ("Placa(s) com economia de energia LIGADA: " + (($placasComEconomia | Select-Object -Unique) -join ', '))
    } else {
        Write-Info 'Nao foi possivel confirmar pelo WMI; a correcao sera aplicada assim mesmo.'
    }
    $q = Read-Host '  Desligar a economia de energia das placas de rede? (S/N) [S]'
    if (-not $q -or $q -match '^[Ss]') {
        $n = 0
        foreach ($a in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
            # 1) WMI: "permitir que o computador desligue este dispositivo"
            try {
                foreach ($d in @(Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi -ErrorAction SilentlyContinue)) {
                    $idc = ($d.InstanceName -split '\\')[1]
                    if ($a.PnPDeviceID -and $idc -and $a.PnPDeviceID -match [regex]::Escape($idc) -and $d.Enable) {
                        $d.Enable = $false
                        $d.Put() | Out-Null
                        $n++
                    }
                }
            } catch { }
            # 2) Propriedades avancadas do driver que derrubam link
            foreach ($prop in @('Energy Efficient Ethernet','Efficient Ethernet','Green Ethernet',
                                'Power Saving Mode','Ultra Low Power Mode','Gigabit Lite')) {
                try {
                    $p = Get-NetAdapterAdvancedProperty -Name $a.Name -DisplayName $prop -ErrorAction SilentlyContinue
                    if ($p) {
                        Set-NetAdapterAdvancedProperty -Name $a.Name -DisplayName $prop -DisplayValue 'Disabled' -NoRestart -ErrorAction SilentlyContinue
                        Write-Ok "$($a.Name): '$prop' desativado."
                    }
                } catch { }
            }
        }
        if ($n -gt 0) {
            Write-Ok "$n placa(s): 'permitir desligar para economizar energia' DESMARCADO."
            $aplicado.Add('economia de energia da placa de rede desligada')
        } else {
            Write-Ok 'Economia de energia da placa: ja estava desativada ou nao aplicavel.'
        }
    } else { Write-Info 'Placa de rede mantida como esta.' }

    # =====================================================================
    # 4. PERFIL DE REDE
    # =====================================================================
    Write-Etapa '4/5  Perfil da rede'
    $mudou = Set-PerfilRedePrivado
    if ($mudou) { $aplicado.Add('perfil de rede para privado') }
    Write-Info 'Atualizacao de recurso do Windows as vezes devolve o perfil para Publico'
    Write-Info 'e a maquina some da rede sem ninguem ter mexido. Se isso acontecer,'
    Write-Info 'rode esta ferramenta de novo - ou o diagnostico da rede local.'

    # =====================================================================
    # 5. ANTIVIRUS E BANCO DE DADOS COMPARTILHADO
    # =====================================================================
    Write-Etapa '5/5  Desempenho da pasta compartilhada'

    $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\$$' })
    if ($shares.Count -eq 0) {
        Write-Info 'Nenhuma pasta compartilhada nesta maquina - etapa dispensada.'
    } else {
        Write-Info 'Pastas compartilhadas encontradas:'
        foreach ($s in $shares) { Write-Info ("   $($s.Name) -> $($s.Path)") }
        Write-Host ''
        Write-Info 'Duas coisas deixam o acesso lento e podem travar sistema juridico'
        Write-Info 'que usa banco de dados compartilhado:'
        Write-Info '  - o antivirus escaneia cada arquivo aberto pela rede;'
        Write-Info '  - o cache do SMB (oplocks) segura registros do banco.'
        Write-Host ''
        Write-Aviso 'Excluir a pasta do antivirus reduz a protecao NAQUELA pasta.'
        Write-Info  'Faz sentido quando o escritorio usa sistema com base compartilhada e'
        Write-Info  'reclama de lentidao ou travamento. Nao faca por padrao.'
        Write-Host ''
        $q = Read-Host '  O escritorio usa sistema com banco de dados nessa pasta? (S/N)'
        if ($q -match '^[Ss]') {
            foreach ($s in $shares) {
                try {
                    Add-MpPreference -ExclusionPath $s.Path -ErrorAction Stop
                    Write-Ok "Antivirus: $($s.Path) excluido da varredura em tempo real."
                    $aplicado.Add("exclusao de antivirus em $($s.Path)")
                } catch { Write-Aviso "Nao foi possivel excluir $($s.Path): $($_.Exception.Message)" }
            }
            try {
                Set-SmbServerConfiguration -EnableLeasing $false -Force -ErrorAction Stop
                Write-Ok 'Cache de arquivo (leasing) desativado no servidor.'
                Write-Info 'Isso evita travamento de registro quando duas pessoas usam o'
                Write-Info 'sistema ao mesmo tempo. O acesso a arquivo comum fica um pouco'
                Write-Info 'mais lento, mas o banco para de travar.'
                $aplicado.Add('leasing do SMB desativado')
            } catch { Write-Aviso "Leasing: $($_.Exception.Message)" }
        } else {
            Write-Info 'Nada alterado. Se aparecer lentidao com o sistema juridico, volte aqui.'
        }
    }

    # =====================================================================
    Write-Host ''
    if ($aplicado.Count -eq 0) {
        Write-Titulo 'NADA FOI ALTERADO'
        Write-Info 'Nenhuma protecao foi aplicada nesta execucao.'
    } else {
        Write-Titulo 'SERVIDOR BLINDADO'
        foreach ($a in $aplicado) { Write-Ok $a }
        Write-Host ''
        Write-Info 'O que isso evita: unidade de rede quebrando quando o IP muda, servidor'
        Write-Info 'inacessivel de manha, queda aleatoria de conexao e lentidao no sistema.'
        Write-Host ''
        Write-Aviso 'Ainda falta o que nenhuma configuracao resolve: BACKUP.'
        Write-Info  'Os arquivos continuam num disco so. Use a opcao de backup do menu.'
        Add-Alerta 'Servidor blindado - conferir se ha backup configurado.'
    }
    return [long]0
}

function Repair-AcessoAoServidor {
    <#
      "Esse computador parou de acessar o servidor."
      Segue a cadeia na ordem em que ela quebra e para no primeiro elo com
      defeito, em vez de despejar tudo de uma vez. Cada elo tem a correcao
      correspondente.
    #>
    Write-Titulo 'ESTE COMPUTADOR NAO CONECTA NO SERVIDOR'

    # --- Descobrir o servidor --------------------------------------------
    $candidatos = [System.Collections.Generic.List[string]]::new()
    foreach ($m in @(Get-CimInstance Win32_NetworkConnection -ErrorAction SilentlyContinue)) {
        if ($m.RemoteName -match '^\\\\([^\\]+)\\') {
            if (-not $candidatos.Contains($Matches[1])) { [void]$candidatos.Add($Matches[1]) }
        }
    }
    try {
        foreach ($l in @(& cmdkey.exe /list 2>&1)) {
            if ($l.ToString() -match '(?i)(Destino|Target):\s*Domain:target=(.+)$') {
                $a = $Matches[2].Trim()
                if ($a -match '^[A-Za-z0-9][A-Za-z0-9\.\-_]{0,62}$' -and -not $candidatos.Contains($a)) {
                    [void]$candidatos.Add($a)
                }
            }
        }
    } catch { }

    $servidor = ''
    if ($candidatos.Count -gt 0) {
        Write-Info 'Servidores que este computador ja usou:'
        $i = 1
        foreach ($c in $candidatos) { Write-Host ("     [$i] $c") -ForegroundColor White; $i++ }
        Write-Host ''
        if ($SemInteracao) { $servidor = $candidatos[0] }
        else {
            $s = (Read-Host '  Numero, ou digite o nome/IP do servidor').Trim().TrimStart('\')
            if ($s -match '^\d+$' -and [int]$s -ge 1 -and [int]$s -le $candidatos.Count) { $servidor = $candidatos[[int]$s - 1] }
            elseif ($s) { $servidor = ($s -split '\\')[0] }
        }
    } else {
        if ($SemInteracao) { Write-Aviso 'Modo desatendido e nenhum servidor conhecido nesta maquina.'; return [long]0 }
        Write-Info 'Nenhum servidor conhecido nesta maquina.'
        Write-Info 'Informe o nome ou IP do servidor (ex.: SERVIDOR ou 192.168.0.10).'
        $servidor = (Read-Host '  Servidor').Trim().TrimStart('\')
        $servidor = ($servidor -split '\\')[0]
    }
    if (-not $servidor) { Write-Info 'Cancelado.'; return [long]0 }

    Write-Host ''
    Write-Dest ("Diagnosticando o acesso a: " + $servidor)

    $ondeQuebrou = ''
    $comoResolver = [System.Collections.Generic.List[string]]::new()

    # --- ELO 1: esta maquina esta em rede? -------------------------------
    Write-Etapa '1/6  Esta maquina esta conectada a uma rede?'
    $minhas = @(Get-ConexoesReais | Where-Object { $_.Vale })
    if ($minhas.Count -eq 0) {
        Write-Falha 'Este computador nao esta em nenhuma rede.'
        $ondeQuebrou = 'sem rede'
        $comoResolver.Add('Conferir cabo / Wi-Fi. Use a opcao de resolver problemas de conexao.')
    } else {
        foreach ($c in $minhas) {
            $faixa = Get-FaixaRede -IP $c.IP -Prefixo $c.Prefixo
            Write-Ok "$($c.Alias): $($c.IP)  faixa $faixa  gateway $($c.Gateway)"
        }
    }

    # --- ELO 2: o servidor esta na MESMA rede? ---------------------------
    if (-not $ondeQuebrou) {
        Write-Etapa '2/6  O servidor esta na mesma rede que este computador?'
        # Um nome pode resolver para VARIOS IPs: servidor com duas placas, ou
        # com adaptador virtual (Hyper-V, VPN, WSL). Pegar so o primeiro da
        # lista da diagnostico errado - basta UM deles estar na nossa faixa
        # para as maquinas se enxergarem.
        $ipsServidor = [System.Collections.Generic.List[string]]::new()
        if ($servidor -match '^\d{1,3}(\.\d{1,3}){3}$') { [void]$ipsServidor.Add($servidor) }
        else {
            try {
                $r = Resolve-DnsName -Name $servidor -Type A -ErrorAction Stop -QuickTimeout
                foreach ($x in @($r | Where-Object { $_.IPAddress })) {
                    if (-not $ipsServidor.Contains($x.IPAddress)) { [void]$ipsServidor.Add($x.IPAddress) }
                }
                if ($ipsServidor.Count -gt 1) {
                    Write-Ok ("O nome '$servidor' resolveu para " + $ipsServidor.Count + " enderecos: " + ($ipsServidor -join ', '))
                } elseif ($ipsServidor.Count -eq 1) {
                    Write-Ok "O nome '$servidor' resolveu para $($ipsServidor[0])"
                }
            } catch { }

            if ($ipsServidor.Count -eq 0) {
                Write-Aviso "O nome '$servidor' nao foi resolvido por DNS."
                # NetBIOS ainda pode achar na rede local
                try {
                    $t = Test-Connection -ComputerName $servidor -Count 1 -ErrorAction Stop
                    [void]$ipsServidor.Add($t.IPV4Address.IPAddressToString)
                    Write-Ok "Encontrado pela rede local: $($ipsServidor[0])"
                } catch {
                    Write-Falha "Nao foi possivel descobrir o IP de '$servidor'."
                    Write-Info  'O servidor pode estar desligado, ou o nome mudou.'
                    $ondeQuebrou = 'nome nao resolve'
                    $comoResolver.Add("Tentar pelo IP em vez do nome (\\IP\Pasta)")
                    $comoResolver.Add('Conferir se o servidor esta ligado')
                }
            }
        }

        if ($ipsServidor.Count -gt 0 -and -not $ondeQuebrou) {
            $ipNaMinhaRede = ''
            foreach ($c in $minhas) {
                $minhaFaixa = Get-FaixaRede -IP $c.IP -Prefixo $c.Prefixo
                foreach ($ipS in $ipsServidor) {
                    if ((Get-FaixaRede -IP $ipS -Prefixo $c.Prefixo) -eq $minhaFaixa) {
                        $ipNaMinhaRede = $ipS
                        break
                    }
                }
                if ($ipNaMinhaRede) { break }
            }

            if ($ipNaMinhaRede) {
                Write-Ok "Servidor $ipNaMinhaRede esta na mesma faixa de rede. Correto."
                if ($ipsServidor.Count -gt 1) {
                    Write-Info 'Os outros enderecos sao de placa extra ou adaptador virtual do'
                    Write-Info 'servidor - nao atrapalham, mas se o mapeamento usar um deles,'
                    Write-Info ("prefira " + $ipNaMinhaRede + " ou o proprio nome.")
                }
            } else {
                Write-Falha 'O SERVIDOR ESTA EM OUTRA REDE.'
                Write-Info  ("   Este computador : " + (Get-FaixaRede -IP $minhas[0].IP -Prefixo $minhas[0].Prefixo))
                Write-Info  ("   Servidor        : " + ($ipsServidor -join ', '))
                Write-Host ''
                Write-Info 'Esta e a causa mais comum de "parou de acessar o servidor".'
                Write-Info 'Acontece quando a maquina cai no Wi-Fi de visitantes, quando'
                Write-Info 'alguem liga um roteador extra, ou quando ha VPN ativa.'
                Write-Info 'Confira a rede das duas maquinas com a opcao "Qual Rede Estou Usando".'
                $ondeQuebrou = 'redes diferentes'
                $comoResolver.Add('Conectar este computador na MESMA rede do servidor')
                $comoResolver.Add('Se for Wi-Fi: trocar da rede de visitantes para a principal')
                $comoResolver.Add('Se houver VPN ligada: desconectar')
                Add-Alerta "Computador em rede diferente do servidor $servidor."
            }
        }
    }

    # --- ELO 3: o servidor responde? -------------------------------------
    if (-not $ondeQuebrou) {
        Write-Etapa '3/6  O servidor responde?'
        $ping = Test-Connection -ComputerName $servidor -Count 2 -Quiet -ErrorAction SilentlyContinue
        if ($ping) { Write-Ok "$servidor respondeu ao ping." }
        else { Write-Aviso "$servidor nao respondeu ao ping (o firewall dele pode so estar bloqueando ping)." }

        $porta = $false
        try {
            $t = Test-NetConnection -ComputerName $servidor -Port 445 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            $porta = ($t -and $t.TcpTestSucceeded)
        } catch { }

        if ($porta) {
            Write-Ok "Porta 445 (compartilhamento) aberta em $servidor."
        } else {
            Write-Falha "Porta 445 fechada ou sem resposta em $servidor."
            if ($ping) {
                Write-Info 'O servidor esta ligado e na rede, mas nao aceita compartilhamento.'
                Write-Info 'No SERVIDOR: o servico de compartilhamento pode ter parado, ou o'
                Write-Info 'firewall dele fechou. Rode o diagnostico da rede local NELE.'
                $comoResolver.Add("No servidor $servidor : rodar o diagnostico da rede local")
                $comoResolver.Add('No servidor: conferir se o servico LanmanServer esta rodando')
            } else {
                Write-Info 'O servidor parece desligado ou fora da rede.'
                $comoResolver.Add("Conferir se o servidor $servidor esta ligado")
            }
            $ondeQuebrou = 'servidor nao aceita conexao'
        }
    }

    # --- ELO 4: credencial ------------------------------------------------
    if (-not $ondeQuebrou) {
        Write-Etapa '4/6  Autenticacao (usuario e senha)'
        $listou = $false
        try {
            $saida = & net view "\\$servidor" 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Ok 'Autenticacao aceita pelo servidor.'
                # O net view escreve na codepage do console e as mensagens dele
                # saem com acento quebrado. Ficamos so com as linhas que sao
                # nome de pasta (comecam na coluna 0 e tem tipo "Disco").
                $pastas = [System.Collections.Generic.List[string]]::new()
                foreach ($l in @($saida)) {
                    $t = $l.ToString()
                    if ($t -match '^(\S+)\s+(Disco|Disk)\s*') { [void]$pastas.Add($Matches[1]) }
                }
                if ($pastas.Count -gt 0) {
                    Write-Info 'Pastas compartilhadas visiveis:'
                    foreach ($p in $pastas) { Write-Info ("   " + $p) }
                } else {
                    Write-Aviso 'O servidor respondeu, mas nao mostrou nenhuma pasta compartilhada.'
                    Write-Info  'Ou o servidor nao compartilha nada, ou este usuario nao tem'
                    Write-Info  'permissao para ver as pastas. No servidor, rode o diagnostico'
                    Write-Info  'da rede local para conferir os compartilhamentos.'
                    $comoResolver.Add("No servidor $servidor : conferir se ha pasta compartilhada e a permissao do usuario")
                }
                $listou = $true
            } else {
                $txt = ($saida -join ' ')
                Write-Falha 'O servidor recusou a autenticacao.'
                if ($txt -match '(?i)(5|acesso negado|access is denied)') {
                    Write-Info 'Acesso negado: usuario ou senha errados, ou a senha mudou no servidor.'
                } elseif ($txt -match '(?i)(1219|conflito|conflict|multiple connections)') {
                    Write-Falha 'CONFLITO DE CREDENCIAL (erro 1219).'
                    Write-Info  'O Windows ja tem uma conexao aberta com esse servidor usando outro'
                    Write-Info  "usuario. E' a causa classica de 'parou do nada' depois que a"
                    Write-Info  'senha foi trocada no servidor.'
                }
                $ondeQuebrou = 'credencial'
                $comoResolver.Add('Apagar a credencial salva e entrar de novo com a senha atual')
            }
        } catch {
            Write-Falha "Nao foi possivel consultar o servidor: $($_.Exception.Message)"
            $ondeQuebrou = 'credencial'
        }
    }

    # --- ELO 5: unidades mapeadas ----------------------------------------
    # Se a cadeia ja quebrou, os elos seguintes nao teriam como passar: dizer
    # isso e' melhor do que deixar o numero das etapas saltando sem explicacao.
    if ($ondeQuebrou) {
        Write-Host ''
        Write-Info "Etapas seguintes puladas: a cadeia ja quebrou em '$ondeQuebrou'."
        Write-Info 'Resolva esse ponto primeiro e rode de novo.'
    }
    Write-Etapa '5/6  Unidades de rede deste computador'
    $mapeadas = @(Get-CimInstance Win32_NetworkConnection -ErrorAction SilentlyContinue |
                  Where-Object { $_.RemoteName -match "(?i)^\\\\$([regex]::Escape($servidor))\\" })
    if ($mapeadas.Count -eq 0) {
        Write-Info "Nenhuma unidade mapeada para $servidor."
        Write-Info 'O acesso pode estar sendo feito pelo caminho completo (\\SERVIDOR\Pasta).'
    } else {
        foreach ($m in $mapeadas) {
            if ($m.ConnectionState -eq 'Connected') {
                Write-Ok "$($m.LocalName) -> $($m.RemoteName)  (conectada)"
            } else {
                Write-Falha "$($m.LocalName) -> $($m.RemoteName)  ($($m.ConnectionState))"
                if (-not $ondeQuebrou) { $ondeQuebrou = 'unidade desconectada' }
                $comoResolver.Add("Reconectar a unidade $($m.LocalName)")
            }
        }
    }

    # --- ELO 6: configuracao local ---------------------------------------
    Write-Etapa '6/6  Configuracao de rede deste computador'
    foreach ($p in @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)) {
        if ($p.NetworkCategory -eq 'Public') {
            Write-Falha "Rede '$($p.Name)': perfil PUBLICO - bloqueia o acesso a rede."
            if (-not $ondeQuebrou) { $ondeQuebrou = 'perfil publico' }
            $comoResolver.Add('Mudar o perfil da rede para Privado')
        }
    }
    $ws = Get-Service -Name 'LanmanWorkstation' -ErrorAction SilentlyContinue
    if ($ws -and $ws.Status -ne 'Running') {
        Write-Falha 'Servico "Estacao de trabalho" parado - sem ele nao se acessa rede nenhuma.'
        if (-not $ondeQuebrou) { $ondeQuebrou = 'servico parado' }
        $comoResolver.Add('Iniciar o servico LanmanWorkstation')
    } elseif ($ws) { Write-Ok 'Servico "Estacao de trabalho": em execucao.' }

    # --- Conclusao ---------------------------------------------------------
    Write-Host ''
    if (-not $ondeQuebrou -and $comoResolver.Count -eq 0) {
        Write-Titulo 'ACESSO AO SERVIDOR ESTA FUNCIONANDO'
        Write-Ok "Este computador alcanca $servidor, autentica e enxerga as pastas."
        Write-Info 'Se o usuario ainda reclama, pode ser permissao na pasta especifica'
        Write-Info 'ou o programa dele apontando para um caminho antigo.'
        return [long]0
    }

    Write-Titulo 'ONDE ESTA O PROBLEMA'
    Write-Falha ("Elo que quebrou: " + $ondeQuebrou)
    Write-Host ''
    Write-Dest 'O que resolve:'
    foreach ($s in ($comoResolver | Select-Object -Unique)) { Write-Info ("   - " + $s) }
    Add-Alerta ("Acesso ao servidor $servidor : $ondeQuebrou")

    if ($SomenteRelatorio -or $SemInteracao) { return [long]0 }

    # --- Correcoes guiadas -------------------------------------------------
    Write-Host ''
    Write-Host '     [1] Renovar a credencial (apaga a salva e entra com a senha atual)' -ForegroundColor White
    Write-Host '     [2] Reconectar as unidades de rede' -ForegroundColor White
    Write-Host '     [3] Corrigir a configuracao local (perfil privado + servicos)' -ForegroundColor White
    Write-Host '     [4] Limpar cache de nomes (DNS e NetBIOS)' -ForegroundColor White
    Write-Host '     [0] Nao corrigir agora' -ForegroundColor DarkGray
    Write-Host ''
    $opc = (Read-Host '  Opcao').Trim()

    switch ($opc) {
        '1' {
            Write-Etapa 'Renovando a credencial'
            # Derrubar as conexoes abertas evita o erro 1219 (conflito)
            foreach ($m in $mapeadas) { & net use $m.LocalName /delete /y 2>&1 | Out-Null }
            & net use "\\$servidor" /delete /y 2>&1 | Out-Null
            & cmdkey.exe /delete:$servidor 2>&1 | Out-Null
            Write-Ok 'Credencial antiga e conexoes removidas.'
            Write-Host ''
            $u = (Read-Host '  Usuario do servidor').Trim()
            if ($u) {
                $pw = Read-Host '  Senha' -AsSecureString
                $pwT = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))
                $alvo = if ($u -match '\\') { $u } else { "$servidor\$u" }
                & cmdkey.exe /add:$servidor /user:$alvo /pass:$pwT | Out-Null
                Write-Ok 'Credencial nova salva.'
                $t = & net view "\\$servidor" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Ok 'Autenticacao funcionando agora.'
                    foreach ($m in $mapeadas) {
                        & net use $m.LocalName $m.RemoteName /persistent:yes 2>&1 | Out-Null
                        if ($LASTEXITCODE -eq 0) { Write-Ok "Unidade $($m.LocalName) reconectada." }
                    }
                } else {
                    Write-Falha 'Ainda recusado. Confira o usuario e a senha no servidor.'
                }
            }
        }
        '2' {
            Write-Etapa 'Reconectando as unidades'
            foreach ($m in $mapeadas) {
                & net use $m.LocalName /delete /y 2>&1 | Out-Null
                & net use $m.LocalName $m.RemoteName /persistent:yes 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) { Write-Ok "$($m.LocalName) reconectada." }
                else { Write-Falha "$($m.LocalName) nao reconectou - veja a credencial (opcao 1)." }
            }
        }
        '3' {
            Write-Etapa 'Corrigindo a configuracao local'
            Set-PerfilRedePrivado | Out-Null
            Set-ServicosRede
            Enable-RegrasFirewallRede -Grupo $script:GrupoFWDescoberta `
                -RegexNome 'Descoberta de Rede|Network Discovery' -Rotulo 'Descoberta de rede'
            Enable-RegrasFirewallRede -Grupo $script:GrupoFWCompartilhamento `
                -RegexNome 'Compartilhamento de Arquivo e Impressora|File and Printer Sharing' `
                -Rotulo 'Compartilhamento de arquivos'
        }
        '4' {
            Write-Etapa 'Limpando cache de nomes'
            try { Clear-DnsClientCache -ErrorAction Stop; Write-Ok 'Cache DNS limpo.' }
            catch { & ipconfig /flushdns | Out-Null; Write-Ok 'Cache DNS limpo.' }
            try { & nbtstat -R 2>&1 | Out-Null; & nbtstat -RR 2>&1 | Out-Null; Write-Ok 'Cache NetBIOS limpo.' } catch { }
            Write-Info 'Util quando o servidor trocou de IP e o nome ainda aponta para o antigo.'
        }
        default { Write-Info 'Nada foi alterado.' }
    }
    return [long]0
}

function Remove-ConfiguracaoRede {
    <#
      Tira a maquina da rede de compartilhamento: para de compartilhar pastas,
      desconecta unidades, apaga credenciais salvas e pode remover a conta de
      acesso criada pela ferramenta de servidor.

      NAO APAGA ARQUIVO NENHUM. Parar de compartilhar so remove o "atalho" que
      a rede enxerga; a pasta e o conteudo continuam no disco, intactos.

      Os compartilhamentos administrativos (C$, ADMIN$, IPC$) NAO sao tocados:
      sao padrao do Windows, o proprio sistema recria, e remove-los quebra
      administracao remota.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Listaria e removeria as configuracoes de rede desta maquina.'; return [long]0 }

    Write-Titulo 'DESFAZER A CONFIGURACAO DE REDE DESTA MAQUINA'
    Write-Info 'Use quando o computador sai do escritorio, e vendido, ou quando a rede'
    Write-Info 'precisa ser refeita do zero.'
    Write-Host ''
    Write-Ok 'NENHUM ARQUIVO E APAGADO. Parar de compartilhar nao mexe no conteudo'
    Write-Ok 'das pastas - elas continuam no disco exatamente como estao.'

    # --- Levantamento ----------------------------------------------------
    Write-Etapa '1/2  O que existe hoje nesta maquina'

    $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\$$' })
    Write-Host ''
    Write-Dest 'Pastas compartilhadas:'
    if ($shares.Count -eq 0) { Write-Info '   nenhuma' }
    else { foreach ($s in $shares) { Write-Info ("   \\$env:COMPUTERNAME\$($s.Name)  ->  $($s.Path)") } }

    $mapeadas = @(Get-CimInstance Win32_NetworkConnection -ErrorAction SilentlyContinue)
    Write-Dest 'Unidades de rede mapeadas:'
    if ($mapeadas.Count -eq 0) { Write-Info '   nenhuma' }
    else { foreach ($m in $mapeadas) { Write-Info ("   $($m.LocalName)  ->  $($m.RemoteName)") } }

    # Credenciais de rede salvas.
    # CUIDADO: o cofre do Windows guarda de tudo - token do GitHub, conta
    # Microsoft, licenca de aplicativo. Apagar por engano quebra outras coisas.
    # Credencial de compartilhamento e SEMPRE do tipo 'Domain:target=' ("Senha
    # do dominio"); aplicativo e site usam 'LegacyGeneric:' ou 'WindowsLive:'.
    # Por isso so aceitamos Domain:target= e ainda conferimos se o alvo parece
    # nome de maquina ou IP.
    $creds = [System.Collections.Generic.List[string]]::new()
    try {
        $saida = & cmdkey.exe /list 2>&1
        foreach ($l in @($saida)) {
            $t = $l.ToString()
            if ($t -match '(?i)(Destino|Target):\s*Domain:target=(.+)$') {
                $alvo = $Matches[2].Trim()
                # nome de maquina (NetBIOS/DNS) ou IP - nada de espaco, barra ou esquema
                if ($alvo -match '^[A-Za-z0-9][A-Za-z0-9\.\-_]{0,62}$') {
                    if (-not $creds.Contains($alvo)) { [void]$creds.Add($alvo) }
                }
            }
        }
    } catch { }
    Write-Dest 'Credenciais de rede salvas:'
    if ($creds.Count -eq 0) { Write-Info '   nenhuma' }
    else { foreach ($c in $creds) { Write-Info ("   $c") } }

    # Contas locais que parecem ter sido criadas para a rede
    $contasRede = @(Get-LocalUser -ErrorAction SilentlyContinue |
        Where-Object { $_.Description -match 'pastas compartilhadas|acesso a rede' -or
                       $_.FullName -match 'Acesso a rede' })
    Write-Dest 'Contas de acesso a rede (criadas por esta ferramenta):'
    if ($contasRede.Count -eq 0) { Write-Info '   nenhuma' }
    else { foreach ($u in $contasRede) { Write-Info ("   $($u.Name)   habilitada: $($u.Enabled)") } }

    # Perfil e senha
    $perfis = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
    Write-Dest 'Perfil da rede:'
    foreach ($p in $perfis) { Write-Info ("   $($p.Name) ($($p.InterfaceAlias)): $($p.NetworkCategory)") }

    $semSenha = $false
    try {
        $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'everyoneincludesanonymous' -ErrorAction SilentlyContinue).everyoneincludesanonymous
        if ($v -eq 1) { $semSenha = $true }
    } catch { }
    if ($semSenha) {
        Write-Aviso 'Compartilhamento SEM SENHA esta ativo nesta maquina.'
    }

    $temAlgo = ($shares.Count + $mapeadas.Count + $creds.Count + $contasRede.Count) -gt 0 -or $semSenha
    if (-not $temAlgo) {
        Write-Host ''
        Write-Ok 'Esta maquina nao tem configuracao de rede de compartilhamento para desfazer.'
        return [long]0
    }

    if ($SemInteracao) { Write-Aviso 'Modo desatendido: esta ferramenta precisa de confirmacao.'; return [long]0 }

    # --- O que desfazer ---------------------------------------------------
    Write-Etapa '2/2  O que voce quer desfazer'
    Write-Host ''
    Write-Host '     [1] TUDO - tirar a maquina da rede por completo' -ForegroundColor White
    Write-Host '     [2] So parar de compartilhar as pastas (deixa de ser servidor)' -ForegroundColor White
    Write-Host '     [3] So desconectar as unidades de rede (deixa de acessar o servidor)' -ForegroundColor White
    Write-Host '     [4] So apagar as credenciais salvas' -ForegroundColor White
    Write-Host '     [0] Cancelar' -ForegroundColor DarkGray
    Write-Host ''
    $opc = (Read-Host '  Opcao').Trim()
    if ($opc -eq '0' -or -not $opc) { Write-Info 'Cancelado. Nada foi alterado.'; return [long]0 }
    if ($opc -notin @('1','2','3','4')) { Write-Aviso 'Opcao invalida.'; return [long]0 }

    $tudo = ($opc -eq '1')
    $feito = [System.Collections.Generic.List[string]]::new()

    # --- Parar de compartilhar -------------------------------------------
    if (($tudo -or $opc -eq '2') -and $shares.Count -gt 0) {
        Write-Host ''
        Write-Etapa 'Parando de compartilhar as pastas'
        Write-Info 'Lembrando: os arquivos NAO sao apagados, so deixam de aparecer na rede.'
        $c = Read-Host '  Confirma? (S/N)'
        if ($c -match '^[Ss]') {
            foreach ($s in $shares) {
                try {
                    Remove-SmbShare -Name $s.Name -Force -ErrorAction Stop
                    Write-Ok "Deixou de ser compartilhada: $($s.Name)  (pasta $($s.Path) intacta)"
                    $feito.Add("compartilhamento '$($s.Name)' removido")
                } catch {
                    Write-Falha "Nao foi possivel remover '$($s.Name)': $($_.Exception.Message)"
                }
            }
        } else { Write-Info 'Compartilhamentos mantidos.' }
    }

    # --- Desconectar unidades --------------------------------------------
    if (($tudo -or $opc -eq '3') -and $mapeadas.Count -gt 0) {
        Write-Host ''
        Write-Etapa 'Desconectando as unidades de rede'
        $c = Read-Host '  Confirma? (S/N)'
        if ($c -match '^[Ss]') {
            foreach ($m in $mapeadas) {
                try {
                    & net use $m.LocalName /delete /y 2>&1 | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Ok "Unidade $($m.LocalName) desconectada ($($m.RemoteName))."
                        $feito.Add("unidade $($m.LocalName) desconectada")
                    } else {
                        Write-Aviso "Nao foi possivel desconectar $($m.LocalName) - pode estar em uso."
                        Write-Info  'Feche o Explorer e os programas que usam essa unidade e tente de novo.'
                    }
                } catch { Write-Aviso "Erro em $($m.LocalName): $($_.Exception.Message)" }
            }
        } else { Write-Info 'Unidades mantidas.' }
    }

    # --- Credenciais ------------------------------------------------------
    if (($tudo -or $opc -eq '4') -and $creds.Count -gt 0) {
        Write-Host ''
        Write-Etapa 'Apagando as credenciais de rede salvas'
        Write-Info 'Depois disso o Windows volta a pedir usuario e senha ao acessar o servidor.'
        $c = Read-Host '  Confirma? (S/N)'
        if ($c -match '^[Ss]') {
            foreach ($alvo in $creds) {
                try {
                    & cmdkey.exe /delete:$alvo 2>&1 | Out-Null
                    Write-Ok "Credencial removida: $alvo"
                    $feito.Add("credencial de $alvo apagada")
                } catch { Write-Aviso "Nao foi possivel remover a credencial de $alvo." }
            }
        } else { Write-Info 'Credenciais mantidas.' }
    }

    # --- Daqui para baixo, so no modo TUDO -------------------------------
    if ($tudo) {

        # Conta de acesso
        if ($contasRede.Count -gt 0) {
            Write-Host ''
            Write-Etapa 'Conta de acesso a rede'
            foreach ($u in $contasRede) {
                Write-Info "Conta: $($u.Name)"
                Write-Info 'Se outros computadores ainda usam esta conta para acessar esta'
                Write-Info 'maquina, eles vao perder o acesso.'
                Write-Host ''
                Write-Host '     [1] Desativar (mantem a conta, bloqueia o acesso - reversivel)' -ForegroundColor White
                Write-Host '     [2] Remover a conta' -ForegroundColor White
                Write-Host '     [3] Deixar como esta' -ForegroundColor DarkGray
                $ac = (Read-Host '  Opcao [3]').Trim()
                if ($ac -eq '1') {
                    try { Disable-LocalUser -Name $u.Name -ErrorAction Stop
                          Write-Ok "Conta '$($u.Name)' desativada."
                          $feito.Add("conta '$($u.Name)' desativada") }
                    catch { Write-Falha "Nao foi possivel desativar: $($_.Exception.Message)" }
                } elseif ($ac -eq '2') {
                    try {
                        Remove-LocalUser -Name $u.Name -ErrorAction Stop
                        Write-Ok "Conta '$($u.Name)' removida."
                        Write-Info 'A pasta de perfil dela, se existir, continua em C:\Users.'
                        $feito.Add("conta '$($u.Name)' removida")
                        # tira tambem a chave que ocultava a conta do login
                        try {
                            $regLogin = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
                            if (Test-Path $regLogin) { Remove-ItemProperty -Path $regLogin -Name $u.Name -ErrorAction SilentlyContinue }
                        } catch { }
                    } catch { Write-Falha "Nao foi possivel remover: $($_.Exception.Message)" }
                } else { Write-Info 'Conta mantida.' }
            }
        }

        # Compartilhamento sem senha -> volta ao padrao seguro
        if ($semSenha) {
            Write-Host ''
            Write-Etapa 'Compartilhamento protegido por senha'
            Write-Info 'Esta maquina esta com o acesso sem senha ligado. Religar a protecao'
            Write-Info 'devolve o Windows ao padrao seguro.'
            $c = Read-Host '  Religar a protecao por senha? (S/N) [S]'
            if (-not $c -or $c -match '^[Ss]') {
                try {
                    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'everyoneincludesanonymous' -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RestrictNullSessAccess' -Value 1 -Type DWord -Force
                    Write-Ok 'Compartilhamento protegido por senha RELIGADO.'
                    $feito.Add('protecao por senha religada')
                } catch { Write-Aviso "Nao foi possivel religar: $($_.Exception.Message)" }
            }
        }

        # Firewall
        Write-Host ''
        Write-Etapa 'Firewall'
        Write-Info 'Fechar as regras de compartilhamento e descoberta deixa a maquina'
        Write-Info 'invisivel na rede. Faz sentido em notebook que vai rodar fora do'
        Write-Info 'escritorio, ou em maquina que nao compartilha mais nada.'
        $c = Read-Host '  Fechar essas regras no firewall? (S/N)'
        if ($c -match '^[Ss]') {
            foreach ($g in @(@{ G = $script:GrupoFWCompartilhamento; N = 'Compartilhamento de arquivos' },
                             @{ G = $script:GrupoFWDescoberta;       N = 'Descoberta de rede' })) {
                try {
                    $regras = @(Get-NetFirewallRule -Group $g.G -ErrorAction SilentlyContinue |
                                Where-Object { $_.Enabled -eq 'True' })
                    $n = 0
                    foreach ($r in $regras) {
                        try { Disable-NetFirewallRule -Name $r.Name -ErrorAction Stop; $n++ } catch { }
                    }
                    Write-Ok "$($g.N): $n regra(s) desabilitada(s)."
                    if ($n -gt 0) { $feito.Add("firewall fechado para $($g.N)") }
                } catch { Write-Aviso "$($g.N): $($_.Exception.Message)" }
            }
        } else { Write-Info 'Firewall mantido como esta.' }

        # Perfil de rede
        $privados = @($perfis | Where-Object { $_.NetworkCategory -eq 'Private' })
        if ($privados.Count -gt 0) {
            Write-Host ''
            Write-Etapa 'Perfil da rede'
            Write-Info 'Voltar para PUBLICO esconde a maquina das outras e e o mais seguro'
            Write-Info 'para notebook que sai do escritorio (Wi-Fi de hotel, aeroporto).'
            $c = Read-Host '  Mudar o perfil para Publico? (S/N)'
            if ($c -match '^[Ss]') {
                foreach ($p in $privados) {
                    try {
                        Set-NetConnectionProfile -InterfaceIndex $p.InterfaceIndex -NetworkCategory Public -ErrorAction Stop
                        Write-Ok "Rede '$($p.Name)': Privada -> PUBLICA."
                        $feito.Add("perfil de '$($p.Name)' para publico")
                    } catch { Write-Falha "Nao foi possivel mudar '$($p.Name)': $($_.Exception.Message)" }
                }
            } else { Write-Info 'Perfil mantido.' }
        }
    }

    # --- Resumo ------------------------------------------------------------
    Write-Host ''
    if ($feito.Count -eq 0) {
        Write-Info 'Nada foi alterado.'
    } else {
        Write-Titulo 'RESUMO DO QUE FOI DESFEITO'
        foreach ($f in $feito) { Write-Ok $f }
        Write-Host ''
        Write-Ok 'Reforcando: nenhum arquivo foi apagado. As pastas que deixaram de ser'
        Write-Ok 'compartilhadas continuam no disco, com o conteudo intacto.'
        Write-Host ''
        Write-Info 'Para montar a rede de novo, use as opcoes de configurar servidor e'
        Write-Info 'conectar a rede deste mesmo menu.'
        Add-Alerta 'Configuracao de rede desfeita nesta maquina.'
    }
    return [long]0
}

function Remove-PastaAnyDesk {
    param(
        [ValidateSet('Completo', 'SomenteLogs')][string]$Modo = 'SomenteLogs',
        [switch]$Forcar,
        [switch]$IncluirProgramData
    )

    $pastas = @()
    $pastas += [pscustomobject]@{ Nome = 'APPDATA';      Caminho = (Join-Path $env:APPDATA 'AnyDesk') }
    $pastas += [pscustomobject]@{ Nome = 'LOCALAPPDATA'; Caminho = (Join-Path $env:LOCALAPPDATA 'AnyDesk') }
    if ($IncluirProgramData) {
        $pastas += [pscustomobject]@{ Nome = 'PROGRAMDATA'; Caminho = (Join-Path $env:ProgramData 'AnyDesk') }
    }
    $pastas = @($pastas | Where-Object { Test-Path -LiteralPath $_.Caminho })

    if ($pastas.Count -eq 0) { Write-Info 'Nenhuma pasta do AnyDesk encontrada.'; return [long]0 }

    foreach ($p in $pastas) {
        $s = Get-ChildItem -LiteralPath $p.Caminho -Recurse -File -Force -ErrorAction SilentlyContinue |
             Measure-Object -Property Length -Sum
        Write-Info ("{0,-13}: {1}  ({2} arquivos, {3})" -f $p.Nome, $p.Caminho, $s.Count, (Format-Tamanho ([long]$s.Sum)))
    }

    # AnyDesk em execucao trava os arquivos e regrava a config ao fechar.
    $proc = Get-Process -Name 'AnyDesk' -ErrorAction SilentlyContinue
    if ($proc) {
        if ($Forcar) {
            Write-Aviso 'Encerrando AnyDesk...'
            if (-not $SomenteRelatorio) {
                $proc | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 1500
            }
        } else {
            Write-Aviso 'AnyDesk esta em execucao - use -ForcarFecharAnyDesk ou feche manualmente.'
            Write-Aviso 'Etapa cancelada para nao corromper a configuracao.'
            return [long]0
        }
    }

    if ($Modo -eq 'Completo') {
        Write-Aviso 'MODO COMPLETO: o ID do AnyDesk e a senha de acesso nao supervisionado SERAO PERDIDOS.'
    }

    if ($SomenteRelatorio) {
        Write-Simul "Removeria dados do AnyDesk no modo $Modo."
        return [long]0
    }

    # Backup integral antes de remover - reversivel
    $liberado = [long]0
    try {
        $bkp = Join-Path $script:pastaExec 'backup-anydesk'
        New-Item -ItemType Directory -Path $bkp -Force -ErrorAction SilentlyContinue | Out-Null
        foreach ($p in $pastas) {
            Copy-Item -LiteralPath $p.Caminho -Destination (Join-Path $bkp $p.Nome) -Recurse -Force -ErrorAction SilentlyContinue
        }
        Protect-PastaBackup -Caminho $bkp
        Write-Ok "Backup do AnyDesk em: $bkp"
    } catch { Write-Aviso "Backup do AnyDesk falhou: $($_.Exception.Message)" }

    foreach ($p in $pastas) {
        if ($Modo -eq 'SomenteLogs') {
            # Preserva *.conf (ID, senha, config). Remove logs e miniaturas.
            foreach ($filtro in @('*.trace', '*.log', '*.old', '*.bak')) {
                $liberado += Remove-Files -Pasta $p.Caminho -Filtro $filtro
            }
            foreach ($sub in @('chat', 'thumbnails', 'msg_thumbnails', 'incoming', 'video')) {
                $alvo = Join-Path $p.Caminho $sub
                if (Test-Path -LiteralPath $alvo) { $liberado += Remove-Files -Pasta $alvo }
            }
        } else {
            $tam = [long](Get-ChildItem -LiteralPath $p.Caminho -Recurse -File -Force -ErrorAction SilentlyContinue |
                          Measure-Object -Property Length -Sum).Sum
            try {
                Remove-Item -LiteralPath $p.Caminho -Recurse -Force -ErrorAction Stop
                $liberado += $tam
                Write-Ok "Removido: $($p.Caminho)"
            } catch {
                Write-Falha "Falha ao remover $($p.Caminho): $($_.Exception.Message)"
            }
        }
    }

    Write-Ok "AnyDesk ($Modo): $(Format-Tamanho $liberado) liberados."
    if ($Modo -eq 'Completo') {
        Write-Aviso 'Ao abrir o AnyDesk sera gerado um ID NOVO. Reconfigure a senha de acesso.'
        Write-Info  "Para desfazer: copie de volta $($script:pastaExec)\backup-anydesk"
    }
    return [long]$liberado
}

# =========================================================================
# REGIAO: INICIALIZACAO
# =========================================================================

function Test-Excecao {
    param([string]$Nome, [string]$Comando)
    foreach ($exc in $script:excecoes) {
        if ($Nome    -like "*$exc*") { return $true }
        if ($Comando -like "*$exc*") { return $true }
    }
    return $false
}

function Get-ItensInicializacao {
    $origens = @(
        @{ RunKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
           ApprovalKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
           Label = 'HKCU' },
        @{ RunKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
           ApprovalKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
           Label = 'HKLM' },
        @{ RunKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
           ApprovalKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
           Label = 'HKLM32' }
    )

    $psProps = @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider')
    $itens = @()

    foreach ($origem in $origens) {
        if (-not (Test-Path $origem.RunKey)) { continue }
        $props = Get-ItemProperty -Path $origem.RunKey -ErrorAction SilentlyContinue
        if (-not $props) { continue }

        $props.PSObject.Properties |
            Where-Object { $_.Name -notin $psProps } |
            ForEach-Object {
                $itens += [pscustomobject]@{
                    Nome        = $_.Name
                    Comando     = [string]$_.Value
                    Origem      = $origem.Label
                    ApprovalKey = $origem.ApprovalKey
                    Protegido   = (Test-Excecao -Nome $_.Name -Comando ([string]$_.Value))
                }
            }
    }
    return $itens
}

function Invoke-EtapaInicializacao {
    $itens = @(Get-ItensInicializacao)
    if ($itens.Count -eq 0) { Write-Ok 'Nenhum item de inicializacao no registro.'; return [long]0 }

    $manter    = @($itens | Where-Object { $_.Protegido })
    $desativar = @($itens | Where-Object { -not $_.Protegido })

    Write-Host ('     {0,-38} {1,-8} {2}' -f 'Programa', 'Origem', 'Acao') -ForegroundColor White
    Write-Host ('     ' + ('-' * 60)) -ForegroundColor DarkGray
    foreach ($i in $itens) {
        $curto = if ($i.Nome.Length -gt 36) { $i.Nome.Substring(0, 33) + '...' } else { $i.Nome }
        if ($i.Protegido) {
            Write-Host ('     {0,-38} {1,-8} {2}' -f $curto, $i.Origem, 'MANTIDO') -ForegroundColor Green
        } else {
            Write-Host ('     {0,-38} {1,-8} {2}' -f $curto, $i.Origem, 'a desativar') -ForegroundColor Yellow
        }
    }
    Write-Host ''
    Write-Info "Mantidos: $($manter.Count)  |  Candidatos a desativacao: $($desativar.Count)"

    if ($desativar.Count -eq 0) { Write-Ok 'Nada a desativar.'; return [long]0 }
    if ($SomenteRelatorio) { Write-Simul "$($desativar.Count) item(ns) seriam desativados."; return [long]0 }

    # Confirmacao explicita: desativar startup as cegas ja derrubou antivirus,
    # audio e agente de ERP em campo. So aplica com aval do tecnico.
    if (-not $AplicarInicializacao) {
        if ($SemInteracao) {
            Write-Aviso 'Modo desatendido sem -AplicarInicializacao: nada foi alterado.'
            return [long]0
        }
        Write-Host ''
        Write-Aviso 'Revise a lista acima antes de confirmar.'
        $r = (Read-Host '  Desativar os itens marcados? (S/N)').Trim()
        if ($r -notmatch '^[SsYy]') { Write-Aviso 'Cancelado pelo operador.'; return [long]0 }
    }

    $binDesativado = [byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    $ok = 0; $falhas = 0
    foreach ($i in $desativar) {
        try {
            if (-not (Test-Path $i.ApprovalKey)) { New-Item -Path $i.ApprovalKey -Force | Out-Null }
            Set-ItemProperty -Path $i.ApprovalKey -Name $i.Nome -Value $binDesativado -Type Binary -ErrorAction Stop
            $ok++
        } catch { $falhas++; Write-Falha "Falha em $($i.Nome): $($_.Exception.Message)" }
    }

    Write-Ok "Desativados: $ok  |  Falhas: $falhas"
    Write-Info 'Para reativar: Gerenciador de Tarefas > Inicializar, ou RESTAURAR.cmd no log.'
    return [long]0
}

# =========================================================================
# REGIAO: OTIMIZACAO E AJUSTES
# =========================================================================

function Invoke-OtimizacaoDiscos {
    param([string[]]$Letras)
    foreach ($letra in $Letras) {
        Write-Etapa "Analisando unidade ${letra}:"
        $vol = Get-Volume -DriveLetter $letra -ErrorAction SilentlyContinue
        if (-not $vol) { Write-Aviso "Volume ${letra}: nao encontrado."; continue }

        $bl = Get-BitLockerVolume -MountPoint "${letra}:" -ErrorAction SilentlyContinue
        if ($bl -and $bl.LockStatus -eq 'Locked') {
            Write-Aviso "${letra}: bloqueado pelo BitLocker - pulado."; continue
        }

        $pctLivre = if ($vol.Size -gt 0) { ($vol.SizeRemaining / $vol.Size) * 100 } else { 0 }
        $tipo = Get-TipoMidia -Letra $letra
        Write-Info ("Tipo: $tipo  |  Livre: {0:N1}% ({1})" -f $pctLivre, (Format-Tamanho $vol.SizeRemaining))

        if ($SomenteRelatorio) { Write-Simul "Otimizaria ${letra}: como $tipo."; continue }

        try {
            if ($tipo -eq 'HDD') {
                if ($pctLivre -lt 15) {
                    Write-Aviso "${letra}: com menos de 15% livre - desfragmentacao pulada (risco de falhar)."
                    continue
                }
                Write-Info 'Executando desfragmentacao... pode levar varios minutos.'
                Optimize-Volume -DriveLetter $letra -Defrag -NormalPriority -ErrorAction Stop
                Write-Ok "Desfragmentacao concluida em ${letra}:"
            } else {
                Write-Info 'Executando TRIM (ReTrim)...'
                Optimize-Volume -DriveLetter $letra -ReTrim -NormalPriority -ErrorAction Stop
                Write-Ok "TRIM concluido em ${letra}:"
                if ($tipo -eq 'Desconhecido') {
                    Write-Info 'Tipo de midia nao identificado; TRIM aplicado por seguranca (nunca danifica).'
                }
            }
        } catch {
            Write-Falha "Nao foi possivel otimizar ${letra}: $($_.Exception.Message)"
        }
    }
    return [long]0
}

# =========================================================================
# TECLADO MIDI (CONTROLADOR USB) NAO FUNCIONA
# =========================================================================
# O diagnostico aqui nao e' por sintoma: e' por camada. A pergunta que
# resolve o caso e' UMA - o teclado esta chegando no Windows?
#
# Se chegar, o problema e' configuracao do programa (VMPK, DAW, o que for) e
# nao adianta mexer em driver. Se nao chegar, e' cabo/porta/driver e nao
# adianta mexer no programa. Por isso a ferramenta ABRE a porta MIDI e LE o
# que o teclado manda: da para ver a nota, a forca e o canal na tela.
#
# Duas coisas que quase ninguem sabe e explicam a maioria dos chamados:
#   1. porta MIDI no Windows e' EXCLUSIVA - so um programa por vez. Uma
#      instancia travada do proprio programa segura a porta e a nova nao abre;
#   2. programas como o VMPK leem a lista de portas UMA VEZ, ao abrir. Teclado
#      conectado depois nao aparece, e teclado que mudou de porta USB pode
#      trocar de nome - a conexao salva aponta para um nome que nao existe
#      mais. E' a causa classica do "parou de funcionar do nada".

function Initialize-ApiMIDI {
    <# Carrega o acesso a winmm.dll, que e' a mesma API que os programas usam. #>
    if ('MidiSuporteADV' -as [type]) { return $true }
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class MidiSuporteADV
{
    public delegate void MidiInProc(IntPtr h, uint msg, IntPtr inst, IntPtr p1, IntPtr p2);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct MIDIINCAPS {
        public ushort wMid; public ushort wPid; public uint vDriverVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string szPname;
        public uint dwSupport;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct MIDIOUTCAPS {
        public ushort wMid; public ushort wPid; public uint vDriverVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string szPname;
        public ushort wTechnology; public ushort wVoices; public ushort wNotes;
        public ushort wChannelMask; public uint dwSupport;
    }

    [DllImport("winmm.dll")] public static extern uint midiInGetNumDevs();
    [DllImport("winmm.dll")] public static extern uint midiOutGetNumDevs();
    [DllImport("winmm.dll", EntryPoint = "midiInGetDevCapsW", CharSet = CharSet.Unicode)]
    public static extern uint midiInGetDevCaps(UIntPtr id, ref MIDIINCAPS caps, uint cb);
    [DllImport("winmm.dll", EntryPoint = "midiOutGetDevCapsW", CharSet = CharSet.Unicode)]
    public static extern uint midiOutGetDevCaps(UIntPtr id, ref MIDIOUTCAPS caps, uint cb);
    [DllImport("winmm.dll")] public static extern uint midiOutOpen(out IntPtr h, uint id, IntPtr cb, IntPtr inst, uint flags);
    [DllImport("winmm.dll")] public static extern uint midiOutShortMsg(IntPtr h, uint msg);
    [DllImport("winmm.dll")] public static extern uint midiOutReset(IntPtr h);
    [DllImport("winmm.dll")] public static extern uint midiOutClose(IntPtr h);
    [DllImport("winmm.dll")] public static extern uint midiInOpen(out IntPtr h, uint id, MidiInProc cb, IntPtr inst, uint flags);
    [DllImport("winmm.dll")] public static extern uint midiInStart(IntPtr h);
    [DllImport("winmm.dll")] public static extern uint midiInStop(IntPtr h);
    [DllImport("winmm.dll")] public static extern uint midiInReset(IntPtr h);
    [DllImport("winmm.dll")] public static extern uint midiInClose(IntPtr h);

    // A referencia do delegate precisa ficar viva num campo estatico. Se ficar
    // so na pilha, o coletor de lixo recolhe e o Windows passa a chamar um
    // endereco morto - o processo cai no meio do teste.
    private static MidiInProc _cb;
    private static IntPtr _h = IntPtr.Zero;
    private static List<string> _msgs = new List<string>();
    private static object _trava = new object();
    public static int Total = 0;

    public static string NomeEntrada(int id) {
        MIDIINCAPS c = new MIDIINCAPS();
        uint r = midiInGetDevCaps((UIntPtr)id, ref c, (uint)Marshal.SizeOf(typeof(MIDIINCAPS)));
        return (r == 0) ? c.szPname : "";
    }
    public static string NomeSaida(int id) {
        MIDIOUTCAPS c = new MIDIOUTCAPS();
        uint r = midiOutGetDevCaps((UIntPtr)id, ref c, (uint)Marshal.SizeOf(typeof(MIDIOUTCAPS)));
        return (r == 0) ? c.szPname : "";
    }

    // Abre e fecha na hora: e' exatamente o que o programa faz. O codigo de
    // erro diz se a porta esta livre ou ja tomada por outro.
    public static uint TestarPorta(int id) {
        IntPtr h;
        uint r = midiInOpen(out h, (uint)id, null, IntPtr.Zero, 0);
        if (r == 0) { midiInClose(h); }
        return r;
    }

    // Mesmo teste, do lado da SAIDA, e sem tocar nota nenhuma. Serve para
    // separar "programa segurando a entrada" de "cabo/porta/driver": se a
    // saida abre e a entrada nao, o aparelho esta inteiro.
    public static uint TestarSaida(int id) {
        IntPtr h;
        uint r = midiOutOpen(out h, (uint)id, IntPtr.Zero, IntPtr.Zero, 0);
        if (r == 0) { midiOutClose(h); }
        return r;
    }

    private static string Nota(int n) {
        string[] nomes = { "Do", "Do#", "Re", "Re#", "Mi", "Fa", "Fa#", "Sol", "Sol#", "La", "La#", "Si" };
        return nomes[n % 12] + (n / 12 - 1).ToString();
    }

    private static void Receber(IntPtr h, uint msg, IntPtr inst, IntPtr p1, IntPtr p2) {
        if (msg != 0x3C3) { return; }   // MIM_DATA
        int dw = (int)(p1.ToInt64() & 0xFFFFFF);
        int status = dw & 0xFF, d1 = (dw >> 8) & 0xFF, d2 = (dw >> 16) & 0xFF;
        int canal = (status & 0x0F) + 1, tipo = status & 0xF0;
        string t;
        if (tipo == 0x90 && d2 > 0)                     t = "tecla PRESSIONADA  " + Nota(d1) + " (nota " + d1 + ")  forca " + d2;
        else if (tipo == 0x80 || (tipo == 0x90 && d2 == 0)) t = "tecla SOLTA        " + Nota(d1) + " (nota " + d1 + ")";
        else if (tipo == 0xB0)                          t = "controle " + d1 + " = " + d2 + " (botao, knob ou pedal)";
        else if (tipo == 0xE0)                          t = "roda de afinacao (pitch bend)";
        else if (tipo == 0xD0)                          t = "pressao (aftertouch)";
        else if (tipo == 0xC0)                          t = "troca de timbre (program change " + d1 + ")";
        else                                            t = "mensagem 0x" + status.ToString("X2");
        lock (_trava) { Total++; if (_msgs.Count < 30) { _msgs.Add(t + "  |  canal " + canal); } }
    }

    public static uint Abrir(int id) {
        lock (_trava) { _msgs.Clear(); Total = 0; }
        _cb = new MidiInProc(Receber);
        uint r = midiInOpen(out _h, (uint)id, _cb, IntPtr.Zero, 0x00030000);  // CALLBACK_FUNCTION
        if (r != 0) { _h = IntPtr.Zero; _cb = null; return r; }
        return midiInStart(_h);
    }
    public static void Fechar() {
        if (_h != IntPtr.Zero) {
            midiInStop(_h); midiInReset(_h); midiInClose(_h); _h = IntPtr.Zero;
        }
        _cb = null;
    }
    public static string[] Mensagens() { lock (_trava) { return _msgs.ToArray(); } }

    // Toca um arpejo pela saida MIDI escolhida. E' o mesmo caminho que o
    // programa usa para soar: porta MIDI de saida -> sintetizador -> placa de
    // som. Se sair som daqui, a cadeia de audio inteira esta boa.
    public static uint Tocar(int id) {
        IntPtr h;
        uint r = midiOutOpen(out h, (uint)id, IntPtr.Zero, IntPtr.Zero, 0);
        if (r != 0) { return r; }
        midiOutShortMsg(h, 0x0000C0);                 // timbre 0 = piano, canal 1
        int[] notas = { 60, 64, 67, 72 };             // do - mi - sol - do
        foreach (int n in notas) {
            midiOutShortMsg(h, (uint)(0x90 | (n << 8) | (110 << 16)));
            System.Threading.Thread.Sleep(420);
            midiOutShortMsg(h, (uint)(0x80 | (n << 8)));
        }
        System.Threading.Thread.Sleep(300);
        midiOutReset(h); midiOutClose(h);
        return 0;
    }
}
'@ -ErrorAction Stop
        return $true
    } catch {
        Write-Falha "Nao foi possivel carregar a API de MIDI do Windows: $($_.Exception.Message)"
        return $false
    }
}

function Get-ErroMIDI {
    <#
      Traducao dos codigos do winmm que interessam no diagnostico.

      ATENCAO ao codigo 7. O nome dele na documentacao e MMSYSERR_NOMEM, e a
      mensagem que o proprio Windows devolve e "nao ha memoria suficiente para
      esta tarefa; feche um ou mais aplicativos". Isso e' MENTIRA no caso de
      MIDI: o driver wdmaud devolve 7 - e nao o 4 (MMSYSERR_ALLOCATED), que
      seria o correto - quando a porta de ENTRADA ja esta aberta por outro
      processo. Visto em campo em 29/07/2026: entrada dava 7 com o sforzando
      aberto e passou a dar 0 assim que ele foi fechado, com a memoria da
      maquina inteira livre. Quem seguir a mensagem do Windows vai procurar
      memoria e nao vai achar nada.
    #>
    param([uint32]$Codigo)
    switch ($Codigo) {
        0  { 'porta livre' }
        1  { 'erro generico do driver' }
        2  { 'porta nao existe mais (o dispositivo saiu)' }
        4  { 'PORTA OCUPADA por outro programa' }
        5  { 'identificador invalido' }
        6  { 'sem driver instalado' }
        7  { 'PORTA OCUPADA por outro programa (o Windows chama isso de "sem memoria")' }
        11 { 'parametro invalido' }
        default { "codigo $Codigo" }
    }
}

function Test-PortaMIDIOcupada {
    <# Os dois codigos que, na pratica, significam "tem programa segurando". #>
    param([uint32]$Codigo)
    return ($Codigo -eq 4 -or $Codigo -eq 7)
}

function Get-ProgramasDeAudio {
    <#
      Candidatos a estar segurando a porta. Nao da para perguntar ao Windows
      "quem abriu esta porta MIDI" - a API nao conta. Entao listamos os
      programas de audio/MIDI que estao rodando, que na pratica resolve: em
      99% dos casos e' uma instancia travada do proprio programa.
    #>
    $conhecidos = @(
        'vmpk', 'reaper', 'ableton', 'live', 'flstudio', 'fl64', 'cubase', 'nuendo',
        'studioone', 'protools', 'cakewalk', 'sonar', 'bandlab', 'musescore', 'sibelius',
        'finale', 'guitarpro', 'kontakt', 'serum', 'omnisphere', 'midiox', 'midi-ox',
        'loopmidi', 'loopbe', 'rtpmidi', 'synthfont', 'coolsoft', 'virtualmidi',
        'audacity', 'garageband', 'mixcraft', 'waveform', 'tracktion', 'lmms',
        'pianoteq', 'sforzando', 'vst', 'daw', 'midi'
    )
    $achados = New-Object System.Collections.Generic.List[object]
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $nome = $p.ProcessName.ToLower()
        foreach ($c in $conhecidos) {
            if ($nome -like "*$c*") {
                $achados.Add([pscustomobject]@{ Nome = $p.ProcessName; Id = $p.Id; Titulo = $p.MainWindowTitle })
                break
            }
        }
    }
    return $achados
}

$script:Drivers32MIDI = @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32'
)

function Get-SlotsMIDI {
    <#
      O Windows tem, ate hoje, DEZ vagas para driver MIDI legado no registro:
      os valores midi, midi1 ... midi9 em Drivers32. Cada porta de cada
      aparelho que ja foi conectado ocupa uma vaga - E NAO DEVOLVE quando o
      aparelho e' desconectado.

      Quando as dez enchem, o proximo teclado plugado nao consegue iniciar e
      aparece no Gerenciador com "Codigo 10 - nao pode iniciar". Nao ha
      mensagem falando de limite: o teclado simplesmente nao funciona, e o
      programa nao mostra porta nenhuma para escolher.

      Teclado com duas portas (teclado + controles) come DUAS vagas, entao o
      limite chega mais rapido do que parece.
    #>
    $ocupadas = New-Object System.Collections.Generic.List[object]
    foreach ($raiz in $script:Drivers32MIDI) {
        if (-not (Test-Path -LiteralPath $raiz)) { continue }
        $item = Get-Item -LiteralPath $raiz -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        foreach ($nome in @($item.Property)) {
            if ($nome -notmatch '^midi(\d?)$') { continue }
            $valor = (Get-ItemProperty -LiteralPath $raiz -Name $nome -ErrorAction SilentlyContinue).$nome
            $ocupadas.Add([pscustomobject]@{ Raiz = $raiz; Nome = $nome; Valor = [string]$valor })
        }
    }
    return $ocupadas
}

function Get-PortasMIDIFantasma {
    <# Portas MIDI registradas de aparelhos que nao estao mais conectados. #>
    $lista = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($d in @(Get-PnpDevice -Class 'SoftwareDevice' -ErrorAction Stop)) {
            if ($d.InstanceId -notlike 'SWD\MMDEVAPI\MIDI*') { continue }
            if ($d.Present) { continue }
            $lista.Add($d)
        }
        foreach ($d in @(Get-PnpDevice -Class 'MEDIA' -ErrorAction Stop)) {
            if ($d.Present) { continue }
            if ($d.InstanceId -notlike 'USB\*') { continue }
            $lista.Add($d)
        }
    } catch { }
    return $lista
}

function Clear-VagasMIDI {
    <#
      Libera as vagas apagando os valores midi1..midi9 do Drivers32, nas duas
      visoes do registro (64 e 32 bits). O valor "midi" (sem numero) fica: e' o
      do proprio Windows.

      Isso nao desinstala driver nenhum. As vagas sao reconstruidas na proxima
      vez que cada aparelho for conectado - so os aparelhos que existem de
      verdade voltam a ocupar lugar. Uma copia .reg vai para a pasta de log
      antes de qualquer alteracao.
    #>
    $apagados = 0
    foreach ($raiz in $script:Drivers32MIDI) {
        if (-not (Test-Path -LiteralPath $raiz)) { continue }
        $marca = if ($raiz -match 'WOW6432Node') { '32bits' } else { '64bits' }
        $bkp = Join-Path $script:pastaExec "Drivers32_$marca.reg"
        $caminhoReg = ($raiz -replace '^HKLM:\\', 'HKLM\')
        & reg.exe export $caminhoReg $bkp /y 2>&1 | Out-Null
        if (Test-Path -LiteralPath $bkp) { Write-Info ("Copia de seguranca: $bkp") }
        else {
            Write-Falha "Nao consegui guardar a copia de $raiz - nada foi alterado ali."
            continue
        }

        $item = Get-Item -LiteralPath $raiz -ErrorAction SilentlyContinue
        foreach ($nome in @($item.Property)) {
            if ($nome -notmatch '^midi\d$') { continue }   # so os numerados
            $valor = (Get-ItemProperty -LiteralPath $raiz -Name $nome -ErrorAction SilentlyContinue).$nome
            try {
                Remove-ItemProperty -LiteralPath $raiz -Name $nome -Force -ErrorAction Stop
                Write-Ok "Vaga liberada: $nome (era $valor)"
                $apagados++
            } catch {
                Write-Aviso "Nao consegui apagar $nome - $($_.Exception.Message)"
            }
        }
    }
    return $apagados
}

function Test-CadeiaDeAudio {
    <#
      A metade que falta do problema: o teclado pode estar chegando e mesmo
      assim nao sair som. O VMPK nao gera audio sozinho - ele manda MIDI para
      uma SAIDA (normalmente o Microsoft GS Wavetable Synth), e o sintetizador
      e' que toca na placa de som. Cada elo dessa corrente pode quebrar.
    #>
    $problemas = 0

    foreach ($svc in @('Audiosrv', 'AudioEndpointBuilder')) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if (-not $s) { continue }
        if ($s.Status -ne 'Running') {
            Write-Falha "Servico de audio '$svc' esta $($s.Status) - sem ele nao sai som nenhum."
            $problemas++
        } else { Write-Ok "Servico de audio '$svc' rodando." }
    }

    # Sintetizador do Windows: se a entrada some do Drivers32, o programa fica
    # sem para onde mandar o MIDI e nao sai som.
    $d32 = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32'
    $mm  = (Get-ItemProperty -LiteralPath $d32 -Name 'midimapper' -ErrorAction SilentlyContinue).midimapper
    if ($mm) { Write-Ok "Mapeador MIDI do Windows: $mm" }
    else {
        Write-Aviso 'Mapeador MIDI (midimapper) ausente no Drivers32.'
        $problemas++
    }

    # Saidas de audio ativas. Padrao apontando para HDMI/monitor sem som e'
    # causa comum de "parou de tocar do nada" depois de mexer em cabo/monitor.
    try {
        $raiz = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render'
        $ativas = New-Object System.Collections.Generic.List[string]
        foreach ($k in @(Get-ChildItem -LiteralPath $raiz -ErrorAction SilentlyContinue)) {
            $estado = (Get-ItemProperty -LiteralPath $k.PSPath -Name 'DeviceState' -ErrorAction SilentlyContinue).DeviceState
            if ($estado -ne 1) { continue }   # 1 = ativo
            $props = Join-Path $k.PSPath 'Properties'
            $nome = (Get-ItemProperty -LiteralPath $props -Name '{a45c254e-df1c-4efd-8020-67d146a850e0},2' -ErrorAction SilentlyContinue).'{a45c254e-df1c-4efd-8020-67d146a850e0},2'
            if ($nome) { $ativas.Add([string]$nome) }
        }
        if ($ativas.Count -eq 0) {
            Write-Falha 'Nenhuma saida de audio ATIVA no Windows.'
            $problemas++
        } else {
            Write-Info 'Saidas de audio ativas:'
            foreach ($a in $ativas) { Write-Dest ("   $a") }
            $soHdmi = -not (@($ativas | Where-Object { $_ -notmatch '(?i)hdmi|display|monitor|tv' }).Count -gt 0)
            if ($soHdmi) {
                Write-Aviso 'So ha saida por HDMI/monitor. Se o monitor nao tem caixa, nao sai som.'
                $problemas++
            }
        }
    } catch { }

    return $problemas
}

function Show-ConfiguracaoVMPK {
    <#
      O VMPK guarda as configuracoes no registro (Qt/QSettings). O que
      interessa sao as conexoes salvas - entrada E saida: se apontarem para um
      nome de porta que nao existe mais, o programa abre normal e simplesmente
      nao recebe nem emite nada, sem mensagem de erro nenhuma.

      Nao adivinhamos o nome dos valores: lemos tudo o que estiver la e
      comparamos com as portas reais.
    #>
    param([string[]]$PortasReais)

    # O VMPK grava em HKCU\Software\vmpk.sourceforge.net\VMPK (nome da
    # organizacao no Qt). Versoes antigas usaram so "VMPK".
    $raizes = @('HKCU:\Software\vmpk.sourceforge.net', 'HKCU:\Software\VMPK', 'HKCU:\Software\vmpk')
    $achou = $false
    $suspeitas = New-Object System.Collections.Generic.List[string]

    foreach ($raiz in $raizes) {
        if (-not (Test-Path -LiteralPath $raiz)) { continue }
        $achou = $true
        $chaves = @($raiz) + @(Get-ChildItem -LiteralPath $raiz -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $_.PSPath })
        foreach ($ch in $chaves) {
            $item = Get-Item -LiteralPath $ch -ErrorAction SilentlyContinue
            if (-not $item) { continue }
            foreach ($nome in @($item.Property)) {
                if ($nome -notmatch '(?i)in|out|port|driver|connect|midi|thru|channel|omni') { continue }
                $valor = (Get-ItemProperty -LiteralPath $ch -Name $nome -ErrorAction SilentlyContinue).$nome
                if ($null -eq $valor) { continue }
                $curto = ($ch -replace '^.*\\Software\\', '')
                Write-Info ("   $curto\$nome = $valor")
                # Qualquer valor que pareca ser "nome de porta salva" - entrada
                # ou saida - vai para conferencia contra as portas reais.
                if ($nome -match '(?i)(connection|port|device)' -and $valor -is [string] -and $valor.Trim()) {
                    $suspeitas.Add([string]$valor)
                }
            }
        }
    }

    if (-not $achou) {
        Write-Info 'Nenhuma configuracao do VMPK encontrada no registro deste usuario.'
        Write-Info '(Se o VMPK roda com outro usuario do Windows, rode o menu com esse usuario.)'
        return $null
    }

    # Entrada habilitada e porta em branco: o VMPK abre normal, o teclado
    # aparece na lista do Windows, e nada acontece ao tocar. Acontece quando o
    # programa foi aberto sem o teclado ligado - ele limpa a escolha.
    $inHab = $null; $inPorta = $null
    foreach ($raiz in $raizes) {
        foreach ($sub in @("$raiz\VMPK\Connections", "$raiz\Connections")) {
            if (-not (Test-Path -LiteralPath $sub)) { continue }
            $pp = Get-ItemProperty -LiteralPath $sub -ErrorAction SilentlyContinue
            if ($null -ne $pp.InEnabled) { $inHab = [string]$pp.InEnabled }
            if ($null -ne $pp.InPort)    { $inPorta = [string]$pp.InPort }
        }
    }
    if ($inHab -match '(?i)true' -and -not ($inPorta -and $inPorta.Trim())) {
        Write-Host ''
        Write-Falha 'O VMPK esta com a entrada MIDI habilitada e NENHUMA porta escolhida.'
        Write-Info  'E por isso que as teclas nao fazem nada: ele nao esta escutando ninguem.'
        Write-Info  'Isso acontece quando o programa e aberto sem o teclado conectado - a'
        Write-Info  'escolha se perde. Depois de o teclado voltar a aparecer, refaca em'
        Write-Info  'Editar > Conexoes MIDI.'
        Add-Alerta  'VMPK: entrada MIDI habilitada mas sem porta selecionada.'
    }

    $mortas = New-Object System.Collections.Generic.List[string]
    foreach ($s in ($suspeitas | Sort-Object -Unique)) {
        $bate = $false
        foreach ($p in $PortasReais) { if ($p -and ($p -eq $s -or $s -like "*$p*" -or $p -like "*$s*")) { $bate = $true } }
        if (-not $bate) { $mortas.Add($s) }
    }
    if ($mortas.Count -gt 0) {
        Write-Host ''
        foreach ($s in $mortas) {
            Write-Falha "O VMPK tem salva a porta '$s', e nao existe porta com esse nome agora."
        }
        Write-Info 'E a causa classica do "parou de funcionar do nada": o teclado mudou de'
        Write-Info 'porta USB, ou foi ligado depois de abrir o programa, o nome mudou, e o'
        Write-Info 'VMPK segue apontando para o nome antigo. Ele nao avisa - so fica mudo.'
        Add-Alerta ("VMPK aponta para porta(s) MIDI que nao existem mais: " + ($mortas -join ', ') + ". Refazer em Editar > Conexoes MIDI.")
        return $mortas[0]
    }
    return $null
}

function Repair-MIDI {
    if ($SomenteRelatorio) {
        Write-Simul 'Verificaria as portas MIDI, quem esta segurando, e leria o teclado ao vivo.'
        return [long]0
    }

    Write-Titulo 'TECLADO MIDI (CONTROLADOR USB) NAO FUNCIONA'
    Write-Info 'A pergunta que resolve o caso: o teclado esta chegando no Windows?'
    Write-Info 'Se chegar, o problema e do programa. Se nao chegar, e cabo/porta/driver.'

    if (-not (Initialize-ApiMIDI)) { return [long]0 }
    $corrigidos = 0

    # --- 1. portas que os programas enxergam ------------------------------
    Write-Host ''
    Write-Etapa '1/7  Portas MIDI que o Windows oferece aos programas'

    $qtdIn  = [int][MidiSuporteADV]::midiInGetNumDevs()
    $qtdOut = [int][MidiSuporteADV]::midiOutGetNumDevs()
    $entradas = New-Object System.Collections.Generic.List[object]

    if ($qtdIn -eq 0) {
        Write-Falha 'NENHUMA entrada MIDI. O Windows nao esta vendo o teclado.'
        Write-Info  'Nao adianta mexer no programa: nao ha o que ele selecionar.'
    } else {
        for ($i = 0; $i -lt $qtdIn; $i++) {
            $nome = [MidiSuporteADV]::NomeEntrada($i)
            $entradas.Add([pscustomobject]@{ Id = $i; Nome = $nome })
            Write-Ok ("ENTRADA  [$i]  $nome")
        }
    }
    for ($i = 0; $i -lt $qtdOut; $i++) {
        Write-Info ("SAIDA    [$i]  " + [MidiSuporteADV]::NomeSaida($i))
    }
    if ($qtdOut -eq 0) {
        Write-Aviso 'Nenhuma saida MIDI - o programa nao tem para onde mandar o som.'
    }

    # --- 2. o dispositivo no Gerenciador ----------------------------------
    Write-Host ''
    Write-Etapa '2/7  O dispositivo no Gerenciador de Dispositivos'
    $comProblema = New-Object System.Collections.Generic.List[object]
    try {
        $devs = @(Get-PnpDevice -ErrorAction Stop | Where-Object {
            $_.Class -in @('MEDIA', 'AudioEndpoint', 'USB', 'SoftwareDevice') -and
            ($_.FriendlyName -match '(?i)midi|keyboard controller|usb audio|audio device|keystation|mpk|launchkey|oxygen|impulse|nektar|arturia|akai|novation|m-audio|roland|yamaha|casio|korg|alesis|nord|studiologic|worlde|midiplus')
        })
        if ($devs.Count -eq 0) {
            Write-Aviso 'Nenhum dispositivo com cara de teclado MIDI no Gerenciador.'
            Write-Info  'Se o teclado esta ligado por USB, isso aponta para CABO ou PORTA.'
        }
        foreach ($d in $devs) {
            $txt = "$($d.FriendlyName)  [$($d.Status)]"
            if ($d.Status -eq 'OK') { Write-Ok $txt }
            else {
                Write-Falha $txt
                $comProblema.Add($d)
                $prob = (Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue).Data
                if ($prob) {
                    $exp = switch ([int]$prob) {
                        10 { 'o dispositivo nao consegue iniciar (driver ou hardware)' }
                        28 { 'driver nao instalado' }
                        43 { 'o Windows parou o dispositivo por erro relatado' }
                        45 { 'o dispositivo nao esta conectado agora' }
                        default { "codigo de problema $prob" }
                    }
                    Write-Info ("   $exp")
                }
            }
        }
    } catch {
        Write-Aviso "Nao foi possivel consultar o Gerenciador de Dispositivos: $($_.Exception.Message)"
    }

    # --- 2b. as dez vagas de MIDI do Windows ------------------------------
    Write-Host ''
    $vagas = @(Get-SlotsMIDI)
    $vagas64 = @($vagas | Where-Object { $_.Raiz -notmatch 'WOW6432Node' })
    $usadas = $vagas64.Count
    $fantasmas = @(Get-PortasMIDIFantasma)

    Write-Info "Vagas de driver MIDI do Windows: $usadas de 10 em uso."
    foreach ($v in $vagas64) { Write-Info ("   $($v.Nome) = $($v.Valor)") }

    $limiteCheio = ($usadas -ge 9)
    $codigo10 = @($comProblema | Where-Object {
        $p = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue).Data
        $p -eq 10
    })

    if ($fantasmas.Count -gt 0) {
        Write-Aviso "$($fantasmas.Count) porta(s)/aparelho(s) MIDI registrado(s) que nao estao mais conectados:"
        foreach ($f in $fantasmas) { Write-Info ("   $($f.FriendlyName)") }
        Write-Info 'Cada um continua ocupando vaga. Teclado com duas portas ocupa duas.'
    }

    if ($limiteCheio -and $codigo10.Count -gt 0) {
        Write-Host ''
        Write-Falha 'ACHADO: as vagas de MIDI acabaram e por isso o teclado nao inicia.'
        Write-Info  'O Windows so tem dez vagas de driver MIDI, e elas nao sao devolvidas'
        Write-Info  'quando um aparelho e desconectado. Com as vagas cheias, o teclado novo'
        Write-Info  'aparece no Gerenciador com "Codigo 10 - nao pode iniciar" e nenhuma'
        Write-Info  'porta chega aos programas. Nao ha aviso nenhum sobre o limite.'
        Add-Alerta  'Vagas de driver MIDI do Windows esgotadas - teclado com Codigo 10.'
    } elseif ($limiteCheio) {
        Write-Aviso 'As vagas de MIDI estao quase cheias. Se um teclado novo nao iniciar, e isso.'
    }

    # --- 3. a porta esta livre? -------------------------------------------
    Write-Host ''
    Write-Etapa '3/7  A porta esta livre, ou ja tem programa segurando?'
    Write-Info 'Porta MIDI no Windows e EXCLUSIVA: so um programa por vez.'

    $ocupadas = New-Object System.Collections.Generic.List[object]
    foreach ($e in $entradas) {
        $r = [MidiSuporteADV]::TestarPorta([int]$e.Id)
        $txt = ("[$($e.Id)] $($e.Nome): " + (Get-ErroMIDI -Codigo $r))
        if ($r -eq 0) { Write-Ok $txt }
        else {
            Write-Falha $txt
            if (Test-PortaMIDIOcupada -Codigo $r) { $ocupadas.Add($e) }
        }
    }

    # A saida abrir e a entrada nao e' a assinatura de "programa segurando":
    # se fosse cabo, porta ou driver, as duas falhariam juntas.
    if ($ocupadas.Count -gt 0 -and $qtdOut -gt 0) {
        $saidaAbre = $false
        for ($i = 0; $i -lt $qtdOut; $i++) {
            if ([MidiSuporteADV]::TestarSaida($i) -eq 0) { $saidaAbre = $true; break }
        }
        if ($saidaAbre) {
            Write-Info 'A SAIDA MIDI abre normalmente e so a ENTRADA recusa. Isso descarta'
            Write-Info 'cabo, porta USB e driver: e programa segurando a entrada.'
        }
    }

    $progs = @(Get-ProgramasDeAudio)
    if ($progs.Count -gt 0) {
        Write-Host ''
        Write-Info 'Programas de audio/MIDI abertos agora:'
        foreach ($p in $progs) {
            $t = "   $($p.Nome) (PID $($p.Id))"
            if ($p.Titulo) { $t = "$t - $($p.Titulo)" }
            Write-Info $t
        }
        $vmpks = @($progs | Where-Object { $_.Nome -match '(?i)vmpk' })
        if ($vmpks.Count -gt 1) {
            Write-Falha "Ha $($vmpks.Count) instancias do VMPK abertas. A primeira segura a porta e as outras ficam mudas."
            Add-Alerta 'Mais de uma instancia do VMPK aberta - fechar todas e abrir uma so.'
        }
    }
    if ($ocupadas.Count -gt 0) {
        Write-Host ''
        Write-Info 'Feche o programa que esta usando o teclado e rode esta opcao de novo.'
        Write-Info 'O Windows nao diz quem abriu a porta - por isso a lista acima.'
        Write-Info 'Cuidado com os que ficam so no relogio, ao lado do horario: eles'
        Write-Info 'seguram a porta sem janela aparecendo na tela.'
        if ($progs.Count -gt 0) {
            Add-Alerta ('Entrada MIDI ocupada. Programas de audio abertos: ' + (($progs | ForEach-Object { $_.Nome }) -join ', ') + '. Fechar e testar de novo.')
        } else {
            Add-Alerta 'Entrada MIDI ocupada por algum programa, e nenhum conhecido foi encontrado aberto.'
        }
    }

    # --- 4. teste ao vivo --------------------------------------------------
    Write-Host ''
    Write-Etapa '4/7  Teste ao vivo: o teclado chega no Windows?'

    $recebeu = $false
    $testouAoVivo = $false
    $livres = @($entradas | Where-Object { [MidiSuporteADV]::TestarPorta([int]$_.Id) -eq 0 })

    if ($livres.Count -eq 0) {
        Write-Aviso 'Nenhuma porta livre para testar agora.'
    } elseif ($SemInteracao) {
        Write-Aviso 'Modo desatendido: o teste ao vivo precisa de alguem tocando o teclado.'
    } else {
        $alvo = $livres[0]
        if ($livres.Count -gt 1) {
            Write-Host ''
            foreach ($e in $livres) { Write-Host "     [$($e.Id)] $($e.Nome)" -ForegroundColor White }
            $esc = (Read-Host "  Qual porta e o seu teclado? (numero) [$($livres[0].Id)]").Trim()
            if ($esc) {
                $achado = $livres | Where-Object { [string]$_.Id -eq $esc } | Select-Object -First 1
                if ($achado) { $alvo = $achado }
            }
        }

        Write-Host ''
        Write-Info ("Escutando a porta [$($alvo.Id)] $($alvo.Nome).")
        Write-Host '  >> TOQUE ALGUMAS TECLAS DO TECLADO AGORA (15 segundos)...' -ForegroundColor Yellow

        $testouAoVivo = $true
        $r = [MidiSuporteADV]::Abrir([int]$alvo.Id)
        if ($r -ne 0) {
            Write-Falha ("Nao foi possivel abrir a porta: " + (Get-ErroMIDI -Codigo $r))
        } else {
            $fim = (Get-Date).AddSeconds(15)
            $ultimo = 0
            while ((Get-Date) -lt $fim) {
                Start-Sleep -Milliseconds 300
                $t = [MidiSuporteADV]::Total
                if ($t -gt $ultimo) {
                    $ultimo = $t
                    $fim = (Get-Date).AddSeconds(3)   # chegou algo: encerra logo
                }
            }
            [MidiSuporteADV]::Fechar()

            $msgs = [MidiSuporteADV]::Mensagens()
            if ($msgs.Count -gt 0) {
                $recebeu = $true
                Write-Ok "$([MidiSuporteADV]::Total) mensagem(ns) recebida(s) do teclado:"
                foreach ($m in $msgs) { Write-Dest ("   $m") }
                $canais = @($msgs | ForEach-Object { if ($_ -match 'canal (\d+)') { [int]$Matches[1] } } | Sort-Object -Unique)
                if ($canais.Count -gt 0) {
                    Write-Host ''
                    Write-Info ("O teclado esta enviando no canal MIDI: " + ($canais -join ', '))
                    if ($canais -notcontains 1) {
                        Write-Aviso 'O teclado NAO esta no canal 1, que e o que a maioria dos programas escuta.'
                        Write-Info  'Ou mude o canal no teclado para 1, ou ponha o programa em OMNI (todos).'
                        Add-Alerta ("Teclado enviando no canal " + ($canais -join ', ') + " - conferir o canal de entrada do programa.")
                    }
                }
            } else {
                Write-Falha 'Nada chegou. O teclado nao esta mandando nada para o Windows.'
            }
        }
    }

    # --- 5. saida de som ----------------------------------------------------
    Write-Host ''
    Write-Etapa '5/7  A outra metade: sai som?'
    Write-Info 'O VMPK nao gera audio sozinho. Ele manda MIDI para uma SAIDA (em geral o'
    Write-Info 'Microsoft GS Wavetable Synth), e o sintetizador e que toca na placa de som.'
    Write-Host ''
    $probAudio = Test-CadeiaDeAudio

    $ouviu = $null
    $saidas = @()
    for ($i = 0; $i -lt $qtdOut; $i++) { $saidas += [pscustomobject]@{ Id = $i; Nome = [MidiSuporteADV]::NomeSaida($i) } }

    if ($qtdOut -eq 0) {
        Write-Falha 'Nao ha saida MIDI nenhuma - o programa nao tem para onde mandar as notas.'
    } elseif (-not $SemInteracao) {
        $alvoOut = $saidas[0]
        $gs = $saidas | Where-Object { $_.Nome -match '(?i)wavetable|synth' } | Select-Object -First 1
        if ($gs) { $alvoOut = $gs }
        if ($saidas.Count -gt 1) {
            Write-Host ''
            foreach ($s in $saidas) { Write-Host "     [$($s.Id)] $($s.Nome)" -ForegroundColor White }
            $esc = (Read-Host "  Testar o som por qual saida? (numero) [$($alvoOut.Id)]").Trim()
            if ($esc) {
                $ach = $saidas | Where-Object { [string]$_.Id -eq $esc } | Select-Object -First 1
                if ($ach) { $alvoOut = $ach }
            }
        }
        Write-Host ''
        Write-Info ("Tocando do-mi-sol-do por: $($alvoOut.Nome)")
        Write-Host '  >> ESCUTE AGORA (deixe o volume audivel)...' -ForegroundColor Yellow
        $rt = [MidiSuporteADV]::Tocar([int]$alvoOut.Id)
        if ($rt -ne 0) {
            Write-Falha ("Nao foi possivel abrir a saida: " + (Get-ErroMIDI -Codigo $rt))
        } else {
            $r = (Read-Host '  Ouviu as quatro notas? (S/N)').Trim()
            $ouviu = ($r -match '^[Ss]')
            if ($ouviu) {
                Write-Ok 'A cadeia de som esta boa: MIDI de saida, sintetizador e placa de som.'
                Write-Info 'Se o VMPK nao emite som, e a SAIDA MIDI dele que esta errada.'
            } else {
                Write-Falha 'O som nao chega ate a caixa. O problema nao e do teclado.'
                Write-Info  'Confira, nesta ordem:'
                Write-Info  '   1. o volume do Windows e o mudo do proprio programa (mixer);'
                Write-Info  '   2. a saida padrao do Windows - fone, caixa, HDMI do monitor;'
                Write-Info  '   3. a opcao 40 do menu (Reparar Audio e Microfone) faz o resto.'
                Add-Alerta 'Saida de audio nao produz som nem pelo sintetizador do Windows - ver opcao 40.'
            }
        }
    }

    # --- 6. VMPK ------------------------------------------------------------
    Write-Host ''
    Write-Etapa '6/7  Configuracao salva do VMPK'
    $nomes = @($entradas | ForEach-Object { $_.Nome }) + @($saidas | ForEach-Object { $_.Nome })
    $entradaMorta = Show-ConfiguracaoVMPK -PortasReais $nomes

    # --- 7. correcoes --------------------------------------------------------
    Write-Host ''
    Write-Etapa '7/7  Correcoes'

    if ($recebeu) {
        Write-Ok 'O teclado CHEGA no Windows. Hardware, cabo e driver estao bons.'
        Write-Info 'O que falta e no programa. No VMPK, menu Editar > Conexoes MIDI'
        Write-Info '(Edit > MIDI Connections):'
        Write-Info '   1. marque "Habilitar entrada MIDI" (Enable MIDI input);'
        Write-Info '   2. em ENTRADA MIDI, escolha:'
        foreach ($e in $entradas) { Write-Dest ("        $($e.Nome)") }
        Write-Info '   3. em SAIDA MIDI, escolha:'
        foreach ($s in $saidas) { Write-Dest ("        $($s.Nome)") }
        if ($ouviu -eq $true) {
            $gsn = ($saidas | Where-Object { $_.Nome -match '(?i)wavetable|synth' } | Select-Object -First 1)
            if ($gsn) { Write-Info ("      (o teste de som passou por: $($gsn.Nome))") }
        }
        Write-Info '   4. deixe o canal de entrada em OMNI/todos, ou no canal que apareceu acima;'
        Write-Info '   5. o driver MIDI, nas duas pontas, deve estar em "Windows MM".'
        Write-Info ''
        Write-Info 'Importante: o VMPK le a lista de portas UMA VEZ, ao abrir. Conecte o'
        Write-Info 'teclado ANTES de abrir o programa, sempre. Se ja estava aberto, feche e'
        Write-Info 'abra de novo depois de conectar - so isso ja resolve muito caso.'
    } elseif ($qtdIn -eq 0) {
        Write-Falha 'O Windows nao ve o teclado. Nesta ordem:'
        Write-Info  '   1. TROQUE O CABO USB. Muito cabo so tem os fios de carga, sem dados -'
        Write-Info  '      o teclado acende e nao transmite nada. E a causa numero 1;'
        Write-Info  '   2. ligue direto numa porta do computador, sem hub e sem extensao;'
        Write-Info  '   3. tente uma porta USB de tras (traseiras costumam ser mais estaveis);'
        Write-Info  '   4. se o teclado tiver chave USB/MIDI ou fonte externa, confira;'
        Write-Info  '   5. veja se o fabricante pede driver proprio (muitos sao plug-and-play).'
    } elseif (-not $testouAoVivo) {
        Write-Info 'O teste ao vivo nao foi feito nesta execucao, entao nao da para afirmar'
        Write-Info 'se o teclado chega ou nao. Rode de novo e toque teclas quando for pedido.'
    } else {
        Write-Aviso 'Ha porta MIDI, mas nao chegou nota nenhuma no teste.'
        Write-Info  'Possiveis causas, em ordem: a porta escolhida no teste nao e a do teclado;'
        Write-Info  'o teclado esta em modo de transporte/local off; ou o cabo transmite mal.'
    }

    # --- liberar as vagas de MIDI ------------------------------------------
    if (($limiteCheio -or $codigo10.Count -gt 0) -and -not $SemInteracao) {
        Write-Host ''
        Write-Host '  ' -NoNewline
        Write-Host 'LIBERAR AS VAGAS DE MIDI' -ForegroundColor Yellow
        Write-Info 'Apaga os valores midi1..midi9 do registro (nas versoes 64 e 32 bits).'
        Write-Info 'O valor "midi", que e do proprio Windows, fica.'
        Write-Info 'Isso NAO desinstala driver: as vagas sao refeitas quando cada aparelho'
        Write-Info 'for conectado de novo - so os que existem de verdade voltam a ocupar.'
        Write-Info 'Uma copia .reg vai para a pasta de log antes.'
        Write-Info 'Depois: desconectar e reconectar o teclado (ou reiniciar o computador).'
        Write-Host ''
        $r = (Read-Host '  Liberar as vagas agora? (S/N) [S]').Trim()
        if (-not $r -or $r -match '^[Ss]') {
            $n = Clear-VagasMIDI
            if ($n -gt 0) {
                $corrigidos += $n
                Write-Ok "$n vaga(s) liberada(s)."

                # Tira tambem os registros dos aparelhos que nao existem mais,
                # senao eles reocupam vaga na proxima varredura.
                foreach ($f in $fantasmas) {
                    & pnputil /remove-device $f.InstanceId 2>&1 | Out-Null
                }
                if ($fantasmas.Count -gt 0) { Write-Info "$($fantasmas.Count) registro(s) de aparelho antigo removido(s)." }

                # Reinicia o teclado com problema, que e' o equivalente a
                # desconectar e reconectar sem levantar da cadeira.
                foreach ($d in $codigo10) {
                    try {
                        Disable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop
                        Start-Sleep -Seconds 2
                        Enable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop
                        Write-Ok "Reiniciado: $($d.FriendlyName)"
                    } catch {
                        Write-Aviso "Reinicie a mao (desconecte e reconecte o cabo): $($d.FriendlyName)"
                    }
                }
                & pnputil /scan-devices 2>&1 | Out-Null
                Start-Sleep -Seconds 3

                $agora = [int][MidiSuporteADV]::midiInGetNumDevs()
                Write-Host ''
                if ($agora -gt $qtdIn) {
                    Write-Ok "Resolvido: agora ha $agora entrada(s) MIDI (antes havia $qtdIn)."
                    for ($i = 0; $i -lt $agora; $i++) { Write-Dest ("   " + [MidiSuporteADV]::NomeEntrada($i)) }
                    Write-Info 'Abra o VMPK AGORA (com o teclado ja conectado) e escolha a entrada'
                    Write-Info 'em Editar > Conexoes MIDI.'
                } else {
                    Write-Aviso 'Ainda sem entrada MIDI nova nesta janela.'
                    Write-Info  'Desconecte e reconecte o cabo do teclado. Se nao resolver, REINICIE'
                    Write-Info  'o computador: as vagas so sao remontadas do zero na inicializacao.'
                    $script:precisaReiniciar = $true
                }
            }
        }
    }

    if ($null -ne $entradaMorta) {
        Write-Host ''
        Write-Info 'O VMPK tem uma entrada MIDI salva que nao existe mais. Da para limpar a'
        Write-Info 'configuracao de conexoes para ele perguntar de novo na proxima abertura.'
        Write-Info 'Uma copia do registro e guardada antes, na pasta de log.'
        if (-not $SemInteracao) {
            $r = (Read-Host '  Limpar as conexoes salvas do VMPK? (S/N) [N]').Trim()
            if ($r -match '^[Ss]') {
                if (@(Get-Process -Name 'vmpk' -ErrorAction SilentlyContinue).Count -gt 0) {
                    Write-Aviso 'O VMPK esta aberto - feche antes, senao ele regrava ao sair.'
                } else {
                    try {
                        $bkp = Join-Path $script:pastaExec 'VMPK.reg'
                        foreach ($rz in @('HKCU\Software\vmpk.sourceforge.net', 'HKCU\Software\VMPK')) {
                            if (Test-Path -LiteralPath ($rz -replace '^HKCU\\', 'HKCU:\')) {
                                & reg.exe export $rz $bkp /y 2>&1 | Out-Null
                                Write-Info ("Copia guardada em: $bkp")
                                break
                            }
                        }
                        foreach ($sub in @('HKCU:\Software\vmpk.sourceforge.net\VMPK\Connections',
                                           'HKCU:\Software\VMPK\vmpk\Connections',
                                           'HKCU:\Software\VMPK\VMPK\Connections')) {
                            if (Test-Path -LiteralPath $sub) {
                                Remove-Item -LiteralPath $sub -Recurse -Force -ErrorAction Stop
                                Write-Ok "Conexoes salvas removidas: $sub"
                                $corrigidos++
                            }
                        }
                        if ($corrigidos -eq 0) { Write-Aviso 'Nao achei a subchave de conexoes - nada foi removido.' }
                        else { Write-Info 'Abra o VMPK e refaca em Editar > Conexoes MIDI.' }
                    } catch {
                        Write-Falha "Nao foi possivel limpar: $($_.Exception.Message)"
                    }
                }
            }
        }
    }

    # economia de energia do USB: desliga o teclado sozinho depois de um tempo
    if (-not $SemInteracao) {
        Write-Host ''
        Write-Info 'O Windows pode desligar portas USB para economizar energia - o teclado'
        Write-Info 'para de responder depois de um tempo parado e so volta reconectando.'
        $r = (Read-Host '  Impedir que o Windows desligue as portas USB? (S/N) [S]').Trim()
        if (-not $r -or $r -match '^[Ss]') {
            $mexidos = 0
            try {
                $todos = @(Get-CimInstance -Namespace 'root\WMI' -ClassName 'MSPower_DeviceEnable' -ErrorAction Stop)
                foreach ($d in $todos) {
                    if ($d.InstanceName -notmatch '(?i)USB') { continue }
                    if (-not $d.Enable) { continue }
                    try {
                        Set-CimInstance -InputObject $d -Property @{ Enable = $false } -ErrorAction Stop
                        $mexidos++
                    } catch { }
                }
                if ($mexidos -gt 0) {
                    Write-Ok "$mexidos porta(s)/dispositivo(s) USB nao serao mais desligados para economizar energia."
                    $corrigidos += $mexidos
                } else {
                    Write-Info 'Nenhuma porta USB estava configurada para desligar. Nada a fazer.'
                }
            } catch {
                Write-Aviso "Nao foi possivel ajustar a economia de energia do USB: $($_.Exception.Message)"
            }
        }
    }

    # reabilitar o dispositivo com problema
    if ($comProblema.Count -gt 0 -and -not $SemInteracao) {
        Write-Host ''
        Write-Info "$($comProblema.Count) dispositivo(s) com problema no Gerenciador."
        $r = (Read-Host '  Desabilitar e reabilitar (equivale a desconectar e reconectar)? (S/N) [S]').Trim()
        if (-not $r -or $r -match '^[Ss]') {
            foreach ($d in $comProblema) {
                try {
                    Disable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop
                    Start-Sleep -Seconds 2
                    Enable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop
                    Write-Ok "Reiniciado: $($d.FriendlyName)"
                    $corrigidos++
                } catch {
                    Write-Aviso "Nao foi possivel reiniciar $($d.FriendlyName): $($_.Exception.Message)"
                    & pnputil /enable-device $d.InstanceId 2>&1 | Out-Null
                }
            }
            Write-Info 'Procurando dispositivos novos...'
            & pnputil /scan-devices 2>&1 | Out-Null
        }
    }

    # --- veredicto ----------------------------------------------------------
    Write-Host ''
    Write-Host ('  ' + ('-' * 66)) -ForegroundColor DarkCyan
    if ($recebeu -and $ouviu -eq $true) {
        Write-Ok 'VEREDICTO: entrada e saida do Windows estao BOAS.'
        Write-Info 'O teclado chega e o som sai. O que sobra e a configuracao das conexoes'
        Write-Info 'dentro do VMPK - refaca as duas pontas em Editar > Conexoes MIDI.'
    } elseif ($recebeu -and $ouviu -eq $false) {
        Write-Aviso 'VEREDICTO: o teclado chega, mas nao sai som.'
        Write-Info  'O controlador esta bom. O problema e na saida de audio da maquina -'
        Write-Info  'rode a opcao 40 (Reparar Audio e Microfone).'
    } elseif ($recebeu) {
        Write-Ok 'VEREDICTO: o teclado chega no Windows - o controlador esta bom.'
        Write-Info 'Ajuste a entrada MIDI dentro do programa.'
    } elseif ($qtdIn -eq 0) {
        Write-Falha 'VEREDICTO: o Windows nao ve o teclado. Comece pelo CABO USB.'
    } elseif (-not $testouAoVivo) {
        Write-Info 'VEREDICTO: o teclado aparece para o Windows, mas o teste ao vivo nao foi'
        Write-Info 'feito - rode de novo e toque algumas teclas quando for pedido.'
    } else {
        Write-Aviso 'VEREDICTO: ha porta MIDI, mas nada chegou no teste.'
    }
    if ($probAudio -gt 0) { Write-Aviso "$probAudio ponto(s) da cadeia de audio merecem atencao (acima)." }
    Write-Host ('  ' + ('-' * 66)) -ForegroundColor DarkCyan

    Write-Host ''
    Write-Info 'Se nada resolveu: teste o teclado em OUTRO computador. Se funcionar la,'
    Write-Info 'o problema e nesta maquina; se nao funcionar, e o teclado ou o cabo.'
    return [long]$corrigidos
}

# =========================================================================
# PADRONIZAR NAVEGADORES E BARRA DE TAREFAS
# =========================================================================
# Todo escritorio tem a mesma cena: o usuario abre o navegador e fica
# procurando o sistema no historico, ou usa um favorito velho que aponta
# para o endereco antigo. Aqui os tres navegadores passam a abrir sempre nas
# mesmas abas, e os tres ficam fixados na barra de tarefas.
#
# Feito por POLITICA (Policies no registro / policies.json), nao mexendo no
# perfil do usuario. Motivo: as paginas iniciais do Chrome e do Edge ficam
# nas "Secure Preferences", protegidas por hash - editar o arquivo a mao faz
# o navegador detectar adulteracao e reverter na proxima abertura. Politica
# e' o caminho suportado e e' o unico que gruda.

$script:UrlsInicioEscritorio = @(
    'https://suporteadv.suporte.adv.br/',
    'https://www.suporte.adv.br/sistemas'
)

function Get-CaminhoNavegador {
    <#
      Caminho do executavel pelo App Paths - registro oficial, vale para
      instalacao por maquina e por usuario. So depois disso chuta pastas.
    #>
    param([string]$Exe)

    foreach ($raiz in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths',
                        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths')) {
        $chave = Join-Path $raiz $Exe
        $valor = (Get-ItemProperty -LiteralPath $chave -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
        if ($valor) {
            $valor = $valor.Trim('"')
            if (Test-Path -LiteralPath $valor) { return $valor }
        }
    }

    $palpites = switch ($Exe) {
        'chrome.exe'  { @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
                          "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
                          "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe") }
        'msedge.exe'  { @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
                          "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") }
        'firefox.exe' { @("$env:ProgramFiles\Mozilla Firefox\firefox.exe",
                          "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe",
                          "$env:LOCALAPPDATA\Mozilla Firefox\firefox.exe") }
        default       { @() }
    }
    foreach ($p in $palpites) { if ($p -and (Test-Path -LiteralPath $p)) { return $p } }
    return $null
}

function Set-AbasIniciaisChromium {
    <#
      Chrome e Edge compartilham o mesmo motor de politicas: RestoreOnStartup=4
      significa "abrir esta lista de paginas", e RestoreOnStartupURLs guarda a
      lista numerada 1, 2, 3.

      Travar   -> HKLM\...\Policies\<navegador>            (usuario nao muda)
      Sugerir  -> HKLM\...\Policies\<navegador>\Recommended (vira o padrao,
                  e quem ja tinha configurado a mao continua com o dele)
    #>
    param(
        [string]$Nome,
        [string]$ChavePolitica,
        [string]$UrlNovaGuia,
        [switch]$Travar
    )

    $alvo = if ($Travar) { $ChavePolitica } else { Join-Path $ChavePolitica 'Recommended' }
    $urls = @($UrlNovaGuia) + $script:UrlsInicioEscritorio

    try {
        # Se ja houver configuracao ali (politica de dominio, por exemplo), ela
        # vai para o log ANTES de ser substituida - senao some sem deixar
        # rastro e ninguem sabe mais o que estava valendo.
        $subUrls = Join-Path $alvo 'RestoreOnStartupURLs'
        if (Test-Path -LiteralPath $subUrls) {
            $velhas = @()
            $pp = Get-ItemProperty -LiteralPath $subUrls -ErrorAction SilentlyContinue
            if ($pp) {
                # Nao usar $nome aqui: colide com o parametro $Nome (o
                # PowerShell nao diferencia maiusculas) e o rotulo do navegador
                # vira lixo nas mensagens.
                foreach ($prop in ($pp.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | Sort-Object { [int]$_.Name })) {
                    $velhas += [string]$prop.Value
                }
            }
            $iguais = ((@($velhas) -join '|') -eq (($urls) -join '|'))
            if ($velhas.Count -gt 0 -and -not $iguais) {
                Write-Aviso "$Nome ja tinha paginas iniciais configuradas - serao substituidas:"
                foreach ($v in $velhas) { Write-Info ("   (antes) $v") }
            }
        }

        if (-not (Test-Path -LiteralPath $alvo)) {
            New-Item -Path $alvo -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -LiteralPath $alvo -Name 'RestoreOnStartup' -Value 4 -Type DWord -ErrorAction Stop

        # Recria a lista: se sobrasse endereco antigo com numero maior, ele
        # continuaria abrindo junto.
        if (Test-Path -LiteralPath $subUrls) {
            Remove-Item -LiteralPath $subUrls -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -Path $subUrls -Force -ErrorAction Stop | Out-Null

        $i = 0
        foreach ($u in $urls) {
            $i++
            Set-ItemProperty -LiteralPath $subUrls -Name ([string]$i) -Value $u -Type String -ErrorAction Stop
        }

        Write-Ok ("$Nome configurado para abrir $i aba(s) ao iniciar.")
        foreach ($u in $urls) { Write-Info ("   - $u") }

        # Politica obrigatoria ganha da recomendada: se existir uma, o que
        # acabamos de gravar em Recommended nao aparece e parece que falhou.
        if (-not $Travar) {
            $mand = (Get-ItemProperty -LiteralPath $ChavePolitica -Name 'RestoreOnStartup' -ErrorAction SilentlyContinue).RestoreOnStartup
            if ($null -ne $mand) {
                Write-Aviso "$Nome ja tem politica OBRIGATORIA de pagina inicial - ela ganha da sugerida."
                Add-Alerta "$Nome tem politica obrigatoria de pagina inicial (talvez de dominio). A configuracao sugerida nao vai aparecer."
            }
        }
        return $true
    } catch {
        Write-Falha "Nao foi possivel configurar $Nome - $($_.Exception.Message)"
        return $false
    }
}

function Get-PastasFirefox {
    <# Todas as instalacoes do Firefox na maquina (pode haver 32 e 64 bits). #>
    $lista = New-Object System.Collections.Generic.List[string]

    $exe = Get-CaminhoNavegador 'firefox.exe'
    if ($exe) { $lista.Add([System.IO.Path]::GetDirectoryName($exe)) }

    foreach ($raiz in @('HKLM:\SOFTWARE\Mozilla\Mozilla Firefox',
                        'HKLM:\SOFTWARE\WOW6432Node\Mozilla\Mozilla Firefox')) {
        foreach ($ver in @(Get-ChildItem -LiteralPath $raiz -ErrorAction SilentlyContinue)) {
            $pe = (Get-ItemProperty -LiteralPath (Join-Path $ver.PSPath 'Main') -Name 'PathToExe' -ErrorAction SilentlyContinue).PathToExe
            if ($pe -and (Test-Path -LiteralPath $pe)) {
                $dir = [System.IO.Path]::GetDirectoryName($pe)
                if ($lista -notcontains $dir) { $lista.Add($dir) }
            }
        }
    }
    return $lista
}

function Set-AbasIniciaisFirefox {
    <#
      O Firefox nao le as politicas do Chrome. Usa policies.json dentro da
      pasta de instalacao, em "distribution".

      A pagina inicial dele aceita varios enderecos separados por "|", e cada
      um abre numa aba - e' assim que se consegue "nova guia + dois sites".
      about:newtab entra como primeira, atendendo a mesma ordem dos outros.

      Se ja existir um policies.json, ele e' LIDO E MESCLADO: outra politica
      que ja esteja ali (bloqueio de telemetria, extensao obrigatoria) fica.
      O original vai para .bak antes de qualquer alteracao.
    #>
    param([switch]$Travar)

    $status  = if ($Travar) { 'locked' } else { 'default' }
    $inicial = (@('about:newtab') + $script:UrlsInicioEscritorio) -join '|'
    $pastas  = @(Get-PastasFirefox)

    if ($pastas.Count -eq 0) {
        # Nao esta instalado agora: deixa a politica no registro, que o Firefox
        # le assim que for instalado. Melhor do que nao configurar nada.
        try {
            $kFF = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
            if (-not (Test-Path -LiteralPath $kFF)) { New-Item -Path $kFF -Force -ErrorAction Stop | Out-Null }
            $prefsReg = [ordered]@{
                'browser.startup.page'     = [ordered]@{ Value = 1;        Status = $status }
                'browser.startup.homepage' = [ordered]@{ Value = $inicial; Status = $status }
            }
            Set-ItemProperty -LiteralPath $kFF -Name 'Preferences' `
                -Value ($prefsReg | ConvertTo-Json -Depth 6 -Compress) -Type String -ErrorAction Stop
            Write-Info 'Firefox nao esta instalado - politica deixada no registro para quando for.'
            return $true
        } catch {
            Write-Aviso "Firefox nao instalado e nao foi possivel deixar a politica: $($_.Exception.Message)"
            return $false
        }
    }

    $algum = $false
    foreach ($pasta in $pastas) {
        $dist = Join-Path $pasta 'distribution'
        $arq  = Join-Path $dist 'policies.json'
        $obj  = $null

        if (Test-Path -LiteralPath $arq) {
            try {
                $obj = Get-Content -LiteralPath $arq -Raw -ErrorAction Stop | ConvertFrom-Json
            } catch {
                Write-Aviso 'policies.json existente esta invalido - vai ser refeito (copia salva em .bak).'
            }
            $bak = '{0}.bak_{1}' -f $arq, (Get-Date -Format 'yyyyMMdd_HHmmss')
            Copy-Item -LiteralPath $arq -Destination $bak -Force -ErrorAction SilentlyContinue
        }

        try {
            if (-not (Test-Path -LiteralPath $dist)) {
                New-Item -ItemType Directory -Path $dist -Force -ErrorAction Stop | Out-Null
            }

            $politicas = [ordered]@{}
            if ($obj -and $obj.policies) {
                foreach ($p in $obj.policies.PSObject.Properties) { $politicas[$p.Name] = $p.Value }
            }
            $prefs = [ordered]@{}
            if ($politicas.Contains('Preferences') -and $politicas['Preferences']) {
                foreach ($p in $politicas['Preferences'].PSObject.Properties) { $prefs[$p.Name] = $p.Value }
            }
            $prefs['browser.startup.page']     = [ordered]@{ Value = 1;        Status = $status }
            $prefs['browser.startup.homepage'] = [ordered]@{ Value = $inicial; Status = $status }
            $politicas['Preferences'] = $prefs

            $json = ([ordered]@{ policies = $politicas } | ConvertTo-Json -Depth 12)
            # Sem BOM: o Firefox le o arquivo como UTF-8 puro.
            [System.IO.File]::WriteAllText($arq, $json, (New-Object System.Text.UTF8Encoding($false)))

            Write-Ok ("Firefox configurado em: $pasta")
            $algum = $true
        } catch {
            Write-Falha "Nao foi possivel gravar o policies.json em $pasta - $($_.Exception.Message)"
        }
    }

    if ($algum) {
        Write-Info '   - about:newtab (nova guia)'
        foreach ($u in $script:UrlsInicioEscritorio) { Write-Info ("   - $u") }
    }
    return $algum
}

function Get-PastaFixadosBarra {
    return (Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar')
}

function Get-FixadosNaBarra {
    <# Lista dos atalhos fixados hoje, com o executavel de cada um. #>
    $pasta = Get-PastaFixadosBarra
    $lista = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $pasta)) { return $lista }
    try {
        $ws = New-Object -ComObject WScript.Shell
        foreach ($lnk in @(Get-ChildItem -LiteralPath $pasta -Filter '*.lnk' -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $alvo = ''
            try { $alvo = [string]$ws.CreateShortcut($lnk.FullName).TargetPath } catch { }
            $lista.Add([pscustomobject]@{ Lnk = $lnk.FullName; Nome = $lnk.BaseName; Alvo = $alvo })
        }
    } catch { }
    return $lista
}

function Add-BarraTarefasPeloVerbo {
    <#
      Tentativa barata: invocar o comando "Fixar na barra de tarefas" do
      proprio Windows. Ele foi tirado da lista de verbos dos .exe no Windows 10
      1703, mas o manipulador seguia registrado no CommandStore e dava para
      chamar por uma chave temporaria. Nas atualizacoes recentes do Windows 10
      e 11 nem isso funciona mais: o verbo e' aceito e ignorado, sem erro.
      Continua sendo a primeira tentativa porque, quando funciona, resolve sem
      reiniciar o Explorer. Quando nao funciona, caimos no metodo de layout.
    #>
    param([string]$Caminho)

    if (-not $Caminho -or -not (Test-Path -LiteralPath $Caminho)) { return $false }

    $handler = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.taskbarpin' `
                -Name 'ExplorerCommandHandler' -ErrorAction SilentlyContinue).ExplorerCommandHandler
    if (-not $handler) { return $false }

    $sub = 'SOFTWARE\Classes\*\shell\SuporteADVFixar'
    try {
        $k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($sub)
        $k.SetValue('ExplorerCommandHandler', $handler, [Microsoft.Win32.RegistryValueKind]::String)
        $k.Close()

        $shell = New-Object -ComObject Shell.Application
        $item  = $shell.Namespace([System.IO.Path]::GetDirectoryName($Caminho)).ParseName([System.IO.Path]::GetFileName($Caminho))
        try { $item.InvokeVerb('SuporteADVFixar') } catch { }
        Start-Sleep -Milliseconds 900
    } catch {
        return $false
    } finally {
        try { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($sub, $false) } catch { }
        try {
            $pai = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('SOFTWARE\Classes\*\shell', $true)
            if ($pai -and $pai.SubKeyCount -eq 0 -and $pai.ValueCount -eq 0) {
                $pai.Close()
                [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKey('SOFTWARE\Classes\*\shell', $false)
            } elseif ($pai) { $pai.Close() }
        } catch { }
    }

    return (@(Get-FixadosNaBarra | Where-Object { $_.Alvo -eq $Caminho }).Count -gt 0)
}

function Get-AtalhoDeOrigem {
    <#
      Para montar o layout da barra e' preciso apontar um .lnk de ORIGEM para
      cada programa - de preferencia o do menu Iniciar.

      Nao serve apontar para o .lnk que ja esta na pasta dos fixados: o Windows
      copia cada atalho do layout para dentro dessa mesma pasta, e o nome
      colide com o que ja esta la - resultado, a barra fica com "Chrome" e
      "Chrome (2)", tudo duplicado. Quem nao tem atalho no menu Iniciar ganha
      uma copia em C:\ProgramData\SuporteTI\atalhos.
    #>
    param([string]$Alvo, [string]$LnkFixado, [string]$Nome, [hashtable]$IndiceIniciar)

    if ($Alvo -and $IndiceIniciar -and $IndiceIniciar.ContainsKey($Alvo.ToLower())) {
        return $IndiceIniciar[$Alvo.ToLower()]
    }

    $pastaAt = 'C:\ProgramData\SuporteTI\atalhos'
    if (-not (Test-Path -LiteralPath $pastaAt)) {
        New-Item -ItemType Directory -Path $pastaAt -Force -ErrorAction SilentlyContinue | Out-Null
    }
    $destino = Join-Path $pastaAt (($Nome -replace '[\\/:*?"<>|]', '_') + '.lnk')

    if ($LnkFixado -and (Test-Path -LiteralPath $LnkFixado)) {
        try { Copy-Item -LiteralPath $LnkFixado -Destination $destino -Force -ErrorAction Stop; return $destino } catch { }
    }
    if ($Alvo -and (Test-Path -LiteralPath $Alvo)) {
        try {
            $ws = New-Object -ComObject WScript.Shell
            $at = $ws.CreateShortcut($destino)
            $at.TargetPath       = $Alvo
            $at.WorkingDirectory = [System.IO.Path]::GetDirectoryName($Alvo)
            $at.Save()
            return $destino
        } catch { }
    }
    return $null
}

function Get-IndiceAtalhosIniciar {
    <# executavel (minusculo) -> caminho do .lnk no menu Iniciar #>
    $idx = @{}
    try {
        $ws = New-Object -ComObject WScript.Shell
        foreach ($raiz in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
                            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs")) {
            foreach ($lnk in @(Get-ChildItem -LiteralPath $raiz -Filter '*.lnk' -Recurse -ErrorAction SilentlyContinue)) {
                try {
                    $t = [string]$ws.CreateShortcut($lnk.FullName).TargetPath
                    if ($t) {
                        $ch = $t.ToLower()
                        if (-not $idx.ContainsKey($ch)) { $idx[$ch] = $lnk.FullName }
                    }
                } catch { }
            }
        }
    } catch { }
    return $idx
}

function Restart-ExplorerEEsperar {
    Stop-Process -Name 'explorer' -Force -ErrorAction SilentlyContinue
    $fim = (Get-Date).AddSeconds(12)
    while ((Get-Date) -lt $fim) {
        Start-Sleep -Milliseconds 700
        if (Get-Process -Name 'explorer' -ErrorAction SilentlyContinue) { break }
    }
    if (-not (Get-Process -Name 'explorer' -ErrorAction SilentlyContinue)) {
        # AutoRestartShell desligado: sobe na mao, senao o usuario fica sem barra
        try { Start-Process 'explorer.exe' -ErrorAction Stop } catch { }
    }
    Start-Sleep -Seconds 5
}

function Set-BarraTarefasPorLayout {
    <#
      Metodo suportado pela Microsoft (LayoutModification.xml), que e' o unico
      que ainda funciona: monta a lista completa da barra e manda o Windows
      reconstruir.

      Dois cuidados que fazem toda a diferenca:

      - a lista e' montada com O QUE JA ESTA FIXADO + os navegadores. O layout
        substitui a barra inteira; sem isso, o usuario perderia os icones dele;
      - o XML e' APAGADO depois de aplicar. Se ficasse, a barra voltaria a essa
        lista a cada logon e todo icone que o usuario fixasse depois sumiria no
        dia seguinte - reclamacao certa no escritorio.

      Antes de mexer, a pasta de fixados e a chave Taskband vao para a pasta de
      log desta execucao. Se a barra vier menor do que era, desfaz sozinho.
    #>
    param([string[]]$Executaveis)

    $pastaPin = Get-PastaFixadosBarra
    $antes    = @(Get-FixadosNaBarra)
    $alvosAntes = @($antes | ForEach-Object { $_.Alvo } | Where-Object { $_ })

    # --- backup ----------------------------------------------------------
    $pastaBkp = Join-Path $script:pastaExec 'barra_tarefas'
    $regBkp   = Join-Path $pastaBkp 'Taskband.reg'
    try {
        New-Item -ItemType Directory -Path $pastaBkp -Force -ErrorAction Stop | Out-Null
        foreach ($a in $antes) {
            Copy-Item -LiteralPath $a.Lnk -Destination (Join-Path $pastaBkp ([System.IO.Path]::GetFileName($a.Lnk))) -Force -ErrorAction SilentlyContinue
        }
        & reg.exe export 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband' $regBkp /y 2>&1 | Out-Null
        Write-Info ("Copia de seguranca da barra: $pastaBkp")
    } catch {
        Write-Falha "Nao consegui guardar a copia de seguranca da barra - nada foi alterado."
        return [long]0
    }

    # --- monta a lista ----------------------------------------------------
    $indice = Get-IndiceAtalhosIniciar
    $origens = New-Object System.Collections.Generic.List[string]

    foreach ($a in $antes) {
        $o = Get-AtalhoDeOrigem -Alvo $a.Alvo -LnkFixado $a.Lnk -Nome $a.Nome -IndiceIniciar $indice
        if ($o) { $origens.Add($o) } else { Write-Aviso ("Nao achei atalho de origem para '$($a.Nome)' - ele sai da barra.") }
    }
    foreach ($exe in $Executaveis) {
        if ($alvosAntes -contains $exe) { continue }
        $nome = [System.IO.Path]::GetFileNameWithoutExtension($exe)
        $o = Get-AtalhoDeOrigem -Alvo $exe -LnkFixado $null -Nome $nome -IndiceIniciar $indice
        if ($o) { $origens.Add($o) } else { Write-Aviso ("Nao consegui criar atalho para $exe") }
    }

    $modelo = @'
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
    Version="1">
  <CustomTaskbarLayoutCollection PinListPlacement="Replace">
    <defaultlayout:TaskbarLayout>
      <taskbar:TaskbarPinList>
__ITENS__
      </taskbar:TaskbarPinList>
    </defaultlayout:TaskbarLayout>
  </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
'@
    $itens = ($origens | ForEach-Object {
        '        <taskbar:DesktopApp DesktopApplicationLinkPath="' + ($_ -replace '&', '&amp;') + '" />'
    }) -join "`r`n"
    $xml = $modelo.Replace('__ITENS__', $itens)

    # XML torto deixaria a barra vazia: confere antes de gravar.
    try { [xml]$xml | Out-Null } catch {
        Write-Falha "O layout gerado ficou invalido - nada foi alterado. $($_.Exception.Message)"
        return [long]0
    }

    $pastaShell = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Shell'
    $arqXml     = Join-Path $pastaShell 'LayoutModification.xml'
    $xmlAntigo  = $null
    try {
        if (-not (Test-Path -LiteralPath $pastaShell)) { New-Item -ItemType Directory -Path $pastaShell -Force -ErrorAction Stop | Out-Null }
        if (Test-Path -LiteralPath $arqXml) {
            $xmlAntigo = Join-Path $pastaBkp 'LayoutModification.xml'
            Copy-Item -LiteralPath $arqXml -Destination $xmlAntigo -Force -ErrorAction SilentlyContinue
        }
        [System.IO.File]::WriteAllText($arqXml, $xml, (New-Object System.Text.UTF8Encoding($false)))
    } catch {
        Write-Falha "Nao foi possivel gravar o layout da barra - $($_.Exception.Message)"
        return [long]0
    }

    # --- aplica -----------------------------------------------------------
    Write-Info ("Reconstruindo a barra com $($origens.Count) icone(s). O Explorer reinicia agora...")

    # A pasta dos fixados precisa ser esvaziada antes: o Windows COPIA para ela
    # cada atalho do layout, e se o arquivo de mesmo nome ainda estiver la ele
    # cria "Chrome (2)" ao lado de "Chrome" - a barra fica com tudo em dobro.
    # A copia de seguranca ja foi feita logo acima.
    foreach ($f in @(Get-ChildItem -LiteralPath $pastaPin -Filter '*.lnk' -ErrorAction SilentlyContinue)) {
        Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
    }

    Remove-Item -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband' -Recurse -Force -ErrorAction SilentlyContinue
    Restart-ExplorerEEsperar

    # O Windows monta a barra alguns segundos DEPOIS de o Explorer subir.
    # Conferir na hora dava "nao entrou" para uma coisa que entrava logo em
    # seguida: espera ate os navegadores aparecerem, com limite.
    $limite = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $limite) {
        $pres = @(Get-FixadosNaBarra | ForEach-Object { $_.Alvo })
        if (@($Executaveis | Where-Object { $pres -notcontains $_ }).Count -eq 0) { break }
        Start-Sleep -Seconds 2
    }

    # --- confere ----------------------------------------------------------
    $depois = @(Get-FixadosNaBarra)
    $alvosDepois = @($depois | ForEach-Object { $_.Alvo } | Where-Object { $_ })
    $perdidos = @($alvosAntes | Where-Object { $alvosDepois -notcontains $_ })
    $novos    = @($Executaveis | Where-Object { $alvosDepois -contains $_ })

    # O XML sai de cena: ele so servia para esta reconstrucao. Ficando la, a
    # barra voltaria a esta lista a cada logon.
    Remove-Item -LiteralPath $arqXml -Force -ErrorAction SilentlyContinue
    if ($xmlAntigo -and (Test-Path -LiteralPath $xmlAntigo)) {
        Copy-Item -LiteralPath $xmlAntigo -Destination $arqXml -Force -ErrorAction SilentlyContinue
        Write-Info 'O LayoutModification.xml que ja existia foi recolocado.'
    }

    if ($perdidos.Count -gt 0) {
        Write-Falha ("A barra perdeu $($perdidos.Count) icone(s) - desfazendo.")
        foreach ($p in $perdidos) { Write-Info ("   perdido: $p") }
        Restore-BarraTarefas -PastaBackup $pastaBkp
        return [long]0
    }

    foreach ($n in $novos) { Write-Ok ("Fixado na barra: $n") }
    if ($novos.Count -eq 0) { Write-Aviso 'A barra foi reconstruida mas os navegadores nao entraram.' }
    return [long]$novos.Count
}

function Restore-BarraTarefas {
    <# Volta a barra ao que era, usando a copia guardada antes da alteracao. #>
    param([string]$PastaBackup)

    $pastaPin = Get-PastaFixadosBarra
    try {
        Remove-Item -LiteralPath (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Shell\LayoutModification.xml') -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $pastaPin)) { New-Item -ItemType Directory -Path $pastaPin -Force | Out-Null }
        foreach ($f in @(Get-ChildItem -LiteralPath $pastaPin -Filter '*.lnk' -ErrorAction SilentlyContinue)) {
            Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
        }
        # Um a um, com LiteralPath: "pasta\*.lnk" com -LiteralPath nao expande
        # o curinga e o restore silenciosamente nao copia nada.
        foreach ($f in @(Get-ChildItem -Path $PastaBackup -Filter '*.lnk' -ErrorAction SilentlyContinue)) {
            Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $pastaPin $f.Name) -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband' -Recurse -Force -ErrorAction SilentlyContinue
        $reg = Join-Path $PastaBackup 'Taskband.reg'
        if (Test-Path -LiteralPath $reg) { & reg.exe import $reg 2>&1 | Out-Null }
        Restart-ExplorerEEsperar
        $q = @(Get-FixadosNaBarra).Count
        Write-Ok "Barra restaurada como estava ($q icone(s))."
    } catch {
        Write-Falha "Falhou ao restaurar a barra - $($_.Exception.Message)"
        Write-Info  ("Os atalhos originais estao em: $PastaBackup")
        Add-Alerta  ("Barra de tarefas pode ter ficado incompleta. Atalhos originais em $PastaBackup")
    }
}

function Remove-AbasIniciaisPadrao {
    <#
      Desfaz so o que esta ferramenta gravou: RestoreOnStartup e a lista de
      enderecos, nas duas variantes (obrigatoria e recomendada). Nao apaga a
      chave Policies inteira - se a maquina estiver num dominio, ali pode
      haver politica de outra pessoa.
    #>
    $qtd = 0

    foreach ($nav in @(
        @{ Nome = 'Google Chrome';  Chave = 'HKLM:\SOFTWARE\Policies\Google\Chrome' },
        @{ Nome = 'Microsoft Edge'; Chave = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' }
    )) {
        foreach ($alvo in @($nav.Chave, (Join-Path $nav.Chave 'Recommended'))) {
            if (-not (Test-Path -LiteralPath $alvo)) { continue }
            try {
                if ($null -ne (Get-ItemProperty -LiteralPath $alvo -Name 'RestoreOnStartup' -ErrorAction SilentlyContinue).RestoreOnStartup) {
                    Remove-ItemProperty -LiteralPath $alvo -Name 'RestoreOnStartup' -Force -ErrorAction SilentlyContinue
                    $qtd++
                }
                $subUrls = Join-Path $alvo 'RestoreOnStartupURLs'
                if (Test-Path -LiteralPath $subUrls) {
                    Remove-Item -LiteralPath $subUrls -Recurse -Force -ErrorAction SilentlyContinue
                    $qtd++
                }
                Write-Ok ("$($nav.Nome): configuracao de paginas iniciais removida.")
            } catch {
                Write-Aviso "Nao foi possivel limpar $($nav.Nome) - $($_.Exception.Message)"
            }
        }
    }

    # Firefox: tira so as duas preferencias; o resto do policies.json fica.
    foreach ($pasta in @(Get-PastasFirefox)) {
        $arq = Join-Path (Join-Path $pasta 'distribution') 'policies.json'
        if (-not (Test-Path -LiteralPath $arq)) { continue }
        try {
            $obj = Get-Content -LiteralPath $arq -Raw -ErrorAction Stop | ConvertFrom-Json
            if (-not ($obj -and $obj.policies -and $obj.policies.Preferences)) { continue }

            $politicas = [ordered]@{}
            foreach ($p in $obj.policies.PSObject.Properties) { $politicas[$p.Name] = $p.Value }
            $prefs = [ordered]@{}
            foreach ($p in $politicas['Preferences'].PSObject.Properties) {
                if ($p.Name -notin @('browser.startup.page', 'browser.startup.homepage')) { $prefs[$p.Name] = $p.Value }
            }
            if ($prefs.Count -eq 0) { $politicas.Remove('Preferences') } else { $politicas['Preferences'] = $prefs }

            if ($politicas.Count -eq 0) {
                Remove-Item -LiteralPath $arq -Force -ErrorAction Stop
                Write-Ok ("Firefox: policies.json removido (nao restou politica nenhuma) - $pasta")
            } else {
                $json = ([ordered]@{ policies = $politicas } | ConvertTo-Json -Depth 12)
                [System.IO.File]::WriteAllText($arq, $json, (New-Object System.Text.UTF8Encoding($false)))
                Write-Ok ("Firefox: paginas iniciais removidas, demais politicas mantidas - $pasta")
            }
            $qtd++
        } catch {
            Write-Aviso "Nao foi possivel limpar o policies.json em $pasta - $($_.Exception.Message)"
        }
    }

    $kFF = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
    if ((Test-Path -LiteralPath $kFF) -and
        $null -ne (Get-ItemProperty -LiteralPath $kFF -Name 'Preferences' -ErrorAction SilentlyContinue).Preferences) {
        Remove-ItemProperty -LiteralPath $kFF -Name 'Preferences' -Force -ErrorAction SilentlyContinue
        $qtd++
    }

    if ($qtd -eq 0) { Write-Info 'Nao havia configuracao de paginas iniciais para remover.' }
    return [long]$qtd
}

function Set-PadraoNavegadores {
    <#
      Faz os tres navegadores abrirem sempre nas mesmas abas e fixa os tres na
      barra de tarefas. Nao instala navegador nenhum: configura o que existe.
    #>
    if ($SomenteRelatorio) {
        Write-Simul 'Configuraria Chrome, Edge e Firefox para abrir nova guia + suporteadv + sistemas, e fixaria os tres na barra.'
        return [long]0
    }

    Write-Titulo 'PADRONIZAR NAVEGADORES E BARRA DE TAREFAS'
    Write-Info 'Ao abrir, os tres navegadores passam a mostrar sempre:'
    Write-Info '   1. Nova guia'
    foreach ($u in $script:UrlsInicioEscritorio) { Write-Info ("   {0}. {1}" -f ($script:UrlsInicioEscritorio.IndexOf($u) + 2), $u) }

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Falha 'Esta ferramenta precisa de Administrador (grava politica de maquina).'
        Write-Info  'Feche e abra o menu como Administrador.'
        return [long]0
    }

    # --- quem esta instalado ---------------------------------------------
    $navs = @(
        @{ Nome = 'Google Chrome';  Exe = 'chrome.exe';  Chave = 'HKLM:\SOFTWARE\Policies\Google\Chrome';   NovaGuia = 'chrome://newtab' },
        @{ Nome = 'Microsoft Edge'; Exe = 'msedge.exe';  Chave = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge';  NovaGuia = 'edge://newtab' },
        @{ Nome = 'Mozilla Firefox';Exe = 'firefox.exe'; Chave = $null;                                     NovaGuia = 'about:newtab' }
    )
    foreach ($n in $navs) { $n.Caminho = Get-CaminhoNavegador $n.Exe }

    Write-Host ''
    Write-Etapa 'Navegadores encontrados nesta maquina'
    foreach ($n in $navs) {
        if ($n.Caminho) { Write-Ok ("$($n.Nome): $($n.Caminho)") }
        else            { Write-Info ("$($n.Nome): nao instalado") }
    }

    if ($SemInteracao) { Write-Aviso 'Modo desatendido: esta ferramenta pergunta antes de alterar.'; return [long]0 }

    Write-Host ''
    Write-Host '     [1] Aplicar tudo (abas iniciais + fixar na barra)' -ForegroundColor White
    Write-Host '     [2] So as abas iniciais' -ForegroundColor White
    Write-Host '     [3] So fixar na barra de tarefas' -ForegroundColor White
    Write-Host '     [4] Desfazer as abas iniciais' -ForegroundColor White
    Write-Host '     [0] Cancelar' -ForegroundColor DarkGray
    $op = (Read-Host '  Opcao [1]').Trim()
    if (-not $op) { $op = '1' }
    if ($op -eq '0') { Write-Info 'Cancelado - nada foi alterado.'; return [long]0 }
    if ($op -notin @('1', '2', '3', '4')) { Write-Aviso 'Opcao invalida - nada foi alterado.'; return [long]0 }

    if ($op -eq '4') {
        Write-Host ''
        Write-Etapa 'Removendo a configuracao de paginas iniciais'
        $r = Remove-AbasIniciaisPadrao
        Write-Host ''
        Write-Info 'Os icones fixados na barra continuam. Para tirar: botao direito no icone >'
        Write-Info 'Desafixar da barra de tarefas.'
        Write-Info 'Feche e abra os navegadores para valer.'
        return $r
    }

    $qtd = 0

    # --- 1. abas iniciais -------------------------------------------------
    if ($op -in @('1', '2')) {
        Write-Host ''
        Write-Info 'Travado: o usuario nao consegue mudar a pagina inicial (aparece'
        Write-Info '"Gerenciado pela sua organizacao" nas configuracoes do navegador).'
        Write-Info 'Sugerido: vira o padrao, mas quem ja tinha configurado a mao'
        Write-Info 'continua com o dele, e qualquer um pode trocar depois.'
        $rt = (Read-Host '  Travar a configuracao? (S/N) [S]').Trim()
        $travar = (-not $rt -or $rt -match '^[Ss]')

        Write-Host ''
        Write-Etapa ('Gravando as abas iniciais ({0})' -f $(if ($travar) { 'travado' } else { 'sugerido' }))

        foreach ($n in ($navs | Where-Object { $_.Chave })) {
            if (Set-AbasIniciaisChromium -Nome $n.Nome -ChavePolitica $n.Chave -UrlNovaGuia $n.NovaGuia -Travar:$travar) { $qtd++ }
        }
        if (Set-AbasIniciaisFirefox -Travar:$travar) { $qtd++ }

        Write-Host ''
        Write-Info 'Vale na PROXIMA abertura de cada navegador. Se estiver aberto agora,'
        Write-Info 'feche todas as janelas dele (inclusive as em segundo plano) e abra de novo.'
    }

    # --- 2. barra de tarefas ---------------------------------------------
    if ($op -in @('1', '3')) {
        Write-Host ''
        Write-Etapa 'Fixando os navegadores na barra de tarefas'

        # A barra e' por usuario. Se o menu foi elevado com OUTRA conta de
        # administrador, os icones iriam para a barra dela, e nao para a do
        # usuario que esta na maquina - erro que so aparece dias depois.
        $interativo = ''
        try { $interativo = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName } catch { }
        $atual = "$env:USERDOMAIN\$env:USERNAME"
        if ($interativo -and ($interativo -ne $atual)) {
            Write-Aviso 'A janela esta rodando como uma conta diferente da que esta usando o Windows:'
            Write-Info  ("   usando o Windows : $interativo")
            Write-Info  ("   rodando o menu   : $atual")
            Write-Info  'Os icones seriam fixados na barra da conta errada.'
            $rr = (Read-Host '  Fixar assim mesmo? (S/N) [N]').Trim()
            if ($rr -notmatch '^[Ss]') {
                Write-Info 'Pulado. Rode o menu na sessao do proprio usuario para fixar.'
                Add-Alerta 'Icones nao fixados: o menu rodou com conta diferente da do usuario da maquina.'
                Write-Host ''
                Write-Ok ("$qtd item(ns) configurado(s).")
                return [long]$qtd
            }
        }

        $instalados = @($navs | Where-Object { $_.Caminho } | ForEach-Object { $_.Caminho })
        foreach ($n in ($navs | Where-Object { -not $_.Caminho })) {
            Write-Info ("$($n.Nome) nao esta instalado - nada a fixar.")
        }

        $jaFixados = @(Get-FixadosNaBarra | ForEach-Object { $_.Alvo })
        $faltando  = @($instalados | Where-Object { $jaFixados -notcontains $_ })

        foreach ($n in ($navs | Where-Object { $_.Caminho -and ($jaFixados -contains $_.Caminho) })) {
            Write-Info ("$($n.Nome) ja estava fixado.")
        }

        if ($faltando.Count -eq 0) {
            if ($instalados.Count -gt 0) { Write-Ok 'Todos os navegadores instalados ja estao na barra.' }
        } else {
            # 1a tentativa: o comando do proprio Windows, que nao mexe em mais
            # nada. Se funcionar, acabou aqui.
            $restam = New-Object System.Collections.Generic.List[string]
            foreach ($exe in $faltando) {
                if (Add-BarraTarefasPeloVerbo -Caminho $exe) {
                    Write-Ok ("Fixado na barra: $exe")
                    $qtd++
                } else { $restam.Add($exe) }
            }

            if ($restam.Count -gt 0) {
                Write-Host ''
                Write-Aviso 'Este Windows nao aceita mais fixar icone por comando (a Microsoft'
                Write-Info  'bloqueou isso nas atualizacoes recentes do 10 e do 11).'
                Write-Info  'Resta o caminho oficial: reconstruir a barra a partir de um layout.'
                Write-Info  'O que isso significa na pratica:'
                Write-Info  "   - a barra e' reconstruida com os icones de hoje MAIS os navegadores;"
                Write-Info  '   - o Explorer reinicia (a barra pisca e as janelas de pastas fecham);'
                Write-Info  '   - programas abertos nao sao fechados;'
                Write-Info  '   - a barra atual e guardada antes, e volta sozinha se algo der errado.'
                Write-Host ''
                $rl = (Read-Host '  Reconstruir a barra agora? (S/N) [S]').Trim()
                if (-not $rl -or $rl -match '^[Ss]') {
                    $qtd += (Set-BarraTarefasPorLayout -Executaveis $restam)
                } else {
                    Write-Info 'Pulado. Para fixar a mao: abra o Iniciar, digite o nome do navegador,'
                    Write-Info 'clique com o botao direito no resultado e escolha "Fixar na barra de tarefas".'
                    Add-Alerta ('Navegadores nao fixados na barra: ' + (($restam | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_) }) -join ', '))
                }
            }
        }
    }

    Write-Host ''
    Write-Ok ("$qtd item(ns) configurado(s).")
    Write-Info 'Para conferir: abra o navegador e veja se as tres abas vieram juntas.'
    return [long]$qtd
}
function Set-EfeitosVisuais {
    <#
      Correcao da v1: VisualFXSetting=2 ('melhor desempenho') tambem desliga
      o ClearType, deixando o texto serrilhado. Usamos 3 (personalizado) e
      reativamos explicitamente a suavizacao de fontes.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Ajustaria efeitos visuais mantendo ClearType.'; return [long]0 }

    $qtd = 0
    $chaveVFX = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
    $chaveAdv = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    $chaveDsk = 'HKCU:\Control Panel\Desktop'
    $chaveWM  = 'HKCU:\Control Panel\Desktop\WindowMetrics'

    foreach ($k in @($chaveVFX, $chaveAdv, $chaveWM)) {
        if (-not (Test-Path $k)) { New-Item -Path $k -Force -ErrorAction SilentlyContinue | Out-Null }
    }

    $ajustes = @(
        @{ Chave = $chaveVFX; Nome = 'VisualFXSetting';    Valor = 3; Tipo = 'DWord';  Desc = 'Modo personalizado de desempenho' },
        @{ Chave = $chaveWM;  Nome = 'MinAnimate';         Valor = '0'; Tipo = 'String'; Desc = 'Animacao de minimizar/maximizar' },
        @{ Chave = $chaveDsk; Nome = 'DragFullWindows';    Valor = '0'; Tipo = 'String'; Desc = 'Conteudo ao arrastar janela' },
        @{ Chave = $chaveDsk; Nome = 'MenuShowDelay';      Valor = '0'; Tipo = 'String'; Desc = 'Atraso de abertura de menus' },
        @{ Chave = $chaveAdv; Nome = 'TaskbarAnimations';  Valor = 0; Tipo = 'DWord';  Desc = 'Animacoes da barra de tarefas' },
        @{ Chave = $chaveAdv; Nome = 'ListviewAlphaSelect';Valor = 0; Tipo = 'DWord';  Desc = 'Caixa de selecao translucida' },
        @{ Chave = $chaveAdv; Nome = 'ListviewShadow';     Valor = 0; Tipo = 'DWord';  Desc = 'Sombra nos rotulos de icones' },
        # Legibilidade preservada:
        @{ Chave = $chaveDsk; Nome = 'FontSmoothing';      Valor = '2'; Tipo = 'String'; Desc = 'ClearType MANTIDO ligado' },
        @{ Chave = $chaveDsk; Nome = 'FontSmoothingType';  Valor = 2; Tipo = 'DWord';  Desc = 'Suavizacao ClearType' },
        # Miniaturas LIGADAS: o escritorio navega em pastas de documentos e
        # imagens e precisa da pre-visualizacao sem abrir o arquivo.
        # IconsOnly=1 e' o que o modo "melhor desempenho" (usado pela v1)
        # deixava ligado, escondendo as miniaturas. Aqui isso e' revertido.
        @{ Chave = $chaveAdv; Nome = 'IconsOnly';          Valor = 0; Tipo = 'DWord';  Desc = 'Miniaturas LIGADAS (nao mostrar so icones)' }
    )

    foreach ($a in $ajustes) {
        try {
            Set-ItemProperty -Path $a.Chave -Name $a.Nome -Value $a.Valor -Type $a.Tipo -ErrorAction Stop
            $qtd++
            Write-Ok $a.Desc
        } catch {
            Write-Aviso "Falhou: $($a.Desc) - $($_.Exception.Message)"
        }
    }

    # --- Politicas que escondem miniaturas -------------------------------
    # DisableThumbnails apaga a pre-visualizacao em qualquer pasta;
    # DisableThumbnailsOnNetworkFolders so nas pastas de rede - esse pega
    # o servidor de arquivos do escritorio e costuma passar despercebido.
    $polUser = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $polMaq  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'

    foreach ($nome in @('DisableThumbnails', 'DisableThumbnailsOnNetworkFolders')) {
        $valUser = (Get-ItemProperty -Path $polUser -Name $nome -ErrorAction SilentlyContinue).$nome
        if ($valUser -eq 1) {
            try {
                Remove-ItemProperty -Path $polUser -Name $nome -ErrorAction Stop
                Write-Ok "Politica '$nome' removida do usuario - miniaturas liberadas."
                $qtd++
            } catch {
                Write-Aviso "Nao foi possivel remover a politica '$nome': $($_.Exception.Message)"
            }
        }

        # HKLM normalmente vem de GPO de dominio: so avisa, nao mexe.
        $valMaq = (Get-ItemProperty -Path $polMaq -Name $nome -ErrorAction SilentlyContinue).$nome
        if ($valMaq -eq 1) {
            Write-Aviso "Politica de MAQUINA '$nome' esta ativa - miniaturas continuam escondidas."
            Add-Alerta "Miniaturas bloqueadas por politica de maquina ($nome). Se houver dominio, ajustar via GPO."
        }
    }

    try { & rundll32.exe user32.dll,UpdatePerUserSystemParameters 1 True } catch { }
    Write-Ok "$qtd configuracao(s) aplicada(s)."
    Write-Aviso 'Algumas mudancas exigem logoff/logon para efeito completo.'
    Write-Info  'Miniaturas: ligadas. Se o cache estiver corrompido, use a opcao de'
    Write-Info  'limpeza de miniaturas - o Windows refaz na proxima abertura da pasta.'
    return [long]0
}

function Set-DesempenhoEnergia {
    if ($SomenteRelatorio) { Write-Simul 'Ajustaria plano de energia.'; return [long]0 }
    try {
        $linha = & powercfg /list 2>$null | Select-String -Pattern 'Alto desempenho|High performance' | Select-Object -First 1
        if ($linha) {
            $guid = [regex]::Match($linha.ToString(), '[a-fA-F0-9\-]{36}').Value
            if ($guid) { & powercfg /setactive $guid 2>$null; Write-Ok 'Plano de alto desempenho ativado.' }
        } else {
            Write-Info 'Plano de alto desempenho nao disponivel (equilibrado mantido).'
        }
    } catch { Write-Aviso "powercfg: $($_.Exception.Message)" }

    if ($DesativarHibernacao) {
        $temBateria = [bool](Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
        if ($temBateria) {
            Write-Aviso 'Notebook detectado: hibernacao NAO desativada (perderia suspensao para disco).'
        } else {
            & powercfg /hibernate off 2>$null
            Write-Ok 'Hibernacao desativada (hiberfil.sys liberado).'
        }
    }
    return [long]0
}

function Repair-Sistema {
    <#
      DISM em escada (CheckHealth -> ScanHealth -> RestoreHealth) e depois SFC.
      So desce um degrau se o anterior acusou problema: numa maquina sadia isso
      economiza os 10 a 30 minutos do RestoreHealth.
      A deteccao trata PT e EN: o DISM imprime no idioma do Windows, e so
      comparar com o texto em ingles fazia tudo virar "inconclusivo" no PT-BR.
    #>
    if ($SomenteRelatorio) { Write-Simul 'Executaria DISM (CheckHealth/ScanHealth/RestoreHealth) e SFC /scannow.'; return [long]0 }

    $reSemCorrupcao = 'No component store corruption detected|Nenhuma corrup.{0,3}o do reposit.{0,3}rio de componentes|Nenhuma corrup.{0,3}o de armazenamento de componentes'
    $reCorrompido   = 'component store is repairable|component store is corrupted|reposit.{0,3}rio de componentes .{0,3} repar.vel|reposit.{0,3}rio de componentes est. corrompido|armazenamento de componentes .{0,3} repar.vel'
    $reSucesso      = 'The restore operation completed successfully|The operation completed successfully|A opera.{0,3}o de restaura.{0,3}o foi conclu.da com .xito|A opera.{0,3}o foi conclu.da com .xito'

    function Invoke-DISM {
        param([string[]]$Argumentos)
        $linhas = [System.Collections.Generic.List[string]]::new()
        & dism.exe @Argumentos 2>&1 | ForEach-Object {
            $l = $_.ToString()
            $linhas.Add($l)
            if ($l.Trim()) { Write-Host "     $l" -ForegroundColor DarkGray }
        }
        return ($linhas -join ' ')
    }

    $statusDISM = 'nao executado'
    $statusSFC  = 'nao executado'

    # --- Degrau 1: CheckHealth (rapido, so le os metadados) ---
    Write-Etapa 'DISM CheckHealth - verificacao rapida da imagem...'
    $txt = Invoke-DISM @('/Online', '/Cleanup-Image', '/CheckHealth')

    $precisaScan = $true
    if ($txt -match $reSemCorrupcao) {
        Write-Ok 'CheckHealth: imagem sem corrupcao.'
        $statusDISM  = 'OK - sem corrupcao'
        $precisaScan = $false
    } elseif ($txt -match $reCorrompido) {
        Write-Aviso 'CheckHealth: corrupcao detectada.'
    } else {
        Write-Aviso 'CheckHealth: resultado inconclusivo, seguindo para ScanHealth.'
    }

    # --- Degrau 2: ScanHealth (varredura completa) ---
    $precisaRestore = $false
    if ($precisaScan) {
        Write-Etapa 'DISM ScanHealth - varredura completa, alguns minutos...'
        $txt = Invoke-DISM @('/Online', '/Cleanup-Image', '/ScanHealth')
        if ($txt -match $reSemCorrupcao) {
            Write-Ok 'ScanHealth: nenhuma corrupcao confirmada.'
            $statusDISM = 'OK - sem corrupcao'
        } elseif ($txt -match $reCorrompido) {
            Write-Aviso 'ScanHealth: corrupcao confirmada.'
            $statusDISM = 'ATENCAO - corrupcao confirmada'
            $precisaRestore = $true
        } else {
            Write-Aviso 'ScanHealth: inconclusivo, tentando reparar por precaucao.'
            $statusDISM = 'inconclusivo'
            $precisaRestore = $true
        }
    } else {
        Write-Info 'ScanHealth e RestoreHealth dispensados (imagem sadia).'
    }

    # --- Degrau 3: RestoreHealth (repara, precisa de internet) ---
    if ($precisaRestore) {
        Write-Etapa 'DISM RestoreHealth - reparando, de 10 a 30 minutos. Nao feche...'
        $txt = Invoke-DISM @('/Online', '/Cleanup-Image', '/RestoreHealth')
        if ($txt -match $reSucesso) {
            Write-Ok 'RestoreHealth: imagem reparada.'
            $statusDISM = 'OK - reparado'
            $script:precisaReiniciar = $true
        } elseif ($txt -match 'Error|Erro') {
            Write-Falha 'RestoreHealth: erro no reparo. Confira a conexao com a internet.'
            Write-Info  'Alternativa: dism /Online /Cleanup-Image /RestoreHealth /Source:X:\Sources\install.wim'
            $statusDISM = 'FALHA'
            Add-Alerta 'DISM RestoreHealth falhou - imagem do Windows segue corrompida.'
        } else {
            Write-Aviso 'RestoreHealth: resultado inconclusivo.'
            $statusDISM = 'inconclusivo'
        }
    }

    # --- SFC depois do DISM (o SFC usa a imagem que o DISM repara) ---
    Write-Etapa 'SFC /scannow - de 5 a 20 minutos. Nao feche esta janela...'
    & "$env:SystemRoot\System32\sfc.exe" /scannow
    $sfcExit = $LASTEXITCODE

    # O CBS.log e sempre em ingles; as frases do console (traduzidas) NAO
    # aparecem la. O que aparece sao as linhas [SR].
    $cbs = "$env:SystemRoot\Logs\CBS\CBS.log"
    if (Test-Path -LiteralPath $cbs) {
        try {
            $sr = @(Get-Content -LiteralPath $cbs -Tail 1500 -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match '\[SR\]' })
            $naoReparou = @($sr | Where-Object { $_ -match 'Cannot repair member file|Cannot repair' })
            $reparou    = @($sr | Where-Object { $_ -match 'Repairing corrupted file|Repaired file|successfully repaired' })
            $verificou  = @($sr | Where-Object { $_ -match 'Verify complete|Verifying \d+' })

            if ($naoReparou.Count -gt 0) {
                Write-Falha 'SFC: encontrou arquivos corrompidos que NAO conseguiu reparar.'
                $statusSFC = 'ATENCAO - reparo incompleto'
                Add-Alerta 'SFC nao reparou tudo - ver %windir%\Logs\CBS\CBS.log.'
            } elseif ($reparou.Count -gt 0) {
                Write-Ok 'SFC: arquivos corrompidos reparados.'
                $statusSFC = 'OK - reparado'
                $script:precisaReiniciar = $true
            } elseif ($verificou.Count -gt 0 -or $sfcExit -eq 0) {
                Write-Ok 'SFC: nenhuma violacao de integridade.'
                $statusSFC = 'OK - sem violacoes'
            } else {
                Write-Aviso 'SFC: resultado nao determinado. Ver %windir%\Logs\CBS\CBS.log.'
                $statusSFC = 'inconclusivo'
            }
        } catch { Write-Aviso 'Nao foi possivel ler o CBS.log.' }
    } elseif ($sfcExit -eq 0) {
        Write-Ok 'SFC: concluido sem erros.'
        $statusSFC = 'OK'
    }

    # --- Reinicializacao pendente ---
    $chaves = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    )
    foreach ($k in $chaves) {
        if (Test-Path -LiteralPath $k -ErrorAction SilentlyContinue) { $script:precisaReiniciar = $true; break }
    }

    Write-Host ''
    Write-Dest ("Resultado  ->  DISM: $statusDISM   |   SFC: $statusSFC")
    if ($script:precisaReiniciar) { Write-Aviso 'Reinicie o computador para concluir os reparos.' }
    return [long]0
}

function Invoke-ManutencaoRede {
    if ($SomenteRelatorio) { Write-Simul 'Limparia cache DNS e testaria latencia.'; return [long]0 }

    try { Clear-DnsClientCache -ErrorAction Stop; Write-Ok 'Cache DNS limpo.' }
    catch { & ipconfig /flushdns | Out-Null; Write-Ok 'Cache DNS limpo (ipconfig).' }

    foreach ($alvo in @('1.1.1.1', '8.8.8.8')) {
        $r = Test-Connection -ComputerName $alvo -Count 3 -ErrorAction SilentlyContinue
        if ($r) {
            $ms = [math]::Round(($r | Measure-Object -Property ResponseTime -Average).Average)
            Write-Ok "Latencia ate ${alvo}: $ms ms"
            if ($ms -gt 150) { Add-Alerta "Latencia alta ate ${alvo}: $ms ms" }
        } else {
            Add-Alerta "Sem resposta de $alvo - verificar conectividade."
        }
    }

    if ($ResetarRede) {
        & netsh winsock reset | Out-Null
        & netsh int ip reset  | Out-Null
        Write-Aviso 'Winsock e TCP/IP resetados - REINICIALIZACAO NECESSARIA.'
        $script:precisaReiniciar = $true
    }
    return [long]0
}

function Repair-RedeCompleta {
    <#
      Ferramenta da opcao "Corrigir Rede e Internet" (veio de CorrigirRede.ps1).
      Separada da Invoke-ManutencaoRede de proposito: aquela roda dentro da
      manutencao completa e nao pode parar para perguntar nada.
      Dois niveis:
        BASICO   - flush DNS, ARP e renovar IP. Nao derruba a conexao.
        PROFUNDO - + release, netsh int ip reset e winsock reset. DERRUBA.
    #>
    if ($SomenteRelatorio) {
        Write-Simul 'Limparia DNS/ARP e renovaria o IP (modo basico).'
        return [long]0
    }

    Write-Etapa 'Como esta o acesso a esta maquina'

    # Reset de rede derruba atendimento remoto no meio: avisar antes.
    $procRemoto = @(Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -match '(?i)^(anydesk|teamviewer|rustdesk|vncserver|winvnc)' })
    $sessaoRDP = ($env:SESSIONNAME -and $env:SESSIONNAME -match '(?i)^RDP')
    $acessoRemoto = ($procRemoto.Count -gt 0) -or $sessaoRDP

    if ($acessoRemoto) {
        Write-Falha 'ACESSO REMOTO DETECTADO NESTA MAQUINA'
        foreach ($p in ($procRemoto | Select-Object -Unique ProcessName)) {
            Write-Info ("   programa: " + $p.ProcessName)
        }
        if ($sessaoRDP) { Write-Info ("   sessao RDP: " + $env:SESSIONNAME) }
        Write-Aviso 'O modo PROFUNDO derruba a conexao e VOCE PERDE O ACESSO.'
    } else {
        Write-Ok 'Nenhum programa de acesso remoto em execucao.'
    }

    # IP fixo se perde no reset profundo: mostrar antes para poder reconfigurar.
    $temIPFixo = $false
    Write-Etapa 'Configuracao de rede atual'
    try {
        foreach ($ad in @(Get-NetIPConfiguration -ErrorAction SilentlyContinue |
                          Where-Object { $_.NetAdapter.Status -eq 'Up' })) {
            $ipv4 = @($ad.IPv4Address)[0]
            $origem = if ($ipv4) { $ipv4.PrefixOrigin } else { 'sem IP' }
            if ($origem -eq 'Manual') { $temIPFixo = $true }
            $gw  = if ($ad.IPv4DefaultGateway) { @($ad.IPv4DefaultGateway)[0].NextHop } else { '-' }
            $dns = ($ad.DNSServer | Where-Object { $_.AddressFamily -eq 2 } |
                    ForEach-Object { $_.ServerAddresses }) -join ', '
            Write-Dest $ad.InterfaceAlias
            Write-Info ("   IP      : " + $(if ($ipv4) { $ipv4.IPAddress } else { '-' }) + "  ($origem)")
            Write-Info ("   Gateway : $gw")
            Write-Info ("   DNS     : " + $(if ($dns) { $dns } else { '-' }))
        }
    } catch { Write-Aviso "Nao foi possivel ler a configuracao: $($_.Exception.Message)" }

    if ($temIPFixo) {
        Write-Aviso 'Esta maquina usa IP FIXO. O modo profundo devolve o adaptador para DHCP.'
        Write-Info  'Anote os dados acima antes de prosseguir.'
    }

    # --- Escolha do modo ---
    $modoProfundo = $false
    if ($SemInteracao) {
        Write-Info 'Modo desatendido: executando apenas o BASICO.'
    } else {
        Write-Host ''
        Write-Host '     [1] BASICO   - limpa DNS/ARP e renova o IP (nao derruba a conexao)' -ForegroundColor Green
        Write-Host '     [2] PROFUNDO - + reset de TCP/IP e Winsock (DERRUBA e exige reiniciar)' -ForegroundColor Yellow
        Write-Host '     [0] Cancelar' -ForegroundColor DarkGray
        Write-Host ''
        $modo = (Read-Host '  Opcao').Trim()
        if ($modo -eq '0' -or $modo -eq '') { Write-Info 'Cancelado. Nada foi alterado.'; return [long]0 }
        if ($modo -eq '2') {
            Write-Host ''
            Write-Aviso 'O modo PROFUNDO vai executar:'
            Write-Info  '  ipconfig /release e /renew   (a conexao cai por alguns segundos)'
            Write-Info  '  netsh int ip reset           (zera o TCP/IP, volta para DHCP)'
            Write-Info  '  netsh winsock reset          (zera o catalogo Winsock)'
            if ($acessoRemoto) { Write-Falha 'VOCE ESTA CONECTADO REMOTAMENTE - VAI PERDER O ACESSO AGORA.' }
            $conf = Read-Host '  Confirma o modo PROFUNDO? (S/N)'
            if ($conf -match '^[Ss]') { $modoProfundo = $true }
            else { Write-Info 'Modo profundo cancelado. Seguindo apenas com o basico.' }
        }
    }

    # --- Basico ---
    Write-Etapa 'Limpando cache DNS...'
    try { Clear-DnsClientCache -ErrorAction Stop; Write-Ok 'Cache DNS limpo.' }
    catch { & ipconfig /flushdns | Out-Null; Write-Ok 'Cache DNS limpo (ipconfig).' }

    Write-Etapa 'Limpando cache ARP...'
    try { & arp -d '*' 2>&1 | Out-Null; Write-Ok 'Cache ARP limpo.' }
    catch { Write-Info 'Cache ARP: nao foi possivel limpar (normal em algumas versoes).' }

    if ($modoProfundo) {
        Write-Etapa 'Liberando endereco IP...'
        try { & ipconfig /release 2>&1 | Out-Null; Write-Ok 'IP liberado.' }
        catch { Write-Aviso "Falha ao liberar IP: $($_.Exception.Message)" }
    }

    Write-Etapa 'Renovando endereco IP...'
    try {
        $saida = & ipconfig /renew 2>&1
        if ($saida | Where-Object { $_ -match '(?i)(erro|error|failed|falhou|incapaz|unable)' }) {
            Write-Aviso 'Renovacao com avisos. Verifique cabo ou sinal Wi-Fi.'
        } else { Write-Ok 'IP renovado.' }
    } catch { Write-Aviso "Falha ao renovar IP: $($_.Exception.Message)" }

    # --- Profundo ---
    if ($modoProfundo) {
        Write-Etapa 'Resetando TCP/IP...'
        try { & netsh int ip reset 2>&1 | Out-Null; Write-Ok 'TCP/IP resetado.'; $script:precisaReiniciar = $true }
        catch { Write-Aviso "Falha no reset de TCP/IP: $($_.Exception.Message)" }

        Write-Etapa 'Resetando catalogo Winsock...'
        try { & netsh winsock reset 2>&1 | Out-Null; Write-Ok 'Winsock resetado.'; $script:precisaReiniciar = $true }
        catch { Write-Aviso "Falha no reset do Winsock: $($_.Exception.Message)" }

        Add-Alerta 'Reset de TCP/IP e Winsock aplicado - REINICIAR o computador.'
        if ($temIPFixo) { Add-Alerta 'A maquina usava IP FIXO: reconfigurar apos reiniciar.' }
    } else {
        Write-Info 'Reset de TCP/IP e Winsock nao executado (modo basico).'
    }

    # --- Conferencia ---
    Write-Etapa 'Testando conectividade...'
    $ok = 0
    foreach ($alvo in @('1.1.1.1', '8.8.8.8')) {
        $r = Test-Connection -ComputerName $alvo -Count 2 -ErrorAction SilentlyContinue
        if ($r) {
            $ms = [math]::Round(($r | Measure-Object -Property ResponseTime -Average).Average)
            Write-Ok "Resposta de ${alvo}: $ms ms"
            $ok++
        } else { Write-Falha "Sem resposta de $alvo" }
    }
    if ($ok -eq 0) {
        Write-Aviso 'Nenhum host respondeu. Verifique cabo, Wi-Fi e roteador.'
        if ($script:precisaReiniciar) { Write-Info 'Reinicie: o reset de TCP/IP so vale apos reiniciar.' }
        Add-Alerta 'Sem conectividade apos a correcao de rede.'
    }

    Write-Host ''
    Write-Dest ("Modo executado: " + $(if ($modoProfundo) { 'PROFUNDO' } else { 'BASICO' }))
    return [long]0
}

function Update-Defender {
    if ($SomenteRelatorio) { Write-Simul 'Atualizaria assinaturas do Defender.'; return [long]0 }
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        Write-Info "Antivirus ativo: $($mp.AMServiceEnabled)  |  Tempo real: $($mp.RealTimeProtectionEnabled)"
        if (-not $mp.RealTimeProtectionEnabled) { Add-Alerta 'Protecao em tempo real DESATIVADA.' }

        Update-MpSignature -ErrorAction SilentlyContinue
        Write-Ok 'Assinaturas atualizadas.'

        $ameacas = Get-MpThreatDetection -ErrorAction SilentlyContinue
        if ($ameacas) {
            Add-Alerta "$(@($ameacas).Count) deteccao(oes) no historico do Defender - revisar."
        } else {
            Write-Ok 'Nenhuma ameaca no historico.'
        }
    } catch {
        Write-Info 'Windows Defender nao disponivel (provavel antivirus de terceiros).'
    }
    return [long]0
}

# =========================================================================
# REGIAO: RELATORIO
# =========================================================================

function Export-RelatorioHtml {
    param([string]$Caminho, [object]$Sistema, [object[]]$Discos, [object[]]$Boots, [long]$LiberadoReal,
          [object[]]$Potencial, [object]$Inventario, [object[]]$Servicos, [object[]]$Dispositivos,
          [object[]]$Erros, [object[]]$Programas, [object[]]$Impressoras, [object[]]$Admins)

    $css = @'
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2328;background:#fff}
 h1{border-bottom:3px solid #0b5fff;padding-bottom:8px;color:#0b5fff}
 h2{margin-top:28px;color:#333;border-left:4px solid #0b5fff;padding-left:8px}
 table{border-collapse:collapse;width:100%;margin:12px 0;font-size:14px}
 th{background:#0b5fff;color:#fff;text-align:left;padding:8px}
 td{border-bottom:1px solid #e1e4e8;padding:7px}
 tr:nth-child(even){background:#f6f8fa}
 .ok{color:#1a7f37;font-weight:600}.falha{color:#cf222e;font-weight:600}
 .aviso{color:#9a6700;font-weight:600}.pulado{color:#57606a}
 .destaque{background:#0b5fff;color:#fff;padding:16px;border-radius:8px;font-size:20px;margin:16px 0}
 .alerta{background:#fff5f5;border-left:4px solid #cf222e;padding:12px;margin:8px 0}
 .rodape{margin-top:32px;color:#57606a;font-size:12px;border-top:1px solid #e1e4e8;padding-top:12px}
</style>
'@

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8">')
    [void]$sb.AppendLine("<title>Manutencao - $env:COMPUTERNAME</title>$css</head><body>")
    [void]$sb.AppendLine("<h1>Relatorio de Manutencao</h1>")
    [void]$sb.AppendLine("<p><b>$($Sistema.Maquina)</b> - $(Get-Date -Format 'dd/MM/yyyy HH:mm')</p>")
    [void]$sb.AppendLine("<div class='destaque'>Espaco liberado: $(Format-Tamanho $LiberadoReal)</div>")

    if ($script:alertas.Count -gt 0) {
        [void]$sb.AppendLine('<h2>Alertas</h2>')
        foreach ($a in $script:alertas) { [void]$sb.AppendLine("<div class='alerta'>$a</div>") }
    }

    [void]$sb.AppendLine('<h2>Sistema</h2><table>')
    $Sistema.PSObject.Properties | ForEach-Object {
        [void]$sb.AppendLine("<tr><th style='width:200px'>$($_.Name)</th><td>$($_.Value)</td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    if ($Potencial) {
        $comDados = @($Potencial | Where-Object { $_.Bytes -gt 0 } | Sort-Object Bytes -Descending)
        if ($comDados.Count -gt 0) {
            $pPadrao = [long](($comDados | Where-Object { $_.Quando -eq 'padrao' } | Measure-Object Bytes -Sum).Sum)
            $pExtra  = [long](($comDados | Where-Object { $_.Quando -ne 'padrao' -and $_.Categoria -ne 'AnyDesk: pasta completa' } | Measure-Object Bytes -Sum).Sum)
            [void]$sb.AppendLine('<h2>Espaco recuperavel (previsao)</h2>')
            [void]$sb.AppendLine("<div class='destaque'>Potencial total: $(Format-Tamanho ($pPadrao + $pExtra))</div>")
            [void]$sb.AppendLine('<table><tr><th>Categoria</th><th>Tamanho</th><th>Requer</th><th>Observacao</th></tr>')
            foreach ($i in $comDados) {
                $cls = if ($i.Quando -eq 'padrao') { 'ok' } else { 'aviso' }
                [void]$sb.AppendLine("<tr><td>$($i.Categoria)</td><td>$($i.Tamanho)</td><td class='$cls'>$($i.Quando)</td><td>$($i.Observacao)</td></tr>")
            }
            [void]$sb.AppendLine("<tr><td><b>Subtotal execucao padrao</b></td><td colspan='3'><b>$(Format-Tamanho $pPadrao)</b></td></tr>")
            [void]$sb.AppendLine("<tr><td><b>Subtotal etapas opcionais</b></td><td colspan='3'><b>$(Format-Tamanho $pExtra)</b></td></tr>")
            [void]$sb.AppendLine('</table>')
        }
    }

    [void]$sb.AppendLine('<h2>Etapas executadas</h2><table><tr><th>Etapa</th><th>Status</th><th>Liberado</th><th>Detalhe</th></tr>')
    foreach ($r in $script:resultados) {
        $cls = switch ($r.Status) { 'OK' {'ok'} 'FALHA' {'falha'} 'PARCIAL' {'aviso'} default {'pulado'} }
        [void]$sb.AppendLine("<tr><td>$($r.Etapa)</td><td class='$cls'>$($r.Status)</td><td>$($r.Liberado)</td><td>$($r.Detalhe)</td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    if ($Discos) {
        [void]$sb.AppendLine('<h2>Saude dos discos (SMART)</h2><table><tr><th>Disco</th><th>Tipo</th><th>Tamanho</th><th>Saude</th><th>Desgaste</th><th>Horas</th><th>Temp</th></tr>')
        foreach ($d in $Discos) {
            $cls = if ($d.Saude -eq 'Healthy') { 'ok' } else { 'falha' }
            [void]$sb.AppendLine("<tr><td>$($d.Disco)</td><td>$($d.Tipo)</td><td>$($d.Tamanho)</td><td class='$cls'>$($d.Saude)</td><td>$($d.Desgaste)</td><td>$($d.HorasLigado)</td><td>$($d.Temperatura)</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    }

    if ($Boots) {
        [void]$sb.AppendLine('<h2>Tempo de inicializacao (ultimos boots)</h2><table><tr><th>Data</th><th>Segundos</th></tr>')
        foreach ($b in $Boots) { [void]$sb.AppendLine("<tr><td>$($b.Data)</td><td>$($b.Segundos)</td></tr>") }
        [void]$sb.AppendLine('</table>')
    }

    # --- Secoes de diagnostico avancado ---
    function Add-Tabela {
        param([string]$Titulo, [object[]]$Dados, [int]$Max = 0)
        if (-not $Dados -or $Dados.Count -eq 0) { return }
        $linhas = if ($Max -gt 0) { $Dados | Select-Object -First $Max } else { $Dados }
        $cols = $linhas[0].PSObject.Properties.Name
        [void]$sb.AppendLine("<h2>$Titulo</h2><table><tr>")
        foreach ($c in $cols) { [void]$sb.AppendLine("<th>$c</th>") }
        [void]$sb.AppendLine('</tr>')
        foreach ($l in $linhas) {
            [void]$sb.AppendLine('<tr>')
            foreach ($c in $cols) {
                $v = [string]$l.$c
                $v = $v -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;'
                [void]$sb.AppendLine("<td>$v</td>")
            }
            [void]$sb.AppendLine('</tr>')
        }
        [void]$sb.AppendLine('</table>')
        if ($Max -gt 0 -and $Dados.Count -gt $Max) {
            [void]$sb.AppendLine("<p style='color:#57606a;font-size:12px'>Mostrando $Max de $($Dados.Count) itens.</p>")
        }
    }

    if ($Inventario) {
        [void]$sb.AppendLine('<h2>Inventario</h2><table>')
        $Inventario.PSObject.Properties | ForEach-Object {
            [void]$sb.AppendLine("<tr><th style='width:200px'>$($_.Name)</th><td>$($_.Value)</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    }
    Add-Tabela 'Servicos criticos parados' $Servicos
    Add-Tabela 'Dispositivos com erro' $Dispositivos
    Add-Tabela 'Impressoras' $Impressoras
    Add-Tabela 'Administradores locais' $Admins
    Add-Tabela 'Erros recentes (72h)' $Erros 10
    Add-Tabela 'Programas instalados' $Programas 300

    [void]$sb.AppendLine("<div class='rodape'>Gerado por ManutencaoCompleta v2.0 - SuporteTI<br>Backup de reversao: $($script:pastaExec)</div>")
    [void]$sb.AppendLine('</body></html>')

    Set-Content -Path $Caminho -Value $sb.ToString() -Encoding UTF8
}

# =========================================================================
# EXECUCAO
# =========================================================================

New-Item -ItemType Directory -Path $script:pastaExec -Force -ErrorAction SilentlyContinue | Out-Null
try { Start-Transcript -Path (Join-Path $script:pastaExec 'manutencao.log') -Force | Out-Null } catch { }

$script:precisaReiniciar = $false

Write-Host ''
Write-Host ('=' * 68) -ForegroundColor Cyan
Write-Host '        MANUTENCAO COMPLETA DO PC  -  v2.0  (2026.07.27)' -ForegroundColor Cyan
Write-Host ('=' * 68) -ForegroundColor Cyan
Write-Host ("  Maquina : $env:COMPUTERNAME") -ForegroundColor Gray
Write-Host ("  Iniciado: $($script:inicio.ToString('dd/MM/yyyy HH:mm:ss'))") -ForegroundColor Gray
Write-Host ("  Log     : $($script:pastaExec)") -ForegroundColor Gray
if ($SomenteRelatorio) {
    Write-Host ''
    Write-Host '  *** MODO SOMENTE RELATORIO - NADA SERA ALTERADO ***' -ForegroundColor Yellow
}
Write-Host ''
Write-Host '  Senhas salvas e sessoes de navegador SEMPRE preservadas.' -ForegroundColor DarkGray

# --- Modo standalone: FERRAMENTA UNICA (chamado pelo menu SuporteADV) ----
# Roda uma unica ferramenta e sai, sem a manutencao completa. Reaproveita as
# mesmas funcoes usadas nas etapas (fonte de verdade unica).
if ($Ferramenta) {
    $chave = $Ferramenta.ToLower().Trim()
    Write-Titulo "FERRAMENTA: $chave"
    try {
        switch ($chave) {
            'temp'          { Clear-Temporarios | Out-Null }
            'lixeira'       { Clear-LixeiraTodosDiscos | Out-Null }
            'miniaturas'    { Clear-Miniaturas | Out-Null }
            'windowsupdate' { Clear-WindowsUpdate | Out-Null }
            'navegadores'   { Clear-CacheNavegadores | Out-Null }
            'appcache'      { Clear-CacheAplicativos | Out-Null }
            'anydesk'       {
                # Opcao 14 do menu: apaga a PASTA INTEIRA do AnyDesk em
                # %APPDATA% e %LOCALAPPDATA%. Quem chamar com -AnyDeskModo
                # explicito manda no modo; sem isso o padrao aqui e Completo.
                $adModo = if ($PSBoundParameters.ContainsKey('AnyDeskModo')) { $AnyDeskModo } else { 'Completo' }
                $adForcar = [bool]$ForcarFecharAnyDesk

                if ($adModo -eq 'Completo') {
                    Write-Etapa 'Apagar a pasta do AnyDesk (%APPDATA% e %LOCALAPPDATA%)'
                    Write-Aviso 'A pasta inteira sera apagada. Voce PERDE:'
                    Write-Info  '  - o ID desta maquina no AnyDesk (sera gerado um ID novo)'
                    Write-Info  '  - a senha de acesso nao supervisionado'
                    Write-Info  '  - historico, chat e miniaturas'
                    Write-Info  'Um backup da pasta e gravado na pasta de log antes de apagar.'

                    $adProc = Get-Process -Name 'AnyDesk' -ErrorAction SilentlyContinue
                    if ($adProc) {
                        Write-Host ''
                        Write-Aviso 'O AnyDesk esta ABERTO nesta maquina.'
                        Write-Falha 'Se voce estiver atendendo por ele AGORA, a sessao CAI ao fechar.'
                        Write-Info  'Para apagar a pasta o AnyDesk precisa ser encerrado.'
                    }

                    if ($SemInteracao) {
                        if (-not $adForcar -and $adProc) {
                            Write-Aviso 'Modo desatendido com AnyDesk aberto: use -ForcarFecharAnyDesk. Etapa cancelada.'
                            break
                        }
                    } else {
                        Write-Host ''
                        $adResp = Read-Host '  Apagar a pasta do AnyDesk? (S/N)'
                        if ($adResp -notmatch '^[Ss]') {
                            Write-Info 'Cancelado. Nada foi apagado.'
                            break
                        }
                        if ($adProc -and -not $adForcar) {
                            $adResp2 = Read-Host '  Encerrar o AnyDesk agora para poder apagar? (S/N)'
                            if ($adResp2 -match '^[Ss]') { $adForcar = $true }
                            else {
                                Write-Info 'Sem encerrar o AnyDesk a pasta fica travada. Cancelado.'
                                break
                            }
                        }
                    }
                }

                Remove-PastaAnyDesk -Modo $adModo -Forcar:$adForcar | Out-Null
            }
            'winsxs'        { Clear-ComponentesWindows | Out-Null }
            'inicializacao' { Invoke-EtapaInicializacao | Out-Null }
            'appdata'       { Repair-AcessoAppData | Out-Null }
            'efeitos'       { Set-EfeitosVisuais | Out-Null; Set-DesempenhoEnergia | Out-Null }
            'padraonav'     { Set-PadraoNavegadores | Out-Null }
            'midi'          { Repair-MIDI | Out-Null }
            'rede'          { Invoke-ManutencaoRede | Out-Null }
            'horario'       { Sync-HorarioSistema }
            'defender'      { Update-Defender | Out-Null }
            'spooler'       { Repair-Spooler | Out-Null }
            'explorer'      { Restart-Explorer }
            'chkdsk'        { Request-Chkdsk -Letra 'C' }
            'appx'          { Repair-AppXPackages }
            'gpupdate'      { Invoke-GPUpdate }
            'ip'            { Update-EnderecoIP }
            'proxy'         { Reset-ProxyManual }
            'otimizar'      { Invoke-OtimizacaoDiscos -Letras @('C') | Out-Null }
            'sfc'           { Repair-Sistema | Out-Null }
            'smart'         { Test-SaudeDiscos | Format-Table -AutoSize | Out-Host }
            'perfis'        { Get-PerfisAntigos -DiasSemUso 180 -Medir | Format-Table -AutoSize | Out-Host }
            'topprocessos'  { Get-TopProcessos -Por Memoria -Top 12 | Format-Table -AutoSize | Out-Host }
            'programas'     { Get-ProgramasInstalados | Format-Table -AutoSize | Out-Host }
            'desinstalar'   {
                $progs = @(Get-ProgramasDesinstalaveis)
                Write-Info ("{0} programas instalados (estilo Painel de Controle):" -f $progs.Count)
                if ($progs.Count -eq 0) { Write-Aviso 'Nenhum programa listavel.' }
                else {
                    Write-Host ''
                    # Layout ADAPTATIVO: usa a largura da janela para colunas o
                    # mais LARGAS possivel. Prioriza nao cortar; se os nomes
                    # gigantes forcariam 1 coluna, cai para 2 colunas cortando
                    # apenas esses poucos (o resto continua inteiro).
                    $win = 120
                    try { if ($Host.UI.RawUI.WindowSize.Width -gt 20) { $win = $Host.UI.RawUI.WindowSize.Width } } catch { }
                    if ($win -gt 400) { $win = 400 }
                    $maxLen = ($progs | ForEach-Object { $_.Nome.Length } | Measure-Object -Maximum).Maximum
                    $pref = 7    # "NNN) "
                    $gap  = 3
                    $colWfull = $pref + $maxLen + $gap
                    $cols = [math]::Max(1, [math]::Floor(($win - 2) / $colWfull))
                    if ($cols -ge 2) {
                        $colW = $colWfull ; $nameW = $maxLen              # cabe tudo inteiro
                    } else {
                        $cols = 2                                          # forca 2 colunas
                        $colW = [math]::Floor(($win - 2) / $cols)
                        $nameW = $colW - $pref - 1                         # corta so os nomes gigantes
                    }
                    $rows = [math]::Ceiling($progs.Count / $cols)
                    function Fmt-Item($idx) {
                        $nm = $progs[$idx].Nome
                        if ($nm.Length -gt $nameW) { $nm = $nm.Substring(0, $nameW - 2) + '..' }
                        '{0,3}) {1}' -f ($idx + 1), $nm
                    }
                    for ($r = 0; $r -lt $rows; $r++) {
                        $linha = '  '
                        for ($c = 0; $c -lt $cols; $c++) {
                            $idx = $r + ($c * $rows)
                            if ($idx -lt $progs.Count) {
                                $cel = Fmt-Item $idx
                                if ($c -lt ($cols - 1)) { $cel = $cel.PadRight($colW) }
                                $linha += $cel
                            }
                        }
                        Write-Host $linha -ForegroundColor White
                    }
                    Write-Host ''
                    if (-not $SemInteracao) {
                        $sel = (Read-Host '  Numero do programa para DESINSTALAR (Enter cancela)').Trim()
                        if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $progs.Count) {
                            $p = $progs[[int]$sel - 1]
                            Write-Aviso ("Vai desinstalar: {0} {1}" -f $p.Nome, $p.Versao)
                            $c = (Read-Host '  Confirmar? (S/N)').Trim()
                            if ($c -match '^[SsYy]') {
                                $cmd = if ($p.QuietUninstall) { $p.QuietUninstall } else { $p.Desinstalar }
                                if ($p.MSI -or $cmd -match 'msiexec') {
                                    $cod = if ($p.Codigo -match '^\{.*\}$') { $p.Codigo } else { [regex]::Match($cmd, '\{[0-9A-Fa-f\-]+\}').Value }
                                    if ($cod) { Start-Process 'msiexec.exe' -ArgumentList "/x $cod" -ErrorAction SilentlyContinue }
                                    else { Start-Process 'cmd.exe' -ArgumentList '/c', $cmd -ErrorAction SilentlyContinue }
                                } else {
                                    Start-Process 'cmd.exe' -ArgumentList '/c', $cmd -ErrorAction SilentlyContinue
                                }
                                Write-Ok ("Desinstalador de '{0}' iniciado. Siga as instrucoes na janela dele." -f $p.Nome)
                            } else { Write-Aviso 'Cancelado.' }
                        } elseif ($sel) { Write-Aviso 'Numero invalido.' } else { Write-Info 'Nenhum selecionado.' }
                    }
                }
            }
            'diagnostico'   { Show-DiagnosticoCompleto }
            'consoles'      {
                Write-Etapa 'Abrindo Dispositivos, Servicos, Desinstalar Programa e Token Administration...'
                try { Start-Process 'devmgmt.msc' -ErrorAction Stop; Write-Ok 'Gerenciador de Dispositivos aberto.' }
                catch { try { Start-Process 'mmc.exe' -ArgumentList 'devmgmt.msc' -ErrorAction SilentlyContinue; Write-Ok 'Gerenciador de Dispositivos aberto.' } catch { Write-Aviso 'Falha ao abrir Gerenciador de Dispositivos.' } }
                try { Start-Process 'services.msc' -ErrorAction Stop; Write-Ok 'Servicos do Windows abertos.' }
                catch { try { Start-Process 'mmc.exe' -ArgumentList 'services.msc' -ErrorAction SilentlyContinue; Write-Ok 'Servicos do Windows abertos.' } catch { Write-Aviso 'Falha ao abrir Servicos.' } }
                try { Start-Process 'appwiz.cpl' -ErrorAction Stop; Write-Ok 'Desinstalar um programa (Painel de Controle) aberto.' }
                catch { try { Start-Process 'control.exe' -ArgumentList 'appwiz.cpl' -ErrorAction SilentlyContinue; Write-Ok 'Desinstalar um programa (Painel de Controle) aberto.' } catch { Write-Aviso 'Falha ao abrir Desinstalar um programa.' } }
                if (Open-TokenAdmin) { Write-Ok 'Token Administration aberto.' }
                else {
                    Write-Aviso 'Nao encontrei o app de administracao de token (SafeNet/eToken/Gemalto...).'
                    Write-Info  'Abra pelo menu Iniciar. Me diga o nome exato do programa que eu incluo na busca.'
                }
            }
            'certificados'  { Show-CertificadosInstalados | Out-Null }
            'backupcert'    { Backup-CertificadoA1 | Out-Null }
            'audiencia'     { Test-ProntoParaAudiencia | Out-Null }
            'prepararpc'    { Initialize-MaquinaEscritorio | Out-Null }
            'dll'           { Repair-DLLFaltando | Out-Null }
            'atendimento'   { New-RelatorioAtendimento | Out-Null }
            'desfazer'      { Undo-UltimaManutencao | Out-Null }
            'servidor'      { Set-MaquinaServidor | Out-Null }
            'clienterede'   { Set-MaquinaClienteRede | Out-Null }
            'diagrede'      { Test-RedeCompartilhamento | Out-Null }
            'sairrede'      { Remove-ConfiguracaoRede | Out-Null }
            'qualrede'      { Show-QualRede | Out-Null }
            'conexao'       { Repair-ProblemasConexao | Out-Null }
            'semservidor'   { Repair-AcessoAoServidor | Out-Null }
            'blindar'       { Protect-Servidor | Out-Null }
            'backup'        { Set-BackupCompartilhado | Out-Null }
            'fichrede'      { Export-FichaRede | Out-Null }
            'monitor'       { Set-MonitoramentoRede | Out-Null }
            'memoriaram'    { Test-MemoriaRAM | Out-Null }
            'reparoavancado' { Repair-SistemaAvancado | Out-Null }
            'bsod'          { Show-AnaliseBSOD | Out-Null }
            'proxycert'      { Repair-ProxyECertificados | Out-Null }
            'limparcerts'    { Clear-CertificadosVencidos | Out-Null }
            'pje'            { Set-AmbientePJe | Out-Null }
            'permissoesps'   { Repair-PermissoesPowerShell | Out-Null }
            'audio'          { Repair-Audio | Out-Null }
            'webcam'         { Repair-Webcam | Out-Null }
            'impressora'     { Remove-ImpressoraEDriver | Out-Null }
            'java'           { Set-JavaJuridico | Out-Null }
            'visualc'       { Install-VisualCRedist | Out-Null }
            'corrigirrede'  { Repair-RedeCompleta | Out-Null }
            'memoriavirtual' {
                Write-Etapa 'Memoria virtual (arquivo de paginacao)'

                # Situacao atual antes de abrir a tela: evita mexer as cegas.
                try {
                    $cs     = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
                    $ramGB  = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
                    Write-Info ("Memoria RAM instalada : $ramGB GB")
                    if ($cs.AutomaticManagedPagefile) {
                        Write-Info 'Arquivo de paginacao  : GERENCIADO PELO WINDOWS (automatico)'
                    } else {
                        Write-Info 'Arquivo de paginacao  : TAMANHO PERSONALIZADO (definido a mao)'
                        foreach ($ps in @(Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue)) {
                            $ini = if ($ps.InitialSize) { "$($ps.InitialSize) MB" } else { 'sem limite' }
                            $max = if ($ps.MaximumSize) { "$($ps.MaximumSize) MB" } else { 'sem limite' }
                            Write-Info ("   $($ps.Name)  inicial: $ini   maximo: $max")
                        }
                    }
                } catch { Write-Aviso "Nao foi possivel ler a configuracao atual: $($_.Exception.Message)" }

                try {
                    foreach ($pu in @(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue)) {
                        $tam  = [math]::Round($pu.AllocatedBaseSize / 1024, 2)
                        $uso  = [math]::Round($pu.CurrentUsage      / 1024, 2)
                        $pico = [math]::Round($pu.PeakUsage         / 1024, 2)
                        Write-Info ("   $($pu.Name)  tamanho: $tam GB   em uso: $uso GB   pico: $pico GB")
                        # Pico encostando no tamanho = RAM insuficiente, nao pagefile pequeno.
                        if ($pu.AllocatedBaseSize -gt 0 -and ($pu.PeakUsage / $pu.AllocatedBaseSize) -gt 0.9) {
                            Add-Alerta 'Pico de uso do arquivo de paginacao acima de 90% - avaliar aumento de RAM.'
                        }
                    }
                } catch { }

                # Espaco livre no disco do sistema: pagefile grande precisa caber.
                try {
                    $sys = Get-Volume -DriveLetter ($env:SystemDrive.Substring(0,1)) -ErrorAction SilentlyContinue
                    if ($sys) { Write-Info ("Livre em $env:SystemDrive        : " + (Format-Tamanho ([long]$sys.SizeRemaining))) }
                } catch { }

                Write-Host ''
                $abriu = $false
                try { Start-Process 'SystemPropertiesPerformance.exe' -ErrorAction Stop; $abriu = $true } catch { }
                if (-not $abriu) {
                    # Plano B: Propriedades do Sistema na aba Avancado
                    try { Start-Process 'control.exe' -ArgumentList 'sysdm.cpl,,3' -ErrorAction Stop; $abriu = $true } catch { }
                }

                if ($abriu) {
                    Write-Ok 'Opcoes de Desempenho abertas.'
                    Write-Info 'Na janela que abriu, siga:'
                    Write-Info '   1. aba "Avancado"'
                    Write-Info '   2. secao "Memoria virtual" > botao "Alterar..."'
                    Write-Info '   3. desmarque "Gerenciar automaticamente..." para definir a mao'
                    Write-Info '   4. depois de aplicar, o Windows pede para REINICIAR'
                } else {
                    Write-Aviso 'Nao foi possivel abrir a tela.'
                    Write-Info  'Abra a mao: Windows + R > SystemPropertiesPerformance'
                    Write-Info  '(ou sysdm.cpl > Avancado > Desempenho > Configuracoes > Avancado)'
                }

                Write-Host ''
                Write-Info 'Referencia: o padrao do Windows (automatico) atende a maioria dos casos.'
                Write-Info 'So mexa com motivo: erro de memoria virtual baixa, disco cheio, ou'
                Write-Info 'exigencia de sistema juridico especifico.'
            }
            'abrirappdata'  {
                Write-Etapa 'Abrindo a pasta %appdata% (Roaming) no Explorer...'
                $roaming = $env:APPDATA
                $abriu = $false
                try { Start-Process 'explorer.exe' -ArgumentList 'shell:AppData' -ErrorAction Stop; $abriu = $true } catch { }
                if (-not $abriu -and $roaming -and (Test-Path -LiteralPath $roaming)) {
                    try { Start-Process 'explorer.exe' -ArgumentList $roaming -ErrorAction Stop; $abriu = $true } catch { }
                }
                if ($abriu) {
                    Write-Ok ("Pasta aberta: $roaming")
                    Write-Info 'Para abrir a mao: Windows + R > shell:AppData   (ou explorer %appdata%)'
                    Write-Info ("Cache de programas fica em Local: $env:LOCALAPPDATA")
                } else {
                    Write-Aviso 'Nao foi possivel abrir a pasta pelo Explorer.'
                    Write-Info  'Abra a mao: Windows + R > shell:AppData   (ou explorer %appdata%)'
                }
            }
            'protecaovirus' {
                Write-Etapa 'Abrindo Seguranca do Windows > Protecao contra virus e ameacas...'
                $ab = $false
                try { Start-Process 'windowsdefender://threatsettings' -ErrorAction Stop; $ab = $true } catch { }
                if (-not $ab) { try { Start-Process 'windowsdefender:' -ErrorAction Stop; $ab = $true } catch { } }
                if (-not $ab) { try { Start-Process 'windowsdefender://' -ErrorAction SilentlyContinue; $ab = $true } catch { } }
                if ($ab) {
                    Write-Ok 'Tela aberta. Ali voce gerencia as Configuracoes de protecao contra virus e ameacas'
                    Write-Info '(inclusive a Protecao contra adulteracao, que precisa ser desligada a mao).'
                } else {
                    Write-Aviso 'Nao consegui abrir. Abra manualmente: Iniciar > Seguranca do Windows.'
                }
            }
            default         {
                Write-Falha "Ferramenta desconhecida: $Ferramenta"
                Write-Info 'Validas: diagnostico, protecaovirus, consoles, abrirappdata, memoriavirtual,'
                Write-Info 'temp, lixeira, miniaturas, windowsupdate, navegadores, appcache, anydesk,'
                Write-Info 'winsxs, inicializacao, appdata, efeitos, rede, horario, defender, spooler,'
                Write-Info 'explorer, chkdsk, appx, gpupdate, ip, proxy, otimizar, sfc, smart, perfis,'
                Write-Info 'topprocessos, programas, desinstalar.'
            }
        }
    } catch {
        Write-Falha "Erro na ferramenta '$chave': $($_.Exception.Message)"
        # Registra a falha num historico local. Sem isso, quando uma ferramenta
        # quebra na maquina do cliente e ele nao comenta, o problema fica
        # invisivel para sempre. A ficha da rede le este arquivo.
        try {
            $pastaFalhas = 'C:\ProgramData\SuporteTI'
            if (-not (Test-Path -LiteralPath $pastaFalhas)) {
                New-Item -ItemType Directory -Path $pastaFalhas -Force -ErrorAction SilentlyContinue | Out-Null
            }
            $arqFalhas = Join-Path $pastaFalhas 'falhas.txt'
            $linha = '{0}  {1}  ferramenta={2}  erro={3}' -f (Get-Date -Format 'dd/MM/yyyy HH:mm'),
                     $env:COMPUTERNAME, $chave, ($_.Exception.Message -replace '\s+', ' ')
            Add-Content -LiteralPath $arqFalhas -Value $linha -ErrorAction SilentlyContinue
            # nao deixar crescer sem fim
            $todas = @(Get-Content -LiteralPath $arqFalhas -ErrorAction SilentlyContinue)
            if ($todas.Count -gt 500) { $todas | Select-Object -Last 200 | Set-Content -LiteralPath $arqFalhas -ErrorAction SilentlyContinue }
        } catch { }
    }

    if ($script:alertas.Count -gt 0) {
        Write-Host ''
        Write-Host '  ATENCAO:' -ForegroundColor Red
        foreach ($a in $script:alertas) { Write-Host "     - $a" -ForegroundColor Red }
    }
    Write-Host ''
    # Ferramentas somente-leitura nao deixam log salvo.
    if ($chave -notin @('diagnostico', 'bsod', 'protecaovirus', 'consoles', 'abrirappdata', 'memoriavirtual', 'certificados', 'dll', 'memoriaram', 'atendimento', 'diagrede', 'qualrede', 'fichrede', 'audiencia')) {
        Write-Host ("  Log desta operacao: $($script:pastaExec)") -ForegroundColor Gray
    }
    Write-Host ('=' * 68) -ForegroundColor Green
    try { Stop-Transcript | Out-Null } catch { }
    # Diagnostico: abre o TXT temporario e nao deixa nada salvo.
    if ($chave -in @('diagnostico', 'bsod')) { Publicar-RelatorioTemp -RemoverPastaLog }
    # protecaovirus/consoles: so abriram telas; nao deixam pasta de log.
    elseif ($chave -in @('protecaovirus', 'consoles', 'abrirappdata', 'memoriavirtual', 'certificados', 'dll', 'memoriaram', 'atendimento', 'diagrede', 'qualrede', 'fichrede', 'audiencia')) {
        Remove-Item -LiteralPath (Join-Path $script:pastaExec 'manutencao.log') -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 200
        if ($script:pastaExec -and (Test-Path -LiteralPath $script:pastaExec)) {
            Remove-Item -LiteralPath $script:pastaExec -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    exit 0
}

# --- Modo standalone: restaurar quarentena ------------------------------
if ($RestaurarQuarentena) {
    $rc = Restore-Quarentena
    Write-Host ''
    Write-Host ("  Log desta operacao: $($script:pastaExec)") -ForegroundColor Gray
    Write-Host ('=' * 68) -ForegroundColor Green
    try { Stop-Transcript | Out-Null } catch { }
    exit $rc
}

# --- Modo standalone: scanner de malware ClamAV -------------------------
if ($EscanearVirus) {
    $rc = Invoke-VirusScan
    Write-Host ''
    Write-Host ("  Log desta operacao: $($script:pastaExec)") -ForegroundColor Gray
    Write-Host ('=' * 68) -ForegroundColor Green
    try { Stop-Transcript | Out-Null } catch { }
    exit $rc
}

# --- Modo standalone: antivirus/firewall --------------------------------
# -ReativarTudo e um atalho que liga as duas reativacoes de uma vez, para o
# tecnico nunca esquecer de religar uma das protecoes.
if ($ReativarTudo) { $ReativarDefender = $true; $ReativarFirewall = $true }

# Se qualquer switch de protecao foi usado, executa SO essa acao e sai, sem
# rodar a manutencao completa (ponto de restauracao, diagnostico, limpeza).
if ($DesativarDefender -or $DesativarFirewall -or $ReativarDefender -or $ReativarFirewall) {
    Invoke-GerenciarProtecao
    if ($script:precisaReiniciar) {
        Write-Host ''
        Write-Host '  >>> Algumas mudancas so completam apos REINICIAR.' -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host ("  Log desta operacao: $($script:pastaExec)") -ForegroundColor Gray
    Write-Host ('=' * 68) -ForegroundColor Green
    try { Stop-Transcript | Out-Null } catch { }
    return
}

# --- Linha de base -------------------------------------------------------
$sistema     = Get-RelatorioSistema
$discosSaude = Test-SaudeDiscos
$livreAntes  = Get-EspacoLivre 'C'

Write-Titulo 'DIAGNOSTICO INICIAL'
$sistema | Format-List | Out-Host

if ($sistema.UptimeDias -ge 7) {
    Add-Alerta "PC ligado ha $($sistema.UptimeDias) dias sem reiniciar - reinicializacao recomendada."
}
if ($sistema.FastStartup -eq 'Ligado' -and $sistema.UptimeDias -ge 7) {
    Write-Aviso 'Fast Startup ligado: "desligar" nao encerra o Windows de fato. Use Reiniciar.'
}

Write-Etapa 'Saude dos discos (SMART):'
$discosSaude | Format-Table -AutoSize | Out-Host
foreach ($d in $discosSaude) {
    if ($d.Saude -ne 'Healthy') { Add-Alerta "DISCO EM RISCO: $($d.Disco) - status $($d.Saude). Faca backup imediato." }
    if ($d.Desgaste -match '^(\d+)%$' -and [int]$Matches[1] -ge 80) {
        Add-Alerta "SSD $($d.Disco) com $($d.Desgaste) de desgaste - planejar troca."
    }
}

$vol = Get-Volume -DriveLetter 'C' -ErrorAction SilentlyContinue
if ($vol -and $vol.Size -gt 0) {
    $pct = ($vol.SizeRemaining / $vol.Size) * 100
    Write-Info ("Disco C: {0} livres de {1} ({2:N1}%)" -f (Format-Tamanho $vol.SizeRemaining), (Format-Tamanho $vol.Size), $pct)
    if ($pct -lt 10) { Add-Alerta ('Disco C: com apenas {0:N1}% livre - critico.' -f $pct) }
}

# --- Diagnostico avancado (somente leitura) ------------------------------
Write-Titulo 'DIAGNOSTICO AVANCADO'

$inventario = Get-InfoInventario
Write-Etapa 'Inventario da maquina:'
$inventario | Format-List | Out-Host

$horario = Test-HorarioSistema
Write-Etapa 'Horario do sistema:'
$horario | Format-List | Out-Host
if ($horario.PSObject.Properties.Name -contains 'DesvioSegundos' -and $horario.DesvioSegundos -gt 60) {
    Add-Alerta ("Relogio fora por {0:N0}s - quebra assinatura digital, PJe, HTTPS e login de dominio." -f $horario.DesvioSegundos)
}

$svcParados = @(Test-ServicosCriticos)
$svcGraves  = @($svcParados | Where-Object { $_.Gravidade -in @('PROBLEMA', 'DESATIVADO') })
if ($svcParados.Count -gt 0) {
    Write-Etapa 'Servicos criticos fora de execucao:'
    $svcParados | Format-Table -AutoSize | Out-Host
    foreach ($s in $svcGraves) { Add-Alerta "Servico $($s.Gravidade): $($s.Servico) ($($s.Descricao))" }
    if ($svcGraves.Count -eq 0) { Write-Ok 'Todos em modo sob demanda - nenhum problema real.' }
} else { Write-Ok 'Todos os servicos criticos estao em execucao.' }

$dispErro = @(Get-DispositivosComErro)
if ($dispErro.Count -gt 0) {
    Write-Etapa 'Dispositivos com problema:'
    $dispErro | Format-Table -AutoSize | Out-Host
    Write-Aviso "$($dispErro.Count) dispositivo(s) com erro - verifique se algum e hardware em uso."
} else { Write-Ok 'Nenhum dispositivo com erro (fantasmas conhecidos ignorados).' }

$proxy = Test-ProxyManual
if ($proxy.Ativo) { Add-Alerta "Proxy manual ativo: $($proxy.Servidor) - pode bloquear a internet." }
else { Write-Ok 'Nenhum proxy manual configurado.' }

Write-Etapa 'Maiores consumidores de memoria:'
Get-TopProcessos -Por Memoria -Top 8 | Format-Table -AutoSize | Out-Host

$impressoras = @(Get-StatusImpressoras)
if ($impressoras.Count -gt 0) {
    Write-Etapa 'Impressoras instaladas:'
    $impressoras | Format-Table -AutoSize | Out-Host
}
$filaPresa = @(Get-ChildItem "$env:SystemRoot\System32\spool\PRINTERS" -File -ErrorAction SilentlyContinue)
if ($filaPresa.Count -gt 0) {
    Add-Alerta "$($filaPresa.Count) trabalho(s) presos na fila de impressao - use -RepararSpooler."
}

$errosRecentes = @(Get-ErrosRecentes -Horas 72 -Max 6)
if ($errosRecentes.Count -gt 0) {
    Write-Etapa 'Erros registrados nas ultimas 72h:'
    $errosRecentes | Format-Table -AutoSize -Wrap | Out-Host
}

$falhasLogon = @(Get-FalhasLogon -Dias 7 -Max 5)
if ($falhasLogon.Count -gt 0) {
    Write-Aviso "$($falhasLogon.Count) falha(s) de logon nos ultimos 7 dias:"
    $falhasLogon | Format-Table -AutoSize | Out-Host
}

$adminsLocais = @(Get-AdminsLocais)
if ($adminsLocais.Count -gt 0) {
    Write-Etapa 'Administradores locais:'
    $adminsLocais | Format-Table -AutoSize | Out-Host
}

$histUpdates = @(Get-HistoricoUpdates -Max 6)
if ($histUpdates.Count -gt 0) {
    Write-Etapa 'Ultimas atualizacoes do Windows:'
    $histUpdates | Format-Table -AutoSize | Out-Host
    $falhou = @($histUpdates | Where-Object { $_.Resultado -eq 'FALHOU' })
    if ($falhou.Count -gt 0) { Add-Alerta "$($falhou.Count) atualizacao(oes) do Windows falharam." }
}

$programas = @(Get-ProgramasInstalados)
Write-Info "$($programas.Count) programa(s) instalado(s) - lista completa no relatorio HTML."

# --- Quanto da para liberar (somente disco C:) --------------------------
Write-Titulo 'ESPACO RECUPERAVEL - PREVISAO (C:)'
$potencial = @(Get-PotencialLimpeza -Completa:$EstimativaCompleta)
Show-PotencialLimpeza -Itens $potencial -Letra 'C'

$perfisAntigos = @(Get-PerfisAntigos -DiasSemUso 180 -Medir:$EstimativaCompleta)
if ($perfisAntigos.Count -gt 0) {
    Write-Aviso "$($perfisAntigos.Count) perfil(is) de usuario sem uso ha mais de 180 dias:"
    $perfisAntigos | Format-Table -AutoSize | Out-Host
    Write-Info 'Apenas listados - remocao deve ser feita manualmente apos confirmar com o cliente.'
}

# --- Selecao de discos ---------------------------------------------------
$discosParaOtimizar = [System.Collections.Generic.List[string]]::new()
$discosParaOtimizar.Add('C')

if (-not $PularOtimizacao) {
    $outrosDiscos = @(Get-Volume -ErrorAction SilentlyContinue |
        Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.DriveLetter -ne 'C' } |
        Sort-Object DriveLetter)

    if ($outrosDiscos.Count -gt 0 -and -not $SemInteracao -and -not $SomenteRelatorio) {
        Write-Titulo 'SELECAO DE DISCOS PARA OTIMIZACAO'
        Write-Info 'O disco C: sera otimizado automaticamente. Outros discos:'
        Write-Host ''
        $mapaDiscos = @{}
        $idx = 1
        foreach ($v in $outrosDiscos) {
            $letra  = [string]$v.DriveLetter
            $rotulo = if ($v.FileSystemLabel) { $v.FileSystemLabel } else { 'sem rotulo' }
            Write-Host ("     [$idx] ${letra}:  $(Format-Tamanho $v.Size) total  $(Format-Tamanho $v.SizeRemaining) livres  ($rotulo)") -ForegroundColor White
            $mapaDiscos[$idx] = $letra
            $idx++
        }
        Write-Host ''
        Write-Info 'Numeros separados por virgula (ex: 1,2), ou apenas ENTER para otimizar so o C:.'
        $resposta = (Read-HostComTimeout -Prompt '  Discos adicionais' -Segundos 20).Trim()
        foreach ($parte in ($resposta -split ',')) {
            $n = $parte.Trim()
            if ($n -match '^\d+$' -and $mapaDiscos.ContainsKey([int]$n)) { $discosParaOtimizar.Add($mapaDiscos[[int]$n]) }
        }
        Write-Info ('Selecionados: ' + (($discosParaOtimizar | ForEach-Object { "${_}:" }) -join '  '))
    } elseif ($outrosDiscos.Count -gt 0) {
        Write-Info 'Modo desatendido: apenas C: sera otimizado.'
    }
}

# --- Etapas --------------------------------------------------------------
$T = 16

# Foto das credenciais ANTES de qualquer alteracao, para conferir no fim.
$snapCredenciais = Get-SnapshotCredenciais

Invoke-Etapa -Nome 'Backup: restauracao, registro e credenciais' -Numero 1 -Total $T -Pular:$SemPontoRestauracao -Acao {
    New-PontoRestauracao | Out-Null
    Backup-Registro -Destino $script:pastaExec
    Backup-CredenciaisNavegador -Destino $script:pastaExec
    return [long]0
}

Invoke-Etapa -Nome 'Arquivos temporarios' -Numero 2 -Total $T -Pular:$PularLimpeza -Acao { Clear-Temporarios }

Invoke-Etapa -Nome 'Lixeira (todos os discos)' -Numero 3 -Total $T -Pular:$PularLimpeza -Acao { Clear-LixeiraTodosDiscos }

Invoke-Etapa -Nome 'Cache de miniaturas' -Numero 4 -Total $T -Pular:$PularLimpeza -Acao { Clear-Miniaturas }

Invoke-Etapa -Nome 'Cache do Windows Update' -Numero 5 -Total $T -Pular:$PularLimpeza -Acao { Clear-WindowsUpdate }

Invoke-Etapa -Nome 'Cache de navegadores (senhas preservadas)' -Numero 6 -Total $T -Pular:$PularNavegadores -Acao { Clear-CacheNavegadores }

Invoke-Etapa -Nome 'Cache de aplicativos (Java, PjeOffice, Teams, Office)' -Numero 7 -Total $T -Pular:$PularLimpeza -Acao { Clear-CacheAplicativos }

Invoke-Etapa -Nome 'AnyDesk em %APPDATA%' -Numero 8 -Total $T -Pular:(-not $LimparAnyDesk) -Acao {
    Remove-PastaAnyDesk -Modo $AnyDeskModo -Forcar:$ForcarFecharAnyDesk
}

Invoke-Etapa -Nome 'Componentes do Windows (WinSxS, cleanmgr)' -Numero 9 -Total $T -Pular:(-not $LimpezaAgressiva) -Acao { Clear-ComponentesWindows }

Invoke-Etapa -Nome 'Programas na inicializacao' -Numero 10 -Total $T -Pular:$PularInicializacao -Acao { Invoke-EtapaInicializacao }

Invoke-Etapa -Nome 'Acesso a %appdata% no Executar' -Numero 11 -Total $T -Pular:(-not $RepararAppData) -Acao { Repair-AcessoAppData }

Invoke-Etapa -Nome 'Efeitos visuais e energia' -Numero 12 -Total $T -Pular:$PularEfeitosVisuais -Acao {
    Set-EfeitosVisuais | Out-Null
    Set-DesempenhoEnergia | Out-Null
    return [long]0
}

Invoke-Etapa -Nome 'Rede, horario e Windows Defender' -Numero 13 -Total $T -Acao {
    Invoke-ManutencaoRede | Out-Null
    # Relogio certo e pre-requisito de assinatura digital e HTTPS.
    Sync-HorarioSistema
    if ($CorrigirProxy) { Reset-ProxyManual }
    if ($RenovarIP)     { Update-EnderecoIP }
    if ($AtualizarGPO)  { Invoke-GPUpdate }
    Update-Defender | Out-Null
    return [long]0
}

Invoke-Etapa -Nome 'Reparos rapidos (spooler, Explorer, disco)' -Numero 14 -Total $T `
             -Pular:(-not ($RepararSpooler -or $ReiniciarExplorer -or $AgendarChkdsk -or $RepararAppX)) -Acao {
    $b = [long]0
    if ($RepararSpooler)    { $b += Repair-Spooler }
    if ($RepararAppX)       { Repair-AppXPackages }
    if ($AgendarChkdsk)     { Request-Chkdsk -Letra 'C' }
    # Explorer por ultimo: reiniciar antes atrapalharia as etapas anteriores.
    if ($ReiniciarExplorer) { Restart-Explorer }
    return $b
}

Invoke-Etapa -Nome 'Integridade do sistema (DISM + SFC)' -Numero 15 -Total $T -Pular:(-not $RepararSistema) -Acao { Repair-Sistema }

# Otimizacao por ultimo: desfragmentar antes de liberar espaco e desperdicio.
Invoke-Etapa -Nome 'Otimizacao de disco' -Numero 16 -Total $T -Pular:$PularOtimizacao -Acao {
    Invoke-OtimizacaoDiscos -Letras $discosParaOtimizar.ToArray()
}

# Conferencia final: nenhuma senha/sessao pode ter sumido durante a execucao.
Write-Titulo 'VERIFICACAO DE CREDENCIAIS'
Test-IntegridadeCredenciais -Antes $snapCredenciais

Write-Progress -Activity 'Manutencao Completa' -Completed

# =========================================================================
# RELATORIO FINAL
# =========================================================================

$livreDepois  = Get-EspacoLivre 'C'
$liberadoReal = [long]($livreDepois - $livreAntes)
if ($liberadoReal -lt 0) { $liberadoReal = 0 }
$somaEtapas   = [long](($script:resultados | Measure-Object -Property Bytes -Sum).Sum)
$boots        = @(Get-TempoBoot)
$duracao      = (Get-Date) - $script:inicio

Write-Host ''
Write-Host ('=' * 68) -ForegroundColor Green
Write-Host '                        RELATORIO FINAL' -ForegroundColor Green
Write-Host ('=' * 68) -ForegroundColor Green
Write-Host ''

$script:resultados |
    Select-Object @{n='Etapa';e={$_.Etapa}}, Status, Liberado, Detalhe |
    Format-Table -AutoSize | Out-Host

Write-Host ''
if ($SomenteRelatorio) {
    Write-Host ("  POTENCIAL na execucao padrao          : $(Format-Tamanho ([long]$script:potencialPadrao))") -ForegroundColor Green
    Write-Host ("  POTENCIAL com etapas opcionais        : $(Format-Tamanho ([long]($script:potencialPadrao + $script:potencialExtra)))") -ForegroundColor Green
    Write-Host  '  (nada foi alterado - modo somente relatorio)' -ForegroundColor Yellow
} else {
    Write-Host ("  Previsto antes de iniciar (C:)        : $(Format-Tamanho ([long]$script:potencialPadrao))") -ForegroundColor Gray
}
Write-Host ("  Espaco liberado (medido no volume C:) : $(Format-Tamanho $liberadoReal)") -ForegroundColor Cyan
Write-Host ("  Soma contabilizada pelas etapas       : $(Format-Tamanho $somaEtapas)") -ForegroundColor Gray
Write-Host ("  Livre em C: antes / depois            : $(Format-Tamanho $livreAntes) / $(Format-Tamanho $livreDepois)") -ForegroundColor Gray
Write-Host ("  Duracao total                         : {0:hh\:mm\:ss}" -f $duracao) -ForegroundColor Gray

if ($boots.Count -gt 0) {
    Write-Host ''
    Write-Host '  Tempo de inicializacao (ultimos boots):' -ForegroundColor White
    foreach ($b in $boots) { Write-Host ("     $($b.Data)  -  $($b.Segundos)s") -ForegroundColor Gray }
    Write-Info 'Compare apos a proxima reinicializacao para medir o ganho.'
}

if ($script:alertas.Count -gt 0) {
    Write-Host ''
    Write-Host '  ATENCAO:' -ForegroundColor Red
    foreach ($a in $script:alertas) { Write-Host "     - $a" -ForegroundColor Red }
}

if ($script:precisaReiniciar) {
    Write-Host ''
    Write-Host '  >>> REINICIALIZACAO NECESSARIA para concluir as alteracoes de rede.' -ForegroundColor Yellow
}

# HTML
$arqHtml = Join-Path $script:pastaExec 'relatorio.html'
try {
    Export-RelatorioHtml -Caminho $arqHtml -Sistema $sistema -Discos $discosSaude -Boots $boots `
                         -LiberadoReal $liberadoReal -Potencial $potencial `
                         -Inventario $inventario -Servicos $svcParados -Dispositivos $dispErro `
                         -Erros $errosRecentes -Programas $programas -Impressoras $impressoras `
                         -Admins $adminsLocais
    Write-Host ''
    Write-Host ("  Relatorio HTML : $arqHtml") -ForegroundColor Cyan
    Write-Host ("  Backup/reversao: $(Join-Path $script:pastaExec 'backup-registro\RESTAURAR.cmd')") -ForegroundColor Cyan
} catch { Write-Aviso "Nao foi possivel gerar o HTML: $($_.Exception.Message)" }

if ($DestinoRelatorio -and (Test-Path $DestinoRelatorio)) {
    try {
        Copy-Item $arqHtml (Join-Path $DestinoRelatorio "$env:COMPUTERNAME-$($script:carimbo).html") -Force -ErrorAction Stop
        Write-Ok "Relatorio copiado para $DestinoRelatorio"
    } catch { Write-Aviso "Falha ao copiar relatorio: $($_.Exception.Message)" }
}

Write-Host ''
Write-Host ("  Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor Gray
Write-Host ('=' * 68) -ForegroundColor Green
Write-Host ''

try { Stop-Transcript | Out-Null } catch { }

# --- Relatorio TXT temporario + abertura automatica ---------------------
# O relatorio abre no Bloco de Notas a partir de um arquivo TEMPORARIO e NAO
# fica salvo (o tecnico usa "Salvar Como" se quiser). Os backups de registro/
# credenciais na pasta de logs continuam salvos (necessarios p/ reverter).
Publicar-RelatorioTemp
