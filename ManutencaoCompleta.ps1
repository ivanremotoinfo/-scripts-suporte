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
    [switch]$LimpezaAgressiva,      # WinSxS /ResetBase, cleanmgr, Prefetch
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

function Disable-DefenderCompleto {
    $st = Get-EstadoProtecao
    if (-not $st.DefenderPresente) { Write-Info 'Windows Defender nao esta presente/ativo nesta maquina.'; return }

    if ($st.TamperProtection) {
        Write-Falha 'PROTECAO CONTRA ADULTERACAO (Tamper Protection) ESTA LIGADA.'
        Write-Aviso 'O Windows bloqueia a desativacao do Defender por script.'
        Write-Info  'Desligue manualmente e rode de novo:'
        Write-Info  '  Seguranca do Windows > Protecao contra virus e ameacas >'
        Write-Info  '  Gerenciar configuracoes > Protecao contra adulteracao = Desligado'
        Add-Alerta 'Defender NAO foi desativado: Tamper Protection ligada (desligue na interface).'
        return
    }

    if ($SomenteRelatorio) { Write-Simul 'Desativaria a protecao em tempo real do Defender.'; return }

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
    try { Set-MpPreference -MAPSReporting Disabled -ErrorAction SilentlyContinue } catch { }
    try { Set-MpPreference -SubmitSamplesConsent NeverSend -ErrorAction SilentlyContinue } catch { }
    try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue } catch { }

    # Reforco via politica (persiste apos reboot enquanto TP estiver desligada)
    try {
        $k1 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        $k2 = "$k1\Real-Time Protection"
        foreach ($k in @($k1, $k2)) { if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null } }
        Set-ItemProperty -Path $k1 -Name 'DisableAntiSpyware' -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $k2 -Name 'DisableRealtimeMonitoring' -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $k2 -Name 'DisableBehaviorMonitoring' -Value 1 -Type DWord -ErrorAction SilentlyContinue
    } catch { }

    $depois = Get-EstadoProtecao
    if ($depois.RealtimeAtivo) {
        Write-Aviso "Protecao em tempo real ainda ativa ($ok pref. aplicadas, $falhou falharam)."
        Write-Info  'O Windows pode reativar sozinho apos alguns minutos ou no reboot.'
    } else {
        Write-Ok "Defender desativado ($ok configuracoes aplicadas)."
    }
    Add-Alerta 'DEFENDER DESATIVADO - reative com -ReativarDefender assim que possivel.'
}

function Enable-DefenderCompleto {
    if ($SomenteRelatorio) { Write-Simul 'Reativaria o Defender e restauraria os padroes.'; return }

    # Remove as politicas que forcavam a desativacao
    try {
        $k1 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        $k2 = "$k1\Real-Time Protection"
        foreach ($n in @('DisableAntiSpyware')) { Remove-ItemProperty -Path $k1 -Name $n -ErrorAction SilentlyContinue }
        foreach ($n in @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring')) {
            Remove-ItemProperty -Path $k2 -Name $n -ErrorAction SilentlyContinue
        }
    } catch { }

    $prefs = @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableBlockAtFirstSeen',
               'DisableIOAVProtection', 'DisableScriptScanning', 'DisableArchiveScanning',
               'DisableEmailScanning', 'DisableRemovableDriveScanning')
    foreach ($p in $prefs) { try { Set-MpPreference -$p $false -ErrorAction SilentlyContinue } catch { } }
    try { Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue } catch { }
    try { Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue } catch { }

    try {
        $svc = Get-Service WinDefend -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') { Start-Service WinDefend -ErrorAction SilentlyContinue }
    } catch { }
    try { Update-MpSignature -ErrorAction SilentlyContinue } catch { }

    $st = Get-EstadoProtecao
    if ($st.RealtimeAtivo) { Write-Ok 'Defender REATIVADO e assinaturas atualizadas.' }
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
            $r = (Read-Host '  Digite DESATIVAR para confirmar').Trim()
            if ($r -ne 'DESATIVAR') { Write-Aviso 'Cancelado pelo operador.'; return }
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
                     "$env:LOCALAPPDATA\CrashDumps", "$env:SystemRoot\Minidump")) {
        $m = Measure-Pasta $p; $bytes += $m.Bytes; $qtd += $m.Arquivos
    }
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
    Add-Item 'Prefetch' $m.Bytes $m.Arquivos '-LimpezaAgressiva' 'piora os proximos boots'

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
    $b += Remove-Files -Pasta "$env:SystemRoot\Minidump"
    $b += Remove-Files -Pasta "$env:SystemRoot\Logs\CBS" -DiasAntigos 7
    $dump = "$env:SystemRoot\MEMORY.DMP"
    if (Test-Path -LiteralPath $dump) {
        $t = [long](Get-Item -LiteralPath $dump -Force -ErrorAction SilentlyContinue).Length
        if ($SomenteRelatorio) {
            $b += $t   # em simulacao tambem precisa entrar na conta
        } else {
            try { Remove-Item -LiteralPath $dump -Force -ErrorAction Stop; $b += $t } catch { }
        }
    }
    $total += $b; Write-Ok "Erros e dumps  : $(Format-Tamanho $b)"

    Write-Etapa 'Cache de instaladores e entrega de conteudo...'
    $b = [long]0
    $b += Remove-Files -Pasta "$env:LOCALAPPDATA\Package Cache" -DiasAntigos 90
    $b += Remove-Files -Pasta "$env:LOCALAPPDATA\Downloaded Installations" -DiasAntigos 90
    $total += $b; Write-Ok "Instaladores   : $(Format-Tamanho $b)"

    if ($LimpezaAgressiva) {
        # Prefetch fora do modo agressivo de proposito: apagar libera ~10 MB
        # e PIORA o boot nos proximos 3-5 inicios ate o Windows reconstruir.
        Write-Etapa 'Prefetch (modo agressivo)...'
        $b = Remove-Files -Pasta "$env:SystemRoot\Prefetch" -Filtro '*.pf'
        $total += $b; Write-Ok "Prefetch       : $(Format-Tamanho $b)"
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
        @{ Chave = $chaveDsk; Nome = 'FontSmoothingType';  Valor = 2; Tipo = 'DWord';  Desc = 'Suavizacao ClearType' }
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

    try { & rundll32.exe user32.dll,UpdatePerUserSystemParameters 1 True } catch { }
    Write-Ok "$qtd configuracao(s) aplicada(s)."
    Write-Aviso 'Algumas mudancas exigem logoff/logon para efeito completo.'
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
    if ($SomenteRelatorio) { Write-Simul 'Executaria DISM /RestoreHealth e SFC /scannow.'; return [long]0 }

    # Ordem correta: DISM primeiro (repara a fonte que o SFC usa), depois SFC.
    Write-Etapa 'DISM /RestoreHealth - pode levar 10 a 20 minutos...'
    & dism.exe /Online /Cleanup-Image /RestoreHealth | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Ok 'Imagem do Windows integra.' }
    else { Write-Aviso "DISM retornou codigo $LASTEXITCODE." }

    Write-Etapa 'SFC /scannow - pode levar 5 a 15 minutos...'
    $saida = (& sfc.exe /scannow) -join ' '
    $saida = $saida -replace "`0", ''   # sfc emite UTF-16 no console
    if ($saida -match 'did not find any integrity violations|nao encontrou nenhuma viola') {
        Write-Ok 'Nenhuma violacao de integridade encontrada.'
    } elseif ($saida -match 'successfully repaired|reparou com exito') {
        Write-Ok 'Arquivos corrompidos foram reparados.'
    } else {
        Write-Aviso 'Verifique %windir%\Logs\CBS\CBS.log para detalhes.'
    }
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
Write-Host '              MANUTENCAO COMPLETA DO PC  -  v2.0' -ForegroundColor Cyan
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
            'anydesk'       { Remove-PastaAnyDesk -Modo $AnyDeskModo -Forcar:$ForcarFecharAnyDesk | Out-Null }
            'winsxs'        { Clear-ComponentesWindows | Out-Null }
            'inicializacao' { Invoke-EtapaInicializacao | Out-Null }
            'appdata'       { Repair-AcessoAppData | Out-Null }
            'efeitos'       { Set-EfeitosVisuais | Out-Null; Set-DesempenhoEnergia | Out-Null }
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
            'diagnostico'   { Show-DiagnosticoCompleto }
            default         {
                Write-Falha "Ferramenta desconhecida: $Ferramenta"
                Write-Info 'Validas: diagnostico, temp, lixeira, miniaturas, windowsupdate, navegadores,'
                Write-Info 'appcache, anydesk, winsxs, inicializacao, appdata, efeitos, rede, horario,'
                Write-Info 'defender, spooler, explorer, chkdsk, appx, gpupdate, ip, proxy, otimizar,'
                Write-Info 'sfc, smart, perfis, topprocessos, programas.'
            }
        }
    } catch { Write-Falha "Erro na ferramenta '$chave': $($_.Exception.Message)" }

    if ($script:alertas.Count -gt 0) {
        Write-Host ''
        Write-Host '  ATENCAO:' -ForegroundColor Red
        foreach ($a in $script:alertas) { Write-Host "     - $a" -ForegroundColor Red }
    }
    Write-Host ''
    if ($chave -ne 'diagnostico') {
        Write-Host ("  Log desta operacao: $($script:pastaExec)") -ForegroundColor Gray
    }
    Write-Host ('=' * 68) -ForegroundColor Green
    try { Stop-Transcript | Out-Null } catch { }
    # Diagnostico: abre o TXT temporario e nao deixa nada salvo.
    if ($chave -eq 'diagnostico') { Publicar-RelatorioTemp -RemoverPastaLog }
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
