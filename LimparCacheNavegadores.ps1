# LimparCacheNavegadores.ps1
# Limpa cache, historico e cookies do Chrome, Edge e Firefox de todos os usuarios
# NAO remove: senhas salvas, favoritos/bookmarks, extensoes

$ErrorActionPreference = 'Continue'

# -------------------------------------------------------------------------
# Funcoes auxiliares
# -------------------------------------------------------------------------

function Write-Etapa { param([string]$t) Write-Host "`n>> $t" -ForegroundColor Cyan }
function Write-Ok    { param([string]$t) Write-Host '   [OK] ' -ForegroundColor Green  -NoNewline; Write-Host $t }
function Write-Aviso { param([string]$t) Write-Host '   [!]  ' -ForegroundColor Yellow -NoNewline; Write-Host $t }
function Write-Falha { param([string]$t) Write-Host '   [X]  ' -ForegroundColor Red    -NoNewline; Write-Host $t }
function Write-Info  { param([string]$t) Write-Host "   $t"   -ForegroundColor Gray }
function Write-Dest  { param([string]$t) Write-Host "   $t"   -ForegroundColor White }

function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -le 0)              { return '0 B'  }
    if ($Bytes -ge 1GB)            { return [math]::Round($Bytes / 1GB, 2).ToString() + ' GB' }
    if ($Bytes -ge 1MB)            { return [math]::Round($Bytes / 1MB, 1).ToString() + ' MB' }
    if ($Bytes -ge 1KB)            { return [math]::Round($Bytes / 1KB, 0).ToString() + ' KB' }
    return $Bytes.ToString() + ' B'
}

function Get-TamanhoBytes {
    param([string]$Caminho)
    if (-not (Test-Path $Caminho -ErrorAction SilentlyContinue)) { return [long]0 }
    $item = Get-Item $Caminho -Force -ErrorAction SilentlyContinue
    if (-not $item) { return [long]0 }
    if ($item.PSIsContainer) {
        $soma = (Get-ChildItem $Caminho -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer } |
            Measure-Object -Property Length -Sum).Sum
        return [long]$(if ($soma) { $soma } else { 0 })
    }
    return [long]$item.Length
}

function Remove-ItemSeguro {
    param([string]$Caminho, [ref]$BytesAcumulados)
    if (-not (Test-Path $Caminho -ErrorAction SilentlyContinue)) { return }
    $tamanho = Get-TamanhoBytes $Caminho
    Remove-Item $Caminho -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $Caminho -ErrorAction SilentlyContinue)) {
        $BytesAcumulados.Value += $tamanho
    }
}

# =========================================================================
# Cabecalho
# =========================================================================

Write-Host ''
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host '   Limpeza de Cache de Navegadores - Todos os Usuarios' -ForegroundColor Cyan
Write-Host '   Chrome  |  Microsoft Edge  |  Mozilla Firefox      ' -ForegroundColor Cyan
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host ("   Iniciado em : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host ''

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if ($isAdmin) {
    Write-Ok 'Executando como Administrador (acesso a todos os perfis de usuario).'
} else {
    Write-Aviso 'Sem privilegios de Administrador. Apenas o usuario atual sera limpo.'
    Write-Info  'Execute como Administrador para limpar todos os usuarios do sistema.'
}

# =========================================================================
# ETAPA 1 - Fechar navegadores
# =========================================================================

Write-Etapa '1/5  Fechando navegadores abertos...'
Write-Host ''

$processos = @(
    @{ Nome = 'chrome';   Label = 'Google Chrome'    }
    @{ Nome = 'msedge';   Label = 'Microsoft Edge'   }
    @{ Nome = 'firefox';  Label = 'Mozilla Firefox'  }
)

foreach ($proc in $processos) {
    $instancias = @(Get-Process -Name $proc.Nome -ErrorAction SilentlyContinue)
    if ($instancias.Count -gt 0) {
        $instancias | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 800
        $restantes = @(Get-Process -Name $proc.Nome -ErrorAction SilentlyContinue)
        if ($restantes.Count -eq 0) {
            Write-Ok ($proc.Label + ': fechado (' + $instancias.Count + ' processo(s) encerrado(s)).')
        } else {
            Write-Aviso ($proc.Label + ': ' + $restantes.Count + ' processo(s) ainda em execucao. Arquivos bloqueados podem ser ignorados.')
        }
    } else {
        Write-Info ($proc.Label + ': nao estava em execucao.')
    }
}

# Aguardar liberacao de handles apos fechar os processos
Start-Sleep -Milliseconds 1500

# =========================================================================
# ETAPA 2 - Identificar perfis de usuario do Windows
# =========================================================================

Write-Etapa '2/5  Identificando perfis de usuario em C:\Users...'
Write-Host ''

$nomesIgnorados = '^(Public|All Users|Default|Default User|defaultuser0|desktop\.ini)$'
$usuariosDir = 'C:\Users'

$usuarios = @(Get-ChildItem $usuariosDir -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch $nomesIgnorados })

if ($usuarios.Count -eq 0) {
    Write-Falha 'Nenhum perfil de usuario encontrado em C:\Users.'
    exit 1
}

Write-Ok ("$($usuarios.Count) perfil(is) encontrado(s): " + ($usuarios.Name -join ', '))

# =========================================================================
# ETAPA 3 - Limpar Google Chrome
# =========================================================================

Write-Etapa '3/5  Limpando Google Chrome...'
Write-Host ''

$totalChrome = [long]0

$pastasPerfil   = @('Cache', 'Code Cache', 'GPUCache', 'Media Cache', 'databases',
                     'Local Storage', 'Session Storage', 'IndexedDB')
$arquivosPerfil = @('History', 'History-journal', 'Cookies', 'Cookies-journal',
                     'Visited Links', 'Network Action Predictor',
                     'Top Sites', 'Top Sites-journal',
                     'Shortcuts', 'Shortcuts-journal')

foreach ($usuario in $usuarios) {
    $chromeBase = Join-Path $usuario.FullName 'AppData\Local\Google\Chrome\User Data'
    if (-not (Test-Path $chromeBase -ErrorAction SilentlyContinue)) { continue }

    $bytesUsuario = [long]0

    $perfisChrome = @(Get-ChildItem $chromeBase -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' -or $_.Name -eq 'Guest Profile' })

    if ($perfisChrome.Count -eq 0) { continue }

    Write-Dest ("   Usuario: $($usuario.Name)  ($($perfisChrome.Count) perfil(is) Chrome)")

    foreach ($perfil in $perfisChrome) {
        $perfilPath  = $perfil.FullName
        $bytesPerfil = [long]0

        # Pastas internas do perfil
        foreach ($pasta in $pastasPerfil) {
            $caminho = Join-Path $perfilPath $pasta
            Remove-ItemSeguro $caminho ([ref]$bytesPerfil)
        }

        # Service Worker CacheStorage (subpasta)
        $swCache = Join-Path $perfilPath 'Service Worker\CacheStorage'
        Remove-ItemSeguro $swCache ([ref]$bytesPerfil)

        # Arquivos de historico e cookies
        foreach ($arq in $arquivosPerfil) {
            $caminho = Join-Path $perfilPath $arq
            Remove-ItemSeguro $caminho ([ref]$bytesPerfil)
        }

        $bytesUsuario += $bytesPerfil
        if ($bytesPerfil -gt 0) {
            Write-Ok ('   [' + $perfil.Name.PadRight(12) + '] liberado: ' + (Format-Bytes $bytesPerfil))
        } else {
            Write-Info ('   [' + $perfil.Name + '] ja estava vazio.')
        }
    }

    $totalChrome += $bytesUsuario
}

if ($totalChrome -eq 0) {
    Write-Info 'Google Chrome: nenhum cache encontrado ou navegador nao instalado.'
} else {
    Write-Ok ('Chrome - Total liberado: ' + (Format-Bytes $totalChrome))
}

# =========================================================================
# ETAPA 4 - Limpar Microsoft Edge
# =========================================================================

Write-Etapa '4/5  Limpando Microsoft Edge...'
Write-Host ''

$totalEdge = [long]0

foreach ($usuario in $usuarios) {
    $edgeBase = Join-Path $usuario.FullName 'AppData\Local\Microsoft\Edge\User Data'
    if (-not (Test-Path $edgeBase -ErrorAction SilentlyContinue)) { continue }

    $bytesUsuario = [long]0

    $perfisEdge = @(Get-ChildItem $edgeBase -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' -or $_.Name -eq 'Guest Profile' })

    if ($perfisEdge.Count -eq 0) { continue }

    Write-Dest ("   Usuario: $($usuario.Name)  ($($perfisEdge.Count) perfil(is) Edge)")

    foreach ($perfil in $perfisEdge) {
        $perfilPath  = $perfil.FullName
        $bytesPerfil = [long]0

        foreach ($pasta in $pastasPerfil) {
            $caminho = Join-Path $perfilPath $pasta
            Remove-ItemSeguro $caminho ([ref]$bytesPerfil)
        }

        $swCache = Join-Path $perfilPath 'Service Worker\CacheStorage'
        Remove-ItemSeguro $swCache ([ref]$bytesPerfil)

        foreach ($arq in $arquivosPerfil) {
            $caminho = Join-Path $perfilPath $arq
            Remove-ItemSeguro $caminho ([ref]$bytesPerfil)
        }

        $bytesUsuario += $bytesPerfil
        if ($bytesPerfil -gt 0) {
            Write-Ok ('   [' + $perfil.Name.PadRight(12) + '] liberado: ' + (Format-Bytes $bytesPerfil))
        } else {
            Write-Info ('   [' + $perfil.Name + '] ja estava vazio.')
        }
    }

    $totalEdge += $bytesUsuario
}

if ($totalEdge -eq 0) {
    Write-Info 'Microsoft Edge: nenhum cache encontrado ou navegador nao instalado.'
} else {
    Write-Ok ('Edge - Total liberado: ' + (Format-Bytes $totalEdge))
}

# =========================================================================
# ETAPA 5 - Limpar Mozilla Firefox
# =========================================================================

Write-Etapa '5/5  Limpando Mozilla Firefox...'
Write-Host ''

$totalFirefox = [long]0

# places.sqlite contem historico E favoritos. Remover apaga ambos.
Write-Aviso 'places.sqlite contem historico E favoritos do Firefox.'
Write-Info  'Sera removido conforme solicitado. Favoritos locais do Firefox serao perdidos.'
Write-Info  'Senhas (key4.db, logins.json) e extensoes serao preservadas.'
Write-Host ''

$pastasCacheFF  = @('cache2', 'startupCache', 'storage')
$arquivosFF     = @(
    'cookies.sqlite', 'cookies.sqlite-wal', 'cookies.sqlite-shm',
    'places.sqlite',  'places.sqlite-wal',  'places.sqlite-shm',
    'formhistory.sqlite',
    'content-prefs.sqlite',
    'webappsstore.sqlite',
    'sessionstore.jsonlz4'
)

# Arquivos que NAO devem ser removidos (protecao explicita)
$protegidos = @('key4.db', 'logins.json', 'signons.sqlite', 'cert9.db',
                'extensions.json', 'extension-settings.json', 'user.js',
                'bookmarkbackups')

foreach ($usuario in $usuarios) {
    $ffBase = Join-Path $usuario.FullName 'AppData\Roaming\Mozilla\Firefox\Profiles'
    if (-not (Test-Path $ffBase -ErrorAction SilentlyContinue)) { continue }

    $perfisFF = @(Get-ChildItem $ffBase -Directory -ErrorAction SilentlyContinue)
    if ($perfisFF.Count -eq 0) { continue }

    $bytesUsuario = [long]0
    Write-Dest ("   Usuario: $($usuario.Name)  ($($perfisFF.Count) perfil(is) Firefox)")

    foreach ($perfil in $perfisFF) {
        $perfilPath  = $perfil.FullName
        $bytesPerfil = [long]0

        # Pastas de cache
        foreach ($pasta in $pastasCacheFF) {
            $caminho = Join-Path $perfilPath $pasta
            Remove-ItemSeguro $caminho ([ref]$bytesPerfil)
        }

        # Arquivos individuais
        foreach ($arq in $arquivosFF) {
            # Verificacao de protecao (nao deve ocorrer, mas por seguranca)
            if ($protegidos -contains $arq) { continue }
            $caminho = Join-Path $perfilPath $arq
            Remove-ItemSeguro $caminho ([ref]$bytesPerfil)
        }

        $bytesUsuario += $bytesPerfil
        if ($bytesPerfil -gt 0) {
            Write-Ok ('   [' + $perfil.Name.Substring(0, [Math]::Min(24, $perfil.Name.Length)).PadRight(24) + '] ' + (Format-Bytes $bytesPerfil))
        } else {
            Write-Info ('   [' + $perfil.Name + '] ja estava vazio.')
        }
    }

    $totalFirefox += $bytesUsuario
}

if ($totalFirefox -eq 0) {
    Write-Info 'Mozilla Firefox: nenhum cache encontrado ou navegador nao instalado.'
} else {
    Write-Ok ('Firefox - Total liberado: ' + (Format-Bytes $totalFirefox))
}

# =========================================================================
# Relatorio final
# =========================================================================

$totalGeral = $totalChrome + $totalEdge + $totalFirefox

Write-Host ''
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host '   RELATORIO FINAL - ESPACO LIBERADO                  ' -ForegroundColor Cyan
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host ''

$corChrome  = if ($totalChrome  -gt 0) { 'Green' } else { 'Gray' }
$corEdge    = if ($totalEdge    -gt 0) { 'Green' } else { 'Gray' }
$corFirefox = if ($totalFirefox -gt 0) { 'Green' } else { 'Gray' }
$corTotal   = if ($totalGeral   -gt 0) { 'White' } else { 'Gray' }

Write-Host ('   Google Chrome    : ' + (Format-Bytes $totalChrome).PadLeft(12))  -ForegroundColor $corChrome
Write-Host ('   Microsoft Edge   : ' + (Format-Bytes $totalEdge).PadLeft(12))    -ForegroundColor $corEdge
Write-Host ('   Mozilla Firefox  : ' + (Format-Bytes $totalFirefox).PadLeft(12)) -ForegroundColor $corFirefox
Write-Host ''
Write-Host ('   TOTAL LIBERADO   : ' + (Format-Bytes $totalGeral).PadLeft(12))   -ForegroundColor $corTotal
Write-Host ''

Write-Host '   Preservados (nao removidos):' -ForegroundColor DarkGray
Write-Host '     Senhas salvas  (Login Data, key4.db, logins.json)' -ForegroundColor DarkGray
Write-Host '     Favoritos Chrome/Edge (arquivo Bookmarks)' -ForegroundColor DarkGray
Write-Host '     Extensoes instaladas' -ForegroundColor DarkGray
Write-Host '     Preferencias e configuracoes dos navegadores' -ForegroundColor DarkGray

Write-Host ''
Write-Host ("   Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host ''
