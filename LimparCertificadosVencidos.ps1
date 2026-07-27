# LimparCertificadosVencidos.ps1
# Limpa certificados indesejados da loja Pessoal (CurrentUser\My) do Windows
# Mantem ICP-Brasil e ICP-Portugal validos, remove residuos, pergunta sobre vencidos

$ErrorActionPreference = 'Continue'

# -------------------------------------------------------------------------
# Funcoes auxiliares de saida
# -------------------------------------------------------------------------

function Write-Etapa { param([string]$t) Write-Host "`n>> $t" -ForegroundColor Cyan }
function Write-Ok    { param([string]$t) Write-Host '   [OK] ' -ForegroundColor Green  -NoNewline; Write-Host $t }
function Write-Aviso { param([string]$t) Write-Host '   [!]  ' -ForegroundColor Yellow -NoNewline; Write-Host $t }
function Write-Falha { param([string]$t) Write-Host '   [X]  ' -ForegroundColor Red    -NoNewline; Write-Host $t }
function Write-Info  { param([string]$t) Write-Host "   $t"   -ForegroundColor Gray }
function Write-Dest  { param([string]$t) Write-Host "   $t"   -ForegroundColor White }

# -------------------------------------------------------------------------
# Funcoes de classificacao de certificados
# -------------------------------------------------------------------------

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
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host '   Limpeza de Certificados - Loja Pessoal (My)        ' -ForegroundColor Cyan
Write-Host '   Mantem ICP-Brasil e ICP-Portugal validos           ' -ForegroundColor Cyan
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host ("   Iniciado em : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host ''

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if ($isAdmin) {
    Write-Ok 'Executando como Administrador.'
} else {
    Write-Ok 'Executando como usuario padrao (suficiente para a loja Pessoal).'
}

# =========================================================================
# ETAPA 1 - Ler a loja CurrentUser\My
# =========================================================================

Write-Etapa '1/7  Lendo loja CurrentUser\My (aba Pessoal do certmgr)...'
Write-Host ''

$StoreName     = [System.Security.Cryptography.X509Certificates.StoreName]::My
$StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
$OpenFlags     = [System.Security.Cryptography.X509Certificates.OpenFlags]

$loja = [System.Security.Cryptography.X509Certificates.X509Store]::new($StoreName, $StoreLocation)

try {
    $loja.Open($OpenFlags::ReadOnly)
} catch {
    Write-Falha ('Nao foi possivel abrir a loja CurrentUser\My: ' + $_.Exception.Message)
    exit 1
}

$certsBrutos = @($loja.Certificates)
$loja.Close()

if ($certsBrutos.Count -eq 0) {
    Write-Ok 'A loja Pessoal esta vazia. Nenhuma acao necessaria.'
    exit 0
}

Write-Ok ("$($certsBrutos.Count) certificado(s) encontrado(s) na loja Pessoal.")

$hoje = Get-Date

# =========================================================================
# ETAPA 2 - Classificar cada certificado nas tres categorias
# =========================================================================

Write-Etapa '2/7  Classificando certificados...'
Write-Host ''

# Categoria A: ICP-Brasil/Portugal validos  -> MANTER (nunca removidos)
# Categoria B: ICP-Brasil/Portugal vencidos -> PERGUNTAR
# Categoria C: Desconhecidos                -> PERGUNTAR (nunca automatico)
#
# IMPORTANTE: certificado com chave privada (A1) removido da loja e' PERDIDO
# se o cliente nao tiver o arquivo .pfx guardado. Por isso nada e' removido
# sem confirmacao e a chave privada e' sempre sinalizada na tela.

$icpValidos   = [System.Collections.Generic.List[PSObject]]::new()
$icpVencidos  = [System.Collections.Generic.List[PSObject]]::new()
$desconhecidos = [System.Collections.Generic.List[PSObject]]::new()

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

    if ($isICP -and -not $vencido)  { $icpValidos.Add($obj)    }
    elseif ($isICP -and $vencido)   { $icpVencidos.Add($obj)   }
    else                            { $desconhecidos.Add($obj)  }
}

$comChave = @($desconhecidos | Where-Object { $_.ChavePrivada })

Write-Ok ("ICP-Brasil/Portugal validos (MANTER)     : " + $icpValidos.Count)
Write-Ok ("ICP-Brasil/Portugal vencidos (PERGUNTAR) : " + $icpVencidos.Count)
Write-Aviso ("Desconhecidos/residuos (PERGUNTAR)    : " + $desconhecidos.Count)
if ($comChave.Count -gt 0) {
    Write-Aviso ("   destes, COM CHAVE PRIVADA (A1)     : " + $comChave.Count + '  <-- atencao')
}

# =========================================================================
# ETAPA 3/5 - Exibir as tres categorias separadas
# =========================================================================

Write-Etapa '3/7  Lista completa por categoria...'

# --- Categoria A: ICP-Brasil validos ---
Write-Host ''
Write-Host '   ============================================================' -ForegroundColor Green
Write-Host '   CATEGORIA A  >>  Cert. ICP-Brasil / ICP-Portugal VALIDOS    ' -ForegroundColor Green
Write-Host '   ============================================================' -ForegroundColor Green
Write-Host ''

if ($icpValidos.Count -eq 0) {
    Write-Info 'Nenhum certificado ICP-Brasil ou ICP-Portugal valido encontrado.'
} else {
    foreach ($c in ($icpValidos | Sort-Object Vencimento)) {
        $diasInfo = if ($c.DiasRestantes -le 30) {
            '  [expira em ' + $c.DiasRestantes + ' dias]'
        } else {
            ''
        }
        $corNome = if ($c.DiasRestantes -le 30) { 'Yellow' } else { 'Green' }
        Write-Host ('   [' + $c.Tipo.PadRight(9) + '] ') -ForegroundColor Green -NoNewline
        Write-Host ($c.Nome + $diasInfo) -ForegroundColor $corNome
        if ($c.Identificador) {
            Write-Host ('   ' + ''.PadRight(12) + ' Ident.: ' + $c.Identificador) -ForegroundColor Gray
        }
        Write-Host ('   ' + ''.PadRight(12) + ' Emiss.: ' + $c.Emissor) -ForegroundColor Gray
        Write-Host ('   ' + ''.PadRight(12) + ' Valido: ' + $c.Vencimento.ToString('dd/MM/yyyy')) -ForegroundColor Gray
        Write-Host ('   ' + ''.PadRight(12) + ' Thumb : ' + $c.Thumbprint) -ForegroundColor DarkCyan
        Write-Host ''
    }
}

# --- Categoria B: ICP-Brasil vencidos ---
Write-Host '   ============================================================' -ForegroundColor Yellow
Write-Host '   CATEGORIA B  >>  Cert. ICP-Brasil / ICP-Portugal VENCIDOS   ' -ForegroundColor Yellow
Write-Host '   ============================================================' -ForegroundColor Yellow
Write-Host ''

if ($icpVencidos.Count -eq 0) {
    Write-Info 'Nenhum certificado ICP-Brasil ou ICP-Portugal vencido encontrado.'
} else {
    foreach ($c in ($icpVencidos | Sort-Object Vencimento -Descending)) {
        $diasAtras = [math]::Abs($c.DiasRestantes)
        Write-Host ('   [' + $c.Tipo.PadRight(9) + '] ') -ForegroundColor Yellow -NoNewline
        Write-Host $c.Nome -ForegroundColor White
        if ($c.Identificador) {
            Write-Host ('   ' + ''.PadRight(12) + ' Ident.: ' + $c.Identificador) -ForegroundColor Gray
        }
        Write-Host ('   ' + ''.PadRight(12) + ' Emiss.: ' + $c.Emissor) -ForegroundColor Gray
        Write-Host ('   ' + ''.PadRight(12) + ' Venceu: ' + $c.Vencimento.ToString('dd/MM/yyyy') + '  (ha ' + $diasAtras + ' dias)') -ForegroundColor Red
        Write-Host ('   ' + ''.PadRight(12) + ' Thumb : ' + $c.Thumbprint) -ForegroundColor DarkCyan
        Write-Host ''
    }
}

# --- Categoria C: Desconhecidos ---
Write-Host '   ============================================================' -ForegroundColor Red
Write-Host '   CATEGORIA C  >>  Certificados DESCONHECIDOS (sob consulta)  ' -ForegroundColor Red
Write-Host '   ============================================================' -ForegroundColor Red
Write-Host ''

if ($desconhecidos.Count -eq 0) {
    Write-Info 'Nenhum certificado desconhecido encontrado.'
} else {
    Write-Info 'Desconhecido = nao bateu com a lista de emissores ICP conhecidos.'
    Write-Info 'Pode ser residuo de software, mas tambem certificado corporativo,'
    Write-Info 'de VPN, de e-mail (S/MIME) ou de AC estrangeira. Confira antes.'
    Write-Host ''
    foreach ($c in ($desconhecidos | Sort-Object Nome)) {
        $statusVenc = if ($c.Vencido) { '  [VENCIDO]' } else { '' }
        Write-Host ('   [Residuo  ] ') -ForegroundColor Red -NoNewline
        Write-Host ($c.Nome + $statusVenc) -ForegroundColor White
        Write-Host ('   ' + ''.PadRight(12) + ' Emiss.: ' + $c.Emissor) -ForegroundColor Gray
        Write-Host ('   ' + ''.PadRight(12) + ' Validade: ' + $c.Vencimento.ToString('dd/MM/yyyy')) -ForegroundColor Gray
        Write-Host ('   ' + ''.PadRight(12) + ' Thumb : ' + $c.Thumbprint) -ForegroundColor DarkCyan
        if ($c.ChavePrivada) {
            Write-Host ('   ' + ''.PadRight(12) + ' CHAVE PRIVADA presente (A1) - remover e PERMANENTE') -ForegroundColor Red
        }
        Write-Host ''
    }
}

# =========================================================================
# ETAPA 4 - Verificar se ha algo a fazer
# =========================================================================

$temAcao = ($desconhecidos.Count -gt 0) -or ($icpVencidos.Count -gt 0)

if (-not $temAcao) {
    Write-Host ''
    Write-Ok 'Nenhum certificado para remover. Loja ja esta limpa.'
    Write-Host ''
    exit 0
}

# =========================================================================
# ETAPA 5/6 - Backup CSV antes de qualquer remocao
# =========================================================================

Write-Etapa '4/7  Exportando backup para a Area de Trabalho...'
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
        Categoria     = if (Test-ICPBrasil $s $i) { if ($c.NotAfter -lt $hoje) { 'ICP Vencido' } else { 'ICP Valido' } } else { 'Desconhecido' }
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

try {
    $linhasCSV | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
    $backupOk = $true
    Write-Ok "Lista salva: $csvPath"
    Write-Info ("$($linhasCSV.Count) certificado(s) registrado(s) no arquivo CSV.")
} catch {
    Write-Aviso 'Nao foi possivel salvar o CSV.'
    Write-Info  ('Erro: ' + $_.Exception.Message)
    Write-Host ''
    $respBackup = Read-Host '   Deseja continuar sem o backup? (S/N)'
    if ($respBackup -notmatch '^[Ss]') {
        Write-Info 'Operacao cancelada pelo usuario. Nenhum certificado foi removido.'
        exit 0
    }
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
    Write-Ok "$cerExportados arquivo(s) .cer exportado(s) em: $backupDir"
}

Write-Host ''
Write-Aviso 'LIMITE DO BACKUP: o .cer guarda apenas a parte PUBLICA do certificado.'
Write-Info  'A CHAVE PRIVADA (certificado A1) NAO e exportada por este backup e NAO'
Write-Info  'pode ser recuperada depois da remocao. So remova certificado com chave'
Write-Info  'privada se o cliente tiver o arquivo .pfx original guardado.'

# =========================================================================
# ETAPA 5 - Decisao sobre ICP-Brasil vencidos (pergunta)
# =========================================================================

# Selecao interativa reaproveitada pelas duas categorias removiveis.
# Nada e' removido sem passar por aqui.
function Select-CertsParaRemover {
    param(
        [PSObject[]]$Certificados,
        [string]$Titulo
    )
    $escolhidos = [System.Collections.Generic.List[PSObject]]::new()
    if (-not $Certificados -or $Certificados.Count -eq 0) { return $escolhidos }

    Write-Host ''
    Write-Host ('   [1] Remover TODOS (' + $Certificados.Count + ') - ' + $Titulo) -ForegroundColor White
    Write-Host  '   [2] Escolher um por um' -ForegroundColor White
    Write-Host  '   [3] Nao remover nenhum (manter por precaucao)' -ForegroundColor White
    Write-Host ''
    $opcao = Read-Host '   Opcao'

    if ($opcao -eq '1') {
        # Mesmo no "todos", chave privada exige um S/N adicional
        foreach ($c in $Certificados) {
            if ($c.ChavePrivada) {
                Write-Host ''
                Write-Aviso ('CHAVE PRIVADA (A1): ' + $c.Nome)
                Write-Info  'Sem o .pfx original este certificado nao volta.'
                $r = Read-Host '   Remover mesmo assim? (S/N)'
                if ($r -match '^[Ss]') { $escolhidos.Add($c) } else { Write-Info ('Mantido: ' + $c.Nome) }
            } else {
                $escolhidos.Add($c)
            }
        }
        Write-Info ("$($escolhidos.Count) certificado(s) marcado(s) para remocao.")
    } elseif ($opcao -eq '2') {
        $modoTodos = $false
        $modoPular = $false
        foreach ($c in ($Certificados | Sort-Object Vencimento -Descending)) {
            if ($modoPular) { break }
            if ($modoTodos -and -not $c.ChavePrivada) {
                $escolhidos.Add($c)
                Write-Info ('Marcado: ' + $c.Nome)
                continue
            }
            Write-Host ''
            Write-Host ('   ' + $c.Tipo.PadRight(12) + '  ' + $c.Nome) -ForegroundColor White
            if ($c.Identificador) { Write-Host ('   Ident. : ' + $c.Identificador) -ForegroundColor Gray }
            Write-Host ('   Validade: ' + $c.Vencimento.ToString('dd/MM/yyyy') + '  |  Emissor: ' + $c.Emissor) -ForegroundColor Gray
            Write-Host ('   Thumb  : ' + $c.Thumbprint) -ForegroundColor DarkCyan
            if ($c.ChavePrivada) {
                Write-Host '   CHAVE PRIVADA presente (A1) - remocao PERMANENTE sem o .pfx' -ForegroundColor Red
            }
            Write-Host '   [S] Remover  [N] Manter  [T] Remover todos restantes  [P] Manter todos restantes' -ForegroundColor Gray
            $resp = Read-Host '   Opcao'

            if     ($resp -match '^[Tt]') { $modoTodos = $true;  $escolhidos.Add($c) }
            elseif ($resp -match '^[Pp]') { $modoPular = $true }
            elseif ($resp -match '^[Ss]') { $escolhidos.Add($c) }
            else { Write-Info ('Mantido: ' + $c.Nome) }
        }
    } else {
        Write-Info 'Nenhum certificado desta categoria sera removido.'
    }
    return $escolhidos
}

# --- Categoria C: desconhecidos (NUNCA automatico) ---
$desconhecidosParaRemover = [System.Collections.Generic.List[PSObject]]::new()

if ($desconhecidos.Count -gt 0) {
    Write-Etapa ('5/7  Certificados desconhecidos (' + $desconhecidos.Count + ')  - aguardando confirmacao...')
    Write-Host ''
    Write-Host '   Estes NAO foram reconhecidos como ICP-Brasil ou ICP-Portugal.' -ForegroundColor Yellow
    Write-Host '   Na maioria dos casos sao residuos de software, mas a lista acima' -ForegroundColor Yellow
    Write-Host '   pode conter certificado corporativo, de VPN, de e-mail ou de AC' -ForegroundColor Yellow
    Write-Host '   estrangeira. Confira a lista antes de confirmar.' -ForegroundColor Yellow
    if ($comChave.Count -gt 0) {
        Write-Host ''
        Write-Host ('   ' + $comChave.Count + ' deste(s) tem CHAVE PRIVADA: remover e permanente.') -ForegroundColor Red
    }
    $desconhecidosParaRemover = Select-CertsParaRemover -Certificados $desconhecidos.ToArray() -Titulo 'desconhecidos/residuos'
}

# --- Categoria B: ICP vencidos ---
$icpVencidosParaRemover = [System.Collections.Generic.List[PSObject]]::new()

if ($icpVencidos.Count -gt 0) {
    Write-Etapa ('6/7  Certificados ICP vencidos (' + $icpVencidos.Count + ')  - aguardando confirmacao...')
    Write-Host ''
    Write-Host '   Estes certificados sao ICP-Brasil (eCPF/eCNPJ/OAB) ou ICP-Portugal (Cartao de Cidadao) porem estao vencidos.' -ForegroundColor Yellow
    Write-Host '   Certificados vencidos nao funcionam para assinar documentos.' -ForegroundColor Yellow
    Write-Host '   Se ja renovou o certificado, os vencidos podem ser removidos com seguranca.' -ForegroundColor Yellow
    $icpVencidosParaRemover = Select-CertsParaRemover -Certificados $icpVencidos.ToArray() -Titulo 'ICP vencidos (Brasil e Portugal)'
}

# =========================================================================
# ETAPA 7 - Executar remocoes e relatorio
# =========================================================================

Write-Etapa '7/7  Removendo certificados e gerando relatorio...'
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
        Write-Ok ('Removido [' + $Motivo + ']: ' + $CertObj.Nome)
    } catch {
        $removidosErro.Add([PSCustomObject]@{ Nome = $CertObj.Nome; Erro = $_.Exception.Message })
        Write-Falha ('Erro ao remover: ' + $CertObj.Nome + ' - ' + $_.Exception.Message)
    }
}

# Remover desconhecidos que o usuario confirmou
if ($desconhecidosParaRemover.Count -gt 0) {
    Write-Dest '   --- Removendo residuos/desconhecidos (confirmado) ---'
    Write-Host ''
    foreach ($c in $desconhecidosParaRemover) {
        Remove-CertDaLoja $c 'Residuo'
    }
}

# Remover ICP-Brasil vencidos se o usuario confirmou
if ($icpVencidosParaRemover.Count -gt 0) {
    Write-Host ''
    Write-Dest '   --- Removendo certificados ICP vencidos (confirmado) ---'
    Write-Host ''
    foreach ($c in $icpVencidosParaRemover) {
        Remove-CertDaLoja $c 'ICP vencido'
    }
}

# =========================================================================
# Relatorio final
# =========================================================================

$totalRemovidos = $removidosOK.Count
$totalErros     = $removidosErro.Count
$corRel = if ($totalRemovidos -gt 0 -and $totalErros -eq 0) { 'Green' } elseif ($totalErros -gt 0) { 'Yellow' } else { 'Cyan' }

Write-Host ''
Write-Host '======================================================' -ForegroundColor $corRel
Write-Host '   RELATORIO FINAL                                     ' -ForegroundColor $corRel
Write-Host '======================================================' -ForegroundColor $corRel
Write-Host ''

Write-Dest '   Resultado da analise:'
Write-Host ('   ICP-Brasil/Portugal validos   : ' + $icpValidos.Count) -ForegroundColor Green
Write-Host ('   ICP-Brasil/Portugal vencidos  : ' + $icpVencidos.Count) -ForegroundColor $(if ($icpVencidos.Count -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host ('   Residuos/desconhecidos encon. : ' + $desconhecidos.Count) -ForegroundColor $(if ($desconhecidos.Count -gt 0) { 'Yellow' } else { 'Gray' })

Write-Host ''
Write-Dest '   Resultado das remocoes:'
Write-Host ('   Removidos com sucesso         : ' + $totalRemovidos) -ForegroundColor $(if ($totalRemovidos -gt 0) { 'Green' } else { 'Gray' })
Write-Host ('   Erros ao remover              : ' + $totalErros) -ForegroundColor $(if ($totalErros -gt 0) { 'Red' } else { 'Gray' })

if ($removidosOK.Count -gt 0) {
    Write-Host ''
    Write-Dest '   Certificados removidos:'
    foreach ($r in $removidosOK) {
        Write-Host ('   [' + $r.Motivo.PadRight(12) + '] ' + $r.Nome) -ForegroundColor Green
        Write-Host ('   ' + ''.PadRight(16) + ' Thumb: ' + $r.Thumb) -ForegroundColor DarkCyan
    }
}

if ($removidosErro.Count -gt 0) {
    Write-Host ''
    Write-Dest '   Erros (certificados que nao puderam ser removidos):'
    foreach ($e in $removidosErro) {
        Write-Host ('   ' + $e.Nome + ' : ' + $e.Erro) -ForegroundColor Red
    }
    Write-Info '   Certificados em uso por outros programas podem nao ser removiveis.'
    Write-Info '   Feche os programas e execute o script novamente se necessario.'
}

Write-Host ''
if ($backupOk) {
    Write-Host ('   Backup : ' + $backupDir) -ForegroundColor DarkCyan
    Write-Host '   (lista em CSV + .cer da parte publica; chave privada NAO incluida)' -ForegroundColor DarkGray
}

if ($totalRemovidos -eq 0 -and $totalErros -eq 0) {
    Write-Host '   Nenhuma remocao realizada nesta execucao.' -ForegroundColor Gray
}

Write-Host ''
Write-Host '   Para verificar manualmente: Win+R  >  certmgr.msc  >  Pessoal' -ForegroundColor DarkGray
Write-Host ''
Write-Host ("   Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host '======================================================' -ForegroundColor $corRel
Write-Host ''
