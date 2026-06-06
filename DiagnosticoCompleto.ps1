# DiagnosticoCompleto.ps1
# Coleta informacoes completas do computador e gera relatorio em TXT na Area de Trabalho
# Zero interacao com usuario

$ErrorActionPreference = 'Continue'

# =========================================================================
# GLOBAIS
# =========================================================================

$sb             = [System.Text.StringBuilder]::new()
$qtdProblemas   = 0
$qtdAvisos      = 0

# =========================================================================
# FUNCOES DE SAIDA DUPLA (tela + arquivo)
# =========================================================================

function Adicionar { param([string]$t) [void]$sb.AppendLine($t) }

function L {
    param([string]$Texto, [string]$Cor = 'Gray')
    Write-Host $Texto -ForegroundColor $Cor
    Adicionar $Texto
}

function LOk    { param([string]$t) L ("  [OK]   $t") 'Green'  }
function LAviso { param([string]$t) L ("  [!]    $t") 'Yellow' }
function LErro  { param([string]$t) L ("  [X]    $t") 'Red'    }
function LInfo  { param([string]$t) L ("  $t")        'Gray'   }
function LDest  { param([string]$t) L ("  $t")        'White'  }
function LBranco{ L '' 'Gray' }

function Secao {
    param([string]$titulo)
    $linha = '=' * 60
    L '' 'Gray'
    L $linha 'Cyan'
    L ("  $titulo") 'Cyan'
    L $linha 'Cyan'
    Adicionar ''
}

function AddProblema { $script:qtdProblemas++ }
function AddAviso    { $script:qtdAvisos++ }

# =========================================================================
# CABECALHO
# =========================================================================

$dataHoraInicio = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'
$separador = '=' * 60

Write-Host '' ; Adicionar ''
L $separador 'Cyan'
L '   DIAGNOSTICO COMPLETO DO SISTEMA' 'Cyan'
L ("   Gerado em: $dataHoraInicio") 'DarkGray'
L $separador 'Cyan'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if ($isAdmin) {
    LOk 'Executando como Administrador.'
} else {
    LAviso 'Sem privilegios de Administrador. Dados de outros usuarios podem estar incompletos.'
    AddAviso
}

# =========================================================================
# SECAO 1 - INFORMACOES DO SISTEMA
# =========================================================================

Secao '1. INFORMACOES DO SISTEMA'

try {
    $os       = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
    $cs       = Get-WmiObject Win32_ComputerSystem  -ErrorAction Stop
    $nomePC   = $env:COMPUTERNAME
    $usuario  = $env:USERNAME
    $dominio  = $cs.Domain

    $winCaption = $os.Caption -replace 'Microsoft ', ''
    $winBuild   = $os.BuildNumber
    $winVersao  = $os.Version
    $winSP      = $os.ServicePackMajorVersion
    $arquitetura = if ([Environment]::Is64BitOperatingSystem) { '64 bits' } else { '32 bits' }

    $ultimoBoot = $os.ConvertToDateTime($os.LastBootUpTime)
    $uptime     = (Get-Date) - $ultimoBoot
    $uptimeTxt  = [string]$uptime.Days + 'd ' + [string]$uptime.Hours + 'h ' + [string]$uptime.Minutes + 'min'

    LDest ("Computador : $nomePC")
    LDest ("Usuario    : $usuario  |  Dominio: $dominio")
    LDest ("Windows    : $winCaption  (Build $winBuild  |  Versao $winVersao)")
    LDest ("Arquitetura: $arquitetura")
    LDest ("Data/Hora  : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')")
    LDest ("Ligado ha  : $uptimeTxt  (boot em $(Get-Date $ultimoBoot -Format 'dd/MM/yyyy HH:mm:ss'))")
} catch {
    LErro "Erro ao coletar informacoes do sistema: $($_.Exception.Message)"
    AddProblema
}

# =========================================================================
# SECAO 2 - HARDWARE
# =========================================================================

Secao '2. HARDWARE'

try {
    $cs2 = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
    LDest ("Fabricante : $($cs2.Manufacturer)")
    LDest ("Modelo     : $($cs2.Model)")
} catch {
    LAviso 'Nao foi possivel obter fabricante/modelo.'
    AddAviso
}

# CPU
try {
    $cpu = Get-WmiObject Win32_Processor -ErrorAction Stop | Select-Object -First 1
    $cpuUso = $cpu.LoadPercentage
    $cpuCor = if ($cpuUso -gt 90) { 'Red' } elseif ($cpuUso -gt 70) { 'Yellow' } else { 'Green' }
    LDest ("Processador: $($cpu.Name.Trim())")
    L ("  Uso atual  : $cpuUso%") $cpuCor
    if ($cpuUso -gt 90) { AddProblema } elseif ($cpuUso -gt 70) { AddAviso }
} catch {
    LAviso 'Nao foi possivel obter informacoes do processador.'
}

# RAM
try {
    $osRam = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
    $ramTotal = [math]::Round($osRam.TotalVisibleMemorySize / 1MB, 2)
    $ramLivre = [math]::Round($osRam.FreePhysicalMemory / 1MB, 2)
    $ramUsada = [math]::Round($ramTotal - $ramLivre, 2)
    $pctRam   = if ($ramTotal -gt 0) { [math]::Round(($ramUsada / $ramTotal) * 100, 0) } else { 0 }
    $ramCor   = if ($pctRam -gt 90) { 'Red' } elseif ($pctRam -gt 75) { 'Yellow' } else { 'Green' }
    L ("  RAM Total  : " + $ramTotal.ToString('N2') + ' GB   Livre: ' + $ramLivre.ToString('N2') + ' GB   Uso: ' + $pctRam + '%') $ramCor
    if ($pctRam -gt 90) { AddProblema } elseif ($pctRam -gt 75) { AddAviso }
} catch {
    LAviso 'Nao foi possivel obter informacoes de RAM.'
}

# Disco C
try {
    $discoC = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
    $totalGB = [math]::Round($discoC.Size / 1GB, 2)
    $livreGB = [math]::Round($discoC.FreeSpace / 1GB, 2)
    $usadoGB = [math]::Round($totalGB - $livreGB, 2)
    $pctDisco = if ($totalGB -gt 0) { [math]::Round((($totalGB - $livreGB) / $totalGB) * 100, 0) } else { 0 }
    $discoCor = if ($pctDisco -gt 90) { 'Red' } elseif ($pctDisco -gt 80) { 'Yellow' } else { 'Green' }
    L ("  Disco C    : Total " + $totalGB.ToString('N2') + ' GB  |  Usado ' + $usadoGB.ToString('N2') + ' GB (' + $pctDisco + '%)  |  Livre ' + $livreGB.ToString('N2') + ' GB') $discoCor
    if ($pctDisco -gt 90) { AddProblema } elseif ($pctDisco -gt 80) { AddAviso }
} catch {
    LAviso 'Nao foi possivel obter informacoes do disco C.'
}

# Tipo de disco (SSD ou HDD)
try {
    $tipoDisco = 'Desconhecido'
    $particao = Get-WmiObject -Query "ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='C:'} WHERE AssocClass=Win32_LogicalDiskToPartition" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($particao) {
        $driveFisico = Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($particao.DeviceID)'} WHERE AssocClass=Win32_DiskDriveToDiskPartition" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($driveFisico) {
            $numDisco = [int]$driveFisico.Index
            $physDisk = Get-WmiObject -Namespace 'root\Microsoft\Windows\Storage' -Class MSFT_PhysicalDisk -ErrorAction SilentlyContinue |
                Where-Object { [int]$_.DeviceId -eq $numDisco } | Select-Object -First 1
            if ($physDisk) {
                $tipoDisco = switch ([int]$physDisk.MediaType) {
                    3 { 'HDD (Mecanico)' }
                    4 { 'SSD' }
                    5 { 'SCM' }
                    default { 'Desconhecido (tipo ' + $physDisk.MediaType + ')' }
                }
            }
        }
    }
    LDest ("  Tipo disco : $tipoDisco")
} catch {
    LInfo 'Tipo do disco nao detectado.'
}

# =========================================================================
# SECAO 3 - REDE
# =========================================================================

Secao '3. REDE'

try {
    $adaptadores = @(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' -ErrorAction Stop)
    $adapter = $adaptadores | Where-Object { $_.DefaultIPGateway -ne $null } | Select-Object -First 1
    if (-not $adapter) { $adapter = $adaptadores | Select-Object -First 1 }

    if ($adapter) {
        $ipv4 = @($adapter.IPAddress) | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' } | Select-Object -First 1
        $gateway = if ($adapter.DefaultIPGateway) { $adapter.DefaultIPGateway[0] } else { 'N/A' }
        $dns1 = if ($adapter.DNSServerSearchOrder -and $adapter.DNSServerSearchOrder.Count -gt 0) { $adapter.DNSServerSearchOrder[0] } else { 'N/A' }
        $dns2 = if ($adapter.DNSServerSearchOrder -and $adapter.DNSServerSearchOrder.Count -gt 1) { $adapter.DNSServerSearchOrder[1] } else { 'N/A' }

        $adapterHW = Get-WmiObject Win32_NetworkAdapter -Filter "Index=$($adapter.Index)" -ErrorAction SilentlyContinue
        $nomeAdapter = if ($adapterHW) { $adapterHW.Name } else { $adapter.Description }

        LDest ("Adaptador  : $nomeAdapter")
        LDest ("IP Local   : $ipv4")
        LDest ("Gateway    : $gateway")
        LDest ("DNS 1      : $dns1")
        LDest ("DNS 2      : $dns2")
    } else {
        LAviso 'Nenhum adaptador de rede ativo encontrado.'
        AddAviso
    }
} catch {
    LErro "Erro ao coletar informacoes de rede: $($_.Exception.Message)"
    AddProblema
}

# Conectividade
LBranco
try {
    $ping = Test-Connection -ComputerName 'google.com' -Count 1 -Quiet -ErrorAction SilentlyContinue
    if ($ping) {
        LOk 'Conectividade com google.com: OK'
    } else {
        LErro 'Conectividade com google.com: FALHA'
        AddProblema
    }
} catch {
    LErro 'Conectividade com google.com: FALHA (excecao de rede)'
    AddProblema
}

# =========================================================================
# SECAO 4 - JAVA
# =========================================================================

Secao '4. JAVA'

$javaEncontrado = $false
$javaCaminhos   = @()

# Verifica registro
$regJavaPaths = @(
    'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment',
    'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment'
)

foreach ($regBase in $regJavaPaths) {
    try {
        $jre8Key = Get-Item (Join-Path $regBase '1.8') -ErrorAction SilentlyContinue
        if ($jre8Key) {
            $javaHome = $jre8Key.GetValue('JavaHome')
            if ($javaHome) { $javaCaminhos += $javaHome }
        }
    } catch { }
}

# Verifica filesystem
$fsJava = @(Get-ChildItem 'C:\Program Files\Java' -Directory -Filter 'jre1.8*' -ErrorAction SilentlyContinue)
$fsJava += @(Get-ChildItem 'C:\Program Files (x86)\Java' -Directory -Filter 'jre1.8*' -ErrorAction SilentlyContinue)
foreach ($dir in $fsJava) {
    if (Test-Path (Join-Path $dir.FullName 'bin\java.exe')) {
        $javaCaminhos += $dir.FullName
    }
}

$javaCaminhos = $javaCaminhos | Where-Object { $_ } | Select-Object -Unique

if ($javaCaminhos.Count -gt 0) {
    foreach ($jHome in $javaCaminhos) {
        $javaExe = Join-Path $jHome 'bin\java.exe'
        if (Test-Path $javaExe) {
            try {
                $javaOutput = & $javaExe -version 2>&1
                $javaVersao = ($javaOutput | Select-Object -First 1).ToString()
                LOk ("Java 8 instalado: $javaVersao")
                LInfo ("Caminho: $jHome")
                $javaEncontrado = $true
            } catch {
                LOk ("Java 8 encontrado em: $jHome  (versao nao obtida)")
                $javaEncontrado = $true
            }
        }
    }
} else {
    LErro 'Java 8: AUSENTE. Nao encontrado no registro nem em C:\Program Files\Java.'
    AddProblema
}

# =========================================================================
# SECAO 5 - PROGRAMAS JURIDICOS
# =========================================================================

Secao '5. PROGRAMAS JURIDICOS'

$regUninstall = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$programasInstalados = @()
foreach ($regPath in $regUninstall) {
    try {
        $keys = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne '' }
        if ($keys) { $programasInstalados += $keys }
    } catch { }
}

$programasEspecificos = @(
    @{ Busca = 'PJe Office';              Regex = 'pje.?office' }
    @{ Busca = 'Shodo';                   Regex = 'shodo' }
    @{ Busca = 'Shomei';                  Regex = 'shomei' }
    @{ Busca = 'Signer';                  Regex = 'signer' }
    @{ Busca = 'eDoc';                    Regex = 'edoc' }
    @{ Busca = 'Autenticador Serpro';     Regex = 'autenticador.?serpro|serpro.?autenticador' }
    @{ Busca = 'TokenOTP';                Regex = 'tokenotp|token.?otp' }
)

foreach ($prog in $programasEspecificos) {
    $encontrado = $programasInstalados | Where-Object { $_.DisplayName -match $prog.Regex } | Select-Object -First 1
    if ($encontrado) {
        $versao = if ($encontrado.DisplayVersion) { ' v' + $encontrado.DisplayVersion } else { '' }
        LOk ($prog.Busca + ': instalado' + $versao)
    } else {
        LAviso ($prog.Busca + ': NAO instalado')
    }
}

# Busca por padroes adicionais
LBranco
LInfo 'Outros programas juridicos encontrados (PJe / projudi / certificado / assinador / token):'
$padraoJuridico = 'pje|projudi|certificado|assinador|token'
$outrosJuridicos = $programasInstalados | Where-Object {
    $_.DisplayName -match $padraoJuridico -and
    ($programasEspecificos | Where-Object { $_.DisplayName -match $_.Regex } | Measure-Object).Count -eq 0
} | Sort-Object DisplayName | Select-Object -Unique DisplayName, DisplayVersion
foreach ($p in $outrosJuridicos) {
    $v = if ($p.DisplayVersion) { ' v' + $p.DisplayVersion } else { '' }
    LInfo ("  + $($p.DisplayName)$v")
}
if (-not $outrosJuridicos) { LInfo '  (nenhum adicional encontrado)' }

# =========================================================================
# SECAO 6 - IMPRESSORAS
# =========================================================================

Secao '6. IMPRESSORAS'

try {
    $impressoras = @(Get-WmiObject Win32_Printer -ErrorAction Stop)
    if ($impressoras.Count -eq 0) {
        LAviso 'Nenhuma impressora instalada.'
        AddAviso
    } else {
        foreach ($imp in $impressoras) {
            $padrao   = if ($imp.Default)      { ' [PADRAO]' } else { '' }
            $offline  = if ($imp.WorkOffline)  { ' [OFFLINE]' } else { '' }

            $statusTxt = switch ([int]$imp.PrinterStatus) {
                1 { 'Outro' }
                2 { 'Desconhecido' }
                3 { 'Ocioso' }
                4 { 'Imprimindo' }
                5 { 'Aquecendo' }
                6 { 'Parou' }
                7 { 'Aguardando impressao' }
                default { 'Status ' + $imp.PrinterStatus }
            }

            if ($imp.WorkOffline) {
                LErro ($imp.Name + $padrao + ' - OFFLINE  (' + $statusTxt + ')')
                AddAviso
            } elseif ($imp.PrinterStatus -eq 3 -or $imp.PrinterStatus -eq 4) {
                LOk ($imp.Name + $padrao + ' - Online  (' + $statusTxt + ')')
            } else {
                LAviso ($imp.Name + $padrao + ' - ' + $statusTxt + $offline)
            }
        }
    }
} catch {
    LErro "Erro ao listar impressoras: $($_.Exception.Message)"
    AddProblema
}

# =========================================================================
# SECAO 7 - TOKENS E DISPOSITIVOS USB
# =========================================================================

Secao '7. TOKENS E DISPOSITIVOS USB'

try {
    $padraoToken = 'token|smartcard|smart card|leitora|leitor|certificado|safenet|gemalto|watchdata|alladin|epass|ikey|oberthur|athena|kobil'

    $dispositivosToken = @(Get-WmiObject Win32_PnPEntity -ErrorAction Stop |
        Where-Object {
            ($_.Name -and $_.Name -match $padraoToken) -or
            ($_.PNPClass -and $_.PNPClass -match 'SmartCardReader') -or
            ($_.Description -and $_.Description -match $padraoToken)
        })

    if ($dispositivosToken.Count -eq 0) {
        LAviso 'Nenhum token, leitora ou smartcard detectado no Gerenciador de Dispositivos.'
        AddAviso
    } else {
        foreach ($dev in $dispositivosToken) {
            $errCode   = [int]$dev.ConfigManagerErrorCode
            $nomeExib  = if ($dev.Name) { $dev.Name } else { $dev.Description }
            $classe    = if ($dev.PNPClass) { ' [' + $dev.PNPClass + ']' } else { '' }

            if ($errCode -eq 0) {
                LOk ("$nomeExib$classe  -  Funcionando corretamente")
            } elseif ($errCode -eq 22) {
                LAviso ("$nomeExib$classe  -  DESABILITADO (codigo $errCode)")
                AddAviso
            } else {
                LErro ("$nomeExib$classe  -  COM ERRO (codigo $errCode)")
                AddProblema
            }
        }
    }
} catch {
    LErro "Erro ao consultar dispositivos: $($_.Exception.Message)"
    AddProblema
}

# =========================================================================
# SECAO 8 - CERTIFICADOS DIGITAIS
# =========================================================================

Secao '8. CERTIFICADOS DIGITAIS (loja Pessoal de todos os usuarios)'

function Test-IsICPBrasil {
    param([string]$issuer)
    $emissores = @('ICP-Brasil', 'AC CAIXA', 'CERTISIGN', 'Certisign', 'SERASA', 'AC SERASA',
                   'AC VALID', 'VALID Certificadora', 'SERPRO', 'SAFEWEB', 'AC SAFEWEB',
                   'SOLUTI', 'AC SOLUTI', 'FENACOR', 'AC-JUS', 'IMPRENSA OFICIAL',
                   'PRODEMGE', 'AC OAB', 'NOTARIAL', 'AC RFB', 'RECEITA FEDERAL',
                   'RFB e-CPF', 'RFB e-CNPJ', 'Autoridade Certificadora', 'Instituto Nacional',
                   'ITI', 'AC DIGITAL', 'SINCOR', 'AC INFRAESTRUTURA', 'DIGITALSIGN',
                   'SCEE', 'Multicert', 'Camerfirma', 'DigitalSign', 'DSTgroup', 'ECEE',
                   'Agencia para a Modernizacao', 'AMA -', 'Cart.o de Cidad')
    foreach ($e in $emissores) {
        if ($issuer -match [regex]::Escape($e)) { return $true }
    }
    if ($issuer -match 'Cart.o de Cidad') { return $true }
    return $false
}

function Test-IsResiduo {
    param([string]$subject, [string]$issuer)
    if ($subject -match 'CrossDevice|You trust_|MS-Organization|MS-MDM|Windows Hello|YouAttest') { return $true }
    if ($subject -match 'CN=\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}') { return $true }
    if ($issuer  -match '^CN=Microsoft|^O=Microsoft Corporation$') { return $true }
    if ($subject -match '^CN=[A-Z0-9]{8,}-[A-Z0-9]{4,}$') { return $true }
    return $false
}

function Get-TipoCertificado {
    param([string]$subject)
    # Detecta CPF (11 digitos) ou CNPJ (14 digitos) no Subject
    $cpf = [regex]::Match($subject, '(CPF|:)[\s=]*(\d{3}\.?\d{3}\.?\d{3}-?\d{2}|\d{11})')
    $cnpj = [regex]::Match($subject, '(CNPJ|:)[\s=]*(\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}|\d{14})')
    if ($cnpj.Success) { return 'eCNPJ' }
    if ($cpf.Success)  { return 'eCPF'  }
    # Heuristica: 11 ou 14 digitos ao final do CN
    $cpfHeur  = [regex]::Match($subject, ':(\d{11})\b')
    $cnpjHeur = [regex]::Match($subject, ':(\d{14})\b')
    if ($cnpjHeur.Success) { return 'eCNPJ' }
    if ($cpfHeur.Success)  { return 'eCPF'  }
    return 'ICP-Brasil'
}

$nomesIgnorados = '^(Public|All Users|Default|Default User|defaultuser0|desktop\.ini)$'
$usuariosDirs   = @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch $nomesIgnorados })

$totalCerts     = 0
$totalValidos   = 0
$totalVencidos  = 0
$totalResiduos  = 0

foreach ($uDir in $usuariosDirs) {
    $certDir = Join-Path $uDir.FullName 'AppData\Roaming\Microsoft\SystemCertificates\My\Certificates'
    if (-not (Test-Path $certDir -ErrorAction SilentlyContinue)) { continue }

    $certFiles = @(Get-ChildItem $certDir -File -ErrorAction SilentlyContinue)
    if ($certFiles.Count -eq 0) { continue }

    LBranco
    LDest ("  Usuario: $($uDir.Name)  ($($certFiles.Count) certificado(s))")

    foreach ($cf in $certFiles) {
        try {
            [byte[]]$bytes = [System.IO.File]::ReadAllBytes($cf.FullName)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$bytes)

            $subject  = $cert.Subject
            $issuer   = $cert.Issuer
            $validade = $cert.NotAfter
            $vencido  = ($validade -lt (Get-Date))
            $totalCerts++

            # Extrair CN do Subject para exibicao
            $cn = ($subject -split ',' | Where-Object { $_ -match '^\s*CN=' } | Select-Object -First 1)
            $cn = if ($cn) { $cn -replace '^\s*CN=', '' } else { $subject }

            $validadeTxt = Get-Date $validade -Format 'dd/MM/yyyy'

            if (Test-IsResiduo $subject $issuer) {
                $totalResiduos++
                LInfo ("    [RESIDUO]   $cn")
                LInfo ("    Emissor: $issuer")
                LInfo ("    Validade: $validadeTxt")
            } elseif (Test-IsICPBrasil $issuer) {
                $tipo = Get-TipoCertificado $subject
                if ($vencido) {
                    $totalVencidos++
                    LAviso ("    [$tipo VENCIDO]  $cn")
                    LInfo  ("    Emissor : $issuer")
                    LInfo  ("    Venceu  : $validadeTxt")
                    AddAviso
                } else {
                    $totalValidos++
                    LOk ("    [$tipo VALIDO]   $cn")
                    LInfo ("    Emissor : $issuer")
                    LInfo ("    Validade: $validadeTxt")
                }
            } else {
                # Outros (nao ICP e nao residuo tipico)
                $totalResiduos++
                LInfo ("    [OUTRO]     $cn")
                LInfo ("    Emissor: $issuer")
                LInfo ("    Validade: $validadeTxt")
            }
        } catch {
            LInfo ("    [ERRO LEITURA]  $($cf.Name): $($_.Exception.Message)")
        }
    }
}

if ($totalCerts -eq 0) {
    LAviso 'Nenhum certificado digital encontrado nas lojas pessoais.'
} else {
    LBranco
    LDest ("  Resumo: $totalCerts certificado(s) total  |  $totalValidos ICP valido(s)  |  $totalVencidos vencido(s)  |  $totalResiduos residuo/outro")
}

# =========================================================================
# SECAO 9 - ERROS CRITICOS DO EVENT LOG
# =========================================================================

Secao '9. ULTIMOS ERROS CRITICOS (Event Log - 7 dias)'

try {
    $inicio7d = (Get-Date).AddDays(-7)
    $eventos  = @(Get-WinEvent -FilterHashtable @{
        LogName   = @('System', 'Application')
        Level     = @(1, 2)
        StartTime = $inicio7d
    } -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending | Select-Object -First 10)

    if ($eventos.Count -eq 0) {
        LOk 'Nenhum erro critico encontrado nos ultimos 7 dias.'
    } else {
        LAviso ("$($eventos.Count) erro(s)/critico(s) encontrado(s) nos ultimos 7 dias:")
        AddAviso
        LBranco
        foreach ($ev in $eventos) {
            $nivelTxt = switch ($ev.Level) { 1 { 'CRITICO' } 2 { 'ERRO' } default { 'AVISO' } }
            $dtEvento = Get-Date $ev.TimeCreated -Format 'dd/MM/yyyy HH:mm:ss'
            $mensagem = ($ev.Message -split "`n" | Select-Object -First 1).Trim()
            if ($mensagem.Length -gt 120) { $mensagem = $mensagem.Substring(0, 120) + '...' }
            $corEvento = if ($ev.Level -eq 1) { 'Red' } else { 'Yellow' }
            L ("  [$nivelTxt] $dtEvento  |  $($ev.ProviderName)") $corEvento
            LInfo ("    $mensagem")
        }
    }
} catch {
    LAviso "Nao foi possivel ler o Event Log: $($_.Exception.Message)"
    AddAviso
}

# =========================================================================
# SECAO 10 - SALVAR ARQUIVO TXT NA AREA DE TRABALHO
# =========================================================================

Secao '10. SALVANDO RELATORIO'

$desktop     = [Environment]::GetFolderPath('Desktop')
$dataArquivo = Get-Date -Format 'yyyyMMdd_HHmmss'
$nomeArquivo = 'Diagnostico_' + $env:COMPUTERNAME + '_' + $dataArquivo + '.txt'
$caminhoTxt  = Join-Path $desktop $nomeArquivo

try {
    $conteudo = $sb.ToString()
    [System.IO.File]::WriteAllText($caminhoTxt, $conteudo, [System.Text.Encoding]::UTF8)
    LOk ("Relatorio salvo em: $caminhoTxt")
} catch {
    LErro ("Erro ao salvar arquivo: $($_.Exception.Message)")
    AddProblema
    # Tentativa alternativa: salvar em Documentos
    try {
        $caminhoAlt = Join-Path ([Environment]::GetFolderPath('MyDocuments')) $nomeArquivo
        [System.IO.File]::WriteAllText($caminhoAlt, $sb.ToString(), [System.Text.Encoding]::UTF8)
        LAviso ("Salvo em alternativa: $caminhoAlt")
    } catch { }
}

# =========================================================================
# RESUMO FINAL
# =========================================================================

$separadorFinal = '=' * 60
Write-Host ''
Write-Host $separadorFinal                            -ForegroundColor Cyan
Write-Host '   RESUMO FINAL DO DIAGNOSTICO'          -ForegroundColor Cyan
Write-Host $separadorFinal                            -ForegroundColor Cyan
Write-Host ''

if ($qtdProblemas -eq 0 -and $qtdAvisos -eq 0) {
    Write-Host '   Sistema sem problemas detectados.' -ForegroundColor Green
} else {
    if ($qtdProblemas -gt 0) {
        Write-Host ("   Problemas encontrados : $qtdProblemas") -ForegroundColor Red
    }
    if ($qtdAvisos -gt 0) {
        Write-Host ("   Avisos encontrados    : $qtdAvisos") -ForegroundColor Yellow
    }
}

Write-Host ''
Write-Host ("   Certificados ICP validos  : $totalValidos")   -ForegroundColor Green
Write-Host ("   Certificados ICP vencidos : $totalVencidos")  -ForegroundColor $(if ($totalVencidos -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ("   Certificados residuo/outro: $totalResiduos")  -ForegroundColor Gray
Write-Host ''
Write-Host ("   Arquivo: $caminhoTxt")                        -ForegroundColor Cyan
Write-Host ("   Concluido em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')") -ForegroundColor DarkGray
Write-Host $separadorFinal                                    -ForegroundColor Cyan
Write-Host ''
