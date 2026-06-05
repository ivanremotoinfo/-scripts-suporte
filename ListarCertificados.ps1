# Lista certificados digitais instalados no Windows com nome e validade

param(
    [string]$Store = "My",           # My, Root, CA, TrustedPeople, etc.
    [string]$Location = "CurrentUser", # CurrentUser ou LocalMachine
    [switch]$ExpiradosApenas,
    [switch]$ProximosAVencer,
    [int]$DiasParaVencer = 30
)

function Get-StatusValidade {
    param([datetime]$DataExpiracao)

    $hoje = Get-Date
    $diasRestantes = ($DataExpiracao - $hoje).Days

    if ($DataExpiracao -lt $hoje) {
        return @{ Status = "EXPIRADO"; Cor = "Red"; DiasRestantes = $diasRestantes }
    } elseif ($diasRestantes -le $DiasParaVencer) {
        return @{ Status = "VENCE EM BREVE"; Cor = "Yellow"; DiasRestantes = $diasRestantes }
    } else {
        return @{ Status = "Valido"; Cor = "Green"; DiasRestantes = $diasRestantes }
    }
}

$caminho = "Cert:\$Location\$Store"

Write-Host "`nCertificados Digitais - $Location\$Store" -ForegroundColor Cyan
Write-Host ("=" * 80) -ForegroundColor Cyan

try {
    $certificados = Get-ChildItem -Path $caminho -ErrorAction Stop
} catch {
    Write-Host "Erro ao acessar '$caminho': $_" -ForegroundColor Red
    exit 1
}

if ($certificados.Count -eq 0) {
    Write-Host "Nenhum certificado encontrado em '$caminho'." -ForegroundColor Yellow
    exit 0
}

$lista = foreach ($cert in $certificados) {
    $sv = Get-StatusValidade -DataExpiracao $cert.NotAfter

    if ($ExpiradosApenas  -and $sv.Status -ne "EXPIRADO")      { continue }
    if ($ProximosAVencer  -and $sv.Status -ne "VENCE EM BREVE") { continue }

    [PSCustomObject]@{
        Nome           = $cert.SubjectName.Name -replace "CN=", "" -split "," | Select-Object -First 1
        Emissor        = $cert.IssuerName.Name  -replace "CN=", "" -split "," | Select-Object -First 1
        ValidoDe       = $cert.NotBefore.ToString("dd/MM/yyyy")
        ValidoAte      = $cert.NotAfter.ToString("dd/MM/yyyy")
        DiasRestantes  = $sv.DiasRestantes
        Status         = $sv.Status
        Thumbprint     = $cert.Thumbprint
        _Cor           = $sv.Cor
    }
}

if (-not $lista) {
    Write-Host "Nenhum certificado corresponde ao filtro aplicado." -ForegroundColor Yellow
    exit 0
}

foreach ($item in $lista) {
    $cor = $item._Cor
    Write-Host "`nNome       : $($item.Nome)" -ForegroundColor White
    Write-Host "Emissor    : $($item.Emissor)" -ForegroundColor Gray
    Write-Host "Valido de  : $($item.ValidoDe)  ate  $($item.ValidoAte)" -ForegroundColor Gray
    Write-Host "Status     : $($item.Status) ($($item.DiasRestantes) dias)" -ForegroundColor $cor
    Write-Host "Thumbprint : $($item.Thumbprint)" -ForegroundColor DarkGray
    Write-Host ("-" * 80) -ForegroundColor DarkGray
}

Write-Host "`nTotal encontrado: $($lista.Count) certificado(s)" -ForegroundColor Cyan

# Exporta para CSV se quiser
$exportar = ""
try { $exportar = Read-Host "`nDeseja exportar para CSV? (s/N)" } catch {}
if ($exportar -match "^[sS]$") {
    $arquivo = ".\certificados_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
    $lista | Select-Object Nome, Emissor, ValidoDe, ValidoAte, DiasRestantes, Status, Thumbprint |
        Export-Csv -Path $arquivo -NoTypeInformation -Encoding UTF8
    Write-Host "Exportado para: $arquivo" -ForegroundColor Green
}
