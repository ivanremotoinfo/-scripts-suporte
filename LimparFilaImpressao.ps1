#Requires -RunAsAdministrator

$fila = 'C:\Windows\System32\spool\PRINTERS'

Write-Host ''
Write-Host '=======================================' -ForegroundColor Cyan
Write-Host '   Limpeza da Fila de Impressao        ' -ForegroundColor Cyan
Write-Host '=======================================' -ForegroundColor Cyan

# 1. Parar o Spooler
Write-Host ''
Write-Host '>> Parando o servico Spooler...' -ForegroundColor Cyan

try {
    Stop-Service -Name 'Spooler' -Force -ErrorAction Stop
    Write-Host '   [OK] Spooler parado.' -ForegroundColor Green
} catch {
    Write-Host "   [X]  Falha ao parar o Spooler: $_" -ForegroundColor Red
    exit 1
}

# 2. Limpar arquivos da fila
Write-Host ''
Write-Host '>> Limpando arquivos da fila...' -ForegroundColor Cyan
Write-Host "   Pasta: $fila" -ForegroundColor DarkGray

try {
    $arquivos = Get-ChildItem -Path $fila -File -ErrorAction Stop

    if ($arquivos.Count -eq 0) {
        Write-Host '   [!]  Fila ja estava vazia.' -ForegroundColor Yellow
    } else {
        $removidos = 0
        foreach ($f in $arquivos) {
            try {
                Remove-Item -Path $f.FullName -Force -ErrorAction Stop
                $removidos++
            } catch {
                Write-Host "   [!]  Nao foi possivel remover $($f.Name): $_" -ForegroundColor Yellow
            }
        }
        Write-Host "   [OK] $removidos arquivo(s) removido(s)." -ForegroundColor Green
    }
} catch {
    Write-Host "   [X]  Erro ao acessar a pasta da fila: $_" -ForegroundColor Red
}

# 3. Reiniciar o Spooler
Write-Host ''
Write-Host '>> Reiniciando o servico Spooler...' -ForegroundColor Cyan

try {
    Start-Service -Name 'Spooler' -ErrorAction Stop

    $ok = $false
    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Seconds 1
        if ((Get-Service -Name 'Spooler').Status -eq 'Running') {
            $ok = $true
            break
        }
    }

    if ($ok) {
        Write-Host '   [OK] Spooler reiniciado com sucesso.' -ForegroundColor Green
    } else {
        Write-Host '   [!]  Spooler iniciado mas status nao confirmado.' -ForegroundColor Yellow
    }
} catch {
    Write-Host "   [X]  Falha ao reiniciar o Spooler: $_" -ForegroundColor Red
    exit 1
}

# Conclusao
Write-Host ''
Write-Host '=======================================' -ForegroundColor Green
Write-Host '   Fila de impressao limpa!            ' -ForegroundColor Green
Write-Host '=======================================' -ForegroundColor Green
Write-Host ''
