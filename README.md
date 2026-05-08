# Security Combine

Automated website security and quality checks.

This project runs a scan pipeline after you submit a URL:

- OWASP ZAP baseline scan (passive checks)
- Nuclei scan with default templates
- Lighthouse audit (performance, SEO, accessibility, best practices)
- Built-in passive checks (security headers, cookie flags, TLS expiration)

Reports are saved as JSON under `reports/`.

Use scanning tools only on targets you are permitted to test.

## Запуск из корня проекта

Корень репозитория — папка `security-combine` (рядом с `app/`, `requirements.txt`, `reports/`). Все команды ниже выполняйте **из этой папки**, иначе модуль `app` не найдётся.

### Требования

- Python 3.12+
- Docker Desktop (для ZAP, Nuclei, Lighthouse; без Docker сработают только встроенные пассивные проверки, если отключить внешние тулзы)

### Первоначальная установка (один раз)

В PowerShell:

```powershell
cd C:\Users\Ian\Desktop\Tbank\security-combine
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Если политика запрещает скрипты: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` (один раз) или запускайте Python без активации: `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`.

### Каждый раз: старт API

Самый простой и единый вариант (рекомендуется):

```powershell
cd C:\Users\Ian\Desktop\Tbank\security-combine
.\start-api.ps1
```

Скрипт всегда запускает API через `.\.venv\Scripts\python.exe`, при необходимости ставит зависимости и `playwright chromium`, поэтому не возникает рассинхронизации между системным Python и `.venv`.

Параметры:

```powershell
.\start-api.ps1 -BindAddress 0.0.0.0 -Port 8081
.\start-api.ps1 -SkipBootstrap   # если зависимости уже установлены
```

Ручной запуск (если нужен):

```powershell
cd C:\Users\Ian\Desktop\Tbank\security-combine
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Без активации venv:

```powershell
cd C:\Users\Ian\Desktop\Tbank\security-combine
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8080
```

- **Остановка:** в том же окне терминала нажмите `Ctrl+C`.
- **Доступ с других машин в сети:** замените `--host 127.0.0.1` на `--host 0.0.0.0` и откройте брандмауэр для выбранного порта.
- **Порт занят:** укажите другой, например `--port 8081`.

Интерфейс: http://127.0.0.1:8080/ — введите URL и нажмите «Запустить скан».

6. Or use curl:

```powershell
curl -X POST http://localhost:8080/scan -H "Content-Type: application/json" -d "{\"url\":\"https://example.com\",\"run_external_tools\":true}"
```

7. Check job status:

```powershell
curl http://localhost:8080/jobs/<job_id>
```

PowerShell helper:

```powershell
.\submit-scan.ps1 -Url "https://example.com"
.\get-job.ps1 -JobId "<job_id>"
```

## Docker mode (optional)

```bash
docker compose up --build
```

Note: scanner jobs call Docker CLI to launch tool containers. On Windows, local Python mode is usually simpler.

## API

- `POST /scan` — поставить задачу сканирования
- `GET /jobs` — список задач
- `GET /jobs/{job_id}` — статус и сводка
- `GET /jobs/{job_id}/report` — отчёт в JSON (`summary.json`)
- `GET /jobs/{job_id}/report/html` — отчёт в HTML
- `GET /health` — проверка сервиса

## Notes

- First run is slower because scanner images are pulled.
- If your network uses proxy, configure Docker proxy settings.
- Nuclei templates update can take extra time.
- Job metadata is persisted in `reports/jobs_state.json`, so statuses survive API restarts.
