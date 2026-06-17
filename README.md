# SC Checker

Инструмент аудита веб-сурфейса для специалистов по информационной безопасности. / A web surface audit tool for information security professionals.

# Нумерация версий программы

Версия имеет вид: `major.minor.patch`

| Компонент | Значение | Когда меняется |
|-----------|----------|----------------|
| `major` | Крупное обновление | Кардинальные изменения в программе, новые функции, смена логики или интерфейса |
| `minor` | Значительное обновление | Добавление важных возможностей без полного перелома структуры |
| `patch` | Незначительное обновление | Исправления багов, мелкие улучшения, доработки |

## Примеры версий

| Версия | Описание |
|--------|----------|
| `1.0.0.` | Первая стабильная версия |
| `1.1.0.` | Значительное обновление |
| `1.1.1` | Исправления и мелкие улучшения |
| `2.0.0` | Крупный новый релиз |
| `2.3.5` | Продвинутая версия с доработками и обновлениями |

## Правило сброса

| Что увеличилось | Что сбрасывается |
|----------------|------------------|
| `major` | `minor`, `patch` |
| `minor` | `patch` |
| `patch` | `nothing` |

## Формат в коде

```python
version = "1.2.3."
```

## Features / Возможности

- Path brute-force, source leak detection, admin panels, API endpoints
- WAF fingerprinting, CORS, HTTP smuggling, SSTI, CVSS scoring
- JavaScript analysis, Certificate Transparency, WHOIS, Shodan, tech stack
- Port scanning, DNS records, subdomain enumeration
- XSS, SQL injection, CRLF, directory traversal
- Supply chain analysis, GraphQL, WebSocket, JWT analysis, email security
- Screenshots via Playwright, interactive graph, AI analysis
- Discord / Telegram / Slack webhooks, plugin system
- Proxy support (HTTP/HTTPS/SOCKS5), auto-update, EN/RU interface
- And more

---

## Download / Скачать

[Releases](https://github.com/Krimex1/SC-Checker/releases)
