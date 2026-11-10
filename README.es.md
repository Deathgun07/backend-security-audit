<div align="center">

# backend-security-audit

**Un skill de auditoría de seguridad backend, de solo lectura, para asistentes de IA de código.**
Una prueba para cada vulnerabilidad, correcciones en formato diff, un informe priorizado: en minutos, sin salir de tu editor.

[English](README.md) · [Français](README.fr.md) · **Español** · [Português (BR)](README.pt-BR.md) · [简体中文](README.zh-CN.md)

[![Licencia: MIT](https://img.shields.io/badge/Licencia-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Deathgun07/backend-security-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Deathgun07/backend-security-audit/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/backend-security-audit?logo=npm)](https://www.npmjs.com/package/backend-security-audit)
![Asistentes](https://img.shields.io/badge/asistentes-20-informational)
![Stacks](https://img.shields.io/badge/stacks-12-informational)

</div>

Funciona con **Claude Code, Cursor, Codex CLI, Gemini CLI, GitHub Copilot, Windsurf, Kiro** y otros 13 asistentes. Pide *"audita la seguridad de este proyecto"* y obtienes un `SECURITY_AUDIT.md` con una puntuación sobre 100, vulnerabilidades clasificadas por severidad y categoría OWASP, una prueba `archivo:línea` para cada una y una corrección lista para aplicar.

> 📄 Informe de ejemplo, generado por el skill sobre una aplicación intencionadamente vulnerable que cubre los 12 stacks: [examples/SECURITY_AUDIT.md](examples/SECURITY_AUDIT.md) (en inglés; tus informes se redactan en el idioma de tu petición).

## Lo que te aporta

- **Detecta lo que los escáneres genéricos no ven.** Políticas RLS de Supabase, Security Rules de Firebase, API rules de PocketBase, cuentas MySQL, server actions de Next.js: los fallos propios de cada plataforma, origen de la mayoría de fugas de datos reales.
- **Sin vulnerabilidades inventadas.** Cada hallazgo cita `archivo:línea` y un extracto exacto releído por la IA, marcado como **Confirmado** o **A verificar manualmente** (con qué verificar y cómo).
- **Correcciones, no solo alertas.** Cada hallazgo incluye un diff mínimo y, si hace falta, la acción fuera del código: rotar una clave, aplicar una migración, cambiar un ajuste.
- **Prioridades claras.** Puntuación sobre 100, recuento por severidad, tabla resumen y **top 5** a corregir primero, con estimación de esfuerzo.
- **Seguro por diseño.** Solo lectura: el código auditado nunca se modifica, nada se envía a sistemas de terceros, los secretos se enmascaran. Los análisis de base de datos solo se ejecutan en *tu* base, con tu consentimiento.
- **Encuentra secretos filtrados.** Archivos `.env` en el repositorio, claves de API, JWT, claves privadas, cuentas de servicio de Firebase y secretos que siguen en el **historial de git**.
- **Audita tu base real, no solo las migraciones.** `scan_rls.sql` (Postgres/Supabase) y `scan_mysql.sql` (MySQL/MariaDB) listan tablas sin RLS, políticas permisivas, RPC expuestas, cuentas sin contraseña, root remoto y permisos peligrosos.
- **Enseña mientras audita.** 12 checklists con código *vulnerable frente a corregido*: para aprender, formar a un equipo o enseñar.
- **Utilizable sin IA.** Los scripts de detección son bash simple: úsalos en CI o como hook de pre-commit.
- **Gratis y de código abierto** (MIT), sin cuenta, sin servicio externo, funciona sin conexión una vez instalado.

**¿Para quién?** Desarrolladores independientes y "vibe coders" antes de publicar · freelancers que entregan a un cliente · equipos antes de un lanzamiento · estudiantes y docentes · cualquiera que herede un proyecto y quiera saber dónde están los agujeros.

## Stacks soportados

| Tipo | Stacks |
|---|---|
| Bases de datos / BaaS | Supabase (Postgres + RLS), Firebase (Firestore, Realtime Database, Storage, Cloud Functions), PocketBase, MySQL / MariaDB |
| Backends | PHP nativo, Laravel, Node.js (Express, Fastify, Koa, Hono, NestJS), Next.js, Flask, FastAPI, Django, Go (net/http, Gin, Echo, Fiber, Chi) |
| En todos | secretos y `.env` en el repositorio, historial de git, dependencias vulnerables (`bun audit`, `npm audit`, `composer audit`, `pip-audit`, `govulncheck`), ausencia de rate limiting |

El stack se detecta automáticamente y **solo se cargan las checklists pertinentes**.

## Instalación

Elige tu asistente con `--ai` (o `--ai all`). Sin `--ai`, el instalador detecta los asistentes que ya usa el proyecto.

```bash
# npm / Node ≥ 18
npx backend-security-audit init --ai claude
# Bun
bunx backend-security-audit init --ai claude
# pnpm
pnpm dlx backend-security-audit init --ai claude
# Yarn (Berry)
yarn dlx backend-security-audit init --ai claude
# curl (sin Node: bash + curl o wget)
curl -fsSL https://raw.githubusercontent.com/Deathgun07/backend-security-audit/main/install.sh | bash -s -- --ai claude
```

Gestor de plugins de Claude Code:
```
/plugin marketplace add Deathgun07/backend-security-audit
/plugin install backend-security-audit@backend-security-audit
```

Valores de `--ai`: `claude` · `cursor` · `codex` · `gemini` · `copilot` · `windsurf` · `kiro` · `antigravity` · `opencode` · `roocode` · `kilocode` · `continue` · `trae` · `qoder` · `codebuddy` · `droid` · `augment` · `warp` · `amazonq` · `universal` · `all`. La tabla completa de carpetas de instalación está en el [README en inglés](README.md#installation).

Opciones: `--global` (carpeta personal, todos los proyectos) · `--force` (actualizar) · `--dry-run` · `list` · `uninstall`. Reinicia tu asistente después de instalar.

## Uso

Desde la raíz del proyecto, pide a tu asistente:

> *"Audita la seguridad de este proyecto"*, *"Revisa mis políticas RLS de Supabase"*, *"¿Son seguras mis reglas de Firebase?"*

En Claude Code también puedes escribir `/backend-security-audit`. El informe `SECURITY_AUDIT.md` se escribe en la raíz del proyecto, en el idioma de tu petición.

### Auditar tu base de datos (opcional)

```bash
# Supabase / Postgres (transacción revertida al final)
psql "postgresql://postgres:postgres@127.0.0.1:54322/postgres" -f .claude/skills/backend-security-audit/scripts/scan_rls.sql
# MySQL / MariaDB (solo SELECT)
mysql -u root -p -t < .claude/skills/backend-security-audit/scripts/scan_mysql.sql
```
Solo en **tu propia** base. El asistente nunca se conecta a una base sin tu consentimiento.

## Reglas que sigue el skill

1. **Solo lectura**: el código auditado nunca se modifica; las correcciones se proponen como diff.
2. **Ningún hallazgo sin prueba**: `archivo:línea` y un extracto realmente releído.
3. **Dos estados**: *Confirmado* o *A verificar manualmente* (con la explicación).
4. **Ninguna acción ofensiva**: solo el código local y tu propia base de datos.
5. **Secretos enmascarados** en el informe.

## Requisitos y límites

Linux, macOS (bash ≥ 4) o Windows con WSL / Git Bash. Es un análisis estático asistido por IA, no una prueba de penetración: no sustituye las pruebas dinámicas ni una revisión humana.

## Contribuir

Se aceptan PR: nuevos patrones, nuevas checklists (Rails, Spring, ASP.NET, MongoDB…), menos falsos positivos y **traducciones**. Consulta [CONTRIBUTING.md](CONTRIBUTING.md) (en inglés). Para reportar un fallo de seguridad del propio skill: [SECURITY.md](SECURITY.md).

## Licencia

[MIT](LICENSE) © Deathgun07
