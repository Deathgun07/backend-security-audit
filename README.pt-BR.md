<div align="center">

# backend-security-audit

**Um skill de auditoria de segurança de backend, somente leitura, para assistentes de IA de código.**
Uma prova para cada vulnerabilidade, correções em diff, um relatório priorizado: em minutos, sem sair do seu editor.

[English](README.md) · [Français](README.fr.md) · [Español](README.es.md) · **Português (BR)** · [简体中文](README.zh-CN.md)

[![Licença: MIT](https://img.shields.io/badge/Licen%C3%A7a-MIT-blue.svg)](LICENSE)
![Assistentes](https://img.shields.io/badge/assistentes-20-informational)
![Stacks](https://img.shields.io/badge/stacks-12-informational)

</div>

Funciona com **Claude Code, Cursor, Codex CLI, Gemini CLI, GitHub Copilot, Windsurf, Kiro** e mais 13 assistentes. Peça *"audite a segurança deste projeto"* e você recebe um `SECURITY_AUDIT.md` com nota de 0 a 100, vulnerabilidades classificadas por severidade e categoria OWASP, uma prova `arquivo:linha` para cada uma e uma correção pronta para aplicar.

> 📄 Relatório de exemplo: [exemples/SECURITY_AUDIT.md](exemples/SECURITY_AUDIT.md) (em francês; os relatórios são escritos no seu idioma)

## O que ele traz para você

- **Encontra o que scanners genéricos não veem.** Políticas RLS do Supabase, Security Rules do Firebase, API rules do PocketBase, contas MySQL, server actions do Next.js: falhas específicas de cada plataforma, origem da maioria dos vazamentos de dados reais.
- **Nenhuma vulnerabilidade inventada.** Cada achado cita `arquivo:linha` e um trecho exato relido pela IA, marcado como **Confirmado** ou **A verificar manualmente** (com o que verificar e como).
- **Correções, não só alertas.** Cada achado vem com um diff mínimo e, se necessário, a ação fora do código: trocar uma chave, aplicar uma migração, mudar uma configuração.
- **Prioridades claras.** Nota de 0 a 100, contagem por severidade, tabela resumo e **top 5** para corrigir primeiro, com estimativa de esforço.
- **Seguro por design.** Somente leitura: o código auditado nunca é modificado, nada é enviado a sistemas de terceiros, segredos são mascarados. As varreduras de banco só rodam no *seu* banco, com o seu consentimento.
- **Encontra segredos vazados.** Arquivos `.env` commitados, chaves de API, JWT, chaves privadas, contas de serviço do Firebase e segredos que continuam no **histórico do git**.
- **Audita o seu banco real, não só as migrações.** `scan_rls.sql` (Postgres/Supabase) e `scan_mysql.sql` (MySQL/MariaDB) listam tabelas sem RLS, políticas permissivas, RPC expostas, contas sem senha, root remoto e permissões perigosas.
- **Ensina enquanto audita.** 12 checklists com código *vulnerável vs. corrigido*: para aprender, treinar um time ou ensinar.
- **Usável sem IA.** Os scripts de detecção são bash simples: use em CI ou como hook de pre-commit.
- **Gratuito e open source** (MIT), sem conta, sem serviço externo, funciona offline depois de instalado.

**Para quem?** Desenvolvedores solo e "vibe coders" antes de publicar · freelancers entregando para um cliente · times antes de um release · estudantes e professores · qualquer pessoa que herdou um projeto e quer saber onde estão os buracos.

## Stacks suportados

| Tipo | Stacks |
|---|---|
| Bancos de dados / BaaS | Supabase (Postgres + RLS), Firebase (Firestore, Realtime Database, Storage, Cloud Functions), PocketBase, MySQL / MariaDB |
| Backends | PHP puro, Laravel, Node.js (Express, Fastify, Koa, Hono, NestJS), Next.js, Flask, FastAPI, Django, Go (net/http, Gin, Echo, Fiber, Chi) |
| Em todos | segredos e `.env` commitados, histórico do git, dependências vulneráveis (`bun audit`, `npm audit`, `composer audit`, `pip-audit`, `govulncheck`), ausência de rate limiting |

O stack é detectado automaticamente e **só as checklists relevantes são carregadas**.

## Instalação

Escolha seu assistente com `--ai` (ou `--ai all`). Sem `--ai`, o instalador detecta os assistentes já usados no projeto.

```bash
# npm / Node ≥ 18
npx github:Deathgun07/backend-security-audit init --ai claude
# Bun
bunx github:Deathgun07/backend-security-audit init --ai claude
# pnpm
pnpm dlx github:Deathgun07/backend-security-audit init --ai claude
# Yarn (Berry)
yarn dlx -p backend-security-audit@github:Deathgun07/backend-security-audit backend-security-audit init --ai claude
# curl (sem Node: bash + curl ou wget)
curl -fsSL https://raw.githubusercontent.com/Deathgun07/backend-security-audit/main/install.sh | bash -s -- --ai claude
```

Gerenciador de plugins do Claude Code:
```
/plugin marketplace add Deathgun07/backend-security-audit
/plugin install backend-security-audit@backend-security-audit
```

Valores de `--ai`: `claude` · `cursor` · `codex` · `gemini` · `copilot` · `windsurf` · `kiro` · `antigravity` · `opencode` · `roocode` · `kilocode` · `continue` · `trae` · `qoder` · `codebuddy` · `droid` · `augment` · `warp` · `amazonq` · `universal` · `all`. A tabela completa de pastas de instalação está no [README em inglês](README.md#installation).

Opções: `--global` (pasta pessoal, todos os projetos) · `--force` (atualizar) · `--dry-run` · `list` · `uninstall`. Reinicie o assistente depois de instalar.

## Uso

Na raiz do projeto, peça ao seu assistente:

> *"Audite a segurança deste projeto"*, *"Verifique minhas políticas RLS do Supabase"*, *"Minhas regras do Firebase são seguras?"*

No Claude Code você também pode digitar `/backend-security-audit`. O relatório `SECURITY_AUDIT.md` é escrito na raiz do projeto, no idioma do seu pedido.

### Auditar o seu banco de dados (opcional)

```bash
# Supabase / Postgres (transação desfeita no final)
psql "postgresql://postgres:postgres@127.0.0.1:54322/postgres" -f .claude/skills/backend-security-audit/scripts/scan_rls.sql
# MySQL / MariaDB (somente SELECT)
mysql -u root -p -t < .claude/skills/backend-security-audit/scripts/scan_mysql.sql
```
Somente no **seu próprio** banco. O assistente nunca se conecta a um banco sem o seu consentimento.

## Regras que o skill segue

1. **Somente leitura**: o código auditado nunca é modificado; as correções são propostas em diff.
2. **Nenhum achado sem prova**: `arquivo:linha` e um trecho realmente relido.
3. **Dois status**: *Confirmado* ou *A verificar manualmente* (com a explicação).
4. **Nenhuma ação ofensiva**: só o código local e o seu próprio banco.
5. **Segredos mascarados** no relatório.

## Requisitos e limites

Linux, macOS (bash ≥ 4) ou Windows com WSL / Git Bash. É uma análise estática assistida por IA, não um teste de intrusão: não substitui testes dinâmicos nem uma revisão humana.

## Contribuir

PRs são bem-vindos: novos padrões, novas checklists (Rails, Spring, ASP.NET, MongoDB…), menos falsos positivos e **traduções**. Rode `bash tests/run_tests.sh && bash tests/test_cli.sh` antes de abrir um PR.

## Licença

[MIT](LICENSE) © Deathgun07
