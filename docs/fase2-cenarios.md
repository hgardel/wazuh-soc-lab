# Fase 2: cenários controlados

Todos os testes rodam só no lab isolado, com snapshot antes e depois.

## Cenário 1: brute force SSH (ubuntu-endpoint)

Status: concluído (16/10/2026)
Origem: 192.168.56.1 (host, rede host-only)
Usuário alvo: [usuário de teste]
Tentativas manuais com senha errada: 5

Resultados no Discover (agent.name:"ubuntu-endpoint" and rule.groups:"authentication_failed"):

| Regra | Nível | Descrição | Ocorrências |
|---|---|---|---|
| 5710 | 5 | Tentativa com usuário inexistente | 2 (17:52) |
| 5503 | 5 | PAM: falha de login | 5 |
| 5760 | 5 | sshd: falha de autenticação | várias |
| 2502 | 10 | Usuário errou a senha mais de uma vez (T1110) | 3 (17:53:27, 17:53:55, 17:54:18) |

Resposta: a regra de brute force (2502) disparou depois de cerca de 4 falhas registradas, usando só as regras padrão do Wazuh.

Snapshot pós-teste: "Fase 2 pos cenario 1"

## Cenário 2: Falhas de logon no Windows (brute force local)

**Técnica:** T1110 (Brute Force), tática Credential Access
**Agente:** windows-endpoint (Windows 11 com Sysmon, agente Wazuh)
**Origem:** logon interativo na tela de bloqueio, IP 127.0.0.1 (teste local)

### Objetivo
Verificar se o Wazuh detecta falhas repetidas de senha no logon do Windows, tanto como eventos individuais quanto como alerta de agregação, e se o bloqueio de conta é registrado.

### Configuração
- Auditoria de logon com falhas ativa (`auditpol /set /subcategory:"Logon" /failure:enable`).
- Política de bloqueio ativa na conta de teste, com limite de tentativas inválidas.

### Execução
1. Tela de bloqueio (Win + L), senha incorreta em sequência.
2. Reinício da máquina e nova sequência de tentativas incorretas.
3. Após o bloqueio, novas tentativas.

Total de tentativas com senha incorreta (contadas manualmente): 12.

### Resultados no Wazuh

| Evento | Regra | Nível | Observação |
|---|---|---|---|
| 4625 (falha de logon) | 60122 | 5 | Um alerta por tentativa, com "Unknown user or bad password" |
| 60204 (múltiplas falhas) | 60204 | 10 | Disparou na 8ª falha, às 14:03:56 (frequência 8) |
| 4740 (conta bloqueada) | 60115 | 9 | Bloqueio registrado às 14:03:58 |

Total de eventos 4625 registrados no SIEM: 10.

### Análise
- A regra individual (60122) confirma cada tentativa, mas sozinha não indica ataque. Uma falha pode ser erro de digitação.
- A regra 60204 é a que indica padrão de força bruta: várias falhas em pouco tempo. Foi ela que transformou os eventos individuais em um alerta de ataque.
- O bloqueio (4740) mostra que a conta foi protegida pela política do Windows. Depois do bloqueio, o Windows não avalia a senha, por isso algumas tentativas podem não gerar 4625. A contagem no SIEM fica abaixo do total real.
- MITRE: o alerta 60204 mapeia corretamente para T1110. O alerta 60115 também aponta T1531 (Account Access Removal), que não se aplica ao bloqueio. Registrado como limitação da regra padrão.

### Lições
- Eventos isolados não bastam. A correlação por frequência é o que gera alerta útil.
- Confirme o mapeamento MITRE de cada regra antes de documentar, porque regras padrão nem sempre estão corretas.
- Métricas de falha no SIEM devem considerar o bloqueio, senão o número fica subestimado.

### Evidências
- Discover com filtro `agent.name:"windows-endpoint" and (data.win.system.eventID:"4625" or data.win.system.eventID:"4740")`.
- Print dos alertas 60204 e 60115, com nome de usuário e SID cortados.

### Snapshot
- "Fase 2 pos cenario 2" (16/10/2026, 20:48). Os testes de hoje ficaram fora dele.

## Cenário 3: PowerShell com comando codificado

Status: pendente
Técnica: T1059.001
Fonte: Sysmon, evento 1
Pergunta: dá para achar pelo campo CommandLine?
