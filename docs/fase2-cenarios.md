# Fase 2: cenários controlados

Todos os testes rodam só no lab isolado, com snapshot antes e depois.

## Cenário 1: brute force SSH (ubuntu-endpoint)

Status: concluído (16/10/2026)
Origem: 192.168.56.1 (host, rede host-only)
Usuário alvo: hgardel
Tentativas manuais com senha errada: [preencher]

Resultados no Discover (agent.name:"ubuntu-endpoint" and rule.groups:"authentication_failed"):

| Regra | Nível | Descrição | Ocorrências |
|---|---|---|---|
| 5710 | 5 | Tentativa com usuário inexistente | 2 (17:52) |
| 5503 | 5 | PAM: falha de login | 5 |
| 5760 | 5 | sshd: falha de autenticação | várias |
| 2502 | 10 | Usuário errou a senha mais de uma vez (T1110) | 3 (17:53:27, 17:53:55, 17:54:18) |

Resposta: a regra de brute force (2502) disparou depois de cerca de 4 falhas registradas, usando só as regras padrão do Wazuh.

Snapshot pós-teste: "Fase 2 pos cenario 1"

## Cenário 2: falhas de logon no Windows (windows-endpoint)

Status: pendente
Técnica: T1110
Fonte: Security, evento 4625
Pergunta: o Wazuh agrupa as falhas do mesmo usuário ou gera um alerta por evento?

## Cenário 3: PowerShell com comando codificado

Status: pendente
Técnica: T1059.001
Fonte: Sysmon, evento 1
Pergunta: dá para achar pelo campo CommandLine?
