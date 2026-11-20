# Fase 2: cenários controlados

Todos os testes rodam só no lab isolado, com snapshot antes e depois.

## Cenário 1: brute force SSH (ubuntu-endpoint)

Status: concluído (16/10/2026)
Origem: 192.168.56.1 (host, rede host-only)
Usuário alvo: conta de teste (omitida)
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

- **Status:** concluído (31/10/2026)
- **Técnica:** T1059.001 (Command and Scripting Interpreter: PowerShell), tática Execution
- **Fonte:** Sysmon, evento 1 (Process Create)
- **Ambiente:** `windows-endpoint` (Windows 11, Sysmon, agente 002) e `wazuh-server` 4.14.7, em rede host-only isolada. Teste local e controlado.

### Objetivo
Verificar se o Wazuh detecta a execução de PowerShell com `-EncodedCommand` pelo campo CommandLine do evento 1 do Sysmon.

### Execução
Em um PowerShell elevado no endpoint, executei duas vezes:

```
powershell -NoProfile -EncodedCommand aABvAHMAdABuAGEAbQBlAA==
```

O payload é Base64 em UTF-16LE. Decodificado no host, resulta em `hostname`, um comando inofensivo:

```
echo 'aABvAHMAdABuAGEAbQBlAA==' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

Consulta DQL usada (Threat Hunting):

```
data.win.system.eventID:"1" and data.win.eventdata.commandLine:*EncodedCommand*
```

### Resultados

| Item | Valor |
|---|---|
| Evento de origem | Sysmon evento 1 (Process Create) |
| Alertas gerados | 2, um por execução (31/10/2026, cerca de 16:56 e 16:59, horário local) |
| Regra | 92057, arquivo 0800-sysmon_id_1.xml |
| Descrição | Powershell.exe spawned a powershell process which executed a base64 encoded command |
| Nível | 12 |
| Grupos | sysmon, sysmon_eid1_detections, windows |
| Tática e técnica | Execution, PowerShell (T1059.001) |
| Latência | cerca de 2 segundos, do evento no Sysmon ao alerta no Wazuh |

### Campos do evento 1 (primeiro alerta)

| Campo | Valor |
|---|---|
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| OriginalFileName | PowerShell.EXE (igual ao nome do binário, sem renomeação) |
| ParentImage | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| ParentCommandLine | `powershell.exe` (shell interativo, sem argumentos) |
| CommandLine | `powershell.exe -NoProfile -EncodedCommand aABvAHMAdABuAGEAbQBlAA=` |
| IntegrityLevel | High (shell elevado) |
| TerminalSessionId | 1 (sessão interativa) |
| CurrentDirectory | `C:\WINDOWS\system32\` |
| SHA256 | 60C9B29843624DD8AF6B6A7B26147753BE6AEEF65098B9A503CC50850AFE410F |

Usuário e hostname foram omitidos por privacidade. O segundo alerta (cerca de 16:59) não foi aberto individualmente.

### Enriquecimento (VirusTotal)
- Consultei o SHA256 do `powershell.exe` por busca (somente o hash, sem enviar o arquivo).
- Resultado: 0 de 71 fornecedores marcaram como malicioso. Nome do arquivo: PowerShell.EXE, 484 KB.
- Conclusão: o binário é o PowerShell legítimo do Windows, sem reputação maliciosa.
- Os relatórios de sandbox exibem sinais como tags de ofuscação e regras Sigma. Eles refletem o comportamento da própria ferramenta em sandbox (e, provavelmente, o ambiente do teste), não indicam que o binário seja malicioso.
- O PowerShell é um LOLBin. A reputação do hash não detecta o abuso, que aparece só na linha de comando e no processo pai. Por isso a regra 92057 analisa `commandLine` e `parentImage`, e não o hash.

### Análise
- A regra 92057 exige duas condições: o processo pai é `powershell.exe` e a CommandLine contém `powershell.exe` seguido de `-EncodedCommand` ou de uma abreviação (`-e`, `-ec`, `-enc` e variantes). Os dois campos acima atendem a regra.
- Triagem: **verdadeiro positivo de comportamento, atividade benigna e esperada** (teste do lab).
- Um payload inofensivo gerou alerta de nível 12. A regra detecta a técnica, não a intenção. Em produção, o analista decodificaria o comando e checaria processo pai, usuário, nível de integridade, horário e frequência antes de escalar.
- Sinais que aumentariam a suspeita em produção: pai inesperado (Office, navegador), usuário fora do padrão, execução fora do horário e payload que baixa ou executa código remoto.
- O CommandLine registrado termina com um único `=`, diferente do comando planejado (`==`), provável erro de digitação. A regra disparou mesmo assim. O Sysmon registra a criação do processo, não o resultado da execução.

### Limitações
- A regra depende do processo pai ser PowerShell. Não testei a execução a partir de outro pai (por exemplo, o CMD). É uma hipótese a validar.
- Não testei ofuscações além do `-EncodedCommand` padrão.
- O evento 1 não mostra a saída do comando. Ver o conteúdo decodificado exigiria o PowerShell Script Block Logging (evento 4104), que não estava habilitado.
- Foi um único payload, inofensivo e de teste.

### Evidências
- Prints em `evidence/` (usuário e SID omitidos): alerta 92057 de nível 12, evento 1 aberto e consulta do SHA256 no VirusTotal.

### Snapshots
- "Fase 2 pre cenario 3" e "Fase 2 pos cenario 3"
