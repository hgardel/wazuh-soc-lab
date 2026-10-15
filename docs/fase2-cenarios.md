# Fase 2: cenários controlados

Todos os testes rodam só no lab isolado, com snapshot antes.

| # | Cenário | Técnica MITRE | Fonte de log | Pergunta a responder |
|---|---|---|---|---|
| 1 | Brute force SSH no ubuntu-endpoint | T1110 | auth.log | Quantas falhas disparam alerta e de qual regra? |
| 2 | Falhas de logon no Windows | T1110 | Security (evento 4625) | O Wazuh agrupa falhas do mesmo IP ou usuário? |
| 3 | PowerShell com comando codificado | T1059.001 | Sysmon evento 1 | Dá para achar pelo campo CommandLine? |
