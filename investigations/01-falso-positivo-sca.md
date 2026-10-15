# Investigação 1: alerta de nível 9 que era falso positivo

## Alerta
- Regra: 92205 (nível 9), mapeada para T1105 (Ingress Tool Transfer) no MITRE ATT&CK
- Agente: windows-endpoint
- Horário: 14/10/2026 20:49 (horário local)

## Pergunta
O processo foi um download malicioso ou ruído gerado pelo próprio agente?

## Evidências

| Campo | Valor |
|---|---|
| Fonte | Sysmon Event ID 1 (criação de processo) |
| ParentImage | `C:\Program Files (x86)\ossec-agent\wazuh-agent.exe` |
| ParentProcessGuid | `{62b5e579-14ef-6ad0-c905-000000000d00}` |
| Processo filho | `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` |
| ProcessGuid (filho) | `{62b5e579-1505-6ad0-e505-000000000d00}` |
| CommandLine | `powershell -NoProfile -Command "[bool](Get-CimInstance -Query 'SELECT * FROM Win32_UserAccount WHERE LocalAccount = TRUE AND SID LIKE ''S-1-5-21-%-501''' | Where-Object -Property Disabled)"` |
| Usuário | AUTORIDADE NT\SISTEMA |
| Assinatura do agente | Status: Valid |

Evento complementar (ID 11): o mesmo PowerShell criou `__PSScriptPolicyTest_*.ps1` em `C:\Windows\SystemTemp`, comportamento normal de inicialização do PowerShell.

## Conclusão
Falso positivo. O agente Wazuh (binário com assinatura válida) iniciou o PowerShell para uma checagem de configuração do CIS, que verifica se a conta Guest está desativada (SID terminado em -501). Não há download nem processo estranho.

## Ajuste futuro
Supressão restrita: apenas quando `ParentImage` for `wazuh-agent.exe` e a `CommandLine` contiver a checagem do SCA. Não suprimir a regra inteira nem por nível.

## Lições
- Verificar `ParentImage` antes de concluir.
- Checar a assinatura digital do binário.
- Ler a `CommandLine` do processo filho para entender a intenção.
- Ajustar com o menor escopo possível.
