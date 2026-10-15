# Investigação 1: alerta de nível 9 que era falso positivo

## Alerta
- Regra: 92205 (nível 9), mapeada para T1105 (Ingress Tool Transfer) no MITRE ATT&CK
- Agente: windows-endpoint
- Horário: [preencher]

## Pergunta
O processo foi um download malicioso ou ruído gerado pelo próprio agente?

## Evidências

| Campo | Valor |
|---|---|
| Fonte | Sysmon Event ID 1 (criação de processo) |
| ParentImage | `wazuh-agent.exe` |
| Processo filho | [preencher] |
| ProcessGuid | [preencher] |
| Assinatura do agente | Status: Valid |

Consulta usada:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'PROCESS_GUID_AQUI' } |
  Select-Object -First 1 -ExpandProperty Message
```

Verificação de assinatura:
```powershell
Get-AuthenticodeSignature "C:\Program Files (x86)\ossec-agent\wazuh-agent.exe" | Format-List Status, SignerCertificate
```

## Conclusão
Falso positivo. O processo foi iniciado pelo próprio agente Wazuh, com assinatura válida, durante a varredura SCA.

## Ajuste futuro
Supressão restrita: apenas quando `ParentImage` for `wazuh-agent.exe`. Não suprimir a regra inteira nem por nível.

## Lições
- Verificar `ParentImage` antes de concluir.
- Checar a assinatura digital do binário.
- Ajustar com o menor escopo possível.
