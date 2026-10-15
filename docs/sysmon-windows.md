# Endpoint Windows com Sysmon

## Objetivo
Coletar eventos de processo e de arquivo do Windows e enviá-los ao Wazuh.

## Ambiente
- Servidor Wazuh 4.14.7 em Ubuntu Server (VirtualBox, rede host-only)
- Endpoint Windows 11 (VirtualBox)
- Sysmon v15.22 com a configuração SwiftOnSecurity (`sysmonconfig-export.xml`)

## Instalação do Sysmon
```powershell
Expand-Archive .\Sysmon.zip -DestinationPath .\Sysmon -Force
Expand-Archive .\sysmon-config-master.zip -DestinationPath .\ -Force
.\Sysmon\Sysmon64.exe -accepteula -i .\sysmon-config-master\sysmonconfig-export.xml
```

Para atualizar só a configuração:
```powershell
.\Sysmon\Sysmon64.exe -c .\sysmon-config-master\sysmonconfig-export.xml
```

## Integração com o Wazuh
Teste a porta do manager antes de tudo:
```powershell
Test-NetConnection IP_DO_SERVIDOR -Port 1514
```

Adicione dentro de `<ossec_config>` no `ossec.conf` do agente (`C:\Program Files (x86)\ossec-agent\ossec.conf`):
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Reinicie o serviço e confira o log:
```powershell
Restart-Service -Name WazuhSvc
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20
```

## Problemas encontrados
- Pasta `.zip` abria como pasta e `cd` falhava. Solução: extrair com `Expand-Archive`.
- Bloco `<localfile>` fora de `<ossec_config>` não era carregado. Solução: mover para dentro e conferir no `ossec.log`.
- Agente desconectado no início (erros 1216 e 1208 no log). Conectou depois da correção.
- Discover sem resultado por causa do intervalo de tempo antigo. Solução: usar um intervalo recente.
- Comandos colados como XML no PowerShell geram erros inofensivos.
- Teste de conectividade com placeholder não serve. Use o IP real do servidor.

## Baseline de segurança (SCA, CIS Windows 11 v3.0.0)
- Score: 24%
- 482 checks: 114 aprovados, 359 reprovados, 9 inválidos
- Próximo passo: remediar primeiro os itens de maior impacto.
