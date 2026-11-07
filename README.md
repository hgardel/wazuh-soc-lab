# Wazuh SOC Lab

Laboratório local de monitoramento de segurança com Wazuh, Sysmon e VirtualBox. Todo o ambiente roda em rede isolada (host-only). Nenhuma VM fica exposta à internet.

## Arquitetura
- Servidor: Wazuh 4.14.7 em Ubuntu Server
- Endpoint 1: Ubuntu Server com agente Wazuh
- Endpoint 2: Windows 11 com agente Wazuh e Sysmon
- Rede: NAT para saída + host-only para comunicação entre as VMs
- Administração: SSH

## Conteúdo
- [Endpoint Windows com Sysmon](docs/sysmon-windows.md)
- [Investigação 1: alerta de nível 9 que era falso positivo](investigations/01-falso-positivo-sca.md)
- [Fase 2: cenários controlados](docs/fase2-cenarios.md): força bruta SSH (T1110), falhas de logon no Windows (T1110) e PowerShell com comando codificado (T1059.001)
- `evidence/`: prints usados nas investigações (sem IPs reais, usuários ou SIDs)

## O que isso demonstra
- Coleta de logs de Linux e Windows
- Monitoramento e análise de alertas
- Investigação com Sysmon (ParentImage, ProcessGuid, assinatura)
- Detecção de força bruta em SSH e no Windows, com regras padrão do Wazuh
- Detecção de PowerShell com comando codificado, com triagem por processo pai, integridade e hash
- Mapeamento de regras para MITRE ATT&CK
- Documentação de problemas, limitações e correções

## Status
- Fase 1: concluída (agentes conectados e alertas chegando ao dashboard)
- Fase 2: concluída (3 cenários controlados em ambiente isolado, com snapshots antes e depois)
- Próxima fase: Microsoft Sentinel (planejada)
