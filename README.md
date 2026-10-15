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
- `evidence/`: prints usados nas investigações (sem IPs reais)

## O que isso demonstra
- Coleta de logs de Linux e Windows
- Monitoramento e análise de alertas
- Investigação com Sysmon (ParentImage, ProcessGuid, assinatura)
- Mapeamento de regras para MITRE ATT&CK
- Documentação de problemas e correções

## Status
- Fase 1: agentes conectados e alertas chegando ao dashboard
- Fase 2 (em andamento): regras personalizadas e cenários controlados de ataque, com ambiente isolado
