Repositório dedicado à documentação de análises de alertas, triagem de incidentes e investigação de ameaças realizadas em ambientes simulados de laboratório (**LetsDefend** e **TryHackMe**).

O objetivo deste projeto é aplicar metodologias reais de **SOC N1**, incluindo correlação de logs, enriquecimento de Indicadores de Comprometimento (IoCs), mapeamento na matriz **MITRE ATT&CK** e elaboração de relatórios executivos e técnicos.

## Ferramentas:

* **SIEM & Análise de Logs:** TryHackMe, LetsDefend SIEM,
* **Threat Intelligence:** VirusTotal, AbuseIPDB, URLscan.io, AlienVault OTX, Cisco Talos
* **Análise de Rede & Phishing:** Wireshark, análise de cabeçalhos de e-mail (SPF/DKIM/DMARC)
* **Frameworks:** MITRE ATT&CK

## Investigações:

| #  | Caso / Alerta                                     | Categoria                      | Plataforma | Veredito            | Relatório                                                              |
| :- | :------------------------------------------------ | :----------------------------- | :--------- | :------------------ | :---------------------------------------------------------------------- |
| 01 | SOC104 - Malware Detectado                        | Triagem / Malware              | LetsDefend | Falso Positivo      | [Ver Relatório](./investigations/01-soc104-malware-detected.md)         |
| 02 | SOC335 - Exploração CVE-2024-49138              | Privilege Escalation           | LetsDefend | Verdadeiro Positivo | [Ver Relatório](./investigations/02-soc335-cve-2024-49138.md)           |
| 03 | Alerta 1000 - E-mail Suspeito de Domínio Externo | Phishing / Engenharia Social   | TryHackMe  | Verdadeiro Positivo | [Ver Relatório](./investigations/03-thm-phishing-inheritance-scam.md)   |
| 04 | Sysmon - Relação Incomum Pai/Filho              | Análise de Processos / Sysmon | TryHackMe  | Falso Positivo      | [Ver Relatório](./investigations/04-thm-sysmon-false-positive-wudfhost) |
| 05 | SOC282 - Phishing & Execução de Malware         | Phishing / Pós-Exploração   | LetsDefend | Verdadeiro Positivo | [Ver Relatório](./investigations/05-soc282-phishing-deceptive-mail.md)  |

---

*Todos os relatórios documentados neste repositório referem-se a ambientes controlados de treinamento.*
