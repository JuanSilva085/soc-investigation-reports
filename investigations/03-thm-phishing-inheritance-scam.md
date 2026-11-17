
# Relatório de Investigação: Alerta 1000 - E-mail Suspeito de Domínio Externo

**Alert ID:** 1000
**Data Detectada:** 16/11/2026 21:17
**Plataforma:** TryHackMe
**Severidade:** Baixa
**Categoria:** Phishing
**Veredito:** Verdadeiro Positivo (True Positive)

---

## 1. Resumo Executivo

O sistema de monitoramento (SIEM) disparou o **Alerta 1000** após detectar o recebimento de um e-mail externo (`inbound`) proveniente de um domínio de topo incomum (`trendymillineryco.me`) direcionado à caixa departamental `support@tryhatme.com`. A triagem do cabeçalho, do remetente e do conteúdo da mensagem confirmou tratar-se de uma tentativa de fraude financeira (*419 Scam* / golpe da herança) com solicitação direta de dados bancários sob pretexto de urgência. O incidente foi classificado como **Verdadeiro Positivo**, teve os indicadores bloqueados e foi escalado ao SOC N2 para varredura em massa e ajuste (*fine-tuning*) da regra de correlação.

## 2. Detalhes do Alerta e Evidências

* **Regra de Alerta:** E-mail suspeito de domínio externo (`ID 1000`)
* **Fonte de Dados (Datasource):** `email` (Logs de Gateway de E-mail)
* **Carimbo de Data/Hora (Log):** `17/11/2026 00:15:05.664`
* **Direção do Tráfego:** Inbound (Externo → Interno)
* **Remetente (Sender):** `eileen@trendymillineryco.me`
* **Domínio de Origem:** `trendymillineryco.me` (TLD `.me`)
* **Destinatário (Recipient):** `support@tryhatme.com`
* **Assunto (Subject):** *Alerta de Herança: Parente Bilionário Desconhecido Deixou Suas Fortunas do Chapéu*
* **Anexos / Payloads:** Nenhum (`None`)

## 3. Análise Técnica e Engenharia Social

* **Análise de Infraestrutura e TLD:** O remetente utiliza o domínio de nível superior `.me` (`trendymillineryco.me`), frequentemente explorado em campanhas de phishing e spam por apresentar baixo custo de aquisição e ausência de validação empresarial rigorosa. O domínio não possui relação comercial legítima com a organização alvo.
* **Vetores de Engenharia Social Identificados:**
  * **Pretexting (Isca Financeira):** Construção de uma narrativa inverossímil alegando herança bilionária de um parente desconhecido para despertar interesse imediato da vítima.
  * **Senso de Urgência:** Instrução explícita para o envio imediato de dados bancários (*"envie seus dados bancários imediatamente"*), técnica utilizada para pressionar o destinatário e evitar verificações de segurança.
* **Evasão de Controles Baseados em Payload:** Por não conter anexos executáveis ou links externos maliciosos, a mensagem contorna ferramentas tradicionais de *sandboxing* e análise de URL, operando como ataque baseado em resposta direta (*Reply-Based Financial Fraud*).

## 4. Enriquecimento (Threat Intelligence) e MITRE ATT&CK

* **Classificação dos IoCs:** O endereço `eileen@trendymillineryco.me` e o domínio `trendymillineryco.me` foram catalogados como indicadores associados a campanhas de *Advance-Fee Fraud* (fraude de taxa antecipada / golpe da herança) e coleta de informações financeiras.
* **Mapeamento MITRE ATT&CK:**
  * **T1566 (Phishing):** Utilização de correio eletrônico como vetor inicial para enganar o usuário e induzir ações prejudiciais.
  * **T1598 (Phishing for Information):** Solicitação direta de dados bancários sensíveis por meio de manipulação psicológica, sem implantação de malware.

## 5. Ações de Contenção, Escalonamento e Tuning (SIEM)

1. **Contenção Imediata:** Bloqueio do remetente `eileen@trendymillineryco.me` e do domínio `trendymillineryco.me` nas políticas de entrada do Secure Email Gateway (SEG).
2. **Erradicação:** Remoção da mensagem da caixa de entrada `support@tryhatme.com` para impedir interação acidental da equipe de suporte.
3. **Escalonamento ao SOC N2:** Encaminhamento do ticket para pesquisa ampla nos logs de e-mail (`datasource=email`) visando identificar outros colaboradores que possam ter recebido mensagens da mesma campanha.
4. **Proposta de Ajuste Fino (Rule Fine-Tuning):** Conforme sinalizado pelo Líder do SOC, regras baseadas isoladamente em TLDs incomuns geram elevado índice de falsos positivos. Recomenda-se refinar a lógica de detecção no SIEM combinando o TLD incomum com termos críticos no assunto/corpo:
   ```text
   direction="inbound" AND sender_domain IN (*.me, *.xyz, *.top) 
   AND (subject OR content) CONTAINS ("herança", "inheritance", "dados bancários", "banking details", "imediatamente")
   ```
