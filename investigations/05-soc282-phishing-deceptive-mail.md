
* **URL Maliciosa (Download do Payload):** `hxxps://files-ld.s3.us-east-2.amazonaws[.]com/free-coffee.zip`



# Relatório de Investigação: SOC282 - Phishing Alert - Deceptive Mail Detected

**Event ID:** 257 | **Data do Evento:** 13/05/2024 09:22:00 | **Plataforma:** LetsDefend
**Severidade:** Média | **Categoria:** Phishing / Malware Execution | **Veredito:** Verdadeiro Positivo (True Positive)

## 1. Resumo Executivo

Foi detectado o recebimento de um e-mail fraudulento (`free@coffeeshooop.com`) direcionado ao colaborador `Felix@letsdefend.io` contendo o anexo compactado `free-coffee.zip` protegido por senha (`infected`). A investigação no endpoint **EC2AMAZ-ILGVOIN** comprovou que o usuário extraiu e executou o binário malicioso `Coffee.exe`, desencadeando uma sequência automatizada de comandos de reconhecimento do sistema via `cmd.exe`. O incidente foi confirmado como **Verdadeiro Positivo** e o host foi imediatamente isolado da rede.

## 2. Detalhes do Alerta e Evidências

* **Regra Disparada:** `SOC282 - Phishing Alert - Deceptive Mail Detected`
* **Host Comprometido:** `EC2AMAZ-ILGVOIN` (Usuário: `EC2AMAZ-ILGVOIN\Felix`)
* **Remetente / IP SMTP:** `free@coffeeshooop.com` (`103.80.134.63`)
* **Destinatário:** `Felix@letsdefend.io`
* **Assunto:** *Free Coffee Voucher*
* **Anexo do E-mail:** `free-coffee.zip` (Senha fornecida no corpo: `infected`)
* **Payload Extraído:** `"C:\Users\Felix\Downloads\Coffee.exe"` (PID: `6697`)
* **Hash SHA-256 (parcial registrado):** `CD903AD2211CF7D166646D75E57FB866000F4A3B87...`

## 3. Linha do Tempo e Análise da Árvore de Processos (EDR)

* **Entrega e Evasão:** O e-mail oriundo do domínio com *typosquatting* (`coffeeshooop.com`) foi permitido pelo filtro (`Allowed`) devido ao uso de arquivo `.zip` criptografado com senha (`infected`), contornando a análise estática do gateway.
* **Execução Inicial (PID 6697):** O processo `Explorer.EXE` iniciou `"C:\Users\Felix\Downloads\Coffee.exe"`, confirmando a interação e execução manual pelo usuário Felix.
* **Pós-Exploração e Reconhecimento (PIDs 6700–6707):** O malware `Coffee.exe` invocou o interpretador `cmd.exe` (PID `6700`) e executou sequencialmente comandos nativos de descoberta de ambiente:
  * `systeminfo.exe` (PID `6701`) e `hostname.exe` (PID `6702`) — Coleta de informações do SO e identificação do host.
  * `wmic.exe logicaldisk get caption,description,providername` (PID `6703`) — Mapeamento de unidades de disco e compartilhamentos de rede.
  * `net.exe user` (PID `6704`) — Enumeração de contas de usuários locais.
  * `tasklist.exe /svc` (PID `6705`) — Levantamento de processos e serviços em execução.
  * `ipconfig.exe /all` (PID `6706`) e `route.exe print` (PID `6707`) — Mapeamento de topologia de rede e rotas ativas.

## 4. Enriquecimento (Threat Intelligence) e MITRE ATT&CK

* **Indicadores Maliciosos (IoCs):** IP remetente `103.80.134.63`, domínio falso `coffeeshooop.com` e executável `Coffee.exe`.
* **Mapeamento MITRE ATT&CK:**
  * **T1566.001 / T1566.002 (Phishing: Spearphishing Attachment & Link):** Uso de isca promocional falsa com anexo protegido por senha e link de resgate.
  * **T1204.002 (User Execution: Malicious File):** Execução manual do arquivo `Coffee.exe` pelo usuário final.
  * **T1059.003 (Command and Scripting Interpreter: Windows Command Shell):** Uso de `cmd.exe` pelo malware para execução de comandos.
  * **T1082 / T1016 / T1057 / T1087 (Discovery):** Enumeração automatizada de sistema, rede, processos e usuários.

## 5. Ações de Contenção e Remediação

1. **Isolamento do Host (Containment):** Contenção imediata da máquina `EC2AMAZ-ILGVOIN` via EDR para impedir comunicações de Comando e Controle (C2) e movimentação lateral.
2. **Erradicação de E-mail:** Exclusão da mensagem maliciosa da caixa de entrada de `Felix@letsdefend.io` e bloqueio do remetente `free@coffeeshooop.com`, domínio `coffeeshooop.com` e IP `103.80.134.63`.
3. **Remediação de Endpoint e Credenciais:** Reset obrigatório das credenciais do usuário `Felix`, encerramento dos processos maliciosos, remoção do `Coffee.exe` / `free-coffee.zip` e verificação de persistência no Agendador de Tarefas (`svchost.exe -s Schedule`).
4. **Escalonamento:** Encaminhamento ao SOC N2 / Resposta a Incidentes para análise forense completa e bloqueio dos hashes nos controles de endpoint.
