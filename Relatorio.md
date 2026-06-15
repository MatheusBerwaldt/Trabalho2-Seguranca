# Análise Técnica de Falhas: O Caso Equifax Data Breach (2017)

**Disciplina:** Segurança de Sistemas / Segurança da Informação  
**Formato:** Trabalho de Análise de Falhas Famosas de Segurança  
**Grupo:** Matheus Berwaldt, João Coelho

---

## 1. Contextualização do Caso
* **Empresa afetada:** Equifax, uma das três maiores agências de proteção de crédito e relatórios de consumo dos Estados Unidos.
* **Sistema/Software afetado:** O portal web de disputa de crédito online da empresa (*Automated Consumer Interview System* - ACIS).
* **Período:** O ataque começou a **13 de maio de 2017** e continuou ativamente até **30 de julho de 2017**. A vulnerabilidade inicial explorada (CVE-2017-5638) havia sido divulgada publicamente em março de 2017.
* **Breve descrição:** Cibercriminosos exploraram uma vulnerabilidade conhecida e não corrigida no framework web de código aberto Apache Struts utilizado pela Equifax. Isto permitiu que os atacantes invadissem o servidor, encontrassem credenciais internas em texto limpo e realizassem buscas extensas em bases de dados durante meses, roubando informações pessoais sensíveis de centenas de milhões de cidadãos.

---

## 2. Descrição do Problema e Impacto Imediato
* **O que aconteceu:** Devido a uma falha grave de gestão de patches (atualizações de segurança), o portal de disputas da Equifax permaneceu vulnerável mesmo após alertas oficiais emitidos pelas autoridades de segurança cibernética. Os atacantes ganharam a capacidade de executar comandos arbitrários diretamente no servidor da empresa.
* **Impacto imediato:** O comprometimento total do servidor web front-end e a instalação de múltiplos *web shells* (portas das traseiras baseadas em web). Isto garantiu aos invasores controlo remoto persistente sobre o ambiente e permitiu-lhes iniciar o mapeamento da infraestrutura e da rede interna corporativa sem levantar suspeitas imediatas.

---

## 3. Consequências
* **Vazamento de dados:** Exposição massiva de dados altamente sensíveis de **147,9 milhões de consumidores norte-americanos**, além de aproximadamente 15,2 milhões de cidadãos britânicos e 19.000 canadenses. Os dados roubados incluíam:
  * Nomes completos e datas de nascimento.
  * Números de Segurança Social (SSN — equivalente ao CPF/NIF).
  * Moradas residenciais e números de cartas de condução.
  * Cerca de 200.000 números de cartões de crédito.
* **Prejuízos financeiros e legais:** A Equifax fechou um acordo histórico de compensação com a *Federal Trade Commission* (FTC) no valor mínimo de **US$ 575 milhões** (podendo ascender aos US$ 700 milhões) para fundos de indemnização e monitorização de crédito gratuito para as vítimas. As ações da empresa caíram 13% imediatamente após o anúncio público.
* **Impactos reputacionais:** Destruição massiva da confiança do público e do mercado na marca, gerando revolta popular e investigações rigorosas e audições no Congresso Americano.
* **Demissões de executivos:** O incidente resultou na renúncia forçada do CEO (Richard Smith), além da reforma imediata do CIO (David Webb) e da CSO (Susan Mauldin).

---

## 4. Como a Falha Ocorreu (Linha do Tempo e Vetores)
* **Vetor de ataque:** Injeção de código remoto (RCE) através da manipulação do cabeçalho HTTP (`Content-Type`) enviado para a aplicação web.
* **Sequência dos eventos (Linha do Tempo):**
  1. **07 de Março de 2017:** A Apache Software Foundation divulga publicamente a vulnerabilidade crítica no Apache Struts e lança o patch de correção.
  2. **08–09 de Março de 2017:** O Departamento de Segurança Interna dos EUA (DHS/US-CERT) alerta a Equifax. A equipa de segurança da Equifax repassa internamente o alerta por e-mail instruindo a aplicação do patch em 48 horas, mas a equipa de TI responsável pelo portal ACIS falha em atualizar o sistema.
  3. **13 de Maio de 2017:** Os atacantes localizam o servidor vulnerável e ganham acesso inicial, instalando *web shells* para persistência.
  4. **Movimentação Lateral (Maio a Julho):** Os invasores efetuam varreduras internas e encontram um ficheiro de configuração contendo credenciais (utilizadores e passwords) em texto claro (não encriptadas). Isto permitiu saltar do servidor web comprometido e aceder a **48 bases de dados externas e independentes**, correndo mais de 9.000 queries de exfiltração.
  5. **Exfiltração Oculta:** Para evitar que os sistemas de deteção de intrusão (IDS/IPS) notassem o tráfego pesado, os atacantes dividiram os dados roubados em pequenos ficheiros compactados e utilizaram canais de comunicação encriptados.
  6. **29 de Julho de 2017:** A Equifax renova um certificado digital SSL/TLS que estava **expirado há 19 meses**. Assim que o certificado é atualizado, as ferramentas de inspeção de tráfego voltam a conseguir decifrar o tráfego de saída e detetam imediatamente a transferência anómala de dados.
  7. **30 de Julho de 2017:** A aplicação vulnerável é tirada do ar para estancar o vazamento.
  8. **07 de Setembro de 2017:** A Equifax divulga publicamente o incidente após investigações forenses com a Mandiant.

---

## 5. Análise Técnica Detalhada da Vulnerabilidade

Para compreender a fundo o `CVE-2017-5638`, é necessário analisar a interação entre três componentes de software: o framework **Apache Struts**, o parser **Jakarta Multipart**, e a linguagem de expressão **OGNL (Object-Graph Navigation Language)**.

### A Raiz do Problema: O Parser Jakarta Multipart
O Apache Struts utiliza interceptores (*interceptors*) para processar pedidos HTTP antes que estes cheguem à lógica de negócio. Quando é enviado um pedido de upload de ficheiro (geralmente com o cabeçalho `Content-Type: multipart/form-data`), o Struts repassa esse pedido para o parser **Jakarta Multipart** para processar os dados binários.

O erro de programação (*bug*) ocorria quando o parser encontrava um erro ou uma string malformada no cabeçalho. Em vez de simplesmente rejeitar o pedido e retornar um erro estático (como HTTP 400), o Jakarta tentava construir uma mensagem de erro dinâmica que incluía o próprio conteúdo do cabeçalho enviado pelo utilizador para fins de depuração. O perigo técnico reside no facto de o método utilizado para renderizar esta mensagem de erro (`LocalizedTextUtil.findText`) passar a string gerada diretamente para o motor OGNL.

### O Vetor de Injeção OGNL
O OGNL é uma linguagem de expressão poderosa usada em Java para ler e alterar propriedades de objetos Java em tempo de execução. O motor OGNL trata qualquer string delimitada por padrões como `${...}` ou `%{\...}` não como texto puro, mas como **código executável**.

Ao injetar código OGNL malicioso dentro do cabeçalho `Content-Type`, o atacante forçava o parser a falhar. O Struts, então, executava o script injetado com os mesmos privilégios do processo Java subjacente (geralmente privilégios elevados de `root` ou `SYSTEM` no servidor), permitindo a Execução Remota de Código (RCE).

### Anatomia do Exploit (Exemplo do Payload Real)
Um exemplo de cabeçalho HTTP real utilizado para explorar esta vulnerabilidade continha a seguinte estrutura estruturada em OGNL:

```http
Content-Type: %{(#container='ognl.OgnlContext').(#context=#container.DEFAULT_CONTEXT).(#context.setMemberAccess(#(#container='ognl.SecurityMemberAccess').#context.allowStaticMethodAccess=true)).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}

```

#### Desconstrução Técnica do Payload:

1. **Quebra da Sandbox (`setMemberAccess`):** O OGNL possui restrições de segurança por padrão. O payload começa por alterar a flag `allowStaticMethodAccess=true`. Isto desabilita as restrições nativas do Struts e permite a execução de métodos Java estáticos e a manipulação direta do sistema.
2. **Identificação Dinâmica do S.O. (`os.name`):** O payload verifica se o servidor corre Windows ou Linux para invocar o interpretador de comandos correto (`cmd.exe /c` ou `/bin/bash -c`).
3. **Instanciação de Processo (`ProcessBuilder`):** O exploit utiliza a classe nativa `java.lang.ProcessBuilder` para invocar o terminal do sistema operacional e executar um comando arbitrário (no exemplo acima, o comando básico `whoami` para validar o nível de privilégio).
4. **Redirecionamento de Fluxo (`ServletActionContext`):** O script intercepta a resposta HTTP do servidor (`ServletActionContext@getResponse().getOutputStream()`) e injeta a saída do comando do terminal diretamente no corpo da resposta HTTP que retorna para o atacante, transformando o pedido web num terminal interativo.

### Classificação Técnica Formal

| Métrica / Classificação | Identificador / Detalhe Técnico |
| --- | --- |
| **CVE ID** | `CVE-2017-5638` |
| **Gravidade CVSS v3** | **10.0 (Crítica)** — Pontuação máxima devido ao impacto total e facilidade de execução. |
| **CWE Tipo 1** | `CWE-20: Improper Input Validation` (Confiança inadequada em dados controlados pelo utilizador). |
| **CWE Tipo 2** | `CWE-917: Improper Expression Language Expression Validation` (Injeção de Expressão). |
| **Vetor de Ataque (CVSS)** | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (Rede/Remoto, baixa complexidade, sem privilégios). |

---

## 6. Medidas Corretivas e Preventivas

* **Como foi corrigido no caso:** O portal web foi desativado emergencialmente para estancar o ataque. A biblioteca do Apache Struts foi atualizada para a versão estável e corrigida, e todas as credenciais expostas foram revogadas e alteradas antes de o serviço retornar à internet.
* **Medidas preventivas que evitariam o incidente:**
* **Gestão de Ativos e Inventário de Software:** A Equifax falhou em aplicar o patch porque não tinha um inventário centralizado e automatizado para saber em que servidores o framework Apache Struts estava a correr.
* **Gestão de Patches Automatizada:** Implementação de políticas estritas e janelas de manutenção rápidas para a aplicação de correções de segurança críticas em sistemas expostos à internet em menos de 24/48 horas.
* **Gestão de Certificados Criptográficos (PKI):** Monitorização automatizada do ciclo de vida de certificados digitais. O facto de um certificado ter estado expirado por 19 meses "cegou" completamente os sistemas de monitorização de tráfego de saída (IDS/IPS).
* **Princípio do Menor Privilégio e Defesa em Profundidade:** Armazenar credenciais em texto claro em ficheiros de texto é uma falha grave. Adicionalmente, deve existir segmentação de rede estrita: um servidor web na DMZ nunca deve ter permissão direta para comunicar com 48 bases de dados de produção críticas que não fazem parte do seu âmbito de negócio.



---

## 7. Conclusão (Principais Aprendizados)

* **A Segurança é um Processo, Não um Produto:** O caso prova que falhas operacionais simples de processos humanos (negligenciar um e-mail de atualização ou esquecer de renovar um certificado) podem anular investimentos de milhões de dólares em ferramentas de segurança de ponta.
* **Responsabilidade Ética e Legal com Dados:** Companhias que tratam dados sensíveis possuem o dever de manter uma postura proativa, auditada e transparente. A falta de controlos básicos de segurança da informação pode resultar em danos financeiros e reputacionais catastróficos e irreversíveis.

---

**Fontes e Referências Utilizadas:**

* *Apache Software Foundation Security Bulletin (2017).*
* *U.S. Government Accountability Office (GAO) Report on Equifax Data Breach.*
* *Federal Trade Commission (FTC) Official Settlement Release.*
* *NIST National Vulnerability Database (NVD) - CVE-2017-5638.*
