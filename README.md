# 🛡️ PhishGuard

**PhishGuard** é uma ferramenta de segurança cibernética desenvolvida em Python para analisar URLs suspeitas. Ela verifica a idade do domínio e consulta a reputação em bases de dados de inteligência de ameaças (Threat Intelligence).

## 🚀 Funcionalidades

- **Verificação de Idade do Domínio:** Identifica sites criados recentemente (comum em campanhas de Phishing).
- **Integração com VirusTotal:** Consulta a "ficha criminal" do link usando a API pública do VirusTotal.
- **Análise Inteligente:** Cruza dados para fornecer um veredito de risco (Seguro, Suspeito ou Perigoso).
- **Proteção de Credenciais:** Uso de variáveis de ambiente (`.env`) para segurança da API Key.

## 🛠️ Tecnologias Utilizadas

- **Python 3**
- **Bibliotecas:** `requests`, `python-whois`, `python-dotenv`
- **API:** VirusTotal v3

## ⚙️ Como Rodar

1. Clone o repositório:

    git clone [https://github.com/SEU_USUARIO/phishguard.git](https://github.com/SEU_USUARIO/phishguard.git)

2. Instale as dependências:

    pip install -r requirements.txt

3. Configure a API Key:
   - Crie um arquivo `.env` na raiz do projeto.
   - Adicione sua chave do VirusTotal: `VT_API_KEY=sua_chave_aqui`

4. Execute:

    python app.py

## 📝 Licença

Este projeto é de código aberto e destinado a fins educacionais e de conscientização sobre segurança.