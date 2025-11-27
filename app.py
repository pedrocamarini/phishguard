import whois
from datetime import datetime
from urllib.parse import urlparse

def analisar_dominio(url):
    print(f"\n🔍 Analisando: {url}...")
    
    # 1. Extração do Domínio (Limpeza da URL)
    try:
        domain = urlparse(url).netloc
        if not domain:
            domain = url # Caso o usuário não digite http://
        
        # Remove 'www.' se existir
        if domain.startswith('www.'):
            domain = domain[4:]
            
    except Exception as e:
        return f"Erro ao processar URL: {e}"

    print(f"🌐 Domínio extraído: {domain}")

    # 2. Consulta WHOIS
    try:
        domain_info = whois.whois(domain)
        
        data_criacao = domain_info.creation_date
        
        # O whois as vezes retorna uma LISTA de datas. Pegamos a primeira.
        if isinstance(data_criacao, list):
            data_criacao = data_criacao[0]
            
        if not data_criacao:
            return "⚠️ Alerta: Não foi possível obter a data de criação."

        # 3. Cálculo da Idade (Com correção de Fuso Horário)
        hoje = datetime.now()

        # Se a data do site tiver fuso horário (aware), ajustamos o 'hoje' para ter fuso também
        if data_criacao.tzinfo:
            hoje = datetime.now(data_criacao.tzinfo)
        
        idade = hoje - data_criacao
        dias_de_vida = idade.days

        # 4. Veredito
        print(f"📅 Data de criação: {data_criacao}")
        print(f"🎂 Idade do domínio: {dias_de_vida} dias")
        print("-" * 30)
        
        if dias_de_vida < 30:
            return "🚨 PERIGO: Site com menos de 1 mês de vida! Altíssima chance de Phishing."
        elif dias_de_vida < 180:
            return "⚠️ CUIDADO: Site recente (menos de 6 meses). Atenção redobrada."
        else:
            return "✅ SINAL VERDE: Domínio antigo e confiável."

    except Exception as e:
        return f"Erro na consulta WHOIS: {e}"

# --- Execução ---
if __name__ == "__main__":
    url_teste = input("Cole a URL para verificar: ")
    resultado = analisar_dominio(url_teste)
    print(resultado)