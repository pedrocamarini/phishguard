import os
import whois
import requests
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv

# Carrega as variáveis do arquivo .env
load_dotenv()

def limpar_url(url):
    try:
        domain = urlparse(url).netloc
        if not domain:
            domain = url
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except:
        return None

def consultar_virustotal(domain):
    print(f"🦠 Consultando VirusTotal para: {domain}...")
    
    api_key = os.getenv('VT_API_KEY') # Pega a chave do cofre
    
    if not api_key:
        return "❌ ERRO: Chave da API não encontrada no arquivo .env"

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            return {'malicious': malicious, 'suspicious': suspicious}
        
        elif response.status_code == 404:
            return "NaoListado" # O site é tão novo ou irrelevante que o VT não conhece
        else:
            return f"Erro API: {response.status_code}"
            
    except Exception as e:
        return f"Erro na conexão: {e}"

def analisar_dominio(url):
    print(f"\n🔍 INICIANDO ANÁLISE: {url}")
    print("-" * 40)
    
    # 1. Limpeza
    domain = limpar_url(url)
    if not domain: return "Url Inválida"
    print(f"🌐 Domínio: {domain}")

    # 2. WHOIS (Idade)
    veredito_idade = "Desconhecido"
    pontos_perigo = 0
    
    try:
        domain_info = whois.whois(domain)
        data_criacao = domain_info.creation_date
        
        if isinstance(data_criacao, list): data_criacao = data_criacao[0]
        
        if data_criacao:
            hoje = datetime.now()
            if data_criacao.tzinfo: hoje = datetime.now(data_criacao.tzinfo)
            
            idade = (hoje - data_criacao).days
            print(f"📅 Idade: {idade} dias")
            
            if idade < 30:
                veredito_idade = "CRÍTICO (Site Recém-nascido)"
                pontos_perigo += 3
            elif idade < 180:
                veredito_idade = "ALERTA (Site Jovem)"
                pontos_perigo += 1
            else:
                veredito_idade = "Seguro (Antigo)"
    except:
        print("⚠️ Erro ao consultar WHOIS")

    # 3. REPUTAÇÃO (VirusTotal)
    resultado_vt = consultar_virustotal(domain)
    veredito_vt = "Limpo"
    
    if isinstance(resultado_vt, dict):
        maliciosos = resultado_vt['malicious']
        print(f"👿 Detectado como malicioso por: {maliciosos} antivírus")
        
        if maliciosos > 0:
            pontos_perigo += 10 # Se um antivirus pegou, já é crítico
            veredito_vt = f"PERIGOSO ({maliciosos} alertas)"
    elif result_vt == "NaoListado":
        print("👻 VirusTotal não conhece este domínio.")
    
    # 4. CONCLUSÃO FINAL
    print("-" * 40)
    print("📊 RELATÓRIO FINAL")
    print(f"1. Idade: {veredito_idade}")
    print(f"2. Reputação: {veredito_vt}")
    print("-" * 40)
    
    if pontos_perigo >= 3:
        return "🚨 RESULTADO: GOLPE / PERIGOSO! NÃO ACESSE."
    elif pontos_perigo > 0:
        return "⚠️ RESULTADO: SUSPEITO. Tenha cuidado."
    else:
        return "✅ RESULTADO: Aparentemente seguro."

if __name__ == "__main__":
    url_teste = input("Cole a URL: ")
    print(analisar_dominio(url_teste))