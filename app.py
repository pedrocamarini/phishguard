import os
import whois
import requests
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv

# Carrega as variáveis do arquivo .env
load_dotenv()

def obter_url_final(url):
    """
    Segue os redirecionamentos (HTTP 301/302) para encontrar o destino real.
    """
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        # stream=True economiza banda e aumenta segurança ao não baixar o corpo da resposta
        response = requests.get(url, allow_redirects=True, timeout=10, stream=True, headers=headers)
        return response.url
    except Exception as e:
        print(f"⚠️ Aviso: Não foi possível rastrear redirecionamentos: {e}")
        return url

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

def salvar_log(url, veredito, pontos):
    """
    Salva o resultado da análise em um arquivo de texto para auditoria futura.
    """
    arquivo_log = "relatorio_seguranca.txt"
    data_hora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    
    # Define um rótulo visual para o log
    if pontos >= 3:
        status = "[PERIGO]  "
    elif pontos > 0:
        status = "[SUSPEITO]"
    else:
        status = "[SEGURO]  "
        
    linha_log = f"{data_hora} | {status} | {url} | Resultado: {veredito}\n"
    
    try:
        # 'a' (append) adiciona ao final do arquivo sem apagar o histórico
        with open(arquivo_log, 'a', encoding='utf-8') as f:
            f.write(linha_log)
        print(f"📝 Evidência salva em: {arquivo_log}")
    except Exception as e:
        print(f"⚠️ Erro ao salvar log: {e}")

def consultar_virustotal(domain):
    print(f"🦠 Consultando VirusTotal para: {domain}...")
    
    api_key = os.getenv('VT_API_KEY')
    
    if not api_key:
        return "❌ ERRO: Chave da API não encontrada no arquivo .env"

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return stats
        elif response.status_code == 404:
            return "NaoListado"
        else:
            return f"Erro API: {response.status_code}"
            
    except Exception as e:
        return f"Erro na conexão: {e}"

def analisar_dominio(url_inicial):
    print(f"\n🚀 INICIANDO INVESTIGAÇÃO...")
    
    # 1. Rastreio de Redirecionamento
    url_final = obter_url_final(url_inicial)
    
    if url_final != url_inicial:
        print(f"🔀 Redirecionamento detectado!")
        print(f"   Original: {url_inicial}")
        print(f"   Destino Final: {url_final}")
    else:
        print(f"➡️  Sem redirecionamentos. Analisando URL original.")
    
    print("-" * 40)
    
    # 2. Limpeza e Extração do Domínio
    domain = limpar_url(url_final)
    if not domain: return "Url Inválida"
    print(f"🔍 Analisando Domínio: {domain}")

    pontos_perigo = 0
    veredito_idade = "Desconhecido"

    # 3. WHOIS (Idade)
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
        print("⚠️ Erro ao consultar WHOIS (Domínio pode ser privado ou erro de conexão)")

    # 4. REPUTAÇÃO (VirusTotal)
    resultado_vt = consultar_virustotal(domain)
    veredito_vt = "Limpo"
    
    if isinstance(resultado_vt, dict):
        maliciosos = resultado_vt.get('malicious', 0)
        print(f"👿 Detectado como malicioso por: {maliciosos} antivírus")
        
        if maliciosos > 0:
            pontos_perigo += 10
            veredito_vt = f"PERIGOSO ({maliciosos} alertas)"
    elif resultado_vt == "NaoListado":
        print("👻 VirusTotal não conhece este domínio.")
    
    # 5. RELATÓRIO E LOG
    print("-" * 40)
    print("📊 RELATÓRIO FINAL")
    print(f"🔗 URL Analisada: {url_final}")
    print(f"1. Idade: {veredito_idade}")
    print(f"2. Reputação: {veredito_vt}")
    print("-" * 40)
    
    resultado_final_texto = ""
    if pontos_perigo >= 3:
        resultado_final_texto = "GOLPE / PERIGOSO"
    elif pontos_perigo > 0:
        resultado_final_texto = "SUSPEITO"
    else:
        resultado_final_texto = "SEGURO"
        
    # Salva no arquivo de texto
    salvar_log(url_final, resultado_final_texto, pontos_perigo)
    
    return f"Resultado: {resultado_final_texto}"

if __name__ == "__main__":
    url_teste = input("Cole a URL para verificar: ")
    
    # Adiciona http se o usuário esquecer
    if not url_teste.startswith(('http://', 'https://')):
        url_teste = 'http://' + url_teste
        
    print(analisar_dominio(url_teste))