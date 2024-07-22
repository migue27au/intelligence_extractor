#!/usr/bin/python3

import argparse, json, requests, re
from bs4 import BeautifulSoup
import dns.resolver
from time import sleep
import random

import shodan
import whois

# AS = Autonomous System
# IRR = Internet Routing Registry

HEADERS = {
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
	"Accept-Language": "en-US,en;q=0.9",
	"Accept-Encoding": "gzip, deflate, br",
	"Connection": "keep-alive",
	"Upgrade-Insecure-Requests": "1",
	"Sec-Fetch-Dest": "document",
	"Sec-Fetch-Mode": "navigate",
	"Sec-Fetch-Site": "none",
	"Sec-Fetch-User": "?1",
	"Cache-Control": "max-age=0"
}

REGEX_IP = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
REGEX_DOMAIN = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b')

DNS_SERVERS = [
	"1.0.0.1",
	"1.1.1.1",
	"103.86.96.100",
	"149.112.112.112",
	"185.228.168.9",
	"185.228.169.9",
	"208.67.220.220",
	"208.67.222.222",
	"216.146.35.35",
	"45.90.28.190",
	"64.6.64.6",
	"76.76.10.0",
	"76.76.19.19",
	"76.76.2.0",
	"8.26.56.26",
	"8.8.4.4",
	"8.8.8.8",
	"9.9.9.9",
	"94.140.14.14",
	"94.140.15.15",
	"95.85.95.85"
]

def printBeauty(text, mode = 'verbose', indentation = ""):
	BOLD = '\033[1m'
	DEBUG = '\033[105m'
	VERBOSE = '\033[35m'
	BLUE = '\033[94m'
	INFO = '\033[96m'
	OK = '\033[92m'
	WARNING = '\033[93m'
	DANGER = '\033[91m'
	ENDC = '\033[0m'
	if mode == 'verbose':
		print(indentation + VERBOSE + BOLD + "[v] " + ENDC + text)
	elif mode == 'ok':
		print(indentation + OK + BOLD + "[+] " + ENDC + text)
	elif mode == 'info':
		print(indentation + INFO + BOLD + "[i] " + ENDC + text)
	elif mode == 'warning':
		print(indentation + WARNING + BOLD + "[!] " + ENDC + text)
	elif mode == 'bad':
		print(indentation + DANGER + BOLD + "[-] " + ENDC + text)
	elif mode == 'critical':
		print(indentation + DANGER + BOLD + "[!] " + text + ENDC)
	elif mode =='debug':
		current_time = time.strftime("%H:%M:%S", time.localtime())
		print(indentation + DEBUG + BOLD + "[D] " + ENDC + DEBUG + current_time + " -> " + ENDC + text)

def clean_text(text):
		return text.strip().replace('\n', '').replace('\t', '').replace('\r', '')

def intel_nslookup(domain):
	data = {}
	for query in ['A', 'AAAA', 'SOA', 'TXT', 'CNAME']:
		data[query] = []
		for dns_server in DNS_SERVERS: 
			resolver = dns.resolver.Resolver()
			try:
				resolver.nameservers = [dns_server]
				answers = resolver.resolve(domain, query)
				for answer in answers:
					answer = str(answer)
					if answer.endswith("."):
						answer = answer[:-1]
					data[query].append(answer)
					printBeauty(f"Query {query}: {answer}", mode="ok", indentation="\t")

			except Exception as e:
				printBeauty(f"Ocurrió un error: {e}", mode="bad", indentation="\t")


	for key in data.keys():
		data[key] = list(set(data[key]))
	return data

def intel_reverse_nslookup(ip_address):
	data = {"PTR": []}
	for dns_server in DNS_SERVERS: 
		resolver = dns.resolver.Resolver()
		resolver.nameservers = [dns_server]
		try:
			reversed_ip = dns.reversename.from_address(ip_address)
			answers = resolver.resolve(reversed_ip, 'PTR')
			# Imprimir los resultados PTR
			printBeauty(f"Resultados de la consulta PTR para {ip_address} usando el servidor {dns_server}:", indentation="\t")
			for answer in answers:
				answer = str(answer)
				if answer.endswith("."):
					answer = answer[:-1]
				data["PTR"].append(answer)
				printBeauty(f"Query PTR: {answer}", mode="ok", indentation="\t")

		except Exception as e:
			printBeauty(f"Ocurrió un error: {e}", mode="bad", indentation="\t")

	data["PTR"] = list(set(data["PTR"]))
	return data

def intel_whois(url):
	response = requests.get(url, headers=HEADERS)

	if response.status_code == 200:
		soup = BeautifulSoup(response.content, 'html.parser')
		whois_element = soup.find(id="whois")
		dns_element =  soup.find(id='dns').find('div', class_='boundedcontent')
		irr_element = soup.find(id="irr")

		details = {}
		
		if dns_element:
			# Extraer Start of Authority
			dnsdata_section = dns_element.find('div', class_='dnshead', string='Start of Authority')
			if dnsdata_section:
				dnsdata_section = dnsdata_section.find_next_sibling('div', class_='dnsdata').get_text(separator='\n')
				
				details["Start of Authority"] = {}
				dnsdata_section = dnsdata_section.replace("\t", " ")
				while "  " in dnsdata_section:
					dnsdata_section = dnsdata_section.replace("  ", " ")
				for line in dnsdata_section.split("\n"):
					if len(line) > 0 and ":" in line:
						if line.split(": ")[0].startswith(" "):
							line = line[1:]
						if line.split(": ")[0] not in details["Start of Authority"].keys():
							details['Start of Authority'][line.split(": ")[0]] = ": ".join(line.split(": ")[1:])
						else:
							details['Start of Authority'][line.split(": ")[0]] += " " + ": ".join(line.split(": ")[1:])
			# Extraer Nameservers
			nameservers_section = dns_element.find('div', class_='dnshead', string='Nameservers')
			if nameservers_section:
				nameservers_section = nameservers_section.find_next_sibling('div', class_='dnsdata')
				details['Nameservers'] = []
				for item in nameservers_section.find_all('a'):
					details['Nameservers'].append(item["title"])

			# Extraer Mail Exchangers
			mx_section = dns_element.find('div', class_='dnshead', string='Mail Exchangers')
			if mx_section:
				mx_section = mx_section.find_next_sibling('div', class_='dnsdata')
				details['Mail Exchangers'] = []
				for item in mx_section.find_all('a'):
					details['Mail Exchangers'].append(item["title"])

			# Extraer TXT Records
			txt_section = dns_element.find('div', class_='dnshead', string='TXT Records')
			if txt_section:
				txt_section = txt_section.find_next_sibling('div', class_='dnsdata').get_text(separator='\n')
				details['TXT Records'] = [clean_text(record) for record in txt_section.split('\n') if record.strip()]
				details['TXT IPs'] = REGEX_IP.findall(' '.join(details['TXT Records']))
				details['TXT Domains'] = REGEX_DOMAIN.findall(' '.join(details['TXT Records']))


			# Extraer A Records
			a_records_section = dns_element.find('div', class_='dnshead', string='A Records')
			if a_records_section:
				a_records_section = a_records_section.find_next_sibling('div', class_='dnsdata')
				details['A Records'] = [a.get_text() for a in a_records_section.find_all('a')]

			# Extraer AAAA Records
			aaaa_records_section = dns_element.find('div', class_='dnshead', string='AAAA Records')
			if aaaa_records_section:
				aaaa_records_section = aaaa_records_section.find_next_sibling('div', class_='dnsdata')
				details['AAAA Records'] = [a.get_text() for a in aaaa_records_section.find_all('a')]

			# Extraer AAAA Records
			cname_records_section = dns_element.find('div', class_='dnshead', string='Canonical Names')
			if cname_records_section:
				cname_records_section = cname_records_section.find_next_sibling('div', class_='dnsdata')
				details['CNAME Records'] = [a.get_text() for a in cname_records_section.find_all('a')]
			

		if whois_element:
			whois_info = whois_element.get_text()

			details["whois"] = {}
			
			#quitando las tabulaciones. Cambio por " " por si se usa para separar palabras. La línea de abajo quitará los espacios dobles
			whois_info = whois_info.replace("\t", " ")
			#quitando los dobles espacios
			while "  " in whois_info:
				whois_info = whois_info.replace("  ", " ")

			for line in whois_info.split("\n"):
				if len(line) > 0:
					if line.split(": ")[0] not in details["whois"].keys():
						details["whois"][line.split(": ")[0]] = ": ".join(line.split(": ")[1:])
					else:
						details["whois"][line.split(": ")[0]] += " " + ": ".join(line.split(": ")[1:])

			print(f"Información WHOIS para {args.ip}:\n{whois_info}")

		else:
			printBeauty(f"No se encontró el elemento WHOIS en la página", "warning")

		if irr_element:
			irr_info = irr_element.get_text()

			details["irr"] = {}
			#quitando los dobles espacios
			irr_info = irr_info.replace("\t", " ")
			while "  " in irr_info:
				irr_info = irr_info.replace("  ", " ")

			for line in irr_info.split("\n"):
				print(line)
				if len(line) > 0:
					if line.split(": ")[0] not in details["irr"].keys():
						details["irr"][line.split(": ")[0]] = ": ".join(line.split(": ")[1:])
					else:
						details["irr"][line.split(": ")[0]] += " " + ": ".join(line.split(": ")[1:])

			print(f"Información WHOIS para {args.ip}:\n{irr_info}")

		else:
			printBeauty(f"No se encontró el elemento WHOIS en la página", "warning")
		
		return details
	else:
		printBeauty(f"Error al realizar la solicitud HTTP. Código de estado: {response.status_code}", "bad")

	return None

def p_ssh(data):
	service_enumeration = {}
	if "kex" in data.keys():
		if "encryption_algorithms" in data["kex"].keys():
			service_enumeration["encryption_algorithms"] = ', '.join(data["kex"]["encryption_algorithms"])
			printBeauty("Encryption algorithms: {}".format(service_enumeration["encryption_algorithms"]), 'info', indentation="\t\t")
		if "kex_algorithms" in data["kex"].keys():
			service_enumeration["key_exchange_algorithms"] = ', '.join(data["kex"]["kex_algorithms"])
			printBeauty("Key exchange algorithms: {}".format(service_enumeration["key_exchange_algorithms"]), 'info', indentation="\t\t")
		if "mac_algorithms" in data["kex"].keys():
			service_enumeration["MAC_algorithms"] = ', '.join(data["kex"]["mac_algorithms"])
			printBeauty("MAC algorithms: {}".format(service_enumeration["MAC_algorithms"]), 'info', indentation="\t\t")
		if "server_host_key_algorithms" in data["kex"].keys():
			service_enumeration["Server_key_algorithms"] = ', '.join(data["kex"]["server_host_key_algorithms"])
			printBeauty("Server key algorithms: {}".format(service_enumeration["Server_key_algorithms"]), 'info', indentation="\t\t")
		if "compression_algorithms" in data["kex"].keys():
			service_enumeration["compression_algorithms"] = ', '.join(data["kex"]["compression_algorithms"])
			printBeauty("Compression algorithms: {}".format(service_enumeration["compression_algorithms"]), 'info', indentation="\t\t")
	return service_enumeration

def p_minecraft(data):
	service_enumeration = {}
	if "players" in data.keys():
		service_enumeration["Active_players"] = "{}/{} active".format(data["players"]["online"], data["players"]["max"])
		printBeauty("Players: {}".format(service_enumeration["Active_players"]), "info", indentation="\t\t")
	if "description" in data.keys():
		service_enumeration["description"] = data["description"]
		printBeauty("Description: {}".format(service_enumeration["description"]), "info", indentation="\t\t")
	if "modinfo" in data.keys():
		if "modList" in data["modinfo"].keys():
			mods = []
			for mod in data["modinfo"]["modList"]:
				mods.append("{}({})".format(mod["modid"], mod["version"]))
			if len(mods) > 0:
				service_enumeration["mods"] = ', '.join(mods)
				printBeauty("Mods: {}".format(service_enumeration["mods"]), "info", indentation="\t\t")
	return service_enumeration

def p_ftp(data):
	service_enumeration = {}
	if "anonymous" in data.keys() and data["anonymous"] == True:
		service_enumeration["Anonymous"] = True
		printBeauty("Anonymous", "info", indentation="\t\t")
	if "software" in data.keys():
		service_enumeration["Software"] = data["software"]
		printBeauty("Software: {}".format(service_enumeration["Software"]), "info", indentation="\t\t")
	return service_enumeration

def p_dns(data):
	service_enumeration = {}
	if "recursive" in data.keys():
		service_enumeration["Recursive"] = data["recursive"]
		printBeauty("Recursive: {}".format(service_enumeration["Recursive"]), "info", indentation="\t\t")
	if "software" in data.keys():
		service_enumeration["Software"] = data["software"]
		printBeauty("Software: {}".format(service_enumeration["Software"]), "info", indentation="\t\t")
	return service_enumeration

def p_mysql(data):
	service_enumeration = {}
	if "authentication_plugin" in data.keys():
		service_enumeration["Authentication"] = data["authentication_plugin"]
		printBeauty("Authentication: {}".format(service_enumeration["Authentication"]), "info", indentation="\t\t")
	return service_enumeration

def p_ssl(data):
	service_enumeration = {}
	if "versions" in data.keys():
		service_enumeration["SSL_versions"] = ', '.join(data["versions"])
		printBeauty("SSL versions: {}".format(service_enumeration["SSL_versions"]), "info", indentation="\t\t")
	if "subject" in data.keys() and "CN" in data["subject"].keys():
		service_enumeration["Certificate_common_name"] = data["Subject"]["CN"]
		printBeauty("Certificate Common name: {}".format(service_enumeration["Certificate_common_name"]), "info", indentation="\t\t")
	if "pubkey" in data.keys() and "bits" in data["pubkey"].keys() and "type" in data["pubkey"].keys() and data["pubkey"]["type"] == "RSA":
		service_enumeration["Certificate_public_key_size"] = data["pubkey"]["bits"]
		printBeauty("Certificate public key size: {}".format(service_enumeration["Certificate_public_key_size"]), "info", indentation="\t\t")
	if "trust" in data.keys() and "revoked" in data["trust"].keys() and data["trust"]["revoked"] == True:
		service_enumeration["Certificate_revoked"] = True
		printBeauty("Certificate Revoked", "info", indentation="\t\t")
	return service_enumeration

def p_http(data):
	service_enumeration = {}
	if "status" in data.keys():
		service_enumeration["status_code"] = str(data["status"])
		printBeauty("Status Code: {}".format(service_enumeration["status_code"]), "info", indentation="\t\t")
	if "waf" in data.keys():
		service_enumeration["WAF"] = str(data["waf"])
		printBeauty("WAF: {}".format(service_enumeration["WAF"]), "info", indentation="\t\t")
	if "server" in data.keys() and data["server"] != None:
		service_enumeration["server"] = str(data["server"])
		printBeauty("Server: {}".format(service_enumeration["server"]), "info", indentation="\t\t")
	if "sitemap" in data.keys() and data["sitemap"] != None:
		urls = list(set(re.findall(r'<loc>(.*?)</loc>', data["sitemap"])))
		print(urls)
		service_enumeration["sitemap"] = ", ".join(urls)
		printBeauty("Sitemap: {}".format(service_enumeration["sitemap"]), "info", indentation="\t\t")
	if "robots" in data.keys() and data["robots"] != None:
		service_enumeration["robots"] = str(data["robots"])
		printBeauty("Robots: {}".format(service_enumeration["robots"]), "info", indentation="\t\t")
	if "securitytxt" in data.keys() and data["securitytxt"] != None:
		service_enumeration["security.txt"] = str(data["securitytxt"])
		printBeauty("security.txt: {}".format(service_enumeration["securitytxt"]), "info", indentation="\t\t")

	return service_enumeration

def intel_shodan(shodan_api_key, ip):
	api = shodan.Shodan(shodan_api_key)
		
	try:
		ipinfo = api.host(args.ip)
		shodan_parsed_data = {}
		if "country_name" in ipinfo.keys() or "city" in ipinfo.keys() or ("latitude" in ipinfo.keys() and "longitude" in ipinfo.keys()):
			shodan_parsed_data["location"] = {}
			if "country_name" in ipinfo.keys():
				shodan_parsed_data["location"]["country"] = ipinfo["country_name"]
				printBeauty("Country: {}".format(shodan_parsed_data["location"]["country"]), 'info')
			if "city" in ipinfo.keys():
				shodan_parsed_data["location"]["city"] = ipinfo["city"]
				printBeauty("City: {}".format(shodan_parsed_data["location"]["city"]), 'info')
			if "latitude" in ipinfo.keys() and "longitude" in ipinfo.keys():
				shodan_parsed_data["location"]["position"] = {"latitude":ipinfo["latitude"],"longitude":ipinfo["longitude"]}
				printBeauty("Location: {} {}".format(shodan_parsed_data["location"]["position"]["latitude"], shodan_parsed_data["location"]["position"]["longitude"]), 'info')
		if "org" in ipinfo.keys():
			shodan_parsed_data["organization"] = ipinfo["org"]
			printBeauty("Organization: {}".format(shodan_parsed_data["organization"]), 'info')

		if "os" in ipinfo.keys() and ipinfo["os"] != None:
			shodan_parsed_data["os"] = ipinfo["os"]
			printBeauty("OS: {}".format(shodan_parsed_data["os"]), 'info')

		if "hostnames" in ipinfo.keys() and len(ipinfo["hostnames"]) > 0:
			shodan_parsed_data["Hostnames"] = ', '.join(ipinfo["hostnames"])

		shodan_parsed_data["ports"] = []
		if "data" in ipinfo.keys():
			for index,data in enumerate(ipinfo["data"]):
				shodan_parsed_data["ports"].append({
					"port":data["port"],
					"protocol":data["transport"].upper()})
				printBeauty("{}/{}".format(shodan_parsed_data["ports"][index]["protocol"], shodan_parsed_data["ports"][index]["port"]), 'warning')

				if "product" in data.keys():
					shodan_parsed_data["ports"][len(shodan_parsed_data["ports"])-1]["product"] = data["product"]
					printBeauty("Product: {}".format(shodan_parsed_data["ports"][index]["product"]), 'ok', indentation="\t")
				if "version" in data.keys():
					shodan_parsed_data["ports"][len(shodan_parsed_data["ports"])-1]["version"] = data["version"]
					printBeauty("Version: {}".format(shodan_parsed_data["ports"][index]["version"]), 'ok', indentation="\t")

				if "cpe" in data.keys():
					shodan_parsed_data["ports"][index]["CPE"] = ','.join(data["cpe"])
					printBeauty("CPE: {}".format(shodan_parsed_data["ports"][index]["CPE"]), 'ok', indentation="\t")
				
				if "vulns" in data.keys() and len(data["vulns"].keys()) > 0:
					printBeauty("CVE", "bad", indentation="\t")
					for cve in data["vulns"].keys():
						shodan_parsed_data["ports"][index]["CVE"] = []
						if "cvss" in data["vulns"][cve].keys() and data["vulns"][cve]["cvss"] != None:
							shodan_parsed_data["ports"][index]["CVE"].append({"CVE": cve, "CVSS": data["vulns"][cve]["cvss"]})
							printBeauty("{}: {}".format(cve, data["vulns"][cve]["cvss"]), 'info', indentation="\t\t")
						else:
							shodan_parsed_data["ports"][index]["CVE"].append({"CVE": cve})
							printBeauty("{}".format(cve), 'info', indentation="\t\t")
					shodan_parsed_data["ports"][index]["CVE"] = ', '.join(data["vulns"].keys())
				#completar para el resto de protocolos
				shodan_parsed_data["ports"][index]["services"] = {}
				for protocol in set(data.keys())-{"vulns","ip","port","transport","version","cloud","location","product","hash","tags","timestamp","hostnames","org","data","asn","cpe23","info","isp","cpe","domains","ip_str","os","_shodan","opts"}:
					shodan_parsed_data["ports"][index]["services"][protocol] = {}
					if "service" not in shodan_parsed_data["ports"][index].keys():
						printBeauty("Service: {}".format(protocol), 'ok', indentation="\t")

						if protocol == "ssh":
							shodan_parsed_data["ports"][index]["services"][protocol] = p_ssh(data[protocol])
						if protocol == "minecraft":
							shodan_parsed_data["ports"][index]["services"][protocol] = p_minecraft(data[protocol])
						if protocol == "http":
							shodan_parsed_data["ports"][index]["services"][protocol] = p_http(data[protocol])
						if protocol == "ssl":
							shodan_parsed_data["ports"][index]["services"][protocol] = p_ssl(data[protocol])
						if protocol == "ftp":
							shodan_parsed_data["ports"][index]["services"][protocol] = p_ftp(data[protocol])
						if protocol == "dns":
							shodan_parsed_data["ports"][index]["services"][protocol] = p_dns(data[protocol])
						if protocol == "mysql":
							shodan_parsed_data["ports"][index]["services"][protocol] = p_mysql(data[protocol])
		return {"raw":ipinfo, "parsed":shodan_parsed_data, "extracted_ips":list(set(REGEX_IP.findall(str(ipinfo)))),"extracted_domains":list(set(REGEX_DOMAIN.findall(str(ipinfo))))}
	except shodan.exception.APIError:
		printBeauty(f"No se encontró el elemento SHODAN en la página para la IP {args.ip}.", "warning")
		return None

def intel_whois_aux(target):
	w = whois.whois(target)
	if len(str(w)) > 0:
		return json.loads(str(w))
	return None



def main(args):
	return_value = {}


	if args.asn != None:
		return_value["Target"] = args.asn
		return_value["Type"] = "ASN"

		printBeauty(f"Performing ASN search", "info")
		url = f"https://bgp.he.net/super-lg/report/api/v1/prefixes/originated/{(args.asn).replace('AS', '')}"

		response = requests.get(url, headers=HEADERS)
		return_value["BGP"] = {}
		return_value["BGP"]["prefixes"] = []
		print(response.text)
		for prefix in json.loads(response.text)["prefixes"]:
			return_value["BGP"]["prefixes"].append(prefix["Prefix"])

		if args.whois:
			printBeauty(f"Performing WHOIS", "info")
			url = f"https://bgp.he.net/{args.asn}"
			return_value["whois"] = intel_whois(url)
		if args.whois_aux:
			printBeauty(f"Performing WHOIS auxiliar", "info")
			return_value["whois_aux"] = intel_whois_aux(args.asn)

	elif args.domain != None:
		return_value["Target"] = args.domain
		return_value["Type"] = "domain"

		printBeauty(f"Performing DNS search", "info")
		if args.nslookup:
			printBeauty(f"Performing nslookup", "info")
			return_value["nslookup"] = intel_nslookup(args.domain)
		if args.whois:
			printBeauty(f"Performing WHOIS", "info")
			url = f"https://bgp.he.net/dns/{args.domain}"
			return_value["whois"] = intel_whois(url)
		if args.whois_aux:
			printBeauty(f"Performing WHOIS auxiliar", "info")
			return_value["whois_aux"] = intel_whois_aux(args.domain)


	elif args.ip:
		return_value["Target"] = args.ip
		return_value["Type"] = "IP"

		printBeauty(f"Performing IP search", "info")
		if args.reverse_nslookup:
			printBeauty(f"Performing reverse nslookup", "info")
			return_value["nslookup"] = intel_reverse_nslookup(args.ip)
		if args.whois:
			printBeauty(f"Performing WHOIS", "info")
			url = f"https://bgp.he.net/ip/{args.ip}"
			return_value["whois"] = intel_whois(url)
		if args.whois_aux:
			printBeauty(f"Performing WHOIS auxiliar", "info")
			return_value["whois_aux"] = intel_whois_aux(args.ip)
		if args.shodan != None:
			printBeauty(f"Performing SHODAN", "info")
			return_value["shodan"] = intel_shodan(args.shodan, args.ip)
	
	if args.output:
		args.output.write(json.dumps(return_value))
	print(json.dumps(return_value))

	if args.sleep:
		printBeauty(f"Waiting delay 5-8 s")
		sleep(5+(random.random()*4))





def parser():
	parser = argparse.ArgumentParser(description='Script para recopilar distinta información de ASN, dominios o IP.')
	
	# Grupo de parámetros obligatorios
	required_group = parser.add_argument_group('PARAMETROS OBLIGATORIOS')
	required_group.add_argument('-i', '--ip', type=str, help='Dirección IP objetivo')
	required_group.add_argument('-d', '--domain', type=str, help='Dominio objetivo')
	required_group.add_argument('-asn', '--asn', type=str, help='Número AS objetivo')
	
	# Grupo de parámetros opcionales
	optional_group = parser.add_argument_group('PARAMETROS OPCIONALES')
	optional_group.add_argument('--whois', action='store_true', help='Realiza una consulta WHOIS')
	optional_group.add_argument('--whois_aux', action='store_true', help="Realiza una consulta WHOIS auxiliar por si la anterior no devuelve resultados")
	optional_group.add_argument('--nslookup', action='store_true', help='Realiza una consulta NSLOOKUP a muchos servidores DNS')
	optional_group.add_argument('--reverse_nslookup', action='store_true', help='Realiza una consulta inversa NSLOOKUP a muchos servidores DNS')
	optional_group.add_argument('--all', action='store_true', help='Activa todas las flags anteriores')
	optional_group.add_argument('--shodan', type=str, help='Realiza una consulta SHODAN a la dirección IP proporcionada. Requiere un API_KEY')
	optional_group.add_argument("-o", "--output", type=argparse.FileType('a'), help="Guarda la salida json al final del archivo")
	optional_group.add_argument('--sleep', action='store_true', help='Añade un sleep aleatorio entre 5 y 8 segundos al terminar el script. Util para evitar bloqueos automáticos.')

	args = parser.parse_args()
	
	# Verificación de que se haya proporcionado al menos un parámetro obligatorio
	if not (args.ip or args.domain or args.asn):
		parser.error('Se debe proporcionar al menos uno de los siguientes parámetros: -i/--ip, -d/--domain, -asn/--asn.')
	
	if ((args.ip and args.domain) or
		(args.ip and args.asn) or
		(args.domain and args.asn)):
		parser.error('Se debe proporcionar SOLO uno de los siguientes parámetros: -i/--ip, -d/--domain, -asn/--asn.')

	if args.all:
		args.nslookup = True
		args.reverse_nslookup = True
		args.whois = True
		args.whois_aux = True
	
	return args

if __name__ == "__main__":
	args = parser()
	main(args)
