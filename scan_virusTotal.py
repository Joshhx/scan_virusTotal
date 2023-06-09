import re
import sys
import subprocess
from time import sleep
from virus_total_apis import PublicApi

#Anadimos nuestra API_KEY de Virus-Total
API_KEY = '4b5cf6cd61753f876ee093bc2070d5849f9f3e9fdd9ed5fdd28c9caafe867e76'
api = PublicApi(API_KEY)

def command(): #devuelve el stdout
    comando = ' '.join(sys.argv[1:])
    cmdout = subprocess.check_output(comando, shell=True, encoding="utf-8")
    return cmdout

def analize_url(url):
    try:
        response = api.get_url_report(url)
        if response['results']['response_code'] == 1: #Escanning OK
            print(response['results']['url'])
            if response['results']['positives'] > 0:
                print("Malware Detected!!!")
                print(response['results']['positives'],"/",response['results']['total'])  
                for each in response['results']['scans']:
                    if response['results']['scans'][each]['detected'] == True:
                        print(each, ' = ', response['results']['scans'][each]['result'])
            else:
                print('URL sin amenazas detectadas')
        else:
            print("Error en el analisis")
            print(response['results']['resource'])
            print(response['results']['verbose_msg'])
    except Exception as e:
        print(url, "\n", e)

def analize_ip(ip):
    try:
        print(f"IP: {ip}")
        response = api.get_ip_report(ip)
        if response['results']['response_code'] == 1: #Escanning OK
            print(f'Country: {response["results"]["country"]}')

            for each in response['results']['detected_referrer_samples']:
                if each['positives'] > 0:
                    print(f'detected referrer samples: {each["positives"]}/{each["total"]}')
                else:
                    print('No detected referrer samples \n')
            for each in response['results']['detected_urls']:
                if each['positives'] > 0:
                    print(f'detected URL: {each["positives"]}/{each["total"]}')     
                    print(f"scan date: {each['scan_date']}")
            print(response["results"]["verbose_msg"])
    except Exception as e:
        print(e) 

def main():
    stdIn = command().split("\n") #Creamos una lista con las URL
    stdIn_filter = list(filter(None, stdIn))#eliminamos los valores vacios
    patron = r'^[\s-]*([a-zA-Z0-9].*)$'
    re_url = re.compile('^(?!:\/\/)([a-zA-Z0-9-_]{1,63}\.)+[^\s/$.?#].[^\s]*$')
    re_ip = re.compile("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$")
    count = 0

    for element in stdIn_filter: 
        if count % 4 != 0 or count == 0:
            element = re.match(patron, element)
            element = element.group(1)
            if re_ip.findall(element):
                analize_ip(element) #Analizamos IP
            elif re_url.findall(element):
                analize_url(element) #Analizamos las URL 
            else:
                print("ERROR No se Reconoce ", element)
            print('============================')       
        else: 
            print(f"Se han realizado {count} analisis, Esperando 1 minuto...")
            sleep(60) 

        count = count + 1

if __name__ == '__main__':
    main()