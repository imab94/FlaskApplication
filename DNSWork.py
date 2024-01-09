counter = 0


def fetch_api_data(file_name, abuseip, virustotalip):
    import requests
    import pandas as pd
    import csv
    import datetime
    import json
    # abusdb : 2726e60cd7dcb33cefda1642977f5acd7edf1af69e71cb27fbdcf85158c70fabba0df950a8b08cd5
    # virusTotal : d51a0015a19006dc60d4c959efc6af0286635444693572e479c16c2238959c70
    df = pd.read_excel("C:\\Users\\Arun Bhardwaj\\Downloads\\OSINT_datafile.xlsx", engine='openpyxl', sheet_name="Sheet1")
    field_names = ['IP Address', 'IP Risk Score-Abuseipdb', 'Domain Risk Score-VT','Last reported in Abuse DB','Last reported in VT','HostName-for the IP address','domain','Country Code']
    headers1 = {
        'Accept': 'application/json',
        'Key': abuseip,
    }
    headers2 = {
         'Accept': 'application/json',
         'x-apikey': virustotalip,
    }
    Data = []
    # Defining the api-endpoint
    for row in range(len(df)):
        url1 = 'https://api.abuseipdb.com/api/v2/check'
        url2 = f"https://www.virustotal.com/api/v3/ip_addresses/{df['IP Address'][row]}"
        # Columns
        querystring = {
        'ipAddress':df['IP Address'][row],
        'maxAgeInDays': '90'
        }
        # AbuseIP DB Data
        response1 = requests.request(method='GET', url=url1, headers=headers1, params=querystring)
        decodedResponse1 = json.loads(response1.text)
        AbuseIP = json.dumps(decodedResponse1, sort_keys=True, indent=4)
        # Virus Total Data
        response2 = requests.request("GET", url2, headers=headers2)
        VirusTotal = json.loads(response2.text)
        dict1 = json.loads(AbuseIP)
        ipAdd = dict1['data']['ipAddress']
        riskScore = dict1['data']['abuseConfidenceScore']
        DomainRisk = VirusTotal['data']['attributes']['last_analysis_stats']
        DomainRiskHarmless = DomainRisk['harmless']+DomainRisk['undetected']
        Malicious = DomainRisk['malicious']
        LastReportedAbuse = dict1['data']['lastReportedAt']
        if LastReportedAbuse == None:
            LastReportedAbuse = ""
        LastReportedAbuse = LastReportedAbuse[slice(10)]
        LastReportedVT = VirusTotal['data']['attributes']['last_modification_date']
        LastReportedVT = datetime.datetime.fromtimestamp(LastReportedVT).strftime("%d-%m-%Y")
        HostNameIPAddress = dict1['data']['hostnames']
        if HostNameIPAddress == list():
            HostNameIPAddress = ""
        else:
            HostNameIPAddress = HostNameIPAddress[0]
        DomainName = dict1['data']['domain']
        CountryCode = dict1['data']['countryCode']
        Data.append({'IP Address':ipAdd,'IP Risk Score-Abuseipdb':riskScore,'Domain Risk Score-VT':str(Malicious)+"/"+str(DomainRiskHarmless),'Last reported in Abuse DB':LastReportedAbuse,'Last reported in VT':LastReportedVT,'HostName-for the IP address':HostNameIPAddress,'domain':DomainName,'Country Code':CountryCode})
        global counter
        counter += 1
        # print(f"Counter{counter}")
    # saving a file as a CSV file
    fileName = f"{file_name}.csv"
    file = open(fileName,"w",newline='')
    dict_writer = csv.DictWriter(file,fieldnames=field_names)
    dict_writer.writeheader()
    dict_writer.writerows(Data)
    file.close()

