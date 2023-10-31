from scapy.all import *
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By

def get_proto_info():
    service = Service(executable_path = 'C:/Python/Coding/chromedriver/chromedriver-win64/chromedriver.exe')
    options = Options()
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36'
    options.add_argument('user-agent=' + user_agent)
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    driver = webdriver.Chrome(options=options, service = service)
    
    target_url = 'https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml'
    driver.get(target_url)
    time.sleep(1)
    
    proto_info = {}
    
    for k in range(1, 147):
        proto_num = (driver.find_element(By.XPATH, f'//*[@id="table-protocol-numbers-1"]/tbody/tr[{k}]/td[1]')).text
        proto_name = (driver.find_element(By.XPATH, f'//*[@id="table-protocol-numbers-1"]/tbody/tr[{k}]/td[2]')).text
            
        if proto_num not in proto_info:
            proto_info[proto_num] = proto_name
        else:
            proto_info[proto_num].append(proto_name)
    return proto_info

def parse_packet(packet):
    src_ip = packet['IP'].src # IP Addr
    dst_ip = packet['IP'].dst
    proto = packet['IP'].proto
    
    # if proto in proto_info:  
    print(f"protocol: {proto}: {src_ip} -> {dst_ip}")  

    # if proto == 1:  
    #     print(f"TYPE:{packet[0][2].type}, CODE{packet[0][2].code}")
        
def sniffing(filter):
    sniff(filter = filter, prn = parse_packet, count=0)
    
if __name__ == "__main__": 
    filter = 'ip'
    proto_info = get_proto_info()
    sniffing(filter)

# def showPacket(packet):
#     a = packet.show()
#     print(a)
    
# def sniffing(filter):
#     sniff(filter = filter, prn = showPacket, count = 0)

# if __name__ == '__main__':
#     filter = 'ip'
#     sniffing(filter)
