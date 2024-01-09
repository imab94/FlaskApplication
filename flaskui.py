from flask import Flask, render_template, url_for, request, send_file
import DNSWork
import os
import smtplib
from email.message import EmailMessage

app = Flask(__name__) 

UPLOAD_FOLDER = 'UI/templates'
app.config['SECRET_KEY'] = '05a66ec59b57562b4dd3e7243d5b8939'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

toaddr = ""

# count_file = DNSWork.counter
# print("count file ",count_file)


@app.route("/")
def hello():
    return render_template('home.html')


file_names = ""


@app.route('/upload_file', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        global toaddr
        toaddr = request.form.get('email').strip()
        abuseip = request.form.get('abusedbip').strip()
        print(abuseip)
        virustotalip = request.form.get('virustotalid').strip()
        print(virustotalip)
        f = request.files['myfile']
        global file_names
        file_names = f.filename.split(".")
        file_names = file_names[0]
        print(file_names)
        if f.filename.endswith(('.csv', '.xlsx', '.xls')):
            try:
                DNSWork.fetch_api_data(file_names,abuseip,virustotalip)
            except Exception:
                return "<h3>Data Not fetched</h3>"
        else:
            return "<h3>Wrong file Provided!</h3>"
    return render_template('home.html')

    
@app.route('/send_email', methods=['GET','POST'])
def send_email():
    try:
        if request.method == "GET":
            # print("yes")
            fromaddr = "bhardwarun1997@gmail.com"
            msg = EmailMessage()
            msg['From'] = fromaddr
            msg['To'] = "arunbhardwaj01011997@gmail.com"
            msg['Subject'] = "IOC Validation File Attached"
            ascii = chr(92)
            # open the file to be sent
            if file_names:
                abs_file_path = os.path.abspath(file_names)+".csv"
                # print(abs_file_path)
                new_abs_path = abs_file_path.replace('\\', ascii)
                # myfile= f'D:{ascii}PycharmProjects{ascii}pythonProject{ascii}UIinterface{ascii}UI{ascii}OSINT_datafile.csv'
                # new_path = myfile.replace("\\","\\\\")
                # new_path =re.escape(myfile)
                # print(new_abs_path)
                with open(new_abs_path,'rb') as f:
                    file_data = f.read()
                    # print("File data in binary",file_data)
                    file_name = f.name
                    # print("File name",file_name)
                    msg.add_attachment(file_data,maintype='application', subtype="csv",filename=file_name.split("\\")[-1])

                with smtplib.SMTP_SSL('smtp.gmail.com',465) as server:
                    server.login(fromaddr,'AiAm12aNar0')
                    server.send_message(msg)
                # print("logged in!")
                # datas = {"success" : "Success, Email Sent!"}
                data = "Success"
                return render_template("home.html",result=data)
            else:
                # datas = {"error":"Please provide file"}
                data = "error"
                return render_template("home.html",result=data)
    except Exception as e:
        print(e)
        return "<h3>Email not Sent!</h3>"


# def download_file():
#     try:
#         if request.method == "GET":
#             abs_file_path = os.path.abspath(file_names)+".csv"
#             return send_file(abs_file_path, as_attachment=True)
#
#     except Exception:
#         return "<h3>No file Provided!</h3>"
#         # data = "please Provide file"

if __name__=='__main__':
    app.run(debug=True,port=5000)
    
