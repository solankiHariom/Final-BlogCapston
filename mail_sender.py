import smtplib

EMAIL = 'automateharry@gmail.com'
PASSWORD = 'yzkvbfxxlijdazqx'


class SendMail():
    def __init__(self) -> None:
        self.connection = smtplib.SMTP('smtp.gmail.com', 587)
        print('\nconnection status :', self.connection.noop(), '\n')
        self.connection.starttls()
        self.connection.login(user=EMAIL, password=PASSWORD)


    def send_mail(self, data_dict):
        msg = ''
        for key, value in data_dict.items():
            msg += f'{key} : {value}\n'
        print(msg)

        self.connection.sendmail(from_addr=EMAIL, to_addrs=EMAIL,
                                 msg=f"Subject:Blog Capstone Contact.\n\n{msg}")
        self.connection.close()

